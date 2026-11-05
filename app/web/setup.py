"""First-run setup wizard (M1-17, GM decisions Q4a and Q6).

- At startup (`prepare_setup`, called by the lifespan) a pending setup gets a fresh one-time
  setup token, logged ONCE at WARNING on the `app.setup` logger; only its digest is stored.
  It is re-issued at every process start while setup is pending (the previous one stops
  working). If the database cannot be read at startup the token is issued on the first request
  that finds setup pending.
- `SetupGateMiddleware`: while setup is pending every request except /healthz, /static/*,
  /setup and /language (the language switch of the setup page) gets a 303 to /setup. Once setup
  is not required (any user exists) the result is cached on `app.state` and no query is made.
  If the setup state cannot be read (database unavailable, app not started) the gate lets the
  request through and logs a warning once: it is a navigation aid, the protection is /setup
  itself (token, CSRF, 404 once a user exists).
- GET/POST /setup: 404 once setup is not required. POST needs the CSRF double-submit token
  (CSRFMiddleware) and the setup token; token attempts share the login throttle
  (`app.web.auth.login_throttle`) under a fixed account key. Success creates the instance admin,
  the optional first tenant with an owner membership, and logs the admin in.

Logs never carry the password, and the token appears only in the single issuance line.
"""

from __future__ import annotations

import logging
import math
import threading
from datetime import UTC, datetime
from typing import Final

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import Settings
from app.services.auth import SessionPolicy
from app.services.setup import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    SetupOutcome,
    complete_setup,
    issue_setup_token,
    setup_required,
    validate_setup_form,
    verify_setup_token,
)
from app.web import auth as web_auth
from app.web.deps import DbDep, SettingsDep, _session_factory
from app.web.templating import form_value, read_form, render

logger = logging.getLogger("app.setup")

SETUP_PATH: Final = "/setup"
EXEMPT_PATHS: Final = frozenset({"/healthz", SETUP_PATH, "/language"})
EXEMPT_PREFIXES: Final = ("/static/",)
TOKEN_ERROR_KEY: Final = "setup.token_required"
# Throttle key for setup token attempts (not an email address, so never a real account).
SETUP_THROTTLE_ACCOUNT: Final = "#setup-token"
_COMPLETE_ATTR = "setup_complete"
_ISSUED_ATTR = "setup_token_issued"
_WARNED_ATTR = "setup_state_warned"
_issue_lock = threading.Lock()

router = APIRouter()


def _factory_session(app: FastAPI) -> Session:
    # Reuse the request dependency's lazily created, app-wide session factory.
    return _session_factory(Request({"type": "http", "app": app}))()


def _issue_and_log(app: FastAPI, db: Session) -> None:
    with _issue_lock:
        if getattr(app.state, _ISSUED_ATTR, False):
            return
        token = issue_setup_token(db)
        db.commit()
        setattr(app.state, _ISSUED_ATTR, True)
    if token is not None:
        logger.warning(
            "First-run setup is pending. Open %s and enter this one-time setup token: %s "
            "(a new token is issued at every restart until setup is completed)",
            SETUP_PATH,
            token,
            extra={"event": "setup.token_issued"},
        )


def setup_pending(app: FastAPI) -> bool | None:
    """True while setup is pending (a token is issued if this process has none yet), False once
    it is not required (cached), None if the state cannot be read."""
    state = app.state
    if getattr(state, _COMPLETE_ATTR, False):
        return False
    if not isinstance(getattr(state, "settings", None), Settings):
        return None  # app not started (no lifespan): nothing to read the state with
    try:
        db = _factory_session(app)
        try:
            if not setup_required(db):
                setattr(state, _COMPLETE_ATTR, True)
                return False
            _issue_and_log(app, db)
            return True
        finally:
            db.close()
    except SQLAlchemyError as exc:
        if not getattr(state, _WARNED_ATTR, False):
            setattr(state, _WARNED_ATTR, True)
            logger.warning(
                "setup state could not be read from the database (%s)",
                type(exc).__name__,
                extra={"event": "setup.state_unavailable"},
            )
        return None


def prepare_setup(app: FastAPI) -> None:
    """Startup hook: issue and log the setup token if setup is pending."""
    setup_pending(app)


class SetupGateMiddleware:
    """Redirects every non-exempt request to /setup while setup is pending (pure ASGI)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] != "http"
            or "app" not in scope
            or path in EXEMPT_PATHS
            or path.startswith(EXEMPT_PREFIXES)
        ):
            await self.app(scope, receive, send)
            return
        if await run_in_threadpool(setup_pending, scope["app"]):
            await RedirectResponse(SETUP_PATH, status_code=303)(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _page(
    request: Request,
    *,
    status_code: int = 200,
    errors: list[str] | None = None,
    email: str = "",
    tenant_name: str = "",
) -> HTMLResponse:
    return render(
        request,
        "setup.html",
        status_code=status_code,
        errors=errors or [],
        email=email,
        tenant_name=tenant_name,
        password_min=PASSWORD_MIN_LENGTH,
        password_max=PASSWORD_MAX_LENGTH,
    )


def _ensure_pending(request: Request) -> None:
    if not setup_pending(request.app):
        raise HTTPException(status_code=404)


@router.get(SETUP_PATH, include_in_schema=False)
async def setup_form(request: Request) -> HTMLResponse:
    await run_in_threadpool(_ensure_pending, request)
    return _page(request)


@router.post(SETUP_PATH, include_in_schema=False)
async def setup_submit(request: Request, db: DbDep, settings: SettingsDep) -> Response:
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    await run_in_threadpool(_ensure_pending, request)
    email = form_value(form, "email")
    tenant_name = form_value(form, "tenant_name")
    keep = {"email": email, "tenant_name": tenant_name}
    ip = web_auth._client_ip(request)
    throttle = web_auth.login_throttle(request)

    wait = throttle.acquire(ip, SETUP_THROTTLE_ACCOUNT)
    if wait > 0:
        logger.warning("setup token attempt throttled", extra={"event": "setup.throttled"})
        page = _page(request, status_code=429, errors=["auth.login.throttled"], **keep)
        page.headers["Retry-After"] = str(max(1, math.ceil(wait)))
        return page
    token = form_value(form, "setup_token").strip()
    if not await run_in_threadpool(verify_setup_token, db, token):
        logger.info("setup token rejected", extra={"event": "setup.token_rejected"})
        return _page(request, status_code=400, errors=[TOKEN_ERROR_KEY], **keep)
    throttle.record_success(ip, SETUP_THROTTLE_ACCOUNT)

    data, errors = validate_setup_form(
        email, form_value(form, "password"), form_value(form, "password_confirm"), tenant_name
    )
    if data is None:
        return _page(request, status_code=400, errors=errors, **keep)
    result = await run_in_threadpool(
        complete_setup,
        db,
        data,
        token,
        secret_key=settings.secret_key,
        policy=SessionPolicy.from_settings(settings),
        hasher=web_auth.PASSWORD_HASHER,
    )
    if result.outcome is SetupOutcome.ALREADY_DONE:
        setattr(request.app.state, _COMPLETE_ATTR, True)
        raise HTTPException(status_code=404)
    if result.outcome is SetupOutcome.TOKEN_INVALID or result.session is None:
        return _page(request, status_code=400, errors=[TOKEN_ERROR_KEY], **keep)
    setattr(request.app.state, _COMPLETE_ATTR, True)
    logger.info(
        "setup completed",
        extra={
            "event": "setup.completed",
            "user_id": result.user_id,
            "tenant_id": result.tenant_id,
        },
    )
    response = RedirectResponse("/", status_code=303)
    web_auth._set_session_cookie(response, settings, result.session, datetime.now(UTC))
    return response
