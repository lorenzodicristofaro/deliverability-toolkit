"""Login, logout and the active-tenant switch (M1-15, GM decisions Q3 and Q4a).

- GET/POST /login: email + password. One generic failure message whatever the reason (unknown
  user, wrong password, inactive user, no password set). Throttled per (IP, account) by
  `app.services.login_throttle` (in-process: single web process only, see that module).
  Success rotates the session: the session the browser presented (if live) is revoked and a new
  one is issued, so the session-bound CSRF token changes too. Redirect target: `safe_next`.
- POST /logout: revokes the current session and clears the cookie.
- POST /tenants/switch: sets the session's active tenant only if the user holds a membership
  there (else 404). A tenant switch is a privilege change, so the session is rotated; the new
  session keeps the old absolute expiry (switching never extends a session).

CSRF is enforced by CSRFMiddleware: the login form uses the signed double-submit cookie (no
session yet), logout and tenant switch the session-bound token. Logs carry no email, password,
token or cookie value: only an event name and, after authentication, the user id.
"""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime

from argon2 import PasswordHasher
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.config import Settings
from app.core.i18n import t
from app.core.security import DEFAULT_HASHER, SESSION_COOKIE_NAME, session_cookie_settings
from app.models import UserSession
from app.repositories import UserMembershipsRepository
from app.repositories.base import coerce_id
from app.services.auth import (
    IssuedSession,
    SessionPolicy,
    authenticate,
    create_session,
    resolve_session,
    revoke_session,
)
from app.services.login_throttle import LoginThrottle
from app.web.deps import LOGIN_PATH, CurrentSession, DbDep, SettingsDep
from app.web.templating import form_value, read_form, render, request_language, safe_next

logger = logging.getLogger("app.auth")

TENANT_SWITCH_DENIED_KEY = "auth.tenant_switch.denied"
# Tests replace this with a fast hasher; production uses the argon2 defaults.
PASSWORD_HASHER: PasswordHasher = DEFAULT_HASHER
_MAX_ID_DIGITS = 19
_THROTTLE_STATE_ATTR = "login_throttle"

router = APIRouter()


def login_throttle(request: Request) -> LoginThrottle:
    """The app's throttle (created on first use; tests may set `app.state.login_throttle`)."""
    state = request.app.state
    throttle = getattr(state, _THROTTLE_STATE_ATTR, None)
    if not isinstance(throttle, LoginThrottle):
        throttle = LoginThrottle()
        setattr(state, _THROTTLE_STATE_ATTR, throttle)
    return throttle


def _client_ip(request: Request) -> str:
    # The direct peer. Proxy headers (X-Forwarded-For) are not trusted until a trusted-proxy
    # setting exists; behind a reverse proxy every client shares the proxy's address.
    return request.client.host if request.client is not None else ""


def _set_session_cookie(
    response: Response, settings: Settings, issued: IssuedSession, now: datetime
) -> None:
    expires = (
        issued.expires_at if issued.expires_at.tzinfo else issued.expires_at.replace(tzinfo=UTC)
    )
    max_age = max(1, math.ceil((expires - now).total_seconds()))
    base = session_cookie_settings(settings, max_age)
    response.set_cookie(
        base.key,
        issued.cookie_value,
        max_age=base.max_age,
        httponly=base.httponly,
        samesite=base.samesite,
        secure=base.secure,
        path=base.path,
    )


def _login_page(
    request: Request,
    *,
    status_code: int = 200,
    next_path: str = "/",
    email: str = "",
    error: str | None = None,
) -> HTMLResponse:
    return render(
        request,
        "login.html",
        status_code=status_code,
        next_path=next_path,
        email=email,
        error=error,
    )


@router.get(LOGIN_PATH, include_in_schema=False)
def login_form(request: Request) -> HTMLResponse:
    return _login_page(request, next_path=safe_next(request.query_params.get("next")))


def _login(
    db: Session, settings: Settings, email: str, password: str, presented_cookie: str | None
) -> IssuedSession | None:
    user = authenticate(db, email, password, hasher=PASSWORD_HASHER)
    if user is None:
        db.rollback()
        return None
    policy = SessionPolicy.from_settings(settings)
    if presented_cookie is not None:
        old = resolve_session(db, presented_cookie, settings.secret_key, policy=policy)
        if old is not None:
            revoke_session(db, old.session_id)
    memberships = UserMembershipsRepository(db, user.id).list()
    tenant_id = memberships[0].tenant_id if memberships else None
    issued = create_session(
        db, user, settings.secret_key, active_tenant_id=tenant_id, policy=policy
    )
    db.commit()
    logger.info("login succeeded", extra={"event": "auth.login", "user_id": user.id})
    return issued


@router.post(LOGIN_PATH, include_in_schema=False)
async def login(request: Request, db: DbDep, settings: SettingsDep) -> Response:
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    email = form_value(form, "email")
    password = form_value(form, "password")
    next_path = safe_next(form_value(form, "next"))
    ip = _client_ip(request)
    throttle = login_throttle(request)

    # Atomic check-and-reserve: the attempt is counted as a failure before the password is
    # verified, so parallel requests cannot all slip through; success clears the key.
    wait = throttle.acquire(ip, email)
    if wait > 0:
        logger.warning("login throttled", extra={"event": "auth.login_throttled"})
        page = _login_page(
            request, status_code=429, next_path=next_path, email=email, error="throttled"
        )
        page.headers["Retry-After"] = str(max(1, math.ceil(wait)))
        return page

    issued = await run_in_threadpool(
        _login, db, settings, email, password, request.cookies.get(SESSION_COOKIE_NAME)
    )
    if issued is None:  # the failure was already counted by acquire()
        logger.info("login failed", extra={"event": "auth.login_failed"})
        return _login_page(
            request, status_code=401, next_path=next_path, email=email, error="failed"
        )
    throttle.record_success(ip, email)
    response = RedirectResponse(next_path, status_code=303)
    _set_session_cookie(response, settings, issued, datetime.now(UTC))
    return response


def _clear_session_cookie(response: Response, settings: Settings) -> None:
    base = session_cookie_settings(settings)
    response.delete_cookie(
        base.key,
        path=base.path,
        secure=base.secure,
        httponly=base.httponly,
        samesite=base.samesite,
    )


def _logout(db: Session, session_id: int) -> None:
    revoke_session(db, session_id)
    db.commit()


@router.post("/logout", include_in_schema=False)
async def logout(auth: CurrentSession, db: DbDep, settings: SettingsDep) -> Response:
    await run_in_threadpool(_logout, db, auth.session_id)
    logger.info("logout", extra={"event": "auth.logout", "user_id": auth.user.id})
    response = RedirectResponse(LOGIN_PATH, status_code=303)
    _clear_session_cookie(response, settings)
    return response


def _parse_tenant_id(raw: str) -> int | None:
    if not raw.isascii() or not raw.isdigit() or len(raw) > _MAX_ID_DIGITS:
        return None
    return coerce_id(int(raw))


def _switch(
    db: Session, settings: Settings, auth: CurrentSession, tenant_id: int | None
) -> IssuedSession | None:
    if tenant_id is None:
        return None
    if UserMembershipsRepository(db, auth.user.id).get_for_tenant(tenant_id) is None:
        return None
    old = db.scalars(select(UserSession).where(UserSession.id == auth.session_id)).one()
    if not revoke_session(db, auth.session_id):
        db.rollback()  # already revoked (e.g. a concurrent switch or logout won): no new session
        return None
    issued = create_session(
        db,
        auth.user,
        settings.secret_key,
        active_tenant_id=tenant_id,
        policy=SessionPolicy.from_settings(settings),
    )
    new = db.scalars(select(UserSession).where(UserSession.id == issued.session_id)).one()
    new.expires_at = old.expires_at  # rotation never extends the absolute lifetime
    db.commit()
    logger.info(
        "tenant switched",
        extra={"event": "auth.tenant_switch", "user_id": auth.user.id, "tenant_id": tenant_id},
    )
    return IssuedSession(issued.session_id, issued.cookie_value, old.expires_at)


@router.post("/tenants/switch", include_in_schema=False)
async def switch_tenant(
    request: Request, auth: CurrentSession, db: DbDep, settings: SettingsDep
) -> Response:
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    tenant_id = _parse_tenant_id(form_value(form, "tenant_id"))
    next_path = safe_next(form_value(form, "next"))
    issued = await run_in_threadpool(_switch, db, settings, auth, tenant_id)
    if issued is None:
        lang = request_language(request.scope)
        raise HTTPException(status_code=404, detail=t(TENANT_SWITCH_DENIED_KEY, lang))
    response = RedirectResponse(next_path, status_code=303)
    _set_session_cookie(response, settings, issued, datetime.now(UTC))
    return response
