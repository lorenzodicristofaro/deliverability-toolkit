"""Jinja2 environment, per-request rendering and the language switch (M1-16).

Autoescape is on for every template. `t()` is bound to the request language; `csrf_token()` is
the real `csrf_token_for()` from M1-14 (lazy: an anonymous `dt_csrf` cookie is set only when a
template actually asks for the token). Language resolution: `dt_lang` cookie (user preference)
> Accept-Language > default (see `app.core.i18n.resolve_language`). The product name is the
`app_name` template global (a name, not translated).

`read_form` is the shared urlencoded body parser (python-multipart is not a dependency): bodies
are capped at `MAX_FORM_BYTES` and invalid UTF-8 yields an empty form.
"""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qs, unquote, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.datastructures import Headers
from starlette.types import Scope

from app.core.config import Settings
from app.core.csrf import csrf_token_for
from app.core.i18n import SUPPORTED_LANGUAGES, resolve_language, t
from app.core.security import session_cookie_settings

WEB_DIR: Final = Path(__file__).resolve().parent
TEMPLATES_DIR: Final = WEB_DIR / "templates"
STATIC_DIR: Final = WEB_DIR / "static"
LANGUAGE_COOKIE: Final = "dt_lang"
LANGUAGE_COOKIE_MAX_AGE: Final = 365 * 24 * 3600
MAX_FORM_BYTES: Final = 4096
APP_NAME: Final = "Deliverability Toolkit"
# Percent-decoding rounds applied by safe_next (catches /%2F%2F and double encoding).
_NEXT_DECODE_ROUNDS: Final = 3

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html"], default=True),
    undefined=StrictUndefined,
)
env.globals["app_name"] = APP_NAME


def app_settings(request: Request) -> Settings:
    """The Settings stored on the app by the lifespan; a clear error if they are missing."""
    settings = getattr(request.app.state, "settings", None)
    if not isinstance(settings, Settings):
        raise RuntimeError("app.state.settings is not configured (lifespan not run?)")
    return settings


async def read_form(request: Request) -> dict[str, list[str]] | None:
    """The urlencoded body as `parse_qs` values, or None if it exceeds MAX_FORM_BYTES.
    A body that is not valid UTF-8 yields an empty form."""
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_FORM_BYTES:
            return None
    try:
        return parse_qs(raw.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        return {}


def form_value(form: dict[str, list[str]], name: str) -> str:
    """The first value of `name`, or the empty string."""
    return (form.get(name) or [""])[0]


def _parse_cookies(header: str | None) -> dict[str, str]:
    cookie: SimpleCookie = SimpleCookie()
    try:
        cookie.load(header or "")
    except CookieError:
        return {}
    return {k: m.value for k, m in cookie.items()}


def request_language(scope: Scope) -> str:
    headers = Headers(scope=scope)
    preferred = _parse_cookies(headers.get("cookie")).get(LANGUAGE_COOKIE)
    return resolve_language(
        user_pref=preferred if preferred in SUPPORTED_LANGUAGES else None,
        accept_language=headers.get("accept-language"),
    )


def dns_tools_nav(request: Request) -> bool:
    """Whether the nav shows the DNS tools link: the request's session principal holds
    `dns.tools` in its active tenant. False for anonymous, without a tenant, and on any error
    (fail closed). Uses only the session already resolved by `optional_session` for this request;
    it never touches the DB (pages that resolve no session, e.g. /login or an unknown-path 404,
    show no link and must not extend idle sessions)."""
    from app.core.permissions import Action, TenantResource, can  # lazy: deps imports this module

    try:
        auth = getattr(request.state, "auth_session", None)
        if auth is None or auth.active_tenant_id is None:
            return False
        return bool(can(auth.principal, Action.DNS_TOOLS, TenantResource(auth.active_tenant_id)))
    except Exception:
        return False


def message_tools_nav(request: Request) -> bool:
    """Like `dns_tools_nav` for `message.analyze` (fail closed, no DB access)."""
    from app.core.permissions import Action, TenantResource, can  # lazy: deps imports this module

    try:
        auth = getattr(request.state, "auth_session", None)
        if auth is None or auth.active_tenant_id is None:
            return False
        return bool(
            can(auth.principal, Action.MESSAGE_ANALYZE, TenantResource(auth.active_tenant_id))
        )
    except Exception:
        return False


def content_tools_nav(request: Request) -> bool:
    """Like `dns_tools_nav` for `content.analyze` (fail closed, no DB access)."""
    from app.core.permissions import Action, TenantResource, can  # lazy: deps imports this module

    try:
        auth = getattr(request.state, "auth_session", None)
        if auth is None or auth.active_tenant_id is None:
            return False
        return bool(
            can(auth.principal, Action.CONTENT_ANALYZE, TenantResource(auth.active_tenant_id))
        )
    except Exception:
        return False


def rules_tools_nav(request: Request) -> bool:
    """Whether the nav shows the rules and DKIM selectors links: `rules.read` in the active tenant
    or `rules.manage` on the global scope, either one opens a tab (fail closed, no DB access)."""
    from app.core.permissions import (  # lazy: deps imports this module
        Action,
        RuleScope,
        RuleScopeResource,
        TenantResource,
        can,
    )

    try:
        auth = getattr(request.state, "auth_session", None)
        if auth is None:
            return False
        if can(auth.principal, Action.RULES_MANAGE, RuleScopeResource(RuleScope.GLOBAL, None)):
            return True
        if auth.active_tenant_id is None:
            return False
        return bool(can(auth.principal, Action.RULES_READ, TenantResource(auth.active_tenant_id)))
    except Exception:
        return False


def render(request: Request, template: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    """Render `template` for `request` (language, CSRF token and current path in the context)."""
    lang = request_language(request.scope)
    settings = app_settings(request)
    holder = Response()  # collects the Set-Cookie of an anonymous CSRF token
    token: list[str] = []

    def csrf_token() -> str:
        if not token:
            token.append(csrf_token_for(request, holder, settings))
        return token[0]

    html = env.get_template(template).render(
        lang=lang,
        t=lambda key, **params: t(key, lang, **params),
        csrf_token=csrf_token,
        current_path=request.url.path,
        supported_languages=SUPPORTED_LANGUAGES,
        show_dns_tools=dns_tools_nav(request),
        show_message_tools=message_tools_nav(request),
        show_content_tools=content_tools_nav(request),
        show_rules_tools=rules_tools_nav(request),
        show_dkim_selector_tools=rules_tools_nav(request),
        **context,
    )
    response = HTMLResponse(html, status_code=status_code)
    for cookie in holder.headers.getlist("set-cookie"):
        response.headers.append("set-cookie", cookie)
    return response


def render_server_error(scope: Scope) -> bytes:
    """Translated 500 page for the security-headers fallback. No request object, no CSRF token,
    no exception details. May raise; the caller falls back to the plain response."""
    lang = request_language(scope)
    html = env.get_template("errors/500.html").render(
        lang=lang,
        t=lambda key, **params: t(key, lang, **params),
        csrf_token=None,
        current_path="/",
        supported_languages=SUPPORTED_LANGUAGES,
    )
    return html.encode("utf-8")


def _local_path(value: str) -> bool:
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return False
    parts = urlsplit(value)
    return not parts.scheme and not parts.netloc


def safe_next(value: str | None) -> str:
    """Only same-site absolute paths are redirect targets; anything else becomes `/`. The value
    must stay local after percent-decoding too (`/%2F%2Fevil`, `/%5Cevil` are refused)."""
    if not value:
        return "/"
    candidate = value
    for _ in range(_NEXT_DECODE_ROUNDS):
        if not _local_path(candidate):
            return "/"
        decoded = unquote(candidate)
        if decoded == candidate:
            return value
        candidate = decoded
    return value if _local_path(candidate) and unquote(candidate) == candidate else "/"


router = APIRouter()


@router.post("/language", include_in_schema=False)
async def switch_language(request: Request) -> Response:
    """Set the `dt_lang` cookie from the `lang` form field and redirect to `next`.
    CSRF is enforced by the middleware (token in the form body or X-CSRF-Token)."""
    form = await read_form(request)
    if form is None:
        return Response(status_code=413)
    lang = form_value(form, "lang")
    target = safe_next(form_value(form, "next"))
    response = RedirectResponse(target, status_code=303)
    if lang in SUPPORTED_LANGUAGES:
        base = session_cookie_settings(app_settings(request), LANGUAGE_COOKIE_MAX_AGE)
        response.set_cookie(
            LANGUAGE_COOKIE,
            lang,
            max_age=base.max_age,
            httponly=base.httponly,
            samesite=base.samesite,
            secure=base.secure,
            path=base.path,
        )
    return response
