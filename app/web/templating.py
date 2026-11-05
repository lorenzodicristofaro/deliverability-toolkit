"""Jinja2 environment, per-request rendering and the language switch (M1-16).

Autoescape is on for every template. `t()` is bound to the request language; `csrf_token()` is
the real `csrf_token_for()` from M1-14 (lazy: an anonymous `dt_csrf` cookie is set only when a
template actually asks for the token). Language resolution: `dt_lang` cookie (user preference)
> Accept-Language > default (see `app.core.i18n.resolve_language`).
"""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qs, urlsplit

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
_MAX_FORM_BYTES: Final = 4096

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html"], default=True),
    undefined=StrictUndefined,
)


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


def render(request: Request, template: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    """Render `template` for `request` (language, CSRF token and current path in the context)."""
    lang = request_language(request.scope)
    settings = request.app.state.settings
    assert isinstance(settings, Settings)
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


def safe_next(value: str | None) -> str:
    """Only same-site absolute paths are redirect targets; anything else becomes `/`."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return "/"
    parts = urlsplit(value)
    return value if not parts.scheme and not parts.netloc else "/"


router = APIRouter()


@router.post("/language", include_in_schema=False)
async def switch_language(request: Request) -> Response:
    """Set the `dt_lang` cookie from the `lang` form field and redirect to `next`.
    CSRF is enforced by the middleware (token in the form body or X-CSRF-Token)."""
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > _MAX_FORM_BYTES:
            return Response(status_code=413)
    try:
        form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        form = {}
    lang = (form.get("lang") or [""])[0]
    target = safe_next((form.get("next") or [""])[0])
    response = RedirectResponse(target, status_code=303)
    if lang in SUPPORTED_LANGUAGES:
        base = session_cookie_settings(request.app.state.settings, LANGUAGE_COOKIE_MAX_AGE)
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
