"""Security response headers on every HTTP response (M1-14).

Exact values (set unconditionally; a route cannot loosen them):

- Content-Security-Policy:
  `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';
  form-action 'self'; frame-ancestors 'none'`
  No `'unsafe-inline'` or `'unsafe-eval'` anywhere: scripts and styles must be same-origin files.
- X-Content-Type-Options: `nosniff`
- Referrer-Policy: `same-origin`
- X-Frame-Options: `DENY` (legacy companion of `frame-ancestors 'none'`)
- Permissions-Policy: `camera=(), microphone=(), geolocation=()`
- Strict-Transport-Security: `max-age=31536000`, only when BASE_URL is https. No
  `includeSubDomains`/`preload`: the operator's other subdomains are not ours to commit.
- Cache-Control: `no-store` on every response (R1-32, regardless of any cookie), except paths under
  `/static/` and exactly `/healthz` (exact match: `/healthzfoo`, `/healthz/` and `/healthz/x`
  get no-store; `/static` without the trailing slash is not under `/static/` and gets it too).
  A route's own Cache-Control is kept when it already contains `no-store` (equal or stricter);
  any other value (absent, `no-cache`, `public`, max-age) is replaced, since it is weaker for
  private data.

The tests assert that these exact values are sent; they make no claim about how a given browser
enforces them. BASE_URL is read from `app.state.settings` (set by the lifespan); when settings are
not available HSTS is omitted and the other headers are still sent. Responses for unhandled
exceptions (500) carry the same headers (see the `except` branch in the middleware).
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Final

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings

CONTENT_SECURITY_POLICY: Final = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)
HSTS_VALUE: Final = "max-age=31536000"
# Protocol reason phrase (not a translatable UI string), identical to Starlette's default 500 body.
_ERROR_BODY: Final = HTTPStatus.INTERNAL_SERVER_ERROR.phrase.encode("ascii")
SECURITY_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "same-origin"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)
_NO_STORE_EXEMPT_PREFIX: Final = "/static/"
_NO_STORE_EXEMPT_PATH: Final = "/healthz"


def _needs_no_store(scope: Scope) -> bool:
    path = str(scope.get("path", ""))
    return path != _NO_STORE_EXEMPT_PATH and not path.startswith(_NO_STORE_EXEMPT_PREFIX)


def _https(scope: Scope) -> bool:
    app = scope.get("app")
    settings = getattr(getattr(app, "state", None), "settings", None)
    return isinstance(settings, Settings) and settings.base_url.lower().startswith("https://")


def _error_page(scope: Scope) -> tuple[bytes, bytes]:
    """Translated 500 page (M1-16); the plain response if rendering fails for any reason."""
    try:
        from app.web.templating import render_server_error  # lazy: core must not import web

        return render_server_error(scope), b"text/html; charset=utf-8"
    except Exception:
        return _ERROR_BODY, b"text/plain; charset=utf-8"


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        hsts = _https(scope)
        no_store = _needs_no_store(scope)
        started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    headers[name] = value
                if no_store and "no-store" not in headers.get("Cache-Control", "").lower():
                    headers["Cache-Control"] = "no-store"
                if hsts:
                    headers["Strict-Transport-Security"] = HSTS_VALUE
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            # Starlette's ServerErrorMiddleware sits outside user middleware, so its 500 would
            # carry none of these headers. Send the 500 here (generic body: the HTTP reason
            # phrase, as Starlette does; no exception details), then re-raise so the error is
            # still logged and propagated. ServerErrorMiddleware then sees the response as
            # started and does not send a second one.
            if not started:
                body, content_type = _error_page(scope)
                await send_wrapper(
                    {
                        "type": "http.response.start",
                        "status": 500,
                        "headers": [(b"content-type", content_type)],
                    }
                )
                await send({"type": "http.response.body", "body": body})
            raise
