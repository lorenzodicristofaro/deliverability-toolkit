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

The tests assert that these exact values are sent; they make no claim about how a given browser
enforces them. BASE_URL is read from `app.state.settings` (set by the lifespan); when settings are
not available HSTS is omitted and the other headers are still sent.
"""

from __future__ import annotations

from typing import Final

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings

CONTENT_SECURITY_POLICY: Final = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)
HSTS_VALUE: Final = "max-age=31536000"
SECURITY_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "same-origin"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)


def _https(scope: Scope) -> bool:
    app = scope.get("app")
    settings = getattr(getattr(app, "state", None), "settings", None)
    return isinstance(settings, Settings) and settings.base_url.lower().startswith("https://")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        hsts = _https(scope)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS:
                    headers[name] = value
                if hsts:
                    headers["Strict-Transport-Security"] = HSTS_VALUE
            await send(message)

        await self.app(scope, receive, send_wrapper)
