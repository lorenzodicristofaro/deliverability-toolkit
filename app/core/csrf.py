"""CSRF protection for cookie-authenticated UI routes (M1-14).

Deny by default: every request whose method is not GET, HEAD, OPTIONS or TRACE (so POST, PUT,
PATCH, DELETE and any custom method such as PROPFIND) must carry a CSRF token, either in the
`X-CSRF-Token` header (HTMX) or in the `csrf_token` field of an
`application/x-www-form-urlencoded` body.
Missing or invalid token -> 403 with the `csrf.invalid` message. GET, HEAD, OPTIONS and TRACE are
not checked (they must not change state). `/healthz` is exempt so its behaviour is unchanged.

Two token kinds, chosen by whether the request carries a validly signed session cookie:

1. Session-bound token (authenticated). APPROACH: the token is DERIVED, not stored:
   `HMAC-SHA256(K_csrf, session_token)`, where `session_token` is the random opaque token inside
   the signed `dt_session` cookie (verified with `security.unsign_session_token`) and `K_csrf` is
   derived from SECRET_KEY with its own label (domain separation from the session-cookie key).
   No database access is needed; the token changes whenever the session changes (login, rotation)
   and cannot be computed without SECRET_KEY. The token reveals nothing about the session token
   (HMAC output). Whether the session is still live (revoked, expired) is the auth layer's job.

2. Signed double-submit token (pre-session forms: login, setup). The `dt_csrf` cookie holds
   `<nonce>.<HMAC-SHA256(K_double, nonce)>`; the request must submit the identical value. Both
   the cookie signature and the cookie/submitted equality are checked, so an attacker who can
   plant a cookie without knowing SECRET_KEY cannot forge a pair.

All comparisons use `hmac.compare_digest`. Templates get the token through `csrf_token_for`.
The form body is read (and replayed to the app) only when no header token is present, and never
buffered beyond the route's form cap. Default cap: `MAX_FORM_BYTES`; a larger body is refused
(403). A route that accepts larger forms opts in with `register_form_cap(path, max_bytes)` (M5-01:
the message analyzer; later the content analyzer). For such a route the body is read up to its
cap; if it is larger, the token is taken from the complete fields of the read prefix (forms put the
hidden `csrf_token` input first, so browsers serialize it first). A valid token lets the request
through, prefix replayed and the rest streamed, so the route answers with its own localized 413
(it caps its body itself); a missing or invalid token is still a 403, so a big body never
bypasses the check. Multipart bodies are not parsed here (python-multipart is not a
dependency): multipart forms must send the header.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final
from urllib.parse import parse_qs

from pydantic import SecretStr
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.i18n import resolve_language, t
from app.core.security import (
    SESSION_COOKIE_NAME,
    _b64,
    _is_b64url,
    new_session_token,
    session_cookie_settings,
    unsign_session_token,
)

CSRF_INVALID_KEY = "csrf.invalid"
CSRF_HEADER: Final = "X-CSRF-Token"
CSRF_FORM_FIELD: Final = "csrf_token"
CSRF_COOKIE_NAME: Final = "dt_csrf"
# Deny by default: only these methods skip the check.
SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
EXEMPT_PATHS: Final = frozenset({"/healthz"})
MAX_FORM_BYTES: Final = 1024 * 1024
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
# Exact request path -> form cap in bytes, for routes that accept forms over MAX_FORM_BYTES.
_FORM_CAPS: dict[str, int] = {}

_SESSION_LABEL = b"deliverability-toolkit/csrf-session/v1"
_DOUBLE_SUBMIT_LABEL = b"deliverability-toolkit/csrf-double-submit/v1"
_MAC_LEN = 43  # url-safe base64 of a 32-byte HMAC-SHA256, without padding
_NONCE_LEN = 43  # security.new_session_token(): 32 random bytes
_MAX_TOKEN_LEN = _NONCE_LEN + 1 + _MAC_LEN


def _mac(label: bytes, message: str, secret_key: SecretStr) -> str:
    key = hmac.new(secret_key.get_secret_value().encode("utf-8"), label, hashlib.sha256).digest()
    return _b64(hmac.new(key, message.encode("ascii"), hashlib.sha256).digest())


def session_csrf_token(session_token: str, secret_key: SecretStr) -> str:
    """The CSRF token bound to a (verified) session token."""
    return _mac(_SESSION_LABEL, session_token, secret_key)


def new_double_submit_token(secret_key: SecretStr) -> str:
    """A fresh signed double-submit value: `<nonce>.<mac>`."""
    nonce = new_session_token()
    return f"{nonce}.{_mac(_DOUBLE_SUBMIT_LABEL, nonce, secret_key)}"


def valid_double_submit_cookie(value: object, secret_key: SecretStr) -> bool:
    if not isinstance(value, str) or len(value) != _MAX_TOKEN_LEN:
        return False
    nonce, sep, mac = value.partition(".")
    if not sep or not _is_b64url(nonce, _NONCE_LEN) or not _is_b64url(mac, _MAC_LEN):
        return False
    return hmac.compare_digest(mac, _mac(_DOUBLE_SUBMIT_LABEL, nonce, secret_key))


def _same(submitted: str | None, expected: str) -> bool:
    if submitted is None or not submitted.isascii():
        return False
    return hmac.compare_digest(submitted.encode("ascii"), expected.encode("ascii"))


def check_token(submitted: str | None, cookies: dict[str, str], secret_key: SecretStr) -> bool:
    """True if `submitted` is valid for the request's cookies (see module docstring)."""
    session_token = unsign_session_token(cookies.get(SESSION_COOKIE_NAME), secret_key)
    if session_token is not None:
        return _same(submitted, session_csrf_token(session_token, secret_key))
    cookie = cookies.get(CSRF_COOKIE_NAME)
    if not valid_double_submit_cookie(cookie, secret_key):
        return False
    assert cookie is not None
    return _same(submitted, cookie)


def csrf_token_for(conn: HTTPConnection, response: Response, settings: Settings) -> str:
    """Token to embed in a form or HTMX header. Authenticated: the session-bound token.
    Anonymous: the current valid `dt_csrf` cookie value, or a new one set on `response`
    (HttpOnly, SameSite=Lax, Path=/, Secure when BASE_URL is https; browser-session lifetime)."""
    secret = settings.secret_key
    session_token = unsign_session_token(conn.cookies.get(SESSION_COOKIE_NAME), secret)
    if session_token is not None:
        return session_csrf_token(session_token, secret)
    existing = conn.cookies.get(CSRF_COOKIE_NAME)
    if valid_double_submit_cookie(existing, secret):
        assert existing is not None
        return existing
    value = new_double_submit_token(secret)
    base = session_cookie_settings(settings)
    response.set_cookie(
        CSRF_COOKIE_NAME,
        value,
        httponly=base.httponly,
        samesite=base.samesite,
        secure=base.secure,
        path=base.path,
    )
    return value


def register_form_cap(path: str, max_bytes: int) -> None:
    """Opt `path` (exact match) in to a form cap above `MAX_FORM_BYTES`. The route must enforce
    `max_bytes` on its own body and answer an oversize body with its localized 413."""
    if not path.startswith("/") or max_bytes <= MAX_FORM_BYTES:
        raise ValueError("form cap must be registered for an absolute path above MAX_FORM_BYTES")
    _FORM_CAPS[path] = max_bytes


def form_cap_for(path: str) -> int:
    """The form cap the middleware applies to `path`."""
    return _FORM_CAPS.get(path, MAX_FORM_BYTES)


def _forbidden(scope: Scope) -> Response:
    lang = resolve_language(accept_language=Headers(scope=scope).get("accept-language"))
    return JSONResponse({"detail": t(CSRF_INVALID_KEY, lang)}, status_code=403)


async def _read_body(receive: Receive, cap: int) -> tuple[bytes, list[Message], bool]:
    """Read messages until the body ends or exceeds `cap`. Returns (body truncated to `cap`,
    the messages read, complete). Reading stops at the first chunk past the cap."""
    chunks: list[bytes] = []
    messages: list[Message] = []
    size = 0
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        chunks.append(chunk)
        if size > cap:
            return b"".join(chunks)[:cap], messages, False
        if not message.get("more_body", False):
            break
    return b"".join(chunks), messages, True


def _complete_fields(prefix: bytes) -> bytes:
    """The fields of a truncated urlencoded body that are certainly complete."""
    end = prefix.rfind(b"&")
    return prefix[:end] if end >= 0 else b""


def _declared_too_large(headers: Headers, cap: int) -> bool:
    declared = headers.get("content-length")
    return declared is not None and (not declared.isdigit() or int(declared) > cap)


def _form_token(body: bytes) -> str | None:
    try:
        values = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    except (UnicodeDecodeError, ValueError):
        return None
    found = values.get(CSRF_FORM_FIELD)
    # Exactly one value: a duplicated field is ambiguous and refused.
    return found[0] if found is not None and len(found) == 1 else None


class CSRFMiddleware:
    """Pure ASGI middleware. Settings are read from `app.state.settings` (set by the lifespan);
    if they are missing the request is refused (fail closed)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method", "").upper() in SAFE_METHODS
            or scope.get("path") in EXEMPT_PATHS
        ):
            await self.app(scope, receive, send)
            return

        conn = HTTPConnection(scope)
        settings = getattr(conn.app.state, "settings", None) if "app" in scope else None
        if not isinstance(settings, Settings):
            await _forbidden(scope)(scope, receive, send)
            return

        headers = Headers(scope=scope)
        submitted = headers.get(CSRF_HEADER)
        downstream_receive = receive
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if submitted is None and content_type == _FORM_CONTENT_TYPE:
            path = scope.get("path", "")
            cap = form_cap_for(path)
            opted_in = path in _FORM_CAPS
            if not opted_in and _declared_too_large(headers, cap):
                await _forbidden(scope)(scope, receive, send)
                return
            body, messages, complete = await _read_body(receive, cap)
            if not complete and not opted_in:
                await _forbidden(scope)(scope, receive, send)
                return
            submitted = _form_token(body if complete else _complete_fields(body))
            del body
            pending = list(messages)

            async def replay() -> Message:
                if pending:
                    return pending.pop(0)
                return await receive()

            downstream_receive = replay

        if len(submitted or "") > _MAX_TOKEN_LEN or not check_token(
            submitted, dict(conn.cookies), settings.secret_key
        ):
            await _forbidden(scope)(scope, receive, send)
            return
        await self.app(scope, downstream_receive, send)
