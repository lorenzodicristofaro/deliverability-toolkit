"""Password hashing (argon2id), session tokens and the session cookie (M1-13, GM decision Q3).

Password hashing uses `argon2.PasswordHasher()` with the library defaults; this module sets no
parameters of its own. Recorded on 2026-11-05 for argon2-cffi 25.1.0 (installed version, and the
API docs https://argon2-cffi.readthedocs.io/en/stable/api.html): the defaults are
`argon2.profiles.RFC_9106_LOW_MEMORY` (default since 21.2.0) = Argon2id, time_cost=3,
memory_cost=65536 KiB (64 MiB), parallelism=4, hash_len=32, salt_len=16. The docs note the
defaults "may vary depending on the platform" (`argon2.profiles.get_default_parameters()`).
When a future release changes them, `needs_rehash` turns true and the auth service rehashes the
password on the next successful login. tests/core/test_security.py pins the recorded values.

Session tokens: a random opaque token is generated per session; the database stores only its
SHA-256 digest, and the cookie carries the token plus an HMAC-SHA256 signature keyed from
SECRET_KEY. Nothing in this module logs, and no exception message contains a password, token or
secret.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from pydantic import SecretStr

from app.core.config import Settings

DEFAULT_HASHER = PasswordHasher()

SESSION_COOKIE_NAME = "dt_session"
# 32 random bytes (256 bits) -> 43 url-safe base64 characters.
TOKEN_BYTES = 32
_SIG_LEN = 43  # url-safe base64 of a 32-byte HMAC-SHA256, without padding
_TOKEN_LEN = 43
# Domain separation: the cookie key is derived from SECRET_KEY, never SECRET_KEY itself.
_COOKIE_KEY_LABEL = b"deliverability-toolkit/session-cookie/v1"


def hash_password(password: str, hasher: PasswordHasher = DEFAULT_HASHER) -> str:
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    return hasher.hash(password)


def verify_password(
    stored_hash: str, password: str, hasher: PasswordHasher = DEFAULT_HASHER
) -> bool:
    """True only if `password` matches `stored_hash`. A mismatch, a malformed or foreign hash and a
    non-str password all return False (never raise, so nothing can leak into an exception)."""
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    try:
        return hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str, hasher: PasswordHasher = DEFAULT_HASHER) -> bool:
    """True if `stored_hash` was not made with `hasher`'s current parameters."""
    try:
        return hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, ValueError):
        return True


def _hasher_key(hasher: PasswordHasher) -> tuple[int, int, int, int, int, int]:
    return (
        hasher.time_cost,
        hasher.memory_cost,
        hasher.parallelism,
        hasher.hash_len,
        hasher.salt_len,
        int(hasher.type.value),
    )


# Precomputed at import for the default hasher, so the first unknown-user login does not pay
# (and reveal) the extra cost of creating the dummy hash. Other hashers (tests) are cached lazily.
_dummy_hashes: dict[tuple[int, int, int, int, int, int], str] = {
    _hasher_key(DEFAULT_HASHER): DEFAULT_HASHER.hash(secrets.token_urlsafe(16))
}


def dummy_verify(password: object, hasher: PasswordHasher = DEFAULT_HASHER) -> None:
    """Spend the same work as a real verification (unknown user / no password set), so response
    time does not reveal whether an account exists. The result is always discarded."""
    key = _hasher_key(hasher)
    dummy = _dummy_hashes.get(key)
    if dummy is None:
        dummy = _dummy_hashes.setdefault(key, hasher.hash(secrets.token_urlsafe(16)))
    verify_password(dummy, password if isinstance(password, str) else "", hasher)


# --- session tokens and the signed cookie ---------------------------------------------------------


def new_session_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_session_token(token: str) -> str:
    """SHA-256 hex digest of the token: the only form stored in the database. The token is 256
    random bits, so a fast hash is sufficient (no password stretching needed)."""
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signature(token: str, secret_key: SecretStr) -> str:
    key = hmac.new(
        secret_key.get_secret_value().encode("utf-8"), _COOKIE_KEY_LABEL, hashlib.sha256
    ).digest()
    return _b64(hmac.new(key, token.encode("ascii"), hashlib.sha256).digest())


def sign_session_token(token: str, secret_key: SecretStr) -> str:
    """Cookie value: `<token>.<signature>`."""
    return f"{token}.{_signature(token, secret_key)}"


def _is_b64url(text: str, length: int) -> bool:
    if len(text) != length or not text.isascii():
        return False
    try:
        base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return False
    return all(c.isalnum() or c in "-_" for c in text)


def unsign_session_token(cookie_value: object, secret_key: SecretStr) -> str | None:
    """The token if `cookie_value` is well formed and its signature is valid, else None."""
    if not isinstance(cookie_value, str) or len(cookie_value) != _TOKEN_LEN + 1 + _SIG_LEN:
        return None
    token, sep, signature = cookie_value.partition(".")
    if not sep or not _is_b64url(token, _TOKEN_LEN) or not _is_b64url(signature, _SIG_LEN):
        return None
    if not hmac.compare_digest(signature, _signature(token, secret_key)):
        return None
    return token


@dataclass(frozen=True, slots=True)
class CookieSettings:
    """Keyword arguments for Starlette's `Response.set_cookie` (M1-15 uses them)."""

    key: str
    httponly: bool
    samesite: Literal["lax"]
    secure: bool
    path: str
    max_age: int | None


def session_cookie_settings(settings: Settings, max_age: int | None = None) -> CookieSettings:
    """HttpOnly, SameSite=Lax, Path=/; Secure when BASE_URL is https (Settings guarantees the
    scheme is http or https). `max_age` None makes a browser-session cookie."""
    return CookieSettings(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        samesite="lax",
        secure=settings.base_url.lower().startswith("https://"),
        path="/",
        max_age=max_age,
    )
