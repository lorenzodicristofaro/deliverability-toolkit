"""Encryption of stored secrets (M7-14b, ARCHITECTURE section 9).

Secrets the app must store and later use again (SMTP passwords, webhook tokens, API keys) are
encrypted with Fernet from `cryptography` (AES-128-CBC + HMAC-SHA256, authenticated, tokens are
URL-safe base64 text). Keys come from ENCRYPTION_KEY: one or more Fernet keys separated by
commas, combined in a MultiFernet. The FIRST key encrypts, EVERY key decrypts, so rotation is:
prepend a new key, re-encrypt stored tokens with `rotate()`, then drop the old key.

Errors are typed and carry fixed text only: no plaintext, no key material and no token ever goes
into an exception message, its repr or a log record. Library errors are swallowed with
`contextlib.suppress` and every error is raised AFTER that block, never inside an `except`
handler, so `__cause__` and `__context__` are both None (`raise ... from None` would only hide
the context: `__context__` would still reference e.g. a UnicodeEncodeError whose `.object` is
the whole plaintext). This module does not log at all.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import functools
import re

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import ConfigError, Settings

__all__ = [
    "SecretCipher",
    "SecretDecryptError",
    "SecretsConfigError",
    "SecretsError",
    "decrypt",
    "encrypt",
    "get_cipher",
    "rotate",
]

# A Fernet key is 32 bytes, URL-safe base64 with padding: 43 alphabet characters plus "=".
_KEY_SHAPE = re.compile(r"[A-Za-z0-9_-]{43}=")
_KEY_BYTES = 32


class SecretsError(Exception):
    """Base class. Subclasses carry a stable `code` and a fixed, non-sensitive message."""

    code = "secrets.error"

    def __init__(self, message: str) -> None:
        super().__init__(message)


class SecretsConfigError(SecretsError):
    """ENCRYPTION_KEY is missing or not a comma-separated list of valid Fernet keys."""

    code = "secrets.config_invalid"


class SecretDecryptError(SecretsError):
    """A token could not be decrypted: wrong or removed key, tampered, truncated or garbage."""

    code = "secrets.decrypt_failed"


def _parse_key(entry: str, position: int, total: int) -> Fernet:
    where = f"ENCRYPTION_KEY entry {position} of {total}"
    if entry == "":
        raise SecretsConfigError(f"{where} is empty")
    if _KEY_SHAPE.fullmatch(entry) is None:
        raise SecretsConfigError(f"{where} is not a 44-character URL-safe base64 Fernet key")
    raw: bytes | None = None
    # raised after the block, so the error has no __context__
    with contextlib.suppress(binascii.Error, ValueError):
        raw = base64.urlsafe_b64decode(entry)
    if raw is None:
        raise SecretsConfigError(f"{where} is not valid URL-safe base64")
    if len(raw) != _KEY_BYTES:
        raise SecretsConfigError(f"{where} does not decode to 32 bytes")
    fernet: Fernet | None = None
    with contextlib.suppress(ValueError, TypeError):
        fernet = Fernet(entry)
    if fernet is None:
        raise SecretsConfigError(f"{where} is not a valid Fernet key")
    return fernet


class SecretCipher:
    """MultiFernet over the configured keys. repr never shows key material."""

    __slots__ = ("_key_count", "_multi")

    def __init__(self, keys: str) -> None:
        """Parse ENCRYPTION_KEY syntax: comma-separated Fernet keys, primary (encrypting) first.

        Whitespace around entries is ignored. A missing/blank value, an empty entry or an entry
        that is not a Fernet key raises SecretsConfigError naming the entry's position only.
        """
        if not isinstance(keys, str) or keys.strip() == "":
            raise SecretsConfigError("ENCRYPTION_KEY is missing or blank")
        entries = [part.strip() for part in keys.split(",")]
        fernets = [_parse_key(e, i, len(entries)) for i, e in enumerate(entries, start=1)]
        self._multi = MultiFernet(fernets)
        self._key_count = len(fernets)

    def __repr__(self) -> str:
        return f"SecretCipher(keys=<{self._key_count} redacted>)"

    def encrypt(self, plaintext: str) -> str:
        """Encrypt UTF-8 text under the primary key; returns an ASCII Fernet token."""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext must be str")
        data: bytes | None = None
        # Its .object is the whole plaintext: raise after the block, so no __context__.
        with contextlib.suppress(UnicodeEncodeError):
            data = plaintext.encode("utf-8")
        if data is None:
            raise ValueError("plaintext is not encodable as UTF-8")
        return self._multi.encrypt(data).decode("ascii")

    def decrypt(self, token: str) -> str:
        """Decrypt a token made by any configured key; SecretDecryptError on any failure."""
        data = self._token_bytes(token)
        plain: bytes | None = None
        with contextlib.suppress(InvalidToken):
            plain = self._multi.decrypt(data)
        if plain is None:
            raise SecretDecryptError("secret could not be decrypted")
        text: str | None = None
        # its .object is the decrypted plaintext
        with contextlib.suppress(UnicodeDecodeError):
            text = plain.decode("utf-8")
        if text is None:
            raise SecretDecryptError("decrypted secret is not UTF-8 text")
        return text

    def rotate(self, token: str) -> str:
        """Re-encrypt a token under the primary key (keeps its original timestamp)."""
        data = self._token_bytes(token)
        rotated: bytes | None = None
        with contextlib.suppress(InvalidToken):
            rotated = self._multi.rotate(data)
        if rotated is None:
            raise SecretDecryptError("secret could not be decrypted for rotation")
        return rotated.decode("ascii")

    @staticmethod
    def _token_bytes(token: str) -> bytes:
        if not isinstance(token, str):
            raise TypeError("token must be str")
        data: bytes | None = None
        # its .object is the whole token
        with contextlib.suppress(UnicodeEncodeError):
            data = token.encode("ascii")
        if data is None:
            raise SecretDecryptError("secret could not be decrypted")
        return data


@functools.cache
def get_cipher() -> SecretCipher:
    """The process-wide cipher built from ENCRYPTION_KEY on first use (cached).

    Missing or invalid configuration raises SecretsConfigError. Tests that change the
    environment call `get_cipher.cache_clear()`.
    """
    raw: str | None = None
    # Its context chain can reach pydantic's ValidationError, which holds the raw input.
    with contextlib.suppress(ConfigError):
        raw = Settings().encryption_key.get_secret_value()
    if raw is None:
        raise SecretsConfigError("configuration could not be loaded (ENCRYPTION_KEY)")
    return SecretCipher(raw)


def encrypt(plaintext: str) -> str:
    """Encrypt with the configured primary key."""
    return get_cipher().encrypt(plaintext)


def decrypt(token: str) -> str:
    """Decrypt with any configured key."""
    return get_cipher().decrypt(token)


def rotate(token: str) -> str:
    """Re-encrypt under the configured primary key."""
    return get_cipher().rotate(token)
