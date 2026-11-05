"""M1-13 password hashing, session token signing and cookie settings (no DB, no network)."""

from typing import Any

import pytest
from argon2 import PasswordHasher, Type
from pydantic import SecretStr

from app.core import security
from app.core.config import Settings
from app.core.security import (
    dummy_verify,
    hash_password,
    hash_session_token,
    needs_rehash,
    new_session_token,
    session_cookie_settings,
    sign_session_token,
    unsign_session_token,
    verify_password,
)

KEY = "k" * 40
SECRET = SecretStr("s" * 40)
OTHER_SECRET = SecretStr("t" * 40)
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def test_default_hasher_uses_recorded_library_defaults() -> None:
    # Recorded 2026-11-05 for argon2-cffi 25.1.0 (RFC_9106_LOW_MEMORY); see app/core/security.py.
    h = security.DEFAULT_HASHER
    assert (h.type, h.time_cost, h.memory_cost, h.parallelism, h.hash_len, h.salt_len) == (
        Type.ID,
        3,
        65536,
        4,
        32,
        16,
    )


def test_hash_and_verify_roundtrip() -> None:
    stored = hash_password("correct horse", FAST)
    assert stored.startswith("$argon2id$")
    assert "correct horse" not in stored
    assert verify_password(stored, "correct horse", FAST)
    assert hash_password("correct horse", FAST) != stored  # random salt


@pytest.mark.parametrize(
    ("stored", "password"),
    [
        ("VALID", "wrong"),
        ("VALID", ""),
        ("VALID", "correct horse "),
        ("", "correct horse"),
        ("not a hash", "correct horse"),
        ("$argon2id$v=19$m=8,t=1,p=1$garbage", "correct horse"),
        ("$2b$12$abcdefghijklmnopqrstuuDzN7v3gJ2yQ9C1Zfk7X0r8xYwzv5D6a", "correct horse"),
        ("VALID", None),
        ("VALID", b"correct horse"),
        ("VALID", 123),
        (None, "correct horse"),
    ],
)
def test_verify_rejects_without_raising(stored: Any, password: Any) -> None:
    if stored == "VALID":
        stored = hash_password("correct horse", FAST)
    assert verify_password(stored, password, FAST) is False


@pytest.mark.parametrize("password", [None, b"bytes", 1, ["x"]])
def test_hash_rejects_non_str_without_echoing(password: Any) -> None:
    with pytest.raises(TypeError) as exc:
        hash_password(password, FAST)
    assert repr(password) not in str(exc.value)


@pytest.mark.parametrize(
    ("checked_with", "expected"),
    [
        (FAST, False),
        (PasswordHasher(time_cost=2, memory_cost=8, parallelism=1), True),
        (PasswordHasher(time_cost=1, memory_cost=16, parallelism=1), True),
    ],
)
def test_needs_rehash(checked_with: PasswordHasher, expected: bool) -> None:
    assert needs_rehash(hash_password("pw", FAST), checked_with) is expected


@pytest.mark.parametrize("stored", ["", "garbage", "$argon2id$broken"])
def test_needs_rehash_malformed_is_true(stored: str) -> None:
    assert needs_rehash(stored, FAST) is True


@pytest.mark.parametrize("password", ["anything", "", None, 42])
def test_dummy_verify_runs_a_verification(password: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = security.verify_password

    def spy(stored: str, pw: str, hasher: PasswordHasher = FAST) -> bool:
        calls.append(stored)
        return real(stored, pw, hasher)

    monkeypatch.setattr(security, "verify_password", spy)
    dummy_verify(password, FAST)
    assert len(calls) == 1 and calls[0].startswith("$argon2id$v=19$m=8,t=1,p=1$")


def test_default_dummy_hash_precomputed_at_import() -> None:
    assert security._hasher_key(security.DEFAULT_HASHER) in security._dummy_hashes


def test_session_token_and_digest() -> None:
    token = new_session_token()
    assert len(token) == 43 and token != new_session_token()
    digest = hash_session_token(token)
    assert len(digest) == 64 and token not in digest
    assert hash_session_token(token) == digest


def test_sign_unsign_roundtrip() -> None:
    token = new_session_token()
    cookie = sign_session_token(token, SECRET)
    assert unsign_session_token(cookie, SECRET) == token
    assert unsign_session_token(cookie, OTHER_SECRET) is None


def _tampered() -> list[Any]:
    token = new_session_token()
    good = sign_session_token(token, SECRET)
    tok, _, sig = good.partition(".")
    flip = "A" if sig[0] != "A" else "B"
    other = new_session_token()
    return [
        "",
        ".",
        tok,
        f"{tok}.",
        f".{sig}",
        f"{tok}.{flip}{sig[1:]}",  # signature changed
        f"{other}.{sig}",  # token swapped, old signature
        f"{tok}{sig}",  # separator dropped
        good + "x",
        good[:-1],
        f"{tok}:{sig}",
        f"{tok[:-1]}=.{sig}",
        f"{tok[:-1]}é.{sig}",
        f"{tok[:-1]}+.{sig}",
        f"{tok}.{sig[:-1]}/",
        " " + good[1:],
        "x" * 10_000,
        None,
        123,
        good.encode(),
        [good],
    ]


@pytest.mark.parametrize("cookie", _tampered())
def test_unsign_rejects_tampered_or_malformed(cookie: Any) -> None:
    assert unsign_session_token(cookie, SECRET) is None


@pytest.mark.parametrize(
    ("base_url", "secure"),
    [
        ("https://dt.example.com", True),
        ("https://dt.example.com:8443/app", True),
        ("http://localhost:8000", False),
        ("http://dt.example.com", False),
    ],
)
def test_cookie_settings(base_url: str, secure: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setenv("BASE_URL", base_url)
    cookie = session_cookie_settings(Settings(), max_age=3600)
    assert cookie.httponly is True
    assert cookie.samesite == "lax"
    assert cookie.secure is secure
    assert cookie.path == "/"
    assert cookie.max_age == 3600
    assert cookie.key == security.SESSION_COOKIE_NAME
