"""M7-14b secret encryption service (Fernet / MultiFernet). Pure crypto, no network."""

import base64
import logging
from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet

from app.core import secrets_crypto
from app.core.secrets_crypto import (
    SecretCipher,
    SecretDecryptError,
    SecretsConfigError,
    SecretsError,
)

KEY_OLD = Fernet.generate_key().decode()
KEY_NEW = Fernet.generate_key().decode()
KEY_OTHER = Fernet.generate_key().decode()
PLAINTEXT = "smtp-password-Zx9!q"


def _flip(token: str, index: int) -> str:
    """Change one base64 character so the token stays well-formed but the bytes differ."""
    chars = list(token)
    chars[index] = "A" if chars[index] != "A" else "B"
    return "".join(chars)


def _sensitive() -> list[str]:
    return [PLAINTEXT, KEY_OLD, KEY_NEW, KEY_OTHER]


def _assert_clean(exc: BaseException, extra: tuple[str, ...] = ()) -> None:
    """No plaintext, key or token in message, repr or the cause/context chain."""
    assert exc.__cause__ is None
    assert exc.__context__ is None
    for text in (str(exc), repr(exc), repr(exc.args)):
        for secret in (*_sensitive(), *extra):
            if secret:
                assert secret not in text


@pytest.fixture(autouse=True)
def _fresh_cipher() -> Iterator[None]:
    secrets_crypto.get_cipher.cache_clear()
    yield
    secrets_crypto.get_cipher.cache_clear()


@pytest.mark.parametrize(
    "plaintext",
    [
        PLAINTEXT,
        "",
        "è-unicode-ñ-日本語-🔐",
        " leading and trailing spaces ",
        "line\nbreak\x00nul",
        "x" * 10_000,
    ],
    ids=["ascii", "empty", "unicode", "spaces", "control", "long"],
)
def test_round_trip(plaintext: str) -> None:
    cipher = SecretCipher(KEY_OLD)
    token = cipher.encrypt(plaintext)
    assert token.isascii()
    assert plaintext == "" or plaintext not in token
    assert cipher.decrypt(token) == plaintext


def test_encrypt_is_randomised() -> None:
    cipher = SecretCipher(KEY_OLD)
    assert cipher.encrypt(PLAINTEXT) != cipher.encrypt(PLAINTEXT)


@pytest.mark.parametrize(
    ("encrypt_keys", "decrypt_keys", "ok"),
    [
        (KEY_OLD, KEY_OLD, True),
        (KEY_OLD, f"{KEY_NEW},{KEY_OLD}", True),  # rotation: new key prepended, old still decrypts
        (f"{KEY_NEW},{KEY_OLD}", KEY_NEW, True),  # first key encrypts
        (f"{KEY_NEW},{KEY_OLD}", f" {KEY_OTHER} , {KEY_NEW} ", True),  # whitespace, any position
        (f"{KEY_NEW},{KEY_OLD}", KEY_OLD, False),  # token is under the primary, not the old key
        (KEY_OLD, KEY_NEW, False),  # old key removed
        (KEY_OLD, KEY_OTHER, False),  # wrong key
    ],
    ids=["same", "old-in-ring", "primary", "multi-ws", "secondary-only", "removed", "wrong"],
)
def test_multi_key(encrypt_keys: str, decrypt_keys: str, ok: bool) -> None:
    token = SecretCipher(encrypt_keys).encrypt(PLAINTEXT)
    reader = SecretCipher(decrypt_keys)
    if ok:
        assert reader.decrypt(token) == PLAINTEXT
    else:
        with pytest.raises(SecretDecryptError) as info:
            reader.decrypt(token)
        _assert_clean(info.value, (token,))


def test_rotation_old_to_new_then_drop_old() -> None:
    old_token = SecretCipher(KEY_OLD).encrypt(PLAINTEXT)
    ring = SecretCipher(f"{KEY_NEW},{KEY_OLD}")
    new_token = ring.rotate(old_token)
    assert new_token != old_token
    assert ring.decrypt(new_token) == PLAINTEXT
    only_new = SecretCipher(KEY_NEW)
    assert only_new.decrypt(new_token) == PLAINTEXT
    with pytest.raises(SecretDecryptError) as info:
        only_new.decrypt(old_token)
    _assert_clean(info.value, (old_token,))


def test_rotate_unknown_token_is_typed() -> None:
    token = SecretCipher(KEY_OTHER).encrypt(PLAINTEXT)
    with pytest.raises(SecretDecryptError) as info:
        SecretCipher(f"{KEY_NEW},{KEY_OLD}").rotate(token)
    _assert_clean(info.value, (token,))


_GOOD = SecretCipher(KEY_OLD).encrypt(PLAINTEXT)


@pytest.mark.parametrize(
    "token",
    [
        _flip(_GOOD, 30),  # ciphertext byte changed
        _flip(_GOOD, len(_GOOD) - 6),  # HMAC changed
        _flip(_GOOD, 2),  # timestamp changed
        _GOOD[:-10],  # truncated
        _GOOD.rstrip("=") + "AAAA" + _GOOD[len(_GOOD.rstrip("=")) :],  # extra bytes
        "",
        "garbage",
        "not base64 !!!",
        base64.urlsafe_b64encode(b"\x80" + b"\x00" * 60).decode(),  # right version byte, junk
        base64.urlsafe_b64encode(b"\x00" * 80).decode(),  # wrong version byte
        "gAAAAA" + "é" * 40,  # non-ASCII
        "\x00\x01\x02",
    ],
    ids=[
        "tamper-ciphertext",
        "tamper-hmac",
        "tamper-timestamp",
        "truncated",
        "extended",
        "empty",
        "garbage",
        "not-base64",
        "junk-v80",
        "wrong-version",
        "non-ascii",
        "control",
    ],
)
@pytest.mark.parametrize("operation", ["decrypt", "rotate"])
def test_malformed_or_tampered_token_is_typed(token: str, operation: str) -> None:
    cipher = SecretCipher(KEY_OLD)
    with pytest.raises(SecretDecryptError) as info:
        getattr(cipher, operation)(token)
    assert info.value.code == "secrets.decrypt_failed"
    assert isinstance(info.value, SecretsError)
    _assert_clean(info.value, (token, _GOOD))


@pytest.mark.parametrize(
    "keys",
    [
        "",
        "   ",
        "e" * 40,  # long enough for Settings, not a Fernet key
        KEY_OLD[:-1],  # 43 chars
        KEY_OLD + "A",  # 45 chars
        KEY_OLD[:-1] + "A",  # no padding
        KEY_OLD.replace("=", "") + "==",  # wrong padding
        "+" * 43 + "=",  # standard (not URL-safe) alphabet
        "/" * 43 + "=",
        "é" * 43 + "=",
        f"{KEY_OLD},",  # trailing empty entry
        f",{KEY_OLD}",
        f"{KEY_OLD},,{KEY_NEW}",
        f"{KEY_OLD};{KEY_NEW}",  # wrong separator
        f"{KEY_OLD} {KEY_NEW}",
        f"{KEY_OLD},not-a-key",  # one bad key in the ring
        base64.urlsafe_b64encode(b"\x00" * 16).decode(),  # 16-byte key
        base64.urlsafe_b64encode(b"\x00" * 48).decode(),  # 48-byte key
    ],
    ids=[
        "empty",
        "blank",
        "arbitrary-string",
        "short",
        "long",
        "no-padding",
        "double-padding",
        "plus-alphabet",
        "slash-alphabet",
        "non-ascii",
        "trailing-comma",
        "leading-comma",
        "empty-middle",
        "semicolon",
        "space-separated",
        "one-bad-in-ring",
        "16-bytes",
        "48-bytes",
    ],
)
def test_bad_key_format_is_typed(keys: str) -> None:
    with pytest.raises(SecretsConfigError) as info:
        SecretCipher(keys)
    assert info.value.code == "secrets.config_invalid"
    _assert_clean(info.value, tuple(part for part in keys.split(",") if len(part) >= 8))


def test_cipher_repr_hides_keys() -> None:
    cipher = SecretCipher(f"{KEY_NEW},{KEY_OLD}")
    text = repr(cipher) + str(cipher)
    assert KEY_NEW not in text and KEY_OLD not in text
    assert "2" in text


@pytest.mark.parametrize("value", [b"bytes", None, 42])
def test_wrong_input_types_are_caller_bugs(value: object) -> None:
    cipher = SecretCipher(KEY_OLD)
    for operation in (cipher.encrypt, cipher.decrypt, cipher.rotate):
        with pytest.raises(TypeError):
            operation(value)  # type: ignore[arg-type]


def test_unencodable_plaintext_not_chained() -> None:
    lone_surrogate = "pass\ud800word"
    with pytest.raises(ValueError) as info:
        SecretCipher(KEY_OLD).encrypt(lone_surrogate)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
    assert lone_surrogate not in str(info.value) + repr(info.value)


def test_decrypted_bytes_not_utf8_is_typed_and_unchained() -> None:
    raw = b"\xffsecret-bytes\xfe"
    token = Fernet(KEY_OLD.encode()).encrypt(raw)
    with pytest.raises(SecretDecryptError) as info:
        SecretCipher(KEY_OLD).decrypt(token.decode())
    _assert_clean(info.value, (token.decode(), "secret-bytes"))


# --- module-level functions: key from ENCRYPTION_KEY, checked on first use ---


def _env(monkeypatch: pytest.MonkeyPatch, encryption_key: str | None) -> None:
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    if encryption_key is None:
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    else:
        monkeypatch.setenv("ENCRYPTION_KEY", encryption_key)


def test_module_functions_use_env_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _env(monkeypatch, KEY_OLD)
    old_token = secrets_crypto.encrypt(PLAINTEXT)
    assert secrets_crypto.decrypt(old_token) == PLAINTEXT

    _env(monkeypatch, f"{KEY_NEW},{KEY_OLD}")
    secrets_crypto.get_cipher.cache_clear()
    new_token = secrets_crypto.rotate(old_token)
    assert secrets_crypto.decrypt(old_token) == PLAINTEXT

    _env(monkeypatch, KEY_NEW)
    secrets_crypto.get_cipher.cache_clear()
    assert secrets_crypto.decrypt(new_token) == PLAINTEXT
    with pytest.raises(SecretDecryptError) as info:
        secrets_crypto.decrypt(old_token)
    _assert_clean(info.value, (old_token,))


@pytest.mark.parametrize(
    "encryption_key",
    [None, "", "s3cr3t-too-short", "e" * 40, f"{KEY_OLD},garbage-garbage"],
    ids=["missing", "empty", "settings-too-short", "not-fernet", "bad-second"],
)
def test_module_functions_bad_config_is_typed(
    monkeypatch: pytest.MonkeyPatch, encryption_key: str | None
) -> None:
    _env(monkeypatch, encryption_key)
    for operation, argument in (
        (secrets_crypto.encrypt, PLAINTEXT),
        (secrets_crypto.decrypt, "gAAAAA"),
        (secrets_crypto.rotate, "gAAAAA"),
    ):
        with pytest.raises(SecretsConfigError) as info:
            operation(argument)
        _assert_clean(info.value, (encryption_key or "",))


def test_nothing_sensitive_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        ring = SecretCipher(f"{KEY_NEW},{KEY_OLD}")
        token = SecretCipher(KEY_OLD).encrypt(PLAINTEXT)
        rotated = ring.rotate(token)
        assert ring.decrypt(rotated) == PLAINTEXT
        for bad in (_flip(rotated, 30), "garbage", ""):
            with pytest.raises(SecretDecryptError) as decrypt_info:
                ring.decrypt(bad)
            _assert_clean(decrypt_info.value, (rotated,))
        with pytest.raises(SecretsConfigError) as config_info:
            SecretCipher(f"{KEY_OLD},{KEY_OLD[:-1]}")
        _assert_clean(config_info.value)
    logged = caplog.text + "".join(str(r.args) for r in caplog.records)
    for secret in (*_sensitive(), token, rotated):
        assert secret not in logged
