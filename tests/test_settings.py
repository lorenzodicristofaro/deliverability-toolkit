import pytest
from fastapi.testclient import TestClient

from app.core.config import (
    CONFIG_INVALID_VALUE_KEY,
    CONFIG_MISSING_KEY,
    CONFIG_RESOLVER_ADDRS_REQUIRED_KEY,
    RESOLVER_ADDR_INVALID_KEY,
    ConfigError,
    ResolverAddr,
    Settings,
)
from app.main import create_app

SECRET = "s3cr3t-value-DO-NOT-LEAK-0123456789abcdef"
ENC = "enc-value-DO-NOT-LEAK-0123456789abcdef-xyz"
VARS = [
    "DATABASE_URL",
    "SECRET_KEY",
    "ENCRYPTION_KEY",
    "RESOLVER_MODE",
    "RESOLVER_ADDRS",
    "ROLE",
    "ALLOW_SMTP_CHECKS",
    "ALLOW_REGISTRATION",
    "BASE_URL",
    "LOG_LEVEL",
    "SESSION_IDLE_TIMEOUT_MINUTES",
    "SESSION_ABSOLUTE_TIMEOUT_MINUTES",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in VARS:
        monkeypatch.delenv(name, raising=False)


def load(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    base = {"SECRET_KEY": SECRET, "ENCRYPTION_KEY": ENC, **env}
    for name, value in base.items():
        monkeypatch.setenv(name, value)
    return Settings()  # type: ignore[call-arg]


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load(monkeypatch)
    assert s.database_url.get_secret_value() == "sqlite:////data/app.db"
    assert s.resolver_mode == "system"
    assert s.role == "all"
    assert s.allow_smtp_checks is False
    assert s.allow_registration is False
    assert s.log_level == "INFO"
    assert s.parsed_resolver_addrs() == []
    assert s.secret_key.get_secret_value() == SECRET
    assert s.session_idle_timeout_minutes == 30
    assert s.session_absolute_timeout_minutes == 720


def test_all_values(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load(
        monkeypatch,
        DATABASE_URL="postgresql://x/y",
        RESOLVER_MODE="Unbound",
        RESOLVER_ADDRS="172.28.53.2:5353, [::1]",
        ROLE="worker",
        ALLOW_SMTP_CHECKS="true",
        ALLOW_REGISTRATION="1",
        BASE_URL="https://dt.example.org",
        LOG_LEVEL="debug",
        SESSION_IDLE_TIMEOUT_MINUTES="15",
        SESSION_ABSOLUTE_TIMEOUT_MINUTES="15",
    )
    assert s.resolver_mode == "unbound"
    assert s.parsed_resolver_addrs() == [ResolverAddr("172.28.53.2", 5353), ResolverAddr("::1", 53)]
    assert s.role == "worker"
    assert s.allow_smtp_checks and s.allow_registration
    assert s.log_level == "DEBUG"
    assert (s.session_idle_timeout_minutes, s.session_absolute_timeout_minutes) == (15, 15)


@pytest.mark.parametrize("var", ["SECRET_KEY", "ENCRYPTION_KEY"])
@pytest.mark.parametrize("value", [None, "", "   ", "\t\n"])
def test_blank_secret_is_missing(
    monkeypatch: pytest.MonkeyPatch, var: str, value: str | None
) -> None:
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("ENCRYPTION_KEY", ENC)
    if value is None:
        monkeypatch.delenv(var)
    else:
        monkeypatch.setenv(var, value)
    with pytest.raises(ConfigError) as excinfo:
        Settings()  # type: ignore[call-arg]
    assert excinfo.value.key == CONFIG_MISSING_KEY
    assert excinfo.value.params == {"name": var}


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("RESOLVER_MODE", "dnsmasq"),
        ("RESOLVER_MODE", ""),
        ("ROLE", "admin"),
        ("ROLE", ""),
        ("ALLOW_SMTP_CHECKS", "maybe"),
        ("ALLOW_REGISTRATION", ""),
        ("ALLOW_REGISTRATION", "2"),
        ("LOG_LEVEL", "loud"),
        ("BASE_URL", "ftp://x"),
        ("BASE_URL", ""),
        ("SESSION_IDLE_TIMEOUT_MINUTES", "0"),
        ("SESSION_IDLE_TIMEOUT_MINUTES", "-5"),
        ("SESSION_IDLE_TIMEOUT_MINUTES", ""),
        ("SESSION_IDLE_TIMEOUT_MINUTES", "abc"),
        ("SESSION_IDLE_TIMEOUT_MINUTES", "1.5"),
        ("SESSION_IDLE_TIMEOUT_MINUTES", "721"),  # idle > default absolute (720)
        ("SESSION_ABSOLUTE_TIMEOUT_MINUTES", "0"),
        ("SESSION_ABSOLUTE_TIMEOUT_MINUTES", "-1"),
        ("SESSION_ABSOLUTE_TIMEOUT_MINUTES", "12h"),
    ],
)
def test_invalid_values(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load(monkeypatch, **{var: value})
    assert excinfo.value.key == CONFIG_INVALID_VALUE_KEY
    assert excinfo.value.params == {"name": var}


@pytest.mark.parametrize("mode", ["custom", "unbound"])
@pytest.mark.parametrize("addrs", [None, "", "  "])
def test_resolver_addrs_required(
    monkeypatch: pytest.MonkeyPatch, mode: str, addrs: str | None
) -> None:
    env = {"RESOLVER_MODE": mode}
    if addrs is not None:
        env["RESOLVER_ADDRS"] = addrs
    with pytest.raises(ConfigError) as excinfo:
        load(monkeypatch, **env)
    assert excinfo.value.key == CONFIG_RESOLVER_ADDRS_REQUIRED_KEY


def test_session_idle_must_not_exceed_absolute(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load(monkeypatch, SESSION_IDLE_TIMEOUT_MINUTES="61", SESSION_ABSOLUTE_TIMEOUT_MINUTES="60")
    assert excinfo.value.key == CONFIG_INVALID_VALUE_KEY
    assert excinfo.value.params == {"name": "SESSION_IDLE_TIMEOUT_MINUTES"}


def test_system_mode_without_addrs_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    assert load(monkeypatch, RESOLVER_MODE="system").parsed_resolver_addrs() == []


def test_malformed_resolver_addrs(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load(monkeypatch, RESOLVER_ADDRS="example.com")
    assert excinfo.value.key == RESOLVER_ADDR_INVALID_KEY


def test_secrets_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load(monkeypatch)
    for text in (repr(s), str(s)):
        assert SECRET not in text
        assert ENC not in text


@pytest.mark.parametrize("bad", ["ROLE", "RESOLVER_MODE", "ALLOW_SMTP_CHECKS", "LOG_LEVEL"])
def test_secrets_not_in_errors(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load(monkeypatch, **{bad: "bogus"})
    text = f"{excinfo.value} {excinfo.value!r} {excinfo.value.params}"
    assert SECRET not in text
    assert ENC not in text
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__


def test_blank_secret_error_does_not_leak_other_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "   ")
    monkeypatch.setenv("ENCRYPTION_KEY", ENC)
    with pytest.raises(ConfigError) as excinfo:
        Settings()  # type: ignore[call-arg]
    assert ENC not in f"{excinfo.value} {excinfo.value!r}"


def test_create_app_with_explicit_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load(monkeypatch)
    for name in VARS:
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app(s)) as client:
        assert client.get("/healthz").status_code == 200


def test_startup_fails_without_secrets() -> None:
    with pytest.raises(ConfigError) as excinfo, TestClient(create_app()):
        pass
    assert excinfo.value.key == CONFIG_MISSING_KEY


def test_startup_loads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    load(monkeypatch)
    with TestClient(create_app()) as client:
        assert client.get("/healthz").status_code == 200


@pytest.mark.parametrize("var", ["SECRET_KEY", "ENCRYPTION_KEY"])
@pytest.mark.parametrize(
    ("value", "ok"),
    [("x", False), ("a" * 31, False), ("é" * 31, False), ("a" * 32, True), ("a" * 43, True)],
)
def test_secret_minimum_length(
    monkeypatch: pytest.MonkeyPatch, var: str, value: str, ok: bool
) -> None:
    if ok:
        load(monkeypatch, **{var: value})
        return
    with pytest.raises(ConfigError) as excinfo:
        load(monkeypatch, **{var: value})
    assert excinfo.value.key == CONFIG_INVALID_VALUE_KEY
    assert excinfo.value.params == {"name": var}
    assert value not in f"{excinfo.value} {excinfo.value!r}"


def test_database_url_credentials_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    s = load(monkeypatch, DATABASE_URL="postgresql://user:pass-DO-NOT-LEAK@host/db")
    for text in (repr(s), str(s)):
        assert "pass-DO-NOT-LEAK" not in text
    assert s.database_url.get_secret_value() == "postgresql://user:pass-DO-NOT-LEAK@host/db"
