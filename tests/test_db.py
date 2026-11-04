import logging
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, IntegrityError

from app.core.config import ConfigError, Settings
from app.core.db import (
    create_db_engine,
    create_session_factory,
    engine_from_settings,
    normalize_url,
)
from app.main import create_app, log_secrets
from app.models import Base
from tests.conftest import refusal_reason

ROOT = Path(__file__).resolve().parent.parent
KEY = "k" * 40


def alembic_cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def set_env(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("sqlite:////data/app.db", "sqlite:////data/app.db"),
        ("postgresql://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgres://u:p@h:5432/db", "postgresql+psycopg://u:p@h:5432/db"),
        ("postgresql+psycopg://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
    ],
)
def test_normalize_url(url: str, expected: str) -> None:
    assert normalize_url(url) == expected


@pytest.mark.parametrize("url", ["", "not a url", "://x"])
def test_normalize_url_malformed(url: str) -> None:
    with pytest.raises(ArgumentError):
        normalize_url(url)


def test_sqlite_foreign_keys_enforced(db_url: str) -> None:
    if not db_url.startswith("sqlite"):
        pytest.skip("SQLite-specific (PRAGMA foreign_keys)")
    engine = create_db_engine(db_url)
    meta = MetaData()
    parent = Table("parent", meta, Column("id", Integer, primary_key=True))
    Table("child", meta, Column("pid", Integer, ForeignKey(parent.c.id)))
    meta.create_all(engine)
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text("INSERT INTO child (pid) VALUES (99)"))


def test_session_factory(db_url: str) -> None:
    factory = create_session_factory(create_db_engine(db_url))
    with factory() as session:
        assert session.execute(text("SELECT 1")).scalar() == 1


def test_naming_convention() -> None:
    convention = Base.metadata.naming_convention
    assert convention["pk"] == "pk_%(table_name)s"
    assert {"ix", "uq", "ck", "fk", "pk"} <= set(convention)


def test_engine_from_settings_masks_password() -> None:
    s = Settings(  # type: ignore[call-arg]
        secret_key=KEY,  # type: ignore[arg-type]
        encryption_key=KEY,  # type: ignore[arg-type]
        database_url="postgresql://user:pass-DO-NOT-LEAK@localhost/db",  # type: ignore[arg-type]
    )
    engine = engine_from_settings(s)
    assert engine.dialect.driver == "psycopg"
    assert "pass-DO-NOT-LEAK" not in repr(engine)
    assert "pass-DO-NOT-LEAK" not in str(engine.url)


def test_migration_roundtrip(db_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    set_env(monkeypatch, db_url)
    cfg = alembic_cfg()
    command.upgrade(cfg, "head")
    engine = create_db_engine(db_url)
    assert "alembic_version" in inspect(engine).get_table_names()
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0001"


def test_migrations_fail_without_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SECRET_KEY", "ENCRYPTION_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigError):
        command.upgrade(alembic_cfg(), "head")


def test_migrations_do_not_log_secrets(
    db_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    set_env(monkeypatch, db_url)
    with caplog.at_level(logging.DEBUG):
        command.upgrade(alembic_cfg(), "head")
    assert KEY not in caplog.text


PG_PASSWORD = "pg-pass-DO-NOT-LEAK-123"  # noqa: S105


def _settings(url: str) -> Settings:
    return Settings(secret_key=KEY, encryption_key=KEY, database_url=url)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("url", "extra"),
    [
        (f"postgresql://u:{PG_PASSWORD}@host/db", [PG_PASSWORD]),
        ("postgresql://u:short@host/db", []),  # under 8 chars: not masked (would corrupt JSON)
        ("postgresql://u@host/db", []),  # no password
        ("sqlite:////data/app.db", []),
        ("not a url", []),  # malformed: no crash, nothing extra
    ],
)
def test_log_secrets(url: str, extra: list[str]) -> None:
    assert log_secrets(_settings(url)) == [KEY, KEY, *extra]


def test_database_password_masked_in_logs(capsys: pytest.CaptureFixture[str]) -> None:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    try:
        with TestClient(create_app(_settings(f"postgresql://u:{PG_PASSWORD}@host/db"))):
            logging.getLogger("x").error("connect failed: %s", PG_PASSWORD)
    finally:
        root.handlers[:] = handlers
        root.setLevel(level)
    err = capsys.readouterr().err
    assert "connect failed" in err
    assert PG_PASSWORD not in err
    assert "[REDACTED]" in err


def test_migrations_do_not_log_database_password(
    db_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    password = make_url(db_url).password
    if not password:
        pytest.skip("no password on this backend (SQLite)")
    set_env(monkeypatch, db_url)
    with caplog.at_level(logging.DEBUG):
        command.upgrade(alembic_cfg(), "head")
    assert password not in caplog.text


SAME = "postgresql://u:p@h/app_test"


@pytest.mark.parametrize(
    ("test_url", "app_url", "refused"),
    [
        ("postgresql://u:p@h/ci_test", None, False),
        ("postgresql://u:p@h/t_test", "postgresql://u:p@h/app", False),
        ("postgresql://u:p@h/app_test", "", False),
        ("postgresql://u:p@h/app", None, True),
        ("postgresql://u:p@h/postgres", None, True),
        ("postgresql://u:p@h/prod", None, True),
        ("postgresql://u:p@h/", None, True),
        ("", None, True),
        ("not a url", None, True),
        (SAME, SAME, True),
    ],
)
def test_refusal_reason(test_url: str, app_url: str | None, refused: bool) -> None:
    reason = refusal_reason(test_url, app_url)
    assert (reason is not None) is refused
    if reason:
        assert "u:p" not in reason
