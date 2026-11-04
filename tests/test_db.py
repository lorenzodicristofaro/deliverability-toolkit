import logging
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, inspect, text
from sqlalchemy.exc import ArgumentError, IntegrityError

from app.core.config import ConfigError, Settings
from app.core.db import (
    create_db_engine,
    create_session_factory,
    engine_from_settings,
    normalize_url,
)
from app.models import Base

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


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL not set")
def test_migration_roundtrip_postgresql(monkeypatch: pytest.MonkeyPatch) -> None:
    set_env(monkeypatch, os.environ["TEST_DATABASE_URL"])
    cfg = alembic_cfg()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


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
