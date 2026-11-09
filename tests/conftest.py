"""Shared fixtures. Every test that uses `db_url` or `migrated_db_url` runs on SQLite and, when
TEST_DATABASE_URL is set (CI, or a local throwaway container), on PostgreSQL.

- `migrated_db_url`: an empty database at Alembic head. Migrations run once per backend per
  session (lazily): SQLite tests get a copy of a migrated template, PostgreSQL tests a TRUNCATE.
- `db_url`: a truly empty database, for tests that run migrations themselves or need no schema."""

import os
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.db import create_db_engine
from app.models import Base
from tests.support.dns_zones import FakeServerSet, load_zones

ROOT = Path(__file__).resolve().parent.parent
_MIGRATION_KEY = "k" * 40

# A reset that cannot get its locks fails the test instead of hanging CI. The usual cause is a
# connection left "idle in transaction" by an earlier test (a session or engine not closed).
_LOCK_TIMEOUT = "SET LOCAL lock_timeout = '10s'"
_SCHEMA_FINGERPRINT = text(
    """
    SELECT 'index'::text, tablename::text, indexname::text, indexdef::text
      FROM pg_indexes WHERE schemaname = current_schema()
    UNION ALL
    SELECT 'column'::text, table_name::text, column_name::text, data_type::text
      FROM information_schema.columns WHERE table_schema = current_schema()
    UNION ALL
    SELECT 'alembic'::text, 'alembic_version'::text, version_num::text, ''::text
      FROM alembic_version
    ORDER BY 1, 2, 3, 4
    """
)


def refusal_reason(test_url: str, app_url: str | None) -> str | None:
    """Why TEST_DATABASE_URL must not be used (None = safe). The reset drops tables, so it only
    ever runs on a database whose name contains "test" and that is not the app's DATABASE_URL.
    The reason never contains the URL or its password."""
    try:
        database = make_url(test_url).database or ""
    except ArgumentError:
        return "TEST_DATABASE_URL is not a valid database URL"
    if "test" not in database.lower():
        return 'TEST_DATABASE_URL database name must contain "test"'
    if app_url and test_url.strip() == app_url.strip():
        return "TEST_DATABASE_URL equals DATABASE_URL"
    return None


class _PostgresState:
    """What this session knows about the PostgreSQL test database."""

    vetted_url: str | None = None  # set only by pytest_sessionstart, after refusal_reason passed
    engine: Engine | None = None  # for per-test TRUNCATEs; holds no lock between tests
    fingerprint: list[tuple[Any, ...]] | None = None  # None = not known to be migrated


_pg = _PostgresState()


def pytest_sessionstart(session: pytest.Session) -> None:
    """Refuse an unsafe TEST_DATABASE_URL before anything is collected or run (exit code 2)."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        return
    reason = refusal_reason(url, os.environ.get("DATABASE_URL"))
    if reason:
        pytest.exit(f"Refusing to reset the test database: {reason}", returncode=2)
    _pg.vetted_url = url


def _require_vetted(url: str) -> None:
    """Every destructive PostgreSQL path starts here: only the URL vetted at session start may be
    reset. Compared with that URL rather than re-running refusal_reason, because fixtures set
    DATABASE_URL to this very URL while a test runs. The message never contains the URL."""
    if _pg.vetted_url is None or url != _pg.vetted_url:
        raise RuntimeError("Refusing to reset a database not vetted by pytest_sessionstart")


def _reset_postgres(url: str) -> None:
    """Drop only what this project creates, so a clean schema is guaranteed per test."""
    _require_vetted(url)
    _pg.fingerprint = None  # the shared migrated schema is gone: the next user migrates again
    engine = create_db_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(text(_LOCK_TIMEOUT))
            Base.metadata.drop_all(conn)
            conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    finally:
        engine.dispose()


def _run_migrations(url: str) -> None:
    """The real `alembic upgrade head`, through the same env.py path the application uses."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DATABASE_URL", url)
        mp.setenv("SECRET_KEY", _MIGRATION_KEY)
        mp.setenv("ENCRYPTION_KEY", _MIGRATION_KEY)
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")


def _pg_fingerprint(engine: Engine) -> list[tuple[Any, ...]]:
    with engine.connect() as conn:
        return [tuple(row) for row in conn.execute(_SCHEMA_FINGERPRINT)]


def _truncate_postgres(url: str) -> None:
    """Empty every project table and restart its sequences, migrating first if needed. The
    migrations write no rows (checked in migrations/versions), so empty equals freshly migrated;
    alembic_version is not a project table and is kept."""
    _require_vetted(url)
    if _pg.fingerprint is None:
        _reset_postgres(url)  # unknown state: a real migration test ran, or a crashed session
        _run_migrations(url)
        if _pg.engine is None:
            _pg.engine = create_db_engine(url)
        _pg.fingerprint = _pg_fingerprint(_pg.engine)
    assert _pg.engine is not None
    quote = _pg.engine.dialect.identifier_preparer.quote_identifier
    tables = ", ".join(quote(table.name) for table in Base.metadata.sorted_tables)
    with _pg.engine.begin() as conn:
        conn.execute(text(_LOCK_TIMEOUT))
        conn.execute(text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE"))


def _check_postgres_schema_unchanged(url: str) -> None:
    """A test on the shared schema must not have changed it: fail that test, rebuild for the next.
    Tests that alter the schema belong on `db_url`, with real migrations."""
    _require_vetted(url)
    assert _pg.engine is not None
    expected, _pg.fingerprint = _pg.fingerprint, None  # stays None if the query below raises
    if _pg_fingerprint(_pg.engine) != expected:
        pytest.fail("test altered the shared migrated schema: use db_url and real migrations")
    _pg.fingerprint = expected


@pytest.fixture(scope="session")
def _sqlite_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A migrated SQLite file, built on first use. No test ever opens it, they get a copy."""
    template = tmp_path_factory.mktemp("sqlite-template") / "template.db"
    _run_migrations(f"sqlite:///{template}")
    return template


@pytest.fixture(scope="session")
def _postgres_session() -> Iterator[str]:
    """The vetted PostgreSQL URL; leaves the database empty when the session ends."""
    url = os.environ["TEST_DATABASE_URL"]  # already vetted in pytest_sessionstart
    yield url
    if _pg.engine is not None:
        _pg.engine.dispose()
        _pg.engine = None
    _reset_postgres(url)


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgresql",
            marks=pytest.mark.skipif(
                not os.environ.get("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL not set"
            ),
        ),
    ]
)
def db_backend(request: pytest.FixtureRequest) -> str:
    """The parametrisation point shared by `db_url` and `migrated_db_url`."""
    if {"db_url", "migrated_db_url"} <= set(request.fixturenames):
        pytest.fail("a test uses either db_url or migrated_db_url, never both")
    return str(request.param)


@pytest.fixture
def db_url(db_backend: str, request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    """A truly empty database: for tests that run migrations or need no schema at all."""
    if db_backend == "sqlite":
        yield f"sqlite:///{tmp_path / 'test.db'}"
        return
    url = request.getfixturevalue("_postgres_session")
    _reset_postgres(url)
    yield url
    _reset_postgres(url)


@pytest.fixture
def migrated_db_url(
    db_backend: str, request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[str]:
    """An empty database at Alembic head, isolated per test, migrated once per session."""
    if db_backend == "sqlite":
        target = tmp_path / "test.db"
        shutil.copyfile(request.getfixturevalue("_sqlite_template"), target)
        yield f"sqlite:///{target}"
        return
    url = request.getfixturevalue("_postgres_session")
    _truncate_postgres(url)
    yield url
    _check_postgres_schema_unchanged(url)


@pytest.fixture
def real_migrations_engine(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """A database taken from truly empty to head by real migrations, for tests that migrate."""
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", _MIGRATION_KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", _MIGRATION_KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def fake_dns() -> Callable[[str], FakeServerSet]:
    """Load a recorded zone fixture by name (tests/fixtures/zones/<name>.yaml); no network."""
    return lambda name: load_zones(Path(__file__).parent / "fixtures" / "zones" / f"{name}.yaml")
