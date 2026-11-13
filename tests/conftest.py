"""Shared fixtures. Every test that uses `db_url` or `migrated_db_url` runs on SQLite and, when
TEST_DATABASE_URL is set (CI, or a local throwaway container), on PostgreSQL.

- `migrated_db_url`: an empty database at Alembic head. Migrations run once per backend per
  session (lazily): SQLite tests get a copy of a migrated template, PostgreSQL tests a TRUNCATE.
- `db_url`: a truly empty database, for tests that run migrations themselves or need no schema.
- `--db-backend`: runs only one side of the split used by the CI jobs (docs/TESTING.md).
- `seed_table_access`: skips the startup seed sync in `SEEDLESS_MODULES` and guards that choice.
- pytest-xdist: each worker gets its own PostgreSQL database (`<name>_gwN`, created on first use)
  and its own SQLite files (per-worker `tmp_path`), so no DB state is shared between workers."""

import os
import re
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.db import create_db_engine
from app.models import Base
from tests.support.dns_zones import FakeServerSet, load_zones

ROOT = Path(__file__).resolve().parent.parent
_MIGRATION_KEY = "k" * 40
# The skip reason of every PostgreSQL parameter. `--db-backend` selects on it, so a parameter that
# would be skipped without PostgreSQL is by construction a parameter the PostgreSQL job runs.
PG_SKIP_REASON = "TEST_DATABASE_URL not set"

# Test modules that start the app but never read the global knowledge tables: their startup skips
# the seed sync (about 30 ms per test, mostly inserts). Add a module only after checking that it
# needs no global row; `seed_table_access` fails any test here that touches those tables. Seed
# sync, content rule, DKIM, check and acceptance tests must stay out, and keep the real sync.
SEEDLESS_MODULES = frozenset(
    {
        "tests/api/test_dns_tools_api.py",
        "tests/api/test_domains.py",
        "tests/support/test_collection_fixtures.py",
        "tests/web/test_auth_endpoints.py",
        "tests/web/test_dns_tools_trace_ui.py",
        "tests/web/test_dns_tools_ui.py",
        "tests/web/test_domains_ui.py",
        "tests/web/test_landing.py",
        "tests/web/test_setup.py",
        "tests/web/test_templating.py",
    }
)
# Reads and writes only: migrations and the per-test TRUNCATE name these tables too.
SEED_TABLE_DML = re.compile(
    r"^\s*(select|insert|update|delete)\b.*\b(content_rules|dkim_selectors)\b",
    re.IGNORECASE | re.DOTALL,
)

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


_WORKER_NAME = re.compile(r"gw[0-9]+")


def worker_database_url(test_url: str, worker: str | None) -> str:
    """The PostgreSQL database of one pytest-xdist worker: `<name>_<worker>` on the same server
    (the name keeps "test", so `refusal_reason` still applies). Without xdist (`worker` None or
    empty: a plain run, or the xdist controller) the URL is returned unchanged."""
    if not worker:
        return test_url
    if not _WORKER_NAME.fullmatch(worker):
        raise ValueError("unexpected PYTEST_XDIST_WORKER value")
    parsed = make_url(test_url)
    return parsed.set(database=f"{parsed.database}_{worker}").render_as_string(hide_password=False)


def _create_database_if_missing(server_url: str, worker_url: str) -> None:
    """Create the worker database through a connection to the vetted database. The name is
    built by `worker_database_url` from a vetted name and a `gwN` suffix, and quoted."""
    name = make_url(worker_url).database or ""
    engine = create_db_engine(server_url).execution_options(isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": name}
            ).first()
            if exists is None:
                quoted = engine.dialect.identifier_preparer.quote_identifier(name)
                conn.execute(text(f"CREATE DATABASE {quoted}"))
    finally:
        engine.dispose()


class _PostgresState:
    """What this session knows about the PostgreSQL test database."""

    vetted_url: str | None = None  # set only by pytest_sessionstart, after refusal_reason passed
    engine: Engine | None = None  # for per-test TRUNCATEs; holds no lock between tests
    fingerprint: list[tuple[Any, ...]] | None = None  # None = not known to be migrated


_pg = _PostgresState()


def pytest_sessionstart(session: pytest.Session) -> None:
    """Refuse an unsafe TEST_DATABASE_URL before anything is collected or run (exit code 2).
    In a pytest-xdist worker, switch this process to its own database: TEST_DATABASE_URL is
    rewritten for the worker only, so every fixture and subprocess that reads it (here,
    tests/tenancy/conftest.py, spawned migration workers) uses the worker's database."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        return
    app_url = os.environ.get("DATABASE_URL")
    reason = refusal_reason(url, app_url)
    if reason:
        pytest.exit(f"Refusing to reset the test database: {reason}", returncode=2)
    worker_url = worker_database_url(url, os.environ.get("PYTEST_XDIST_WORKER"))
    if worker_url != url:
        reason = refusal_reason(worker_url, app_url)
        if reason:
            pytest.exit(f"Refusing to reset the worker test database: {reason}", returncode=2)
        _create_database_if_missing(url, worker_url)
        os.environ["TEST_DATABASE_URL"] = worker_url
    _pg.vetted_url = worker_url


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


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--db-backend",
        choices=("sqlite", "postgresql"),
        default=None,
        help="sqlite: everything except the PostgreSQL params; postgresql: only those params",
    )


def needs_postgres(item: pytest.Item) -> bool:
    """True for exactly the tests skipped when PostgreSQL is not configured."""
    return any(m.kwargs.get("reason") == PG_SKIP_REASON for m in item.iter_markers("skipif"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply `--db-backend`. Without PostgreSQL the postgresql side would skip every test and
    report success, so that combination is a usage error."""
    backend = config.getoption("--db-backend")
    if backend is None:
        return
    if backend == "postgresql" and not os.environ.get("TEST_DATABASE_URL"):
        raise pytest.UsageError("--db-backend=postgresql requires TEST_DATABASE_URL")
    wanted = backend == "postgresql"
    selected = [item for item in items if needs_postgres(item) == wanted]
    deselected = [item for item in items if needs_postgres(item) != wanted]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected


def _no_seed_sync(*_args: object, **_kwargs: object) -> dict[str, Any]:
    return {}


@pytest.fixture(autouse=True)
def seed_table_access(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[list[str]]:
    """In `SEEDLESS_MODULES`: replace the startup seed sync with a no-op and record every read or
    write of a global knowledge table. Recorded statements fail the test at teardown (not when
    they run: the application may catch an exception raised there), because the test would be
    working on tables the skipped sync left empty. Elsewhere the real sync runs untouched."""
    if request.node.nodeid.partition("::")[0] not in SEEDLESS_MODULES:
        yield []
        return
    statements: list[str] = []

    def record(
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if SEED_TABLE_DML.search(statement):
            statements.append(statement)

    monkeypatch.setattr("app.main.run_seed_sync", _no_seed_sync)
    event.listen(Engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        event.remove(Engine, "before_cursor_execute", record)
    if statements:
        pytest.fail(
            f"{request.node.nodeid} touched a global knowledge table but its module is in "
            f"SEEDLESS_MODULES, so the seed sync did not run: {statements[0][:200]}"
        )


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
                not os.environ.get("TEST_DATABASE_URL"), reason=PG_SKIP_REASON
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
