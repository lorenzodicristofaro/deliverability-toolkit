"""Self-tests of the shared test machinery: the `--db-backend` split used by the CI jobs and the
seed sync skipped in `SEEDLESS_MODULES`. No network; DB tests use the shared backends.

This module is itself in `SEEDLESS_MODULES`, so it sees the skipped sync from the inside. The real
sync is covered by tests/services/test_seed_sync.py, which is deliberately not in the set.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import app.main as app_main
import app.services.seed_sync as seed_sync
from app.core.config import Settings
from app.core.db import create_db_engine
from tests.conftest import (
    PG_SKIP_REASON,
    SEED_TABLE_DML,
    SEEDLESS_MODULES,
    needs_postgres,
    pytest_collection_modifyitems,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40


# --- --db-backend --------------------------------------------------------------------------------


class _Item:
    def __init__(self, name: str, marks: list[Any]) -> None:
        self.name = name
        self.marks = marks

    def iter_markers(self, name: str) -> list[Any]:
        return [m for m in self.marks if m.name == name]


def _mark(reason: str | None) -> Any:
    return SimpleNamespace(name="skipif", kwargs={} if reason is None else {"reason": reason})


PG = _Item("pg", [_mark(PG_SKIP_REASON)])
SQLITE = _Item("sqlite", [])
OTHER_SKIP = _Item("other", [_mark("needs non-root POSIX")])
NO_REASON = _Item("no_reason", [_mark(None)])
ALL_ITEMS = [PG, SQLITE, OTHER_SKIP, NO_REASON]


def _config(backend: str | None) -> tuple[Any, list[Any]]:
    deselected: list[Any] = []
    config = SimpleNamespace(
        getoption=lambda _name: backend,
        hook=SimpleNamespace(pytest_deselected=lambda items: deselected.extend(items)),
    )
    return config, deselected


@pytest.mark.parametrize(
    ("backend", "kept", "dropped"),
    [
        (None, ALL_ITEMS, []),
        ("sqlite", [SQLITE, OTHER_SKIP, NO_REASON], [PG]),
        ("postgresql", [PG], [SQLITE, OTHER_SKIP, NO_REASON]),
    ],
    ids=["unset", "sqlite", "postgresql"],
)
def test_backend_selection_partitions_the_items(
    backend: str | None, kept: list[Any], dropped: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_DATABASE_URL", "postgresql://u:p@h/x_test")
    config, deselected = _config(backend)
    items: list[Any] = list(ALL_ITEMS)
    pytest_collection_modifyitems(config, items)
    assert items == kept
    assert deselected == dropped


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_postgresql_side_without_a_database_is_a_usage_error(
    value: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if value is None:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("TEST_DATABASE_URL", value)
    config, _ = _config("postgresql")
    items: list[Any] = [PG]
    with pytest.raises(pytest.UsageError):
        pytest_collection_modifyitems(config, items)


def test_needs_postgres_matches_every_postgresql_parameter(request: pytest.FixtureRequest) -> None:
    """On the real collection: the skip marker and the parameter value always agree, so a new
    PostgreSQL parameter with another skip reason cannot be silently skipped by both CI jobs.
    This module is left out: its own table above has the bare string as a parameter value."""
    mismatched = [
        item.nodeid
        for item in request.session.items
        if item.path != Path(__file__)
        and needs_postgres(item)
        != ("postgresql" in getattr(getattr(item, "callspec", None), "params", {}).values())
    ]
    assert mismatched == []


# --- seedless modules ----------------------------------------------------------------------------


@pytest.mark.parametrize("module", sorted(SEEDLESS_MODULES))
def test_seedless_module_exists(module: str) -> None:
    assert (ROOT / module).is_file()


@pytest.mark.parametrize(
    "module",
    [
        "tests/api/test_checks_api.py",
        "tests/api/test_content_analyze.py",
        "tests/api/test_message_analyze.py",
        "tests/checks/test_acceptance_m3.py",
        "tests/dns/test_acceptance_m2.py",
        "tests/services/test_acceptance_m4.py",
        "tests/services/test_seed_sync.py",
        "tests/tenancy/test_acceptance_m1.py",
        "tests/tenancy/test_matrix.py",
        "tests/web/test_authentication_tab.py",
        "tests/web/test_checks_stream.py",
        "tests/web/test_message_ui.py",
    ],
)
def test_modules_that_keep_the_real_sync(module: str) -> None:
    assert (ROOT / module).is_file()
    assert module not in SEEDLESS_MODULES


@pytest.mark.parametrize(
    ("statement", "flagged"),
    [
        ("SELECT id FROM content_rules", True),
        ("select id from dkim_selectors where scope = 'global'", True),
        ("\n  SELECT a,\n b FROM\n  content_rules", True),
        ("INSERT INTO dkim_selectors (scope) VALUES ('global')", True),
        ("UPDATE content_rules SET weight = 1", True),
        ("DELETE FROM dkim_selectors", True),
        ("SELECT id FROM domains", False),
        ("SELECT id FROM content_rules_backup", False),
        ("SELECT id FROM my_dkim_selectors", False),
        ("CREATE TABLE content_rules (id INTEGER)", False),
        ("DROP TABLE dkim_selectors", False),
        ('TRUNCATE TABLE "domains", content_rules RESTART IDENTITY CASCADE', False),
        ("PRAGMA table_info(content_rules)", False),
        ("", False),
        ("   ", False),
        ("content_rules", False),
    ],
)
def test_seed_table_statement_detection(statement: str, flagged: bool) -> None:
    assert bool(SEED_TABLE_DML.search(statement)) is flagged


def test_startup_skips_the_sync_here_and_the_guard_sees_table_access(
    migrated_db_url: str, seed_table_access: list[str]
) -> None:
    assert app_main.run_seed_sync is not seed_sync.run_seed_sync
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    with TestClient(app_main.create_app(settings)) as client:
        assert client.get("/healthz").status_code == 200
    assert seed_table_access == []
    engine = create_db_engine(migrated_db_url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT COUNT(*) FROM dkim_selectors")).scalar_one()
    finally:
        engine.dispose()
    assert rows == 0  # the sync really did not run
    assert len(seed_table_access) == 1  # the guard saw the read above
    seed_table_access.clear()  # expected here: anything left fails this test at teardown
