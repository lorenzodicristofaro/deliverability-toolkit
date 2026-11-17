"""M7-06 migration 0011: `monitor_targets` up and down, and its database constraints.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixtures). The schema
is built by Alembic. No network.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DataError, IntegrityError

from app.core.db import create_db_engine

ROOT = Path(__file__).resolve().parents[2]
TABLE = "monitor_targets"


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def test_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert TABLE in inspect(real_migrations_engine).get_table_names()
    command.downgrade(_cfg(), "0010")
    insp = inspect(real_migrations_engine)
    assert TABLE not in insp.get_table_names()
    assert "dnsbl_list_enablements" in insp.get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(real_migrations_engine)
    assert {c["name"] for c in insp.get_columns(TABLE)} == {
        "id",
        "tenant_id",
        "domain_id",
        "check_ids",
        "interval_seconds",
        "enabled",
        "next_run_at",
        "last_run_at",
        "last_status",
        "created_at",
        "updated_at",
    }
    uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints(TABLE)}
    assert ("tenant_id", "domain_id") in uniques
    fks = {
        (tuple(f["constrained_columns"]), f["referred_table"], f["options"].get("ondelete"))
        for f in insp.get_foreign_keys(TABLE)
    }
    assert fks == {
        (("domain_id", "tenant_id"), "domains", "CASCADE"),
        (("tenant_id",), "tenants", "CASCADE"),
    }
    indexes = {tuple(i["column_names"]) for i in insp.get_indexes(TABLE)}
    assert ("enabled", "next_run_at") in indexes


def test_single_head_builds_on_0010() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0011")
    assert revision is not None and revision.down_revision == "0010"


# --- constraints (raw SQL: the database enforces them, not only the repository) -----------------


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


INS = (
    "INSERT INTO monitor_targets (tenant_id, domain_id, check_ids, interval_seconds, "
    "next_run_at, last_status) VALUES ({tenant}, {domain}, '[\"spf\"]', {interval}, "
    "'2026-11-17 10:00:00+00', {status})"
)


def _row(tenant: str = "1", domain: str = "1", interval: str = "3600", status: str = "NULL") -> str:
    return INS.format(tenant=tenant, domain=domain, interval=interval, status=status)


VIOLATIONS = [
    ("domain of another tenant", _row(tenant="1", domain="2")),
    ("unknown domain", _row(domain="99")),
    ("unknown tenant", _row(tenant="99")),
    ("null tenant", _row(tenant="NULL")),
    ("null domain", _row(domain="NULL")),
    ("interval below the minimum", _row(domain="3", interval="3599")),
    ("zero interval", _row(domain="3", interval="0")),
    ("negative interval", _row(domain="3", interval="-1")),
    ("unknown status", _row(domain="3", status="'bogus'")),
    ("duplicate (tenant, domain)", _row()),
]

ALLOWED = [
    ("another domain", _row(domain="3")),
    ("status ok", _row(domain="3", status="'ok'")),
    ("status error", _row(domain="3", status="'error'")),
    ("interval above the minimum", _row(domain="3", interval="86400")),
]

SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    "INSERT INTO domains (id, tenant_id, name) VALUES "
    "(1, 1, 'a.example'), (2, 2, 'b.example'), (3, 1, 'a3.example')",
    _row(),
]


@pytest.fixture
def seeded(engine: Engine) -> Engine:
    with engine.begin() as conn:
        for statement in SEED_ROWS:
            conn.execute(text(statement))
        if engine.dialect.name == "postgresql":
            for table in ("tenants", "domains"):
                conn.execute(
                    text(
                        f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                        f"(SELECT MAX(id) FROM {table}))"
                    )
                )
    return engine


@pytest.mark.parametrize(("case", "statement"), VIOLATIONS, ids=[c for c, _ in VIOLATIONS])
def test_constraint_violation_rejected(seeded: Engine, case: str, statement: str) -> None:
    with pytest.raises((IntegrityError, DataError)), seeded.begin() as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(("case", "statement"), ALLOWED, ids=[c for c, _ in ALLOWED])
def test_valid_insert_accepted(seeded: Engine, case: str, statement: str) -> None:
    with seeded.begin() as conn:
        assert conn.execute(text(statement)).rowcount == 1


def test_moving_a_row_to_another_tenant_is_rejected(seeded: Engine) -> None:
    with pytest.raises(IntegrityError), seeded.begin() as conn:
        conn.execute(text("UPDATE monitor_targets SET tenant_id = 2"))


def _count(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT count(*) FROM monitor_targets")).scalar_one())


def test_domain_delete_cascades(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(text("DELETE FROM domains WHERE id = 1"))
    assert _count(seeded) == 0


def test_tenant_delete_cascades(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(text("DELETE FROM tenants WHERE id = 1"))
    assert _count(seeded) == 0
