"""M7-08 migration 0013: `dns_snapshots` up and down, and its database constraints.

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
from app.models.dns_snapshot import HASH_LENGTH

ROOT = Path(__file__).resolve().parents[2]
TABLE = "dns_snapshots"


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def test_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert TABLE in inspect(real_migrations_engine).get_table_names()
    command.downgrade(_cfg(), "0012")
    insp = inspect(real_migrations_engine)
    assert TABLE not in insp.get_table_names()
    assert "check_runs" in insp.get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(real_migrations_engine)
    assert {c["name"] for c in insp.get_columns(TABLE)} == {
        "id",
        "tenant_id",
        "domain_id",
        "taken_at",
        "content_hash",
        "entries",
        "truncated",
        "created_at",
    }
    fks = {
        (tuple(f["constrained_columns"]), f["referred_table"], f["options"].get("ondelete"))
        for f in insp.get_foreign_keys(TABLE)
    }
    assert fks == {
        (("domain_id", "tenant_id"), "domains", "CASCADE"),
        (("tenant_id",), "tenants", "CASCADE"),
    }
    widths = {c["name"]: getattr(c["type"], "length", None) for c in insp.get_columns(TABLE)}
    assert widths["content_hash"] == HASH_LENGTH
    indexes = {tuple(i["column_names"]) for i in insp.get_indexes(TABLE)}
    assert ("tenant_id", "domain_id", "taken_at") in indexes
    assert ("taken_at",) in indexes


def test_single_head_builds_on_0012() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0013")
    assert revision is not None and revision.down_revision == "0012"


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


INS = (
    "INSERT INTO dns_snapshots (tenant_id, domain_id, taken_at, content_hash, entries) "
    "VALUES ({tenant}, {domain}, '2026-11-17 10:00:00+00', {hash}, {entries})"
)


def _row(
    tenant: str = "1", domain: str = "1", hash_: str | None = None, entries: str = "'[]'"
) -> str:
    return INS.format(
        tenant=tenant, domain=domain, hash=hash_ or f"'{'a' * HASH_LENGTH}'", entries=entries
    )


VIOLATIONS = [
    ("domain of another tenant", _row(tenant="1", domain="2")),
    ("unknown domain", _row(domain="99")),
    ("unknown tenant", _row(tenant="99")),
    ("null tenant", _row(tenant="NULL")),
    ("null domain", _row(domain="NULL")),
    ("null hash", _row(hash_="NULL")),
    ("null entries", _row(entries="NULL")),
]

ALLOWED = [
    ("plain row", _row()),
    ("hash at the width", _row(hash_=f"'{'f' * HASH_LENGTH}'")),
    ("same content twice (history, no uniqueness)", _row()),
]

SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    "INSERT INTO domains (id, tenant_id, name) VALUES (1, 1, 'a.example'), (2, 2, 'b.example')",
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


def test_hash_over_the_width_is_rejected_on_postgresql(seeded: Engine) -> None:
    if seeded.dialect.name != "postgresql":
        pytest.skip("SQLite does not enforce VARCHAR widths")
    with pytest.raises((IntegrityError, DataError)), seeded.begin() as conn:
        conn.execute(text(_row(hash_=f"'{'a' * (HASH_LENGTH + 1)}'")))


@pytest.mark.parametrize(("case", "statement"), ALLOWED, ids=[c for c, _ in ALLOWED])
def test_valid_insert_accepted(seeded: Engine, case: str, statement: str) -> None:
    with seeded.begin() as conn:
        assert conn.execute(text(statement)).rowcount == 1


def test_moving_a_row_to_another_tenant_is_rejected(seeded: Engine) -> None:
    with pytest.raises(IntegrityError), seeded.begin() as conn:
        conn.execute(text("UPDATE dns_snapshots SET tenant_id = 2"))


def _count(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT count(*) FROM dns_snapshots")).scalar_one())


def test_truncated_flag_defaults_to_false(seeded: Engine) -> None:
    with seeded.connect() as conn:
        flag = conn.execute(text("SELECT truncated FROM dns_snapshots")).scalar_one()
    assert not flag


def test_domain_delete_cascades(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(text("DELETE FROM domains WHERE id = 1"))
    assert _count(seeded) == 0


def test_tenant_delete_cascades(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(text("DELETE FROM tenants WHERE id = 1"))
    assert _count(seeded) == 0
