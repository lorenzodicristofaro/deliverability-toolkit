"""M7-14 migration 0016: `alerts`, `alert_deliveries`, `alert_rules` up and down, and their
database constraints (dedup key, tenant-bound composite FKs, cascades, CHECKs).

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
TABLES = ("alerts", "alert_deliveries", "alert_rules")


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def test_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert set(TABLES) <= set(inspect(real_migrations_engine).get_table_names())
    command.downgrade(_cfg(), "0015")
    insp = inspect(real_migrations_engine)
    assert not set(TABLES) & set(insp.get_table_names())
    assert "domains" in insp.get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(real_migrations_engine)
    assert {c["name"] for c in insp.get_columns("alerts")} == {
        "id",
        "tenant_id",
        "domain_id",
        "kind",
        "stream",
        "fingerprint",
        "state_hash",
        "code",
        "params",
        "suppressed",
        "created_at",
    }
    assert {c["name"] for c in insp.get_columns("alert_deliveries")} == {
        "id",
        "tenant_id",
        "alert_id",
        "channel_id",
        "status",
        "attempts",
        "next_attempt_at",
        "last_error",
        "sent_at",
        "created_at",
    }
    uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints("alerts")}
    assert ("tenant_id", "fingerprint", "state_hash") in uniques
    fks = {
        (tuple(f["constrained_columns"]), f["referred_table"], f["options"].get("ondelete"))
        for f in insp.get_foreign_keys("alert_deliveries")
    }
    assert fks == {
        (("alert_id", "tenant_id"), "alerts", "CASCADE"),
        (("tenant_id",), "tenants", "CASCADE"),
    }


def test_single_head_builds_on_0015() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0016")
    assert revision is not None and revision.down_revision == "0015"


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


H = "a" * 64


def _alert(
    id_: str | None = None,
    tenant: str = "1",
    domain: str = "1",
    kind: str = "'new_listing'",
    state: str = f"'{H}'",
) -> str:
    id_col, id_val = ("id, ", f"{id_}, ") if id_ is not None else ("", "")
    return (
        f"INSERT INTO alerts ({id_col}tenant_id, domain_id, kind, stream, fingerprint, "
        f"state_hash, code, params, created_at) VALUES ({id_val}{tenant}, {domain}, {kind}, "
        f"'{H}', '{H}', {state}, 'ALERT_NEW_LISTING', '{{}}', '2026-11-18 10:00:00+00')"
    )


def _delivery(
    tenant: str = "1", alert: str = "1", channel: str = "1", status: str = "'pending'", n: str = "0"
) -> str:
    return (
        "INSERT INTO alert_deliveries (tenant_id, alert_id, channel_id, status, attempts, "
        f"created_at) VALUES ({tenant}, {alert}, {channel}, {status}, {n}, "
        "'2026-11-18 10:00:00+00')"
    )


def _rule(tenant: str = "1", kind: str = "'new_listing'", channel: str = "1") -> str:
    return (
        f"INSERT INTO alert_rules (tenant_id, kind, channel_id) VALUES ({tenant}, {kind}, "
        f"{channel})"
    )


SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    "INSERT INTO domains (id, tenant_id, name) VALUES (1, 1, 'a.example'), (2, 2, 'b.example')",
    _alert(id_="1"),
    _delivery(),
    _rule(),
]

VIOLATIONS = [
    ("alert: same dedup key", _alert()),
    ("alert: domain of another tenant", _alert(tenant="1", domain="2", state="'x'")),
    ("alert: unknown domain", _alert(domain="99", state="'x'")),
    ("alert: unknown kind", _alert(kind="'bogus'", state="'x'")),
    ("alert: null state", _alert(state="NULL")),
    ("delivery: alert of another tenant", _delivery(tenant="2", channel="2")),
    ("delivery: unknown alert", _delivery(alert="99", channel="2")),
    ("delivery: same channel twice", _delivery()),
    ("delivery: unknown status", _delivery(status="'done'", channel="2")),
    ("delivery: negative attempts", _delivery(n="-1", channel="2")),
    ("rule: same rule twice", _rule()),
    ("rule: unknown kind", _rule(kind="'bogus'")),
    ("rule: unknown tenant", _rule(tenant="99")),
]

ALLOWED = [
    ("alert: next stream position", _alert(state="'b'")),
    ("alert: same key in another tenant", _alert(tenant="2", domain="2")),
    *[(f"delivery: {s}", _delivery(status=f"'{s}'", channel="2")) for s in ("sent", "abandoned")],
    ("rule: other channel", _rule(channel="2")),
]


@pytest.fixture
def seeded(engine: Engine) -> Engine:
    with engine.begin() as conn:
        for statement in SEED_ROWS:
            conn.execute(text(statement))
        if engine.dialect.name == "postgresql":
            for table in ("tenants", "domains", "alerts"):
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


def _counts(engine: Engine) -> tuple[int, ...]:
    with engine.connect() as conn:
        return tuple(
            int(conn.execute(text(f"SELECT count(*) FROM {t}")).scalar_one()) for t in TABLES
        )


def test_moving_an_alert_to_another_tenant_is_rejected(seeded: Engine) -> None:
    with pytest.raises(IntegrityError), seeded.begin() as conn:
        conn.execute(text("UPDATE alerts SET tenant_id = 2"))


def test_domain_delete_cascades_to_alerts_and_deliveries(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(text("DELETE FROM domains WHERE id = 1"))
    assert _counts(seeded) == (0, 0, 1)


def test_tenant_delete_cascades(seeded: Engine) -> None:
    with seeded.begin() as conn:
        conn.execute(text("DELETE FROM tenants WHERE id = 1"))
    assert _counts(seeded) == (0, 0, 0)
