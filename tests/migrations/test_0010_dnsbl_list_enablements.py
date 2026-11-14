"""M7-05c migration 0010: `dnsbl_list_enablements` up and down, and its database constraints.

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
TABLE = "dnsbl_list_enablements"


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def test_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert TABLE in inspect(real_migrations_engine).get_table_names()
    command.downgrade(_cfg(), "0009")
    insp = inspect(real_migrations_engine)
    assert TABLE not in insp.get_table_names()
    assert "domain_esps" in insp.get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(real_migrations_engine)
    assert TABLE in insp.get_table_names()
    assert {c["name"] for c in insp.get_columns(TABLE)} == {
        "id",
        "list_id",
        "enabled_by",
        "enabled_at",
        "policy_acknowledged",
        "policy_acknowledged_at",
        "unverified_confirmed",
    }
    uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints(TABLE)}
    assert ("list_id",) in uniques
    fks = {
        (tuple(f["constrained_columns"]), f["referred_table"], f["options"].get("ondelete"))
        for f in insp.get_foreign_keys(TABLE)
    }
    assert fks == {(("enabled_by",), "users", "SET NULL")}


def test_single_head_builds_on_0009() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0010")
    assert revision is not None and revision.down_revision == "0009"


# --- constraints (raw SQL: the database enforces them, not only the repository) -----------------


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


INS = (
    f"INSERT INTO {TABLE} (list_id, enabled_at, policy_acknowledged, policy_acknowledged_at"
    "{extra_cols}) VALUES ({list_id}, '2026-11-14 10:00:00+00', {ack}, "
    "'2026-11-14 10:00:00+00'{extra_vals})"
)


def _insert(list_id: str = "'surbl-multi'", ack: str = "true", **extra: str) -> str:
    cols = "".join(f", {k}" for k in extra)
    vals = "".join(f", {v}" for v in extra.values())
    return INS.format(list_id=list_id, ack=ack, extra_cols=cols, extra_vals=vals)


REJECTED = [
    ("not_acknowledged", _insert(ack="false")),
    ("ack_null", _insert(ack="NULL")),
    ("uppercase_id", _insert(list_id="'SURBL-multi'")),
    ("empty_id", _insert(list_id="''")),
    ("id_too_long", _insert(list_id="'" + "a" * 41 + "'")),
    ("id_null", _insert(list_id="NULL")),
    ("unknown_user", _insert(enabled_by="999999")),
    ("confirmed_null", _insert(unverified_confirmed="NULL")),
]


@pytest.mark.parametrize(("case", "statement"), REJECTED, ids=[c for c, _ in REJECTED])
def test_constraint_violation_rejected(engine: Engine, case: str, statement: str) -> None:
    with (
        pytest.raises((IntegrityError, DataError)),
        engine.begin() as conn,
    ):  # PG: overlong is DataError
        conn.execute(text(statement))


def test_duplicate_list_id_rejected(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text(_insert()))
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text(_insert()))


def test_valid_insert_defaults_unverified_confirmed_false(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text(_insert(list_id="'" + "a" * 40 + "'")))
        stored = conn.execute(text(f"SELECT unverified_confirmed FROM {TABLE}")).scalar_one()
    assert stored in (False, 0)


def test_deleting_the_user_keeps_the_row(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (email) VALUES ('root@example.com')"))
        uid = conn.execute(text("SELECT id FROM users")).scalar_one()
        conn.execute(text(_insert(enabled_by=str(uid))))
        conn.execute(text("DELETE FROM users"))
        row = conn.execute(text(f"SELECT list_id, enabled_by FROM {TABLE}")).one()
    assert tuple(row) == ("surbl-multi", None)
