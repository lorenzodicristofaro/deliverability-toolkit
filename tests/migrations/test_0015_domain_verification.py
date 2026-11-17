"""M7-21a migration 0015: domain verification columns, up and down.

Runs on SQLite (columns added with their CHECKs by ADD COLUMN, never a table rebuild) and, when
TEST_DATABASE_URL is set, on PostgreSQL. Existing domains migrate as unverified; downgrade drops
only the new columns, and child rows (domain_access) survive both ways. No network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError

ROOT = Path(__file__).resolve().parents[2]
NEW = {
    "verification_status",
    "verified_at",
    "verification_method",
    "verification_token_hash",
    "verification_token_expires_at",
}
HASH = "a" * 64


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def _columns(engine: Engine) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns("domains")}


def _seed(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a')"))
        conn.execute(text("INSERT INTO users (id, email) VALUES (1, 'v@example.com')"))
        conn.execute(
            text(
                "INSERT INTO memberships (id, user_id, tenant_id, role) "
                "VALUES (1, 1, 1, 'client_viewer')"
            )
        )
        conn.execute(text("INSERT INTO domains (id, tenant_id, name) VALUES (1, 1, 'old.example')"))
        conn.execute(
            text("INSERT INTO domain_access (membership_id, domain_id, tenant_id) VALUES (1, 1, 1)")
        )


def _scalar(engine: Engine, sql: str) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(sql)).scalar_one()


def test_single_head_builds_on_0014() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert script.get_heads() == ["0015"]
    revision = script.get_revision("0015")
    assert revision is not None and revision.down_revision == "0014"


def test_existing_domains_migrate_unverified_and_downgrade_round_trips(
    real_migrations_engine: Engine,
) -> None:
    engine = real_migrations_engine
    command.downgrade(_cfg(), "0014")
    assert not NEW & _columns(engine)
    _seed(engine)

    command.upgrade(_cfg(), "head")
    assert _columns(engine) >= NEW
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT verification_status, verified_at, verification_method, "
                "verification_token_hash, verification_token_expires_at FROM domains"
            )
        ).one()
    assert tuple(row) == ("unverified", None, None, None, None)
    assert _scalar(engine, "SELECT count(*) FROM domain_access") == 1

    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE domains SET verification_status = 'verified', "
                f"verification_method = 'dns_txt', verification_token_hash = '{HASH}'"
            )
        )
    command.downgrade(_cfg(), "0014")
    assert not NEW & _columns(engine)
    assert _scalar(engine, "SELECT name FROM domains") == "old.example"
    assert _scalar(engine, "SELECT count(*) FROM domain_access") == 1

    command.upgrade(_cfg(), "head")
    assert _scalar(engine, "SELECT verification_status FROM domains") == "unverified"


VIOLATIONS = [
    ("status unknown", "verification_status = 'pending'"),
    ("status null", "verification_status = NULL"),
    ("method unknown", "verification_method = 'http'"),
    ("hash too short", "verification_token_hash = 'abc'"),
    ("hash too long", f"verification_token_hash = '{HASH}0'"),
]


@pytest.mark.parametrize("assignment", [pytest.param(a, id=c) for c, a in VIOLATIONS])
def test_database_enforces_the_columns(real_migrations_engine: Engine, assignment: str) -> None:
    engine = real_migrations_engine
    _seed(engine)
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text(f"UPDATE domains SET {assignment}"))


@pytest.mark.parametrize(
    "assignment",
    [
        "verification_status = 'verified'",
        "verification_method = 'dns_txt'",
        "verification_method = 'email'",
        f"verification_token_hash = '{HASH}'",
    ],
)
def test_database_accepts_valid_values(real_migrations_engine: Engine, assignment: str) -> None:
    engine = real_migrations_engine
    _seed(engine)
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE domains SET {assignment}"))
