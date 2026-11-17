"""M7-02 migration 0014: `http_fetch` accepted by the custom_checks kind CHECK, up and down.

Runs on SQLite (table rebuilt by batch mode) and, when TEST_DATABASE_URL is set, on PostgreSQL.
Downgrade refuses while an `http_fetch` row exists. No network.
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
TABLE = "custom_checks"


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def _insert(key: str, kind: str) -> str:
    return (
        "INSERT INTO custom_checks (scope, tenant_id, check_key, name, kind, definition, "
        f"severity, remediation_text) VALUES ('tenant', 1, '{key}', 'n', '{kind}', "
        '\'{"a": 1}\', \'low\', \'{"en": "e", "it": "i"}\')'
    )


def _keys(engine: Engine) -> list[str]:
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT check_key FROM custom_checks ORDER BY check_key"))
        return [r[0] for r in rows]


KIND_CHECK = "ck_custom_checks_kind_valid"


def _shape(engine: Engine) -> tuple[Any, ...]:
    """Everything but the kind CHECK: columns, indexes (with the partial index SQL on SQLite),
    foreign keys and every other CHECK with its text, so the SQLite rebuild loses nothing."""
    insp = inspect(engine)
    checks = {
        (c["name"], " ".join(str(c["sqltext"]).split()))
        for c in insp.get_check_constraints(TABLE)
        if c["name"] != KIND_CHECK
    }
    index_sql: set[str] = set()
    if engine.dialect.name == "sqlite":
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = :t"),
                {"t": TABLE},
            )
            index_sql = {" ".join(str(r[0]).split()) for r in rows if r[0] is not None}
    return (
        {(c["name"], str(c["type"]), bool(c["nullable"])) for c in insp.get_columns(TABLE)},
        {(i["name"], bool(i["unique"])) for i in insp.get_indexes(TABLE)},
        index_sql,
        {(str(f["name"]), f["referred_table"]) for f in insp.get_foreign_keys(TABLE)},
        checks,
        len(checks) > 10,  # sanity: the CHECKs really are reflected
    )


def _kind_check(engine: Engine) -> str:
    (check,) = [c for c in inspect(engine).get_check_constraints(TABLE) if c["name"] == KIND_CHECK]
    return str(check["sqltext"])


def test_single_head_builds_on_0013() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0014")
    assert revision is not None and revision.down_revision == "0013"


def test_upgrade_accepts_http_fetch_and_downgrade_round_trips(
    real_migrations_engine: Engine,
) -> None:
    engine = real_migrations_engine
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a')"))
        conn.execute(text(_insert("dns", "dns_exists")))
        conn.execute(text(_insert("http", "http_fetch")))
    shape = _shape(engine)
    assert shape[-1] is True
    assert "http_fetch" in _kind_check(engine)
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text(_insert("other", "smtp_probe")))

    # Refused while an http_fetch row exists; nothing changes.
    with pytest.raises(RuntimeError, match="http_fetch rows"):
        command.downgrade(_cfg(), "0013")
    assert _keys(engine) == ["dns", "http"]

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM custom_checks WHERE kind = 'http_fetch'"))
    command.downgrade(_cfg(), "0013")
    assert _keys(engine) == ["dns"]  # other rows survive the SQLite rebuild
    assert _shape(engine) == shape
    assert "http_fetch" not in _kind_check(engine)
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text(_insert("http2", "http_fetch")))

    command.upgrade(_cfg(), "head")
    assert _shape(engine) == shape
    assert "http_fetch" in _kind_check(engine)
    with engine.begin() as conn:
        conn.execute(text(_insert("http3", "http_fetch")))
    assert _keys(engine) == ["dns", "http3"]


def test_other_constraints_survive_the_rebuild(real_migrations_engine: Engine) -> None:
    """The batch rebuild keeps every other CHECK and the partial global unique index."""
    engine = real_migrations_engine
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a')"))
    bad = [
        _insert("Upper", "http_fetch"),  # check_key_lower
        _insert("k", "http_fetch").replace("'low'", "'urgent'"),  # severity_valid
        _insert("k", "http_fetch").replace("'tenant', 1", "'global', 1"),  # scope_tenant
    ]
    for statement in bad:
        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(text(statement))
    glob = (
        "INSERT INTO custom_checks (scope, tenant_id, check_key, name, kind, definition, "
        "severity, remediation_key) VALUES ('global', NULL, 'g', 'n', 'http_fetch', "
        "'{\"a\": 1}', 'low', 'x.y')"
    )
    with engine.begin() as conn:
        conn.execute(text(glob))
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(text(glob))
