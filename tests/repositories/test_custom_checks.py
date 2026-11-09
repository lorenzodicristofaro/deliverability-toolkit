"""M5-07 custom_checks: migration 0008, DB constraints and the repositories.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture; the
PG params skip locally and run on dev CI). The schema is built by Alembic. No network.
"""

import dataclasses
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, and_, bindparam, inspect, or_, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import CustomCheck, Tenant, User
from app.models.custom_check import (
    MAX_DEFINITION_LENGTH,
    MAX_REMEDIATION_JSON_LENGTH,
    MAX_REMEDIATION_LENGTH,
)
from app.repositories import GlobalCustomCheckRepository, repo_for
from app.repositories.base import TenantScopeError
from app.repositories.custom_checks import (
    CheckKeyTaken,
    CustomCheckInvalid,
    CustomCheckRecord,
    CustomCheckRepository,
    LocalizedText,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**31, 2**63 - 1, 2**63, [1], b"1"]
TEXT = {"en": "Publish the record.", "it": "Pubblica il record."}


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def _check(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "check_key": "spf.include",
        "name": "SPF includes the ESP",
        "kind": "dns_matches",
        "definition": {"rrtype": "TXT", "name": "@", "contains": "include:esp.example"},
        "severity": "medium",
        "remediation_text": dict(TEXT),
    }
    values.update(overrides)
    return values


def _new(**overrides: Any) -> dict[str, Any]:
    """A fresh tenant-A check (check_key 'a.new' unless overridden)."""
    return _check(**{"check_key": "a.new", **overrides})


@pytest.fixture
def engine(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    session: Session
    tenant_a: int
    tenant_b: int
    user: int
    checks: dict[str, int]

    def repo(self, tenant: str = "a") -> CustomCheckRepository:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, self.user), self.session).custom_checks

    def global_repo(self) -> GlobalCustomCheckRepository:
        return GlobalCustomCheckRepository(self.session)


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        user = User(email="admin@example.com")
        session.add_all([ta, tb, user])
        session.flush()
        g = GlobalCustomCheckRepository(session)
        checks = {
            "g1": g.create(
                _check(
                    check_key="g.one",
                    remediation_text=None,
                    remediation_key="custom_check.g_one.remediation",
                ),
                actor=None,
            ).id,
            "g2": g.create(_check(check_key="g.two", enabled=False), actor=user.id).id,
        }
        a = repo_for(TenantContext(ta.id, user.id), session).custom_checks
        b = repo_for(TenantContext(tb.id, None), session).custom_checks
        checks["a1"] = a.create(_check(check_key="g.one", enabled=False)).id
        checks["b1"] = b.create(_check(check_key="b.own", kind="dns_exists")).id
        session.commit()
        yield World(session, ta.id, tb.id, user.id, checks)
    finally:
        session.close()


def _ids(records: Any) -> list[int]:
    return [r.id for r in records]


# --- migration ---------------------------------------------------------------------------------


def _index_shapes(engine: Engine) -> dict[str, tuple[tuple[str, ...], bool, bool]]:
    """name -> (columns, unique, partial) for custom_checks."""
    shapes = {}
    for idx in inspect(engine).get_indexes("custom_checks"):
        opts = idx.get("dialect_options", {})
        partial = any(opts.get(k) is not None for k in ("sqlite_where", "postgresql_where"))
        shapes[idx["name"]] = (tuple(idx["column_names"]), bool(idx["unique"]), partial)
    return shapes


INDEXES = {
    "uq_custom_checks_global_check_key": (("check_key",), True, True),
    # Plain on purpose (no partial tenant index: SQLite planner error, see M5-05b).
    "uq_custom_checks_tenant_check_key": (("tenant_id", "check_key"), True, False),
}


def test_migration_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert "custom_checks" in inspect(real_migrations_engine).get_table_names()
    assert _index_shapes(real_migrations_engine) == INDEXES
    command.downgrade(_cfg(), "0007")
    assert "custom_checks" not in inspect(real_migrations_engine).get_table_names()
    assert "content_rules" in inspect(real_migrations_engine).get_table_names()
    command.upgrade(_cfg(), "head")
    assert "custom_checks" in inspect(real_migrations_engine).get_table_names()
    assert _index_shapes(real_migrations_engine) == INDEXES


def test_single_alembic_head() -> None:
    from alembic.script import ScriptDirectory

    assert ScriptDirectory.from_config(_cfg()).get_heads() == ["0008"]


def test_migration_hardcodes_model_limits() -> None:
    migration = next((ROOT / "migrations" / "versions").glob("*_0008_custom_checks.py"))
    source = migration.read_text(encoding="utf-8")
    assert f'"definition", {MAX_DEFINITION_LENGTH})' in source
    assert f'"remediation_text", {MAX_REMEDIATION_JSON_LENGTH}, nullable=True' in source
    assert "http_fetch" not in source.split('"""', 2)[2]  # only mentioned in the docstring


# Tenant OR-filter + check_key with bound parameters (the M5-22 lookup shape). With a partial
# (tenant_id, ...) WHERE scope = 'tenant' index SQLite 3.46-3.53 raised "internal query planner
# error" on this shape.
_VISIBLE = or_(
    and_(CustomCheck.scope == "global", CustomCheck.tenant_id.is_(None)),
    and_(CustomCheck.scope == bindparam("scope"), CustomCheck.tenant_id == bindparam("tid")),
)
PLANNER_CASES = [
    ("check_key", [], {}, ["g1", "a1"]),
    (
        "check_key + kind",
        [CustomCheck.kind == bindparam("kind")],
        {"kind": "dns_matches"},
        ["g1", "a1"],
    ),
    (
        "check_key + enabled",
        [CustomCheck.enabled == bindparam("enabled")],
        {"enabled": True},
        ["g1"],
    ),
    (
        "check_key + kind + enabled",
        [CustomCheck.kind == bindparam("kind"), CustomCheck.enabled == bindparam("enabled")],
        {"kind": "dns_matches", "enabled": False},
        ["a1"],
    ),
    ("unknown check_key", [], {"key": "missing"}, []),
]


@pytest.mark.parametrize(
    ("case", "extra", "params", "expected"), PLANNER_CASES, ids=[c[0] for c in PLANNER_CASES]
)
def test_tenant_or_filter_check_key_lookup_runs(
    world: World, case: str, extra: list[Any], params: dict[str, Any], expected: list[str]
) -> None:
    stmt = (
        select(CustomCheck.id)
        .where(_VISIBLE, CustomCheck.check_key == bindparam("key"), *extra)
        .order_by(CustomCheck.id)
    )
    bound = {"scope": "tenant", "tid": world.tenant_a, "key": "g.one", **params}
    assert list(world.session.execute(stmt, bound).scalars()) == sorted(
        world.checks[k] for k in expected
    )
    bound["tid"] = world.tenant_b
    assert world.checks["a1"] not in set(world.session.execute(stmt, bound).scalars())


def test_repository_key_lookup(world: World) -> None:
    c = world.checks
    assert _ids(world.repo("a").get_by_key("g.one")) == [c["g1"], c["a1"]]
    assert _ids(world.repo("b").get_by_key("g.one")) == [c["g1"]]
    assert _ids(world.repo("a").get_by_key("b.own")) == []
    assert _ids(world.global_repo().get_by_key("g.one")) == [c["g1"]]
    assert world.repo("a").get_by_key(1) == []


# --- constraints (raw SQL: the database enforces them, not only the repository) -----------------

COLS = "(scope, tenant_id, check_key, name, description, kind, definition, severity, "
COLS += "remediation_key, remediation_text) VALUES "
INS = "INSERT INTO custom_checks " + COLS
DEF = "'{\"a\": 1}'"
REM = '\'{"en": "e", "it": "i"}\''


def _row(
    scope: str = "'tenant'",
    tenant: str = "1",
    key: str = "'k'",
    name: str = "'n'",
    description: str = "NULL",
    kind: str = "'dns_exists'",
    definition: str = DEF,
    severity: str = "'low'",
    remediation_key: str = "NULL",
    remediation_text: str = REM,
) -> str:
    vals = [scope, tenant, key, name, description, kind, definition, severity]
    return INS + "(" + ", ".join([*vals, remediation_key, remediation_text]) + ")"


def _json_literal(size: int) -> str:
    """A JSON object literal of exactly `size` characters."""
    head = '{"a": "'
    return "'" + head + "x" * (size - len(head) - 2) + "\"}'"


VIOLATIONS = [
    ("unknown scope", _row(scope="'shared'")),
    ("null scope", _row(scope="NULL")),
    ("global with tenant_id", _row(scope="'global'", tenant="1")),
    ("tenant without tenant_id", _row(tenant="NULL")),
    ("unknown tenant", _row(tenant="99")),
    ("reserved kind http_fetch", _row(kind="'http_fetch'")),
    ("unknown kind", _row(kind="'dns_whatever'")),
    ("null kind", _row(kind="NULL")),
    ("unknown severity", _row(severity="'urgent'")),
    ("empty key", _row(key="''")),
    ("key too long", _row(key=f"'{'k' * 65}'")),
    ("key not lowercase", _row(key="'Key'")),
    ("empty name", _row(name="''")),
    ("name too long", _row(name=f"'{'x' * 201}'")),
    ("empty description", _row(description="''")),
    ("description too long", _row(description=f"'{'d' * 2001}'")),
    ("null definition", _row(definition="NULL")),
    ("definition not an object", _row(definition="'[1]'")),
    ("definition json null", _row(definition="'null'")),
    ("oversize definition", _row(definition=_json_literal(MAX_DEFINITION_LENGTH + 1))),
    ("no remediation", _row(remediation_text="NULL")),
    ("both remediations", _row(scope="'global'", tenant="NULL", remediation_key="'a.b'")),
    ("tenant remediation_key", _row(remediation_key="'a.b'", remediation_text="NULL")),
    (
        "empty remediation_key",
        _row(scope="'global'", tenant="NULL", remediation_key="''", remediation_text="NULL"),
    ),
    (
        "remediation_key too long",
        _row(
            scope="'global'",
            tenant="NULL",
            remediation_key=f"'{'r' * 201}'",
            remediation_text="NULL",
        ),
    ),
    ("remediation_text not an object", _row(remediation_text="'\"text\"'")),
    (
        "oversize remediation_text",
        _row(remediation_text=_json_literal(MAX_REMEDIATION_JSON_LENGTH + 1)),
    ),
    ("duplicate global key", _row(scope="'global'", tenant="NULL", key="'dup'")),
    ("duplicate tenant key", _row(tenant="1", key="'dup'")),
]

ALLOWED = [
    ("same key in another tenant", _row(tenant="2", key="'dup'")),
    ("tenant row reusing a global key", _row(tenant="2", key="'g.only'")),
    ("definition at max size", _row(definition=_json_literal(MAX_DEFINITION_LENGTH))),
    (
        "global remediation_key only",
        _row(scope="'global'", tenant="NULL", remediation_key="'a.b'", remediation_text="NULL"),
    ),
    ("every allowed kind", _row(kind="'dns_value_range'")),
    ("description at max length", _row(description=f"'{'d' * 2000}'")),
]

SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    _row(scope="'global'", tenant="NULL", key="'dup'"),
    _row(scope="'global'", tenant="NULL", key="'g.only'"),
    _row(tenant="1", key="'dup'"),
]


@pytest.fixture
def seeded(engine: Engine) -> Engine:
    with engine.begin() as conn:
        for statement in SEED_ROWS:
            conn.execute(text(statement))
        if engine.dialect.name == "postgresql":
            conn.execute(
                text(
                    "SELECT setval(pg_get_serial_sequence('tenants', 'id'), "
                    "(SELECT MAX(id) FROM tenants))"
                )
            )
    return engine


@pytest.mark.parametrize(("case", "statement"), VIOLATIONS, ids=[c for c, _ in VIOLATIONS])
def test_constraint_violation_rejected(seeded: Engine, case: str, statement: str) -> None:
    # PostgreSQL rejects an over-long VARCHAR or invalid JSON with DataError before the CHECK;
    # SQLite needs the CHECK. Either way the row never lands.
    with pytest.raises((IntegrityError, DataError)), seeded.begin() as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(("case", "statement"), ALLOWED, ids=[c for c, _ in ALLOWED])
def test_valid_insert_accepted(seeded: Engine, case: str, statement: str) -> None:
    with seeded.begin() as conn:
        assert conn.execute(text(statement)).rowcount == 1


def test_server_defaults(seeded: Engine) -> None:
    with seeded.connect() as conn:
        row = conn.execute(
            text("SELECT enabled, created_at, updated_at FROM custom_checks")
        ).first()
    assert row is not None
    assert bool(row[0]) is True and row[1] is not None and row[2] is not None


def test_tenant_delete_cascades_and_user_delete_nulls_created_by(world: World) -> None:
    s = world.session
    s.execute(text("DELETE FROM users WHERE id = :u"), {"u": world.user})
    s.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": world.tenant_a})
    s.commit()
    s.expire_all()
    remaining = set(s.scalars(select(CustomCheck.id)).all())
    assert remaining == {world.checks["g1"], world.checks["g2"], world.checks["b1"]}
    g2 = s.scalars(select(CustomCheck).where(CustomCheck.id == world.checks["g2"])).one()
    assert g2.created_by is None


# --- repository: tenant isolation ---------------------------------------------------------------


def test_reads_return_global_plus_own_tenant(world: World) -> None:
    c = world.checks
    assert _ids(world.repo("a").list()) == [c["g1"], c["g2"], c["a1"]]
    assert _ids(world.repo("b").list()) == [c["g1"], c["g2"], c["b1"]]
    assert _ids(world.repo("a").list(enabled_only=True)) == [c["g1"]]
    assert world.repo("a").count() == 3
    assert world.repo("a").list(limit=1, offset=1)[0].id == c["g2"]


@pytest.mark.parametrize(("limit", "offset"), [(-1, 0), (1001, 0), (True, 0), (1, -1), (1, "0")])
def test_bad_paging_rejected(world: World, limit: object, offset: object) -> None:
    with pytest.raises(ValueError):
        world.repo("a").list(limit=limit, offset=offset)  # type: ignore[arg-type]


@pytest.mark.parametrize(("tenant", "visible", "hidden"), [("a", "a1", "b1"), ("b", "b1", "a1")])
def test_foreign_tenant_rows_are_not_found(
    world: World, tenant: str, visible: str, hidden: str
) -> None:
    repo, c = world.repo(tenant), world.checks
    assert repo.get(c[visible]) is not None
    assert repo.get(c["g1"]) is not None
    assert repo.get(c[hidden]) is None
    assert repo.update(c[hidden], {"name": "pwned"}) is None
    assert repo.delete(c[hidden]) is False
    world.session.commit()
    other = world.repo("b" if tenant == "a" else "a").get(c[hidden])
    assert other is not None and other.name != "pwned"


def test_global_rows_not_writable_from_tenant_path(world: World) -> None:
    repo, gid = world.repo("a"), world.checks["g1"]
    assert repo.update(gid, {"enabled": False}) is None
    assert repo.delete(gid) is False
    record = world.global_repo().get(gid)
    assert record is not None and record.enabled is True


@pytest.mark.parametrize("bad", MALFORMED_IDS)
def test_malformed_ids_are_not_found(world: World, bad: object) -> None:
    for repo in (world.repo("a"), world.global_repo()):
        assert repo.get(bad) is None
        assert repo.update(bad, {"name": "x"}) is None
        assert repo.delete(bad) is False


def test_create_forces_scope_tenant_and_creator(world: World) -> None:
    rec = world.repo("b").create(_check(check_key="b.two"))
    assert (rec.scope, rec.tenant_id, rec.created_by) == ("tenant", world.tenant_b, world.user)
    assert rec.enabled is True and rec.remediation_text == LocalizedText(**TEXT)
    assert rec.created_at is not None and rec.updated_at is not None


@pytest.mark.parametrize("values", [{"scope": "global"}, {"tenant_id": 2}, {"tenant_id": None}])
def test_scope_and_tenant_cannot_be_supplied(world: World, values: dict[str, Any]) -> None:
    with pytest.raises(TenantScopeError):
        world.repo("a").create(_check(**values))
    with pytest.raises(TenantScopeError):
        world.repo("a").update(world.checks["a1"], values)
    with pytest.raises(TenantScopeError):
        world.global_repo().create(_check(**values), actor=None)


@pytest.mark.parametrize("field", ["id", "created_by", "created_at", "updated_at", "key"])
def test_owned_fields_cannot_be_set(world: World, field: str) -> None:
    with pytest.raises(CustomCheckInvalid) as err:
        world.repo("a").update(world.checks["a1"], {field: None})
    assert err.value.reason == "unknown_field"


def test_repo_for_does_not_expose_global_repository(world: World) -> None:
    repos = repo_for(TenantContext(world.tenant_a, world.user), world.session)
    exposed = {type(getattr(repos, f.name)) for f in dataclasses.fields(repos)}
    assert GlobalCustomCheckRepository not in exposed
    assert type(repos.custom_checks) is CustomCheckRepository


def test_global_repository_sees_only_global_rows(world: World) -> None:
    g, c = world.global_repo(), world.checks
    assert _ids(g.list()) == [c["g1"], c["g2"]]
    assert g.count() == 2
    assert g.get(c["a1"]) is None
    assert g.update(c["a1"], {"name": "x"}) is None
    assert g.delete(c["b1"]) is False


def test_global_create_update_delete(world: World) -> None:
    g = world.global_repo()
    rec = g.create(_check(check_key="g.three", description="Line.\n\tMore."), actor=world.user)
    assert (rec.scope, rec.tenant_id, rec.created_by) == ("global", None, world.user)
    updated = g.update(
        rec.id, {"remediation_text": None, "remediation_key": "custom_check.x.remediation"}
    )
    assert updated is not None and updated.remediation_text is None
    assert updated.remediation_key == "custom_check.x.remediation"
    assert g.delete(rec.id) is True and g.get(rec.id) is None


@pytest.mark.parametrize("actor", [0, -1, True, "1"])
def test_global_create_rejects_bad_actor(world: World, actor: object) -> None:
    with pytest.raises(ValueError):
        world.global_repo().create(_check(check_key="g.x"), actor=actor)  # type: ignore[arg-type]


def test_check_key_unique_per_scope(world: World) -> None:
    with pytest.raises(CheckKeyTaken):
        world.global_repo().create(_check(check_key="g.one"), actor=None)
    with pytest.raises(CheckKeyTaken):
        world.repo("a").create(_check(check_key="g.one"))  # a1 already uses it in tenant A
    rec = world.repo("b").create(_check(check_key="g.one"))  # tenant B: allowed
    with pytest.raises(CheckKeyTaken):
        world.repo("b").update(world.checks["b1"], {"check_key": "g.one"})
    assert world.repo("b").update(rec.id, {"check_key": "g.one"}) is not None  # itself


def test_check_key_race_maps_to_check_key_taken(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = world.repo("a")
    monkeypatch.setattr(CustomCheckRepository, "_key_taken", lambda *_a, **_k: False)
    with pytest.raises(CheckKeyTaken):
        repo.create(_check(check_key="g.one"))
    world.session.rollback()


def test_records_are_immutable_and_detached(world: World) -> None:
    rec = world.repo("a").get(world.checks["a1"])
    assert isinstance(rec, CustomCheckRecord)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.tenant_id = world.tenant_b  # type: ignore[misc]
    with pytest.raises(TypeError):
        rec.definition["rrtype"] = "A"  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.remediation_text.en = "x"  # type: ignore[union-attr,misc]


def test_nested_definition_is_deeply_frozen(world: World) -> None:
    definition = {"values": [1, {"min": 0.5}], "nested": {"list": ["a"]}}
    rec = world.repo("a").create(_check(check_key="a.nested", definition=definition))
    with pytest.raises(TypeError):
        rec.definition["nested"]["list"] = []
    assert rec.definition["values"] == (1, {"min": 0.5})
    world.session.commit()
    again = world.repo("a").get(rec.id)
    assert again is not None
    # Frozen records round-trip through update unchanged.
    same = world.repo("a").update(rec.id, {"definition": again.definition})
    assert same is not None and json.dumps(dict(same.definition["nested"])) == '{"list": ["a"]}'


@pytest.mark.parametrize(
    ("attr", "value"), [("tenant_id", 2), ("tenant_id", None), ("scope", "global")]
)
def test_persisted_row_cannot_change_scope_or_tenant(
    world: World, attr: str, value: object
) -> None:
    row = world.session.scalars(
        select(CustomCheck).where(CustomCheck.id == world.checks["a1"])
    ).one()
    with pytest.raises(TenantScopeError):
        setattr(row, attr, value)


def test_repositories_require_context_and_session(world: World) -> None:
    with pytest.raises(TypeError):
        CustomCheckRepository(None, world.session)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GlobalCustomCheckRepository(None)  # type: ignore[arg-type]


# --- validation before the database (table-driven, malformed input) ----------------------------

_BIG = "x" * MAX_DEFINITION_LENGTH
_DEEP: dict[str, Any] = {}
_cursor = _DEEP
for _ in range(20):
    _cursor["n"] = {}
    _cursor = _cursor["n"]
_CYCLE: dict[str, Any] = {}
_CYCLE["self"] = _CYCLE

INVALID = [
    ("check_key", None, "not_a_string"),
    ("check_key", "", "empty"),
    ("check_key", "k" * 65, "too_long"),
    ("check_key", "Upper", "invalid_format"),
    ("check_key", "has space", "invalid_format"),
    ("check_key", "k\x00", "nul"),
    ("check_key", "k\ud800", "surrogate"),
    ("name", None, "not_a_string"),
    ("name", "", "empty"),
    ("name", "x" * 201, "too_long"),
    ("name", "a\x00b", "nul"),
    ("name", "a\ud800b", "surrogate"),
    ("name", "a\nb", "control_char"),
    ("name", " padded", "whitespace"),
    ("description", "", "empty"),
    ("description", "  \n ", "whitespace"),
    ("description", "d" * 2001, "too_long"),
    ("description", "d\x00", "nul"),
    ("description", "d\udc00", "surrogate"),
    ("description", "bell\x07", "control_char"),
    ("kind", "http_fetch", "reserved"),
    ("kind", "glob", "invalid_choice"),
    ("kind", None, "invalid_choice"),
    ("kind", "DNS_EXISTS", "invalid_choice"),
    ("severity", "urgent", "invalid_choice"),
    ("severity", None, "invalid_choice"),
    ("definition", None, "not_an_object"),
    ("definition", [1, 2], "not_an_object"),
    ("definition", "{}", "not_an_object"),
    ("definition", {}, "empty"),
    ("definition", {"a": _BIG}, "too_large"),
    ("definition", {"a": "\x00"}, "nul"),
    ("definition", {"a\x00": 1}, "nul"),
    ("definition", {"a": ["ok", "\ud800"]}, "surrogate"),
    ("definition", {"a": "bell\x07"}, "control_char"),
    ("definition", {"a\n": 1}, "control_char"),
    ("definition", {1: "a"}, "non_string_key"),
    ("definition", {"a": float("nan")}, "not_finite"),
    ("definition", {"a": float("inf")}, "not_finite"),
    ("definition", {"a": b"bytes"}, "not_json"),
    ("definition", {"a": {1, 2}}, "not_json"),
    ("definition", {"a": object()}, "not_json"),
    ("definition", _DEEP, "too_deep"),
    ("definition", _CYCLE, "too_deep"),
    ("remediation_text", "plain string", "not_an_object"),
    ("remediation_text", {"en": "only"}, "languages"),
    ("remediation_text", {**TEXT, "fr": "x"}, "languages"),
    ("remediation_text", {"en": "e", "it": ""}, "empty"),
    ("remediation_text", {"en": "e", "it": None}, "not_a_string"),
    ("remediation_text", {"en": "e", "it": "i" * 2001}, "too_long"),
    ("remediation_text", {"en": "e\x00", "it": "i"}, "nul"),
    ("remediation_text", {"en": "e", "it": "i\ud800"}, "surrogate"),
    ("remediation_text", {"en": "e\x1b[31m", "it": "i"}, "control_char"),
    ("remediation_text", {"en": " \n", "it": "i"}, "whitespace"),
    ("enabled", 1, "not_a_bool"),
    ("enabled", None, "not_a_bool"),
]


@pytest.mark.parametrize(("field", "value", "reason"), INVALID)
def test_invalid_values_rejected_before_db(
    world: World, field: str, value: object, reason: str
) -> None:
    repo = world.repo("a")
    before = repo.count()
    with pytest.raises(CustomCheckInvalid) as err:
        repo.create(_new(**{field: value}))
    assert (err.value.field, err.value.reason) == (field, reason)
    with pytest.raises(CustomCheckInvalid):
        repo.update(world.checks["a1"], {field: value})
    if isinstance(value, str) and len(value) > 3:
        assert value not in str(err.value)  # never echoes the value
    world.session.rollback()
    assert repo.count() == before


REMEDIATION_KEY_INVALID = [
    ("", "empty"),
    ("nodot", "invalid_format"),
    ("Upper.case", "invalid_format"),
    ("a..b", "invalid_format"),
    ("a.b-c", "invalid_format"),
    ("a." + "b" * 199, "too_long"),
    ("a.b\x00", "nul"),
    (5, "not_a_string"),
]


@pytest.mark.parametrize(("value", "reason"), REMEDIATION_KEY_INVALID)
def test_invalid_remediation_key_rejected(world: World, value: object, reason: str) -> None:
    with pytest.raises(CustomCheckInvalid) as err:
        world.global_repo().create(
            _check(check_key="g.new", remediation_text=None, remediation_key=value), actor=None
        )
    assert (err.value.field, err.value.reason) == ("remediation_key", reason)


@pytest.mark.parametrize(
    "values",
    [
        {"remediation_key": "custom_check.g_one.remediation", "remediation_text": None},
        {"remediation_key": "custom_check.g_one.remediation"},
    ],
)
def test_tenant_cannot_set_remediation_key(world: World, values: dict[str, Any]) -> None:
    repo = world.repo("a")
    before = repo.count()
    with pytest.raises(CustomCheckInvalid) as err:
        repo.create(_new(**values))
    assert (err.value.field, err.value.reason) == ("remediation_key", "global_only")
    with pytest.raises(CustomCheckInvalid) as err:
        repo.update(world.checks["a1"], values)
    assert (err.value.field, err.value.reason) == ("remediation_key", "global_only")
    world.session.rollback()
    assert repo.count() == before
    a1 = repo.get(world.checks["a1"])
    assert a1 is not None and a1.remediation_key is None and a1.remediation_text is not None
    # Clearing it explicitly (None) is fine on the tenant path.
    assert repo.update(world.checks["a1"], {"remediation_key": None}) is not None


@pytest.mark.parametrize(
    ("values", "reason"),
    [
        ({"remediation_text": None}, "required"),
        ({"remediation_key": "a.b", "remediation_text": dict(TEXT)}, "both"),
    ],
)
def test_exactly_one_remediation(world: World, values: dict[str, Any], reason: str) -> None:
    g = world.global_repo()
    with pytest.raises(CustomCheckInvalid) as err:
        g.create(_check(check_key="g.new", **values), actor=None)
    assert (err.value.field, err.value.reason) == ("remediation", reason)
    with pytest.raises(CustomCheckInvalid) as err:
        g.update(world.checks["g2"], values)
    assert err.value.reason == reason
    if "remediation_key" not in values:  # tenant path: same rule for its own text
        with pytest.raises(CustomCheckInvalid) as err:
            world.repo("a").update(world.checks["a1"], values)
        assert err.value.reason == reason


@pytest.mark.parametrize("missing", ["check_key", "name", "kind", "definition", "severity"])
def test_required_fields(world: World, missing: str) -> None:
    values = _check(check_key="a.new")
    del values[missing]
    with pytest.raises(CustomCheckInvalid) as err:
        world.repo("a").create(values)
    assert (err.value.field, err.value.reason) == (missing, "required")


def test_non_mapping_values_rejected(world: World) -> None:
    with pytest.raises(TypeError):
        world.repo("a").create([("name", "x")])  # type: ignore[arg-type]


def _definition_of_size(size: int) -> dict[str, str]:
    """A definition whose json.dumps is exactly `size` characters."""
    overhead = len(json.dumps({"a": ""}))
    return {"a": "x" * (size - overhead)}


VALID = [
    ("definition", _definition_of_size(MAX_DEFINITION_LENGTH)),
    ("definition", {"a": None, "b": True, "c": -3, "d": 1.5, "e": [], "f": {}}),
    ("definition", {"pattern": "^v=spf1 .*include:esp\\.example", "multi": "a\n\tb"}),
    ("definition", {"name": "sélecteur «é» 😀"}),
    ("name", "Contrôle «ok»"),
    ("description", "Line one.\n\tLine two."),
    ("description", None),
    ("kind", "dns_exists"),
    ("kind", "dns_value_range"),
    ("severity", "critical"),
    ("enabled", False),
    ("check_key", "a.b-c_1"),
    ("remediation_text", {"en": "😀" * MAX_REMEDIATION_LENGTH, "it": "é" * MAX_REMEDIATION_LENGTH}),
    ("remediation_text", LocalizedText(en="Do it.", it="Fallo.")),
]


@pytest.mark.parametrize(
    ("field", "value"), VALID, ids=[f"{f}-{i}" for i, (f, _) in enumerate(VALID)]
)
def test_valid_values_roundtrip(world: World, field: str, value: object) -> None:
    rec = world.repo("a").create(_new(**{field: value}))
    world.session.commit()
    world.session.expire_all()
    again = world.repo("a").get(rec.id)
    assert again is not None
    stored = getattr(again, field)
    if field == "definition":
        assert json.loads(json.dumps(stored, default=dict)) == value
    elif field == "remediation_text" and isinstance(value, dict):
        assert stored == LocalizedText(**value)
    else:
        assert stored == value


def test_definition_size_limit_matches_db(world: World) -> None:
    # One character over the repository limit is refused before the DB with the same measure
    # the DB CHECK uses; the exact limit (also non-ASCII, escaped by json.dumps) lands.
    repo = world.repo("a")
    with pytest.raises(CustomCheckInvalid) as err:
        repo.create(
            _check(check_key="a.big", definition=_definition_of_size(MAX_DEFINITION_LENGTH + 1))
        )
    assert err.value.reason == "too_large"
    escaped = {"a": "é" * ((MAX_DEFINITION_LENGTH - len(json.dumps({"a": ""}))) // 6)}
    assert len(json.dumps(escaped)) <= MAX_DEFINITION_LENGTH
    assert repo.create(_check(check_key="a.esc", definition=escaped)).definition == escaped
    world.session.commit()


def test_none_json_is_sql_null(world: World) -> None:
    g = world.global_repo()
    rec = g.create(_check(check_key="g.null"), actor=None)
    g.update(rec.id, {"remediation_text": None, "remediation_key": "a.b"})
    world.session.commit()
    nulls = world.session.execute(
        text("SELECT COUNT(*) FROM custom_checks WHERE remediation_text IS NULL")
    ).scalar_one()
    keys = world.session.execute(
        text("SELECT COUNT(*) FROM custom_checks WHERE remediation_key IS NOT NULL")
    ).scalar_one()
    assert nulls == keys == 2
