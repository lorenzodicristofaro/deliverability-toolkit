"""M5-05 content_rules: migration 0005, DB constraints and the repositories.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url` fixture; the
PG params skip locally and run on dev CI). The schema is built by Alembic. No network.
"""

import dataclasses
import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.safe_regex import ALLOWED_FLAGS
from app.core.tenancy import TenantContext
from app.models import ContentRule, Tenant, User
from app.models.content_rule import FLAGS_MASK
from app.repositories import GlobalContentRuleRepository, repo_for
from app.repositories.base import TenantScopeError
from app.repositories.content_rules import (
    ContentRuleInvalid,
    ContentRuleRecord,
    ContentRuleRepository,
    SeedKeyTaken,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**63, [1], b"1"]


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def _rule(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "name": "Shouting",
        "kind": "regex",
        "pattern": r"!{3,}",
        "weight": 5,
        "category": "punctuation",
        "severity": "low",
        "title": "Shouting punctuation",
    }
    values.update(overrides)
    return values


@pytest.fixture
def engine(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(_cfg(), "head")
    eng = create_db_engine(db_url)
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
    rules: dict[str, int]

    def repo(self, tenant: str = "a") -> ContentRuleRepository:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, self.user), self.session).content_rules

    def global_repo(self) -> GlobalContentRuleRepository:
        return GlobalContentRuleRepository(self.session)


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        user = User(email="admin@example.com")
        session.add_all([ta, tb, user])
        session.flush()
        g = GlobalContentRuleRepository(session)
        rules = {
            "g1": g.create(_rule(name="Global 1", seed_key="g.one"), actor=None).id,
            "g2": g.create(_rule(name="Global 2", enabled=False), actor=user.id).id,
        }
        a = repo_for(TenantContext(ta.id, user.id), session).content_rules
        b = repo_for(TenantContext(tb.id, None), session).content_rules
        rules["a1"] = a.create(_rule(name="A 1", seed_key="g.one", enabled=False)).id
        rules["b1"] = b.create(_rule(name="B 1", kind="keyword", pattern="free money")).id
        session.commit()
        yield World(session, ta.id, tb.id, user.id, rules)
    finally:
        session.close()


def _ids(records: Any) -> list[int]:
    return [r.id for r in records]


# --- migration ---------------------------------------------------------------------------------


def test_migration_upgrade_downgrade(engine: Engine) -> None:
    assert "content_rules" in inspect(engine).get_table_names()
    command.downgrade(_cfg(), "0004")
    assert "content_rules" not in inspect(engine).get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(engine)
    assert "content_rules" in insp.get_table_names()
    unique = {i["name"] for i in insp.get_indexes("content_rules") if i["unique"]}
    assert unique == {"uq_content_rules_global_seed_key", "uq_content_rules_tenant_seed_key"}


def test_single_alembic_head() -> None:
    from alembic.script import ScriptDirectory

    assert ScriptDirectory.from_config(_cfg()).get_heads() == ["0005"]


def test_flags_mask_matches_safe_regex_and_migration() -> None:
    # Migration 0005 hardcodes 346 in ck_content_rules_flags_allowed.
    assert FLAGS_MASK == ALLOWED_FLAGS == 346
    migration = next((ROOT / "migrations" / "versions").glob("*_0005_content_rules.py"))
    assert "(flags | 346) = 346" in migration.read_text(encoding="utf-8")


# --- constraints (raw SQL: the database enforces them, not only the repository) -----------------

COLS = "(scope, tenant_id, name, kind, pattern, flags, weight, category, language, severity, "
COLS += "status, seed_key, title, advice) VALUES "
INS = "INSERT INTO content_rules " + COLS


def _row(
    scope: str = "'tenant'",
    tenant: str = "1",
    name: str = "'n'",
    kind: str = "'regex'",
    pattern: str = "'p'",
    flags: str = "0",
    weight: str = "1",
    category: str = "'c'",
    language: str = "NULL",
    severity: str = "'low'",
    status: str = "NULL",
    seed_key: str = "NULL",
    title: str = "'t'",
    advice: str = "NULL",
) -> str:
    vals = [scope, tenant, name, kind, pattern, flags, weight, category, language, severity]
    return INS + "(" + ", ".join([*vals, status, seed_key, title, advice]) + ")"


VIOLATIONS = [
    ("unknown scope", _row(scope="'shared'")),
    ("null scope", _row(scope="NULL")),
    ("global with tenant_id", _row(scope="'global'", tenant="1")),
    ("tenant without tenant_id", _row(tenant="NULL")),
    ("unknown tenant", _row(tenant="99")),
    ("unknown kind", _row(kind="'glob'")),
    ("unknown severity", _row(severity="'urgent'")),
    ("unknown status", _row(status="'maybe'")),
    ("weight below range", _row(weight="-1")),
    ("weight above range", _row(weight="101")),
    ("null weight", _row(weight="NULL")),
    ("unsupported flag bit", _row(flags="1")),
    ("unsupported high flag", _row(flags="4096")),
    ("negative flags", _row(flags="-1")),
    ("empty name", _row(name="''")),
    ("name too long", _row(name=f"'{'x' * 201}'")),
    ("empty pattern", _row(pattern="''")),
    ("pattern too long", _row(pattern=f"'{'x' * 1025}'")),
    ("pattern too long multibyte", _row(pattern=f"'{'é' * 1025}'")),
    ("null pattern", _row(pattern="NULL")),
    ("no seed_key and no title", _row(title="NULL")),
    ("empty title", _row(title="''")),
    ("title too long", _row(title=f"'{'t' * 201}'")),
    ("empty advice", _row(advice="''")),
    ("advice too long", _row(advice=f"'{'a' * 2001}'")),
    ("empty category", _row(category="''")),
    ("category too long", _row(category=f"'{'c' * 65}'")),
    ("language not lowercase", _row(language="'EN'")),
    ("language too long", _row(language=f"'{'e' * 17}'")),
    ("empty seed_key", _row(seed_key="''")),
    ("seed_key too long", _row(seed_key=f"'{'s' * 129}'")),
    ("duplicate global seed_key", _row(scope="'global'", tenant="NULL", seed_key="'dup'")),
    ("duplicate tenant seed_key", _row(tenant="1", seed_key="'dup'")),
]

ALLOWED = [
    ("same seed_key in another tenant", _row(tenant="2", seed_key="'dup'")),
    ("tenant row reusing a global seed_key", _row(tenant="2", seed_key="'g.only'")),
    ("null seed_key repeated", _row(tenant="1")),
    ("pattern at max length multibyte", _row(pattern=f"'{'é' * 1024}'")),
    ("all allowed flags", _row(flags=str(ALLOWED_FLAGS))),
    ("weight bounds", _row(weight="100")),
    (
        "seeded row without title",
        _row(scope="'global'", tenant="NULL", seed_key="'s'", title="NULL"),
    ),
    ("advice at max length", _row(advice=f"'{'a' * 2000}'")),
    ("verified seed row", _row(scope="'global'", tenant="NULL", status="'verified'")),
]

SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    _row(scope="'global'", tenant="NULL", seed_key="'dup'"),
    _row(scope="'global'", tenant="NULL", seed_key="'g.only'"),
    _row(tenant="1", seed_key="'dup'"),
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
    # PostgreSQL rejects an over-long VARCHAR with DataError before the CHECK; SQLite needs the
    # CHECK. Either way the row never lands.
    with pytest.raises((IntegrityError, DataError)), seeded.begin() as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(("case", "statement"), ALLOWED, ids=[c for c, _ in ALLOWED])
def test_valid_insert_accepted(seeded: Engine, case: str, statement: str) -> None:
    with seeded.begin() as conn:
        assert conn.execute(text(statement)).rowcount == 1


def test_server_defaults(seeded: Engine) -> None:
    with seeded.connect() as conn:
        row = conn.execute(
            text(
                "SELECT flags, enabled, locally_modified, created_at, updated_at FROM content_rules"
            )
        ).first()
    assert row is not None
    assert row[0] == 0 and bool(row[1]) is True and bool(row[2]) is False
    assert row[3] is not None and row[4] is not None


def test_tenant_delete_cascades_and_user_delete_nulls_created_by(world: World) -> None:
    s = world.session
    s.execute(text("DELETE FROM users WHERE id = :u"), {"u": world.user})
    s.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": world.tenant_a})
    s.commit()
    s.expire_all()
    remaining = set(s.scalars(select(ContentRule.id)).all())
    assert remaining == {world.rules["g1"], world.rules["g2"], world.rules["b1"]}
    g2 = s.scalars(select(ContentRule).where(ContentRule.id == world.rules["g2"])).one()
    assert g2.created_by is None


# --- repository: tenant isolation ---------------------------------------------------------------


def test_reads_return_global_plus_own_tenant(world: World) -> None:
    r = world.rules
    assert _ids(world.repo("a").list()) == [r["g1"], r["g2"], r["a1"]]
    assert _ids(world.repo("b").list()) == [r["g1"], r["g2"], r["b1"]]
    assert _ids(world.repo("a").list(enabled_only=True)) == [r["g1"]]
    assert world.repo("a").count() == 3
    assert world.repo("a").list(limit=1, offset=1)[0].id == r["g2"]


@pytest.mark.parametrize(("tenant", "visible", "hidden"), [("a", "a1", "b1"), ("b", "b1", "a1")])
def test_foreign_tenant_rows_are_not_found(
    world: World, tenant: str, visible: str, hidden: str
) -> None:
    repo, r = world.repo(tenant), world.rules
    assert repo.get(r[visible]) is not None
    assert repo.get(r["g1"]) is not None
    assert repo.get(r[hidden]) is None
    assert repo.update(r[hidden], {"name": "pwned"}) is None
    assert repo.delete(r[hidden]) is False
    world.session.commit()
    other = world.repo("b" if tenant == "a" else "a").get(r[hidden])
    assert other is not None and other.name != "pwned"


def test_global_rows_not_writable_from_tenant_path(world: World) -> None:
    repo, gid = world.repo("a"), world.rules["g1"]
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
    rec = world.repo("b").create(_rule(name="B 2"))
    assert (rec.scope, rec.tenant_id, rec.created_by) == ("tenant", world.tenant_b, world.user)
    assert rec.enabled is True and rec.flags == 0 and rec.locally_modified is False
    assert rec.created_at is not None and rec.updated_at is not None


@pytest.mark.parametrize(
    "values",
    [
        {"scope": "global"},
        {"tenant_id": 2},
        {"tenant_id": None},
    ],
)
def test_scope_and_tenant_cannot_be_supplied(world: World, values: dict[str, Any]) -> None:
    with pytest.raises(TenantScopeError):
        world.repo("a").create(_rule(**values))
    with pytest.raises(TenantScopeError):
        world.repo("a").update(world.rules["a1"], values)
    with pytest.raises(TenantScopeError):
        world.global_repo().create(_rule(**values), actor=None)


@pytest.mark.parametrize(
    "field", ["status", "verified_on", "sources", "locally_modified", "id", "created_by"]
)
def test_tenant_path_cannot_set_seed_or_owned_fields(world: World, field: str) -> None:
    with pytest.raises(ContentRuleInvalid) as err:
        world.repo("a").update(world.rules["a1"], {field: None})
    assert err.value.reason == "unknown_field"


def test_global_repository_sees_only_global_rows(world: World) -> None:
    g, r = world.global_repo(), world.rules
    assert _ids(g.list()) == [r["g1"], r["g2"]]
    assert g.count() == 2
    assert g.get(r["a1"]) is None
    assert g.update(r["a1"], {"name": "x"}) is None
    assert g.delete(r["b1"]) is False
    found = g.get_by_seed_key("g.one")
    assert found is not None and found.id == r["g1"]
    assert g.get_by_seed_key(1) is None  # type: ignore[arg-type]


def test_global_create_and_update_seed_fields(world: World) -> None:
    g = world.global_repo()
    rec = g.create(
        _rule(
            seed_key="g.two",
            status="unverified",
            verified_on=dt.date(2026, 11, 7),
            sources=["https://example.org/doc", "http://example.net/a?b=1"],
            title=None,
            enabled=False,
        ),
        actor=world.user,
    )
    assert (rec.scope, rec.tenant_id, rec.created_by) == ("global", None, world.user)
    assert rec.sources == ("https://example.org/doc", "http://example.net/a?b=1")
    assert rec.title is None
    world.session.commit()
    again = g.get(rec.id)
    assert again is not None and again.sources == rec.sources
    updated = g.update(rec.id, {"enabled": True, "locally_modified": True})
    assert updated is not None and updated.enabled and updated.locally_modified
    assert g.delete(rec.id) is True and g.get(rec.id) is None


@pytest.mark.parametrize("actor", [0, -1, True, "1"])
def test_global_create_rejects_bad_actor(world: World, actor: object) -> None:
    with pytest.raises(ValueError):
        world.global_repo().create(_rule(), actor=actor)  # type: ignore[arg-type]


def test_seed_key_unique_per_scope(world: World) -> None:
    with pytest.raises(SeedKeyTaken):
        world.global_repo().create(_rule(seed_key="g.one"), actor=None)
    with pytest.raises(SeedKeyTaken):
        world.repo("a").create(_rule(seed_key="g.one"))  # a1 already uses it in tenant A
    rec = world.repo("b").create(_rule(seed_key="g.one"))  # tenant B: allowed
    with pytest.raises(SeedKeyTaken):
        world.repo("b").update(world.rules["b1"], {"seed_key": "g.one"})
    assert world.repo("b").update(rec.id, {"seed_key": "g.one"}) is not None  # itself


def test_seed_key_race_maps_to_seed_key_taken(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = world.repo("a")
    monkeypatch.setattr(ContentRuleRepository, "_seed_key_taken", lambda *_a, **_k: False)
    with pytest.raises(SeedKeyTaken):
        repo.create(_rule(seed_key="g.one"))
    world.session.rollback()


def test_records_are_immutable_and_detached(world: World) -> None:
    rec = world.repo("a").get(world.rules["a1"])
    assert isinstance(rec, ContentRuleRecord)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.tenant_id = world.tenant_b  # type: ignore[misc]


@pytest.mark.parametrize(
    ("attr", "value"), [("tenant_id", 2), ("tenant_id", None), ("scope", "global")]
)
def test_persisted_row_cannot_change_scope_or_tenant(
    world: World, attr: str, value: object
) -> None:
    row = world.session.scalars(
        select(ContentRule).where(ContentRule.id == world.rules["a1"])
    ).one()
    with pytest.raises(TenantScopeError):
        setattr(row, attr, value)


def test_repositories_require_context_and_session(world: World) -> None:
    with pytest.raises(TypeError):
        ContentRuleRepository(None, world.session)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GlobalContentRuleRepository(None)  # type: ignore[arg-type]


# --- validation before the database (table-driven, malformed input) ----------------------------

INVALID = [
    ("name", None, "not_a_string"),
    ("name", "", "empty"),
    ("name", "x" * 201, "too_long"),
    ("name", "a\x00b", "nul"),
    ("name", "a\ud800b", "surrogate"),
    ("name", "a\nb", "control_char"),
    ("name", " padded", "whitespace"),
    ("kind", "glob", "invalid_choice"),
    ("kind", None, "invalid_choice"),
    ("pattern", "", "empty"),
    ("pattern", "x" * 1025, "too_long"),
    ("pattern", "a\x00", "nul"),
    ("pattern", "\udfff", "surrogate"),
    ("pattern", "(unclosed", "invalid_syntax"),
    ("pattern", b"bytes", "not_a_string"),
    ("flags", 1, "unsupported_flags"),
    ("flags", -2, "unsupported_flags"),
    ("flags", True, "not_an_int"),
    ("flags", "2", "not_an_int"),
    ("weight", -1, "out_of_range"),
    ("weight", 101, "out_of_range"),
    ("weight", 1.5, "not_an_int"),
    ("weight", True, "not_an_int"),
    ("category", "Upper", "invalid_format"),
    ("category", "has space", "invalid_format"),
    ("category", "c" * 65, "too_long"),
    ("category", "c\x00", "nul"),
    ("language", "english", "invalid_format"),
    ("language", "e", "invalid_format"),
    ("language", "en_US", "invalid_format"),
    ("language", "ен", "invalid_format"),
    ("language", "e" * 17, "too_long"),
    ("language", "en\x00", "nul"),
    ("enabled", 1, "not_a_bool"),
    ("enabled", None, "not_a_bool"),
    ("severity", "urgent", "invalid_choice"),
    ("seed_key", "", "empty"),
    ("seed_key", "Bad Key", "invalid_format"),
    ("seed_key", "s" * 129, "too_long"),
    ("seed_key", "k\x00", "nul"),
    ("title", "", "empty"),
    ("title", "t" * 201, "too_long"),
    ("title", "t\x00", "nul"),
    ("title", "t\udc00", "surrogate"),
    ("title", "two\nlines", "control_char"),
    ("title", 5, "not_a_string"),
    ("advice", "", "empty"),
    ("advice", "  \n ", "whitespace"),
    ("advice", "a" * 2001, "too_long"),
    ("advice", "a\x00", "nul"),
    ("advice", "a\ud800", "surrogate"),
    ("advice", "bell\x07", "control_char"),
]


@pytest.mark.parametrize(("field", "value", "reason"), INVALID)
def test_invalid_values_rejected_before_db(
    world: World, field: str, value: object, reason: str
) -> None:
    repo = world.repo("a")
    before = repo.count()
    with pytest.raises(ContentRuleInvalid) as err:
        repo.create(_rule(**{field: value}))
    assert (err.value.field, err.value.reason) == (field, reason)
    with pytest.raises(ContentRuleInvalid):
        repo.update(world.rules["a1"], {field: value})
    if isinstance(value, str) and len(value) > 3:
        assert value not in str(err.value)  # never echoes the value
    world.session.rollback()
    assert repo.count() == before


GLOBAL_INVALID = [
    ("status", "maybe", "invalid_choice"),
    ("verified_on", "2026-11-07", "not_a_date"),
    ("verified_on", dt.datetime(2026, 11, 7, tzinfo=dt.UTC), "not_a_date"),
    ("sources", "https://example.org", "not_a_list"),
    ("sources", {"u": "https://example.org"}, "not_a_list"),
    ("sources", [], "empty"),
    ("sources", [f"https://example.org/{i}" for i in range(11)], "too_many"),
    ("sources", ["https://example.org/" + "x" * 2030], "too_long"),
    ("sources", ["https://a\x00"], "nul"),
    ("sources", ["https://a\ud800"], "surrogate"),
    ("sources", ["https://a/\nb"], "control_char"),
    ("sources", ["https://a/ b"], "invalid_url"),
    ("sources", ["ftp://example.org"], "invalid_url"),
    ("sources", ["javascript:alert(1)"], "invalid_url"),
    ("sources", ["example.org/doc"], "invalid_url"),
    ("sources", ["https://"], "invalid_url"),
    ("sources", ["http://[::1"], "invalid_url"),
    ("sources", [1], "not_a_string"),
    ("sources", [""], "empty"),
    ("sources", ["https://a.example", "https://a.example"], "duplicate"),
    ("locally_modified", "yes", "not_a_bool"),
]


@pytest.mark.parametrize(("field", "value", "reason"), GLOBAL_INVALID)
def test_invalid_seed_values_rejected_before_db(
    world: World, field: str, value: object, reason: str
) -> None:
    with pytest.raises(ContentRuleInvalid) as err:
        world.global_repo().create(_rule(**{field: value}), actor=None)
    assert (err.value.field, err.value.reason) == (field, reason)


@pytest.mark.parametrize("missing", ["name", "kind", "pattern", "weight", "category", "severity"])
def test_required_fields(world: World, missing: str) -> None:
    values = _rule()
    del values[missing]
    with pytest.raises(ContentRuleInvalid) as err:
        world.repo("a").create(values)
    assert (err.value.field, err.value.reason) == (missing, "required")


VALID = [
    ("language", "EN", "en"),
    ("language", "pt-BR", "pt-br"),
    ("language", None, None),
    ("flags", ALLOWED_FLAGS, ALLOWED_FLAGS),
    ("weight", 0, 0),
    ("weight", 100, 100),
    ("pattern", "é" * 1024, "é" * 1024),
    ("name", "Règle «ok»", "Règle «ok»"),
    ("category", "links.mismatch_1", "links.mismatch_1"),
    ("advice", "Line one.\n\tLine two.", "Line one.\n\tLine two."),
    ("title", "Règle «ok»", "Règle «ok»"),
]


@pytest.mark.parametrize(("field", "value", "stored"), VALID)
def test_valid_values_roundtrip(world: World, field: str, value: object, stored: object) -> None:
    rec = world.repo("a").create(_rule(**{field: value}))
    world.session.commit()
    again = world.repo("a").get(rec.id)
    assert again is not None and getattr(again, field) == stored


def test_keyword_pattern_is_not_compiled_as_regex(world: World) -> None:
    rec = world.repo("a").create(_rule(kind="keyword", pattern="(unbalanced"))
    assert rec.kind == "keyword"
    # Switching it to regex re-validates the stored pattern.
    with pytest.raises(ContentRuleInvalid) as err:
        world.repo("a").update(rec.id, {"kind": "regex"})
    assert err.value.reason == "invalid_syntax"


def test_update_revalidates_pattern_with_new_flags(world: World) -> None:
    with pytest.raises(ContentRuleInvalid):
        world.repo("a").update(world.rules["a1"], {"flags": 4096})
    rec = world.repo("a").update(world.rules["a1"], {"pattern": "(?x) a b", "flags": 2})
    assert rec is not None and rec.flags == 2


def test_non_mapping_values_rejected(world: World) -> None:
    with pytest.raises(TypeError):
        world.repo("a").create([("name", "x")])  # type: ignore[arg-type]


def test_title_required_without_seed_key(world: World) -> None:
    repo = world.repo("a")
    with pytest.raises(ContentRuleInvalid) as err:
        repo.create(_rule(title=None))
    assert (err.value.field, err.value.reason) == ("title", "required")
    repo = world.repo("b")  # tenant A already overrides g.one with a1
    rec = repo.create(_rule(title=None, seed_key="g.one"))  # tenant override of a seeded rule
    assert rec.title is None
    with pytest.raises(ContentRuleInvalid) as err:
        repo.update(rec.id, {"seed_key": None})  # would leave a rule with no text
    assert err.value.reason == "required"
    with pytest.raises(ContentRuleInvalid):
        world.repo("a").update(world.rules["a1"], {"seed_key": None, "title": None})
    assert repo.update(rec.id, {"seed_key": None, "title": "Own text"}) is not None


def test_global_seeded_row_needs_no_title(world: World) -> None:
    rec = world.global_repo().create(_rule(title=None, seed_key="g.three"), actor=None)
    assert rec.title is None and rec.advice is None and rec.sources is None


@pytest.mark.parametrize("seed_key", ["no.such.key", "g.onex", "g"])
def test_tenant_seed_key_must_name_a_global_rule(world: World, seed_key: str) -> None:
    repo = world.repo("b")
    before = repo.count()
    with pytest.raises(ContentRuleInvalid) as err:
        repo.create(_rule(seed_key=seed_key))
    assert (err.value.field, err.value.reason) == ("seed_key", "unknown")
    with pytest.raises(ContentRuleInvalid) as err:
        repo.update(world.rules["b1"], {"seed_key": seed_key})
    assert (err.value.field, err.value.reason) == ("seed_key", "unknown")
    world.session.rollback()
    assert repo.count() == before
    b1 = repo.get(world.rules["b1"])
    assert b1 is not None and b1.seed_key is None


def test_tenant_seed_key_cannot_reference_a_tenant_only_key(world: World) -> None:
    # A key that exists only on a tenant row (raw insert) is not a seeded global rule.
    world.session.execute(
        text(
            "INSERT INTO content_rules (scope, tenant_id, name, kind, pattern, weight, category, "
            "severity, seed_key) VALUES ('tenant', :t, 'x', 'keyword', 'x', 1, 'c', 'low', "
            "'tenant.only')"
        ),
        {"t": world.tenant_a},
    )
    for tenant in ("a", "b"):
        with pytest.raises(ContentRuleInvalid) as err:
            world.repo(tenant).create(_rule(seed_key="tenant.only"))
        assert err.value.reason == "unknown"


def test_sources_none_is_sql_null(world: World) -> None:
    g = world.global_repo()
    with_sources = g.create(_rule(sources=["https://example.org/a"]), actor=None)
    cleared = g.update(with_sources.id, {"sources": None})
    assert cleared is not None and cleared.sources is None
    world.session.commit()
    total = world.session.execute(text("SELECT COUNT(*) FROM content_rules")).scalar_one()
    nulls = world.session.execute(
        text("SELECT COUNT(*) FROM content_rules WHERE sources IS NULL")
    ).scalar_one()
    assert nulls == total
