"""M5-06 dkim_selectors: migration 0006, DB constraints and the repositories.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture; the
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
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import DkimSelector, Tenant, User
from app.repositories import GlobalDkimSelectorRepository, TenantRepositories, repo_for
from app.repositories.base import TenantScopeError
from app.repositories.dkim_selectors import (
    DkimSelectorInvalid,
    DkimSelectorRecord,
    DkimSelectorRepository,
    SelectorTaken,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**63, [1], b"1"]


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


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
    ids: dict[str, int]

    def repo(self, tenant: str = "a") -> DkimSelectorRepository:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, self.user), self.session).dkim_selectors

    def global_repo(self) -> GlobalDkimSelectorRepository:
        return GlobalDkimSelectorRepository(self.session)


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        user = User(email="admin@example.com")
        session.add_all([ta, tb, user])
        session.flush()
        g = GlobalDkimSelectorRepository(session)
        ids = {
            "g1": g.create(
                {"selector": "google", "provider": "google_workspace", "seed_key": "google"},
                actor=None,
            ).id,
            "g2": g.create({"selector": "zz", "enabled": False}, actor=user.id).id,
        }
        a = repo_for(TenantContext(ta.id, user.id), session).dkim_selectors
        b = repo_for(TenantContext(tb.id, None), session).dkim_selectors
        ids["a1"] = a.create({"selector": "corp2024", "notes": "our selector"}).id
        ids["b1"] = b.create({"selector": "google", "enabled": False}).id
        session.commit()
        yield World(session, ta.id, tb.id, user.id, ids)
    finally:
        session.close()


def _ids(records: Any) -> list[int]:
    return [r.id for r in records]


# --- migration ---------------------------------------------------------------------------------


def test_migration_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert "dkim_selectors" in inspect(real_migrations_engine).get_table_names()
    command.downgrade(_cfg(), "0005")
    assert "dkim_selectors" not in inspect(real_migrations_engine).get_table_names()
    assert "content_rules" in inspect(real_migrations_engine).get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(real_migrations_engine)
    # Reading sqlite_master first refreshes the pooled SQLite connection's schema cache.
    assert "dkim_selectors" in insp.get_table_names()
    unique = {i["name"] for i in insp.get_indexes("dkim_selectors") if i["unique"]}
    assert unique == {
        "uq_dkim_selectors_global_selector",
        "uq_dkim_selectors_tenant_selector",
        "uq_dkim_selectors_global_seed_key",
    }


def test_single_alembic_head_builds_on_0005() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0006")
    assert revision is not None and revision.down_revision == "0005"


# --- constraints (raw SQL: the database enforces them, not only the repository) -----------------

INS = (
    "INSERT INTO dkim_selectors (scope, tenant_id, selector, provider, record_type, notes, "
    "status, seed_key) VALUES "
)


def _row(
    scope: str = "'tenant'",
    tenant: str = "1",
    selector: str = "'s'",
    provider: str = "NULL",
    record_type: str = "'txt'",
    notes: str = "NULL",
    status: str = "NULL",
    seed_key: str = "NULL",
) -> str:
    vals = [scope, tenant, selector, provider, record_type, notes, status, seed_key]
    return INS + "(" + ", ".join(vals) + ")"


def _glob(**kw: str) -> str:
    return _row(scope="'global'", tenant="NULL", **kw)


VIOLATIONS = [
    ("unknown scope", _row(scope="'shared'")),
    ("null scope", _row(scope="NULL")),
    ("global with tenant_id", _row(scope="'global'", tenant="1")),
    ("tenant without tenant_id", _row(tenant="NULL")),
    ("unknown tenant", _row(tenant="99")),
    ("unknown record_type", _row(record_type="'mx'")),
    ("null record_type", _row(record_type="NULL")),
    ("unknown status", _row(status="'maybe'")),
    ("empty selector", _row(selector="''")),
    ("null selector", _row(selector="NULL")),
    ("selector too long", _row(selector=f"'{'x' * 64}'")),
    ("selector too long multibyte", _row(selector=f"'{'é' * 64}'")),
    ("selector uppercase", _row(selector="'Google'")),
    ("empty provider", _row(provider="''")),
    ("provider too long", _row(provider=f"'{'p' * 65}'")),
    ("empty notes", _row(notes="''")),
    ("notes too long", _row(notes=f"'{'n' * 501}'")),
    ("empty seed_key", _glob(seed_key="''")),
    ("seed_key too long", _glob(seed_key=f"'{'s' * 64}'")),
    ("seed_key on a tenant row", _row(seed_key="'s'")),
    ("duplicate global selector", _glob(selector="'dup'")),
    ("duplicate tenant selector", _row(tenant="1", selector="'dup'")),
    ("duplicate seed_key", _glob(selector="'other'", seed_key="'dup'")),
]

ALLOWED = [
    ("same selector in another tenant", _row(tenant="2", selector="'dup'")),
    ("tenant row reusing a global selector", _row(tenant="2", selector="'g.only'")),
    ("selector at max length", _row(selector=f"'{'x' * 63}'")),
    ("notes at max length", _row(notes=f"'{'n' * 500}'")),
    ("verified seeded global", _glob(selector="'v'", status="'verified'", seed_key="'v'")),
    ("unseeded global", _glob(selector="'admin'")),
]

SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    _glob(selector="'dup'", seed_key="'dup'"),
    _glob(selector="'g.only'"),
    _row(tenant="1", selector="'dup'"),
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


def test_server_defaults(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO dkim_selectors (scope, selector) VALUES ('global', 'x')"))
        row = conn.execute(
            text(
                "SELECT record_type, enabled, locally_modified, created_at, updated_at, "
                "sources FROM dkim_selectors"
            )
        ).one()
    assert row[0] == "either" and bool(row[1]) is True and bool(row[2]) is False
    assert row[3] is not None and row[4] is not None and row[5] is None


def test_tenant_delete_cascades_and_user_delete_nulls_created_by(world: World) -> None:
    s = world.session
    s.execute(text("DELETE FROM users WHERE id = :u"), {"u": world.user})
    s.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": world.tenant_a})
    s.commit()
    s.expire_all()
    remaining = set(s.scalars(select(DkimSelector.id)).all())
    assert remaining == {world.ids["g1"], world.ids["g2"], world.ids["b1"]}
    g2 = s.scalars(select(DkimSelector).where(DkimSelector.id == world.ids["g2"])).one()
    assert g2.created_by is None


# --- repository: tenant isolation ---------------------------------------------------------------


def test_repo_for_exposes_tenant_repo_only() -> None:
    fields = {f.name for f in dataclasses.fields(TenantRepositories)}
    assert "dkim_selectors" in fields
    assert not any("global" in f for f in fields)


def test_reads_return_global_plus_own_tenant(world: World) -> None:
    i = world.ids
    # Ordered by selector, then id.
    assert _ids(world.repo("a").list()) == [i["a1"], i["g1"], i["g2"]]
    assert _ids(world.repo("b").list()) == [i["g1"], i["b1"], i["g2"]]
    assert _ids(world.repo("a").list(enabled_only=True)) == [i["a1"], i["g1"]]
    assert _ids(world.repo("b").list(enabled_only=True)) == [i["g1"]]
    assert world.repo("a").count() == 3
    assert _ids(world.repo("a").list(limit=1, offset=1)) == [i["g1"]]


@pytest.mark.parametrize(("tenant", "visible", "hidden"), [("a", "a1", "b1"), ("b", "b1", "a1")])
def test_foreign_tenant_rows_are_not_found(
    world: World, tenant: str, visible: str, hidden: str
) -> None:
    repo, i = world.repo(tenant), world.ids
    assert repo.get(i[visible]) is not None
    assert repo.get(i["g1"]) is not None
    assert repo.get(i[hidden]) is None
    assert repo.update(i[hidden], {"notes": "pwned"}) is None
    assert repo.delete(i[hidden]) is False
    world.session.commit()
    other = world.repo("b" if tenant == "a" else "a").get(i[hidden])
    assert other is not None and other.notes != "pwned"


def test_tenant_cannot_write_global_rows(world: World) -> None:
    repo, i = world.repo("a"), world.ids
    assert repo.update(i["g1"], {"enabled": False}) is None
    assert repo.delete(i["g1"]) is False
    g1 = world.global_repo().get(i["g1"])
    assert g1 is not None and g1.enabled is True


def test_global_repo_never_sees_tenant_rows(world: World) -> None:
    g, i = world.global_repo(), world.ids
    assert _ids(g.list()) == [i["g1"], i["g2"]]
    assert g.count() == 2
    assert g.get(i["a1"]) is None
    assert g.update(i["a1"], {"notes": "x"}) is None
    assert g.delete(i["b1"]) is False
    assert _ids(g.list_seeded()) == [i["g1"]]


@pytest.mark.parametrize("bad", MALFORMED_IDS)
def test_malformed_ids_are_not_found(world: World, bad: object) -> None:
    for repo in (world.repo("a"), world.global_repo()):
        assert repo.get(bad) is None
        assert repo.update(bad, {"enabled": True}) is None
        assert repo.delete(bad) is False


def test_tenant_create_forces_scope_and_tenant(world: World) -> None:
    rec = world.repo("a").create({"selector": "mine", "record_type": "cname"})
    assert rec.scope == "tenant" and rec.tenant_id == world.tenant_a
    assert rec.created_by == world.user and rec.seed_key is None and rec.status is None
    assert rec.enabled is True and rec.locally_modified is False


@pytest.mark.parametrize("key", ["scope", "tenant_id"])
def test_scope_fields_cannot_be_passed(world: World, key: str) -> None:
    with pytest.raises(TenantScopeError):
        world.repo("a").create({"selector": "x", key: "global" if key == "scope" else None})
    with pytest.raises(TenantScopeError):
        world.repo("a").update(world.ids["a1"], {key: world.tenant_b})
    with pytest.raises(TenantScopeError):
        world.global_repo().create({"selector": "x", key: 1}, actor=None)


@pytest.mark.parametrize(
    "field", ["seed_key", "status", "verified_on", "sources", "locally_modified", "id"]
)
def test_tenant_cannot_set_seed_fields(world: World, field: str) -> None:
    with pytest.raises(DkimSelectorInvalid) as err:
        world.repo("a").create({"selector": "x", field: None})
    assert err.value.reason == "unknown_field"


def test_duplicate_selector_in_scope(world: World) -> None:
    with pytest.raises(SelectorTaken):
        world.repo("a").create({"selector": "corp2024"})
    with pytest.raises(SelectorTaken):
        world.global_repo().create({"selector": "google"}, actor=None)
    with pytest.raises(SelectorTaken):
        world.global_repo().create({"selector": "other", "seed_key": "google"}, actor=None)
    with pytest.raises(SelectorTaken):
        world.repo("a").update(
            world.repo("a").create({"selector": "x"}).id, {"selector": "corp2024"}
        )
    # Same name across tenants and across scopes is fine.
    assert world.repo("b").create({"selector": "corp2024"}).tenant_id == world.tenant_b
    assert world.repo("a").create({"selector": "google"}).scope == "tenant"


def test_unique_conflict_from_flush_maps_to_selector_taken(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(DkimSelectorRepository, "_taken", lambda *_a, **_k: False)
    with pytest.raises(SelectorTaken):
        world.repo("a").create({"selector": "corp2024"})
    world.session.rollback()


def test_records_are_frozen_and_rows_cannot_move(world: World) -> None:
    rec = world.repo("a").get(world.ids["a1"])
    assert isinstance(rec, DkimSelectorRecord)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.tenant_id = world.tenant_b  # type: ignore[misc]
    row = world.session.scalars(
        select(DkimSelector).where(DkimSelector.id == world.ids["a1"])
    ).one()
    with pytest.raises(TenantScopeError):
        row.tenant_id = world.tenant_b
    with pytest.raises(TenantScopeError):
        row.scope = "global"


def test_constructors_require_context_and_session(world: World) -> None:
    with pytest.raises(TypeError):
        DkimSelectorRepository(None, world.session)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        GlobalDkimSelectorRepository(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        world.global_repo().create({"selector": "x"}, actor=0)


# --- validation before the database -------------------------------------------------------------

VALID_SELECTORS = ["default", "s1", "selector1", "acdkim1", "k_1", "x" * 63, "2024-01"]

INVALID_SELECTORS = [
    (None, "not_a_string"),
    (123, "not_a_string"),
    (b"s1", "not_a_string"),
    ("", "empty"),
    ("x" * 64, "too_long"),
    ("s\x00", "nul"),
    ("s\ud800", "surrogate"),
    ("s\t1", "control_char"),
    ("s\n1", "control_char"),
    ("s\x7f", "control_char"),
    (" s1", "whitespace"),
    ("s1 ", "whitespace"),
    ("S1", "invalid_label"),
    ("sélecteur", "invalid_label"),
    ("a b", "invalid_label"),
    ("a.b", "not_a_label"),
    (".", "not_a_label"),
    ("a.", "invalid_label"),
    ("a..b", "invalid_label"),
]


@pytest.mark.parametrize("value", VALID_SELECTORS)
def test_valid_selectors(world: World, value: str) -> None:
    assert world.repo("a").create({"selector": value}).selector == value


@pytest.mark.parametrize(("value", "reason"), INVALID_SELECTORS)
def test_invalid_selector_rejected_before_db(world: World, value: object, reason: str) -> None:
    before = world.repo("a").count()
    calls = [
        lambda: world.repo("a").create({"selector": value}),
        lambda: world.repo("a").update(world.ids["a1"], {"selector": value}),
    ]
    if value is not None:  # seed_key is nullable
        calls.append(
            lambda: world.global_repo().create({"selector": "ok", "seed_key": value}, actor=None)
        )
    for call in calls:
        with pytest.raises(DkimSelectorInvalid) as err:
            call()
        assert err.value.reason == reason
        assert "rejected: " + reason in str(err.value)
    assert world.repo("a").count() == before


INVALID_FIELDS: list[tuple[dict[str, Any], str, str]] = [
    ({}, "selector", "required"),
    ({"provider": "Google Workspace"}, "provider", "invalid_format"),
    ({"provider": "p" * 65}, "provider", "too_long"),
    ({"provider": "g\x00"}, "provider", "nul"),
    ({"provider": 1}, "provider", "not_a_string"),
    ({"record_type": "mx"}, "record_type", "invalid_choice"),
    ({"record_type": None}, "record_type", "invalid_choice"),
    ({"notes": "n" * 501}, "notes", "too_long"),
    ({"notes": "a\x00b"}, "notes", "nul"),
    ({"notes": "a\nb"}, "notes", "control_char"),
    ({"notes": "a\ud83db"}, "notes", "surrogate"),
    ({"notes": "  "}, "notes", "whitespace"),
    ({"notes": ""}, "notes", "empty"),
    ({"enabled": 1}, "enabled", "not_a_bool"),
    ({"enabled": None}, "enabled", "not_a_bool"),
    ({"unknown": 1}, "unknown", "unknown_field"),
]


@pytest.mark.parametrize(("extra", "field", "reason"), INVALID_FIELDS)
def test_invalid_fields_rejected(
    world: World, extra: dict[str, Any], field: str, reason: str
) -> None:
    values = {"selector": "new1", **extra} if field != "selector" else {}
    with pytest.raises(DkimSelectorInvalid) as err:
        world.repo("a").create(values)
    assert (err.value.field, err.value.reason) == (field, reason)


GLOBAL_INVALID: list[tuple[dict[str, Any], str, str]] = [
    ({"status": "maybe"}, "status", "invalid_choice"),
    ({"verified_on": dt.datetime(2026, 1, 1)}, "verified_on", "not_a_date"),
    ({"verified_on": "2026-01-01"}, "verified_on", "not_a_date"),
    ({"sources": []}, "sources", "empty"),
    ({"sources": "https://x.example"}, "sources", "not_a_list"),
    ({"sources": ["ftp://x.example"]}, "sources", "invalid_url"),
    ({"sources": ["https://"]}, "sources", "invalid_url"),
    ({"sources": ["https://x.example/a b"]}, "sources", "invalid_url"),
    ({"sources": ["https://x.example/\x00"]}, "sources", "nul"),
    ({"sources": ["https://x.example"] * 2}, "sources", "duplicate"),
    ({"sources": [f"https://x.example/{n}" for n in range(11)]}, "sources", "too_many"),
    ({"locally_modified": "yes"}, "locally_modified", "not_a_bool"),
]


@pytest.mark.parametrize(("extra", "field", "reason"), GLOBAL_INVALID)
def test_invalid_global_fields_rejected(
    world: World, extra: dict[str, Any], field: str, reason: str
) -> None:
    with pytest.raises(DkimSelectorInvalid) as err:
        world.global_repo().create({"selector": "new1", **extra}, actor=None)
    assert (err.value.field, err.value.reason) == (field, reason)


def test_global_seed_fields_round_trip_and_sources_null(world: World) -> None:
    g = world.global_repo()
    rec = g.create(
        {
            "selector": "s1",
            "provider": "sendgrid",
            "record_type": "cname",
            "status": "verified",
            "verified_on": dt.date(2026, 11, 6),
            "sources": ["https://example.org/a"],
            "seed_key": "s1",
        },
        actor=None,
    )
    assert rec.sources == ("https://example.org/a",)
    assert rec.verified_on == dt.date(2026, 11, 6) and rec.status == "verified"
    cleared = g.update(rec.id, {"sources": None})
    assert cleared is not None and cleared.sources is None
    world.session.commit()
    nulls = world.session.execute(
        text("SELECT COUNT(*) FROM dkim_selectors WHERE sources IS NULL")
    ).scalar_one()
    total = world.session.execute(text("SELECT COUNT(*) FROM dkim_selectors")).scalar_one()
    assert nulls == total


@pytest.mark.parametrize("bad", [-1, 1001, True, "10"])
def test_bad_paging_rejected(world: World, bad: object) -> None:
    with pytest.raises(ValueError):
        world.repo("a").list(limit=bad)  # type: ignore[arg-type]
