"""M6-02 domain_esps: migration 0009, DB constraints and the tenant repository.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). The schema
is built by Alembic. No network.
"""

import dataclasses
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
from app.models import DomainEsp, Tenant
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import MAX_LIMIT, TenantScopeError
from app.repositories.domain_esps import (
    MAX_ESPS_PER_DOMAIN,
    DomainEspInvalid,
    DomainEspLimitReached,
    DomainEspRecord,
    DomainEspRepository,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**31, 2**63, [1], b"1"]


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
    domains: dict[str, int]

    def repos(self, tenant: str = "a") -> TenantRepositories:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, None), self.session)

    def repo(self, tenant: str = "a") -> DomainEspRepository:
        return self.repos(tenant).domain_esps

    def rows(self) -> list[tuple[int, int, str, str | None, str | None]]:
        """Every row in the table (raw read, bypassing the repository)."""
        self.session.expire_all()
        stmt = select(
            DomainEsp.tenant_id,
            DomainEsp.domain_id,
            DomainEsp.esp_id,
            DomainEsp.return_path_host,
            DomainEsp.tracking_host,
        ).order_by(DomainEsp.id)
        return [tuple(r) for r in self.session.execute(stmt).all()]  # type: ignore[misc]


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        session.add_all([ta, tb])
        session.flush()
        a = repo_for(TenantContext(ta.id, None), session).domains
        b = repo_for(TenantContext(tb.id, None), session).domains
        domains = {
            "a1": a.create("a.example").id,
            "a2": a.create("a2.example").id,
            "b1": b.create("b.example").id,
        }
        session.commit()
        w = World(session, ta.id, tb.id, domains)
        w.repo("b").add(domains["b1"], "b-esp", return_path_host="bounce.b.example")
        session.commit()
        yield w
    finally:
        session.close()


# --- migration ---------------------------------------------------------------------------------


def test_migration_upgrade_downgrade(real_migrations_engine: Engine) -> None:
    assert "domain_esps" in inspect(real_migrations_engine).get_table_names()
    command.downgrade(_cfg(), "0008")
    insp = inspect(real_migrations_engine)
    assert "domain_esps" not in insp.get_table_names()
    assert "custom_checks" in insp.get_table_names()
    command.upgrade(_cfg(), "head")
    insp = inspect(real_migrations_engine)
    assert "domain_esps" in insp.get_table_names()
    uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints("domain_esps")}
    assert ("domain_id", "esp_id") in uniques
    fks = {
        (tuple(f["constrained_columns"]), f["referred_table"], tuple(f["referred_columns"]))
        for f in insp.get_foreign_keys("domain_esps")
    }
    assert fks == {
        (("domain_id", "tenant_id"), "domains", ("id", "tenant_id")),
        (("tenant_id",), "tenants", ("id",)),
    }


def test_single_alembic_head_builds_on_0008() -> None:
    script = ScriptDirectory.from_config(_cfg())
    assert len(script.get_heads()) == 1
    revision = script.get_revision("0009")
    assert revision is not None and revision.down_revision == "0008"


# --- constraints (raw SQL: the database enforces them, not only the repository) -----------------

INS = "INSERT INTO domain_esps (tenant_id, domain_id, esp_id, return_path_host, tracking_host) "


def _row(
    tenant: str = "1", domain: str = "1", esp: str = "'e'", rp: str = "NULL", tr: str = "NULL"
) -> str:
    return INS + f"VALUES ({tenant}, {domain}, {esp}, {rp}, {tr})"


VIOLATIONS = [
    ("domain of another tenant", _row(tenant="1", domain="2")),
    ("unknown domain", _row(domain="99")),
    ("unknown tenant", _row(tenant="99")),
    ("null tenant", _row(tenant="NULL")),
    ("null domain", _row(domain="NULL")),
    ("null esp_id", _row(esp="NULL")),
    ("empty esp_id", _row(esp="''")),
    ("esp_id too long", _row(esp=f"'{'e' * 41}'")),
    ("esp_id uppercase", _row(esp="'Esp'")),
    ("empty return_path_host", _row(rp="''")),
    ("return_path_host too long", _row(rp=f"'{'h' * 254}'")),
    ("return_path_host uppercase", _row(rp="'Bounce.a.example'")),
    ("empty tracking_host", _row(tr="''")),
    ("tracking_host too long", _row(tr=f"'{'h' * 254}'")),
    ("tracking_host uppercase", _row(tr="'Click.a.example'")),
    ("duplicate (domain, esp)", _row(esp="'dup'")),
]

ALLOWED = [
    ("same esp on another domain", _row(tenant="2", domain="2", esp="'dup'")),
    ("esp_id at max length", _row(esp=f"'{'e' * 40}'")),
    ("hosts set", _row(rp="'bounce.a.example'", tr="'click.a.example'")),
]

SEED_ROWS = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'A', 'a'), (2, 'B', 'b')",
    "INSERT INTO domains (id, tenant_id, name) VALUES (1, 1, 'a.example'), (2, 2, 'b.example')",
    _row(esp="'dup'"),
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
    # PostgreSQL rejects an over-long VARCHAR with DataError before the CHECK.
    with pytest.raises((IntegrityError, DataError)), seeded.begin() as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(("case", "statement"), ALLOWED, ids=[c for c, _ in ALLOWED])
def test_valid_insert_accepted(seeded: Engine, case: str, statement: str) -> None:
    with seeded.begin() as conn:
        assert conn.execute(text(statement)).rowcount == 1


def test_moving_a_row_to_another_tenant_is_rejected(seeded: Engine) -> None:
    with pytest.raises(IntegrityError), seeded.begin() as conn:
        conn.execute(text("UPDATE domain_esps SET tenant_id = 2"))


# --- cascades ----------------------------------------------------------------------------------


def test_domain_delete_cascades(world: World) -> None:
    world.repo().add(world.domains["a1"], "esp-one")
    world.repo().add(world.domains["a2"], "esp-two")
    world.session.commit()
    assert world.repos().domains.delete(world.domains["a1"])
    world.session.commit()
    assert [(r[1], r[2]) for r in world.rows()] == [
        (world.domains["b1"], "b-esp"),
        (world.domains["a2"], "esp-two"),
    ]


def test_tenant_delete_cascades(world: World) -> None:
    world.repo().add(world.domains["a1"], "esp-one")
    world.session.commit()
    world.session.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": world.tenant_a})
    world.session.commit()
    assert [r[0] for r in world.rows()] == [world.tenant_b]


# --- repository: basics ------------------------------------------------------------------------


def test_repo_for_exposes_domain_esps() -> None:
    assert "domain_esps" in {f.name for f in dataclasses.fields(TenantRepositories)}


def test_repository_requires_a_tenant_context(world: World) -> None:
    with pytest.raises(TypeError):
        DomainEspRepository(world.tenant_a, world.session)  # type: ignore[arg-type]


def test_add_and_list(world: World) -> None:
    d = world.domains["a1"]
    rec = world.repo().add(d, "zeta", tracking_host="click.a.example")
    world.repo().add(d, "alpha", return_path_host="a.example")
    assert isinstance(rec, DomainEspRecord) and rec.domain_id == d and rec.created_at is not None
    listed = world.repo().list_for_domain(d)
    assert [(r.esp_id, r.return_path_host, r.tracking_host) for r in listed] == [
        ("alpha", "a.example", None),
        ("zeta", None, "click.a.example"),
    ]
    assert world.repo().list_for_domain(world.domains["a2"]) == []


def test_records_are_immutable(world: World) -> None:
    rec = world.repo().add(world.domains["a1"], "esp")
    assert rec is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.esp_id = "other"  # type: ignore[misc]


def test_duplicate_add_is_idempotent(world: World) -> None:
    d = world.domains["a1"]
    first = world.repo().add(d, "esp", return_path_host="rp.a.example")
    again = world.repo().add(d, "esp", return_path_host="other.a.example")
    assert first is not None and again == first  # existing row returned unchanged
    assert len(world.repo().list_for_domain(d)) == 1
    world.session.commit()


def test_list_for_domains(world: World) -> None:
    a1, a2, b1 = world.domains["a1"], world.domains["a2"], world.domains["b1"]
    world.repo().add(a1, "z-esp")
    world.repo().add(a1, "a-esp")
    world.repo().add(a2, "m-esp")
    result = world.repo().list_for_domains([a1, a2, b1, *MALFORMED_IDS[:3], 999_999])
    assert {k: [r.esp_id for r in v] for k, v in result.items()} == {
        a1: ["a-esp", "z-esp"],
        a2: ["m-esp"],
    }
    assert world.repo().list_for_domains([]) == {}
    assert world.repo().list_for_domains([b1]) == {}


def test_list_for_domains_caps_the_id_count(world: World) -> None:
    with pytest.raises(ValueError):
        world.repo().list_for_domains(list(range(1, MAX_LIMIT + 2)))


def test_update_hosts_sets_and_clears(world: World) -> None:
    d = world.domains["a1"]
    world.repo().add(d, "esp")
    rec = world.repo().update_hosts(
        d, "esp", return_path_host="RP.A.Example.", tracking_host="click.a.example"
    )
    assert rec is not None
    assert (rec.return_path_host, rec.tracking_host) == ("rp.a.example", "click.a.example")
    rec = world.repo().update_hosts(d, "esp", return_path_host=None, tracking_host=None)
    assert rec is not None and (rec.return_path_host, rec.tracking_host) == (None, None)
    missing = world.repo().update_hosts(d, "missing", return_path_host=None, tracking_host=None)
    assert missing is None


def test_remove(world: World) -> None:
    d = world.domains["a1"]
    world.repo().add(d, "esp")
    assert world.repo().remove(d, "esp") is True
    assert world.repo().remove(d, "esp") is False
    assert world.repo().list_for_domain(d) == []


@pytest.mark.parametrize("esp_id", [None, 1, "", "BAD", "a" * 41, "a\x00"], ids=repr)
def test_remove_with_malformed_esp_id_is_not_found(world: World, esp_id: Any) -> None:
    assert world.repo().remove(world.domains["a1"], esp_id) is False


def test_cap_per_domain(world: World) -> None:
    d = world.domains["a1"]
    for n in range(MAX_ESPS_PER_DOMAIN):
        world.repo().add(d, f"esp-{n}")
    with pytest.raises(DomainEspLimitReached):
        world.repo().add(d, "one-too-many")
    assert world.repo().add(d, "esp-0") is not None  # re-adding an existing one is fine
    assert len(world.repo().list_for_domain(d)) == MAX_ESPS_PER_DOMAIN
    assert world.repo().add(world.domains["a2"], "esp-0") is not None  # cap is per domain


# --- repository: tenant isolation --------------------------------------------------------------


def test_tenant_a_cannot_touch_tenant_b_rows(world: World) -> None:
    b1 = world.domains["b1"]
    before = world.rows()
    repo = world.repo("a")
    assert repo.list_for_domain(b1) == []
    assert repo.list_for_domains([b1]) == {}
    assert repo.add(b1, "b-esp") is None
    assert repo.add(b1, "new-esp", return_path_host="bounce.b.example") is None
    assert repo.add(b1, "new-esp", return_path_host="not-a-host.invalid.") is None
    assert repo.update_hosts(b1, "b-esp", return_path_host=None, tracking_host=None) is None
    assert repo.remove(b1, "b-esp") is False
    world.session.commit()
    assert world.rows() == before


def test_foreign_domain_looks_like_a_missing_one(world: World) -> None:
    repo = world.repo("a")
    for did in (world.domains["b1"], 999_999):
        assert repo.add(did, "esp") is None
        assert repo.update_hosts(did, "esp", return_path_host=None, tracking_host=None) is None
        assert repo.remove(did, "esp") is False
        assert repo.list_for_domain(did) == []


def test_tenant_b_cannot_see_tenant_a_rows(world: World) -> None:
    a1 = world.domains["a1"]
    world.repo("a").add(a1, "a-esp")
    assert world.repo("b").list_for_domain(a1) == []
    assert world.repo("b").remove(a1, "a-esp") is False
    assert [r.esp_id for r in world.repo("a").list_for_domain(a1)] == ["a-esp"]


def test_rows_are_written_with_the_context_tenant(world: World) -> None:
    world.repo("a").add(world.domains["a1"], "esp")
    assert (world.tenant_a, world.domains["a1"], "esp", None, None) in world.rows()


def test_persisted_row_cannot_change_tenant(world: World) -> None:
    row = world.session.scalars(select(DomainEsp)).first()
    assert row is not None
    with pytest.raises(TenantScopeError):
        row.tenant_id = world.tenant_a


@pytest.mark.parametrize("bad", MALFORMED_IDS, ids=repr)
def test_malformed_domain_ids_are_not_found(world: World, bad: Any) -> None:
    repo = world.repo()
    assert repo.list_for_domain(bad) == []
    assert repo.add(bad, "esp") is None
    assert repo.update_hosts(bad, "esp", return_path_host=None, tracking_host=None) is None
    assert repo.remove(bad, "esp") is False


# --- validation --------------------------------------------------------------------------------

VALID_ESP_IDS = ["sendgrid", "a", "0", "amazon-ses", "e" * 40, "a-"]
INVALID_ESP_IDS = [
    ("none", None, "not_a_string"),
    ("int", 1, "not_a_string"),
    ("bytes", b"esp", "not_a_string"),
    ("empty", "", "format"),
    ("leading hyphen", "-esp", "format"),
    ("uppercase", "SendGrid", "format"),
    ("underscore", "a_b", "format"),
    ("dot", "a.b", "format"),
    ("too long", "e" * 41, "format"),
    ("nul", "esp\x00", "format"),
    ("newline", "esp\n", "format"),
    ("space", " esp", "format"),
    ("non-ascii", "espé", "format"),
]


@pytest.mark.parametrize("esp_id", VALID_ESP_IDS)
def test_valid_esp_ids(world: World, esp_id: str) -> None:
    rec = world.repo().add(world.domains["a1"], esp_id)
    assert rec is not None and rec.esp_id == esp_id


@pytest.mark.parametrize(
    ("case", "esp_id", "reason"), INVALID_ESP_IDS, ids=[c for c, _, _ in INVALID_ESP_IDS]
)
def test_invalid_esp_ids(world: World, case: str, esp_id: Any, reason: str) -> None:
    d = world.domains["a1"]
    with pytest.raises(DomainEspInvalid) as info:
        world.repo().add(d, esp_id)
    assert (info.value.field, info.value.reason) == ("esp_id", reason)
    with pytest.raises(DomainEspInvalid):
        world.repo().update_hosts(d, esp_id, return_path_host=None, tracking_host=None)
    if isinstance(esp_id, str) and len(esp_id) > 5:
        assert esp_id not in str(info.value)


# Domain a1 is "a.example".
VALID_HOSTS = [
    ("the domain itself", "a.example", "a.example"),
    ("subdomain", "bounce.a.example", "bounce.a.example"),
    ("deep subdomain", "x.y.a.example", "x.y.a.example"),
    ("uppercase is normalised", "Bounce.A.EXAMPLE", "bounce.a.example"),
    ("trailing dot is removed", "bounce.a.example.", "bounce.a.example"),
    ("surrounding whitespace is trimmed", "  bounce.a.example\n", "bounce.a.example"),
    ("A-label", "xn--bcher-kva.a.example", "xn--bcher-kva.a.example"),
    ("max length", ("a" * 60 + ".") * 4 + "a.example", ("a" * 60 + ".") * 4 + "a.example"),
]
INVALID_HOSTS = [
    ("foreign suffix", "bounce.b.example", "not_in_domain"),
    ("suffix without a dot", "xa.example", "not_in_domain"),
    ("parent of the domain", "example", "single_label"),
    ("domain as a prefix", "a.example.evil.example", "not_in_domain"),
    ("nul", "bounce\x00.a.example", "forbidden_character"),
    ("inner space", "bou nce.a.example", "forbidden_character"),
    ("too long", ("a" * 60 + ".") * 5 + "a.example", "idna"),
    ("over the raw input cap", "a" * 2000, "too_long"),
    ("at max length plus one", ("a" * 61 + ".") * 4 + "a.example", "idna"),
    ("label too long", "a" * 64 + ".a.example", "idna"),
    ("empty", "", "empty"),
    ("blank", "   ", "empty"),
    ("two trailing dots", "bounce.a.example..", "idna"),
    ("idn u-label", "bücher.a.example", "not_ascii"),
    ("full-width dot", "bounce．a.example", "not_ascii"),
    ("underscore", "_bounce.a.example", "idna"),
    ("wildcard", "*.a.example", "idna"),
    ("ip address", "192.0.2.1", "ip_address"),
    ("scheme", "https://bounce.a.example", "idna"),
    ("int", 5, "not_a_string"),
    ("bytes", b"bounce.a.example", "not_a_string"),
]


@pytest.mark.parametrize("field", ["return_path_host", "tracking_host"])
@pytest.mark.parametrize(
    ("case", "value", "expected"), VALID_HOSTS, ids=[c for c, _, _ in VALID_HOSTS]
)
def test_valid_hosts(world: World, field: str, case: str, value: str, expected: str) -> None:
    d = world.domains["a1"]
    rec = world.repo().add(d, "esp", **{field: value})
    assert rec is not None and getattr(rec, field) == expected
    world.repo().remove(d, "esp")
    world.repo().add(d, "esp")
    other = "tracking_host" if field == "return_path_host" else "return_path_host"
    rec = world.repo().update_hosts(d, "esp", **{field: value, other: None})
    assert rec is not None and getattr(rec, field) == expected


@pytest.mark.parametrize("field", ["return_path_host", "tracking_host"])
@pytest.mark.parametrize(
    ("case", "value", "reason"), INVALID_HOSTS, ids=[c for c, _, _ in INVALID_HOSTS]
)
def test_invalid_hosts(world: World, field: str, case: str, value: Any, reason: str) -> None:
    d = world.domains["a1"]
    with pytest.raises(DomainEspInvalid) as info:
        world.repo().add(d, "esp", **{field: value})
    assert (info.value.field, info.value.reason) == (field, reason)
    if isinstance(value, str) and value.strip():
        assert value.strip() not in str(info.value)
    assert world.repo().list_for_domain(d) == []
    world.repo().add(d, "esp", return_path_host="rp.a.example")
    other = "tracking_host" if field == "return_path_host" else "return_path_host"
    with pytest.raises(DomainEspInvalid):
        world.repo().update_hosts(d, "esp", **{field: value, other: None})
    rec = world.repo().list_for_domain(d)[0]
    assert rec.return_path_host == "rp.a.example"  # nothing changed


def test_host_rule_follows_each_domain(world: World) -> None:
    """A host valid for one domain of the tenant is not valid for another one."""
    with pytest.raises(DomainEspInvalid):
        world.repo().add(world.domains["a2"], "esp", return_path_host="bounce.a.example")
    assert world.repo().add(world.domains["a2"], "esp", return_path_host="b.a2.example")
