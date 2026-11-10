"""M6-03 domain ESP service: authorization before any repository, PUT semantics (add vs
update_hosts), concurrent duplicates, profile validation, tenant isolation.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL. No network.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.checks.models import CheckContext, CheckResult, Target
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.permissions import MembershipGrant, Principal
from app.core.tenancy import TenantContext
from app.dns.types import DnsQuestion, DnsResult, ResultState
from app.esp.profile import EspProfileError, read_esp_profiles
from app.models import Domain, MembershipRole, Tenant, User
from app.models.domain_esp import DomainEsp
from app.repositories.domain_esps import MAX_ESPS_PER_DOMAIN, DomainEspRepository
from app.services import domain_esps as service_module
from app.services.domain_esps import (
    PROFILES_UNAVAILABLE_KEY,
    DomainEspService,
    EspConflict,
    EspFieldInvalid,
    EspForbidden,
    EspNotFound,
    EspProfilesUnavailable,
    EspRun,
    field_key,
    resolve_esp_run,
)
from tests.support.socket_guard import db_endpoint, install

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "esp" / "valid"
PROFILES = read_esp_profiles(FIXTURES)
ESP = "example-esp"
OTHER = "other-esp"
SECRET_HOST = "bounce.tenantb-secret.example"


@dataclass
class World:
    db: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]

    def principal(self, who: str, toggles: dict[str, Any] | None = None) -> Principal:
        roles = {
            "owner": MembershipRole.OWNER,
            "admin": MembershipRole.ADMIN,
            "analyst": MembershipRole.ANALYST,
            "viewer": MembershipRole.CLIENT_VIEWER,
        }
        if who == "root":
            return Principal(self.users["root"], True, is_instance_admin=True)
        grant = MembershipGrant(
            self.tenant_a,
            roles[who],
            domain_ids=frozenset({self.domains["a"]}) if who == "viewer" else frozenset(),
            feature_toggles=MappingProxyType(toggles or {}),
        )
        return Principal(self.users[who], True, False, self.tenant_a, (grant,))

    def service(self, who: str, toggles: dict[str, Any] | None = None) -> DomainEspService:
        ctx = None if who == "root" else TenantContext(self.tenant_a, self.users[who])
        return DomainEspService(self.db, ctx, self.principal(who, toggles), lambda: PROFILES)

    def b_service(self) -> DomainEspService:
        grant = MembershipGrant(self.tenant_b, MembershipRole.OWNER)
        principal = Principal(self.users["b_owner"], True, False, self.tenant_b, (grant,))
        ctx = TenantContext(self.tenant_b, self.users["b_owner"])
        return DomainEspService(self.db, ctx, principal, lambda: PROFILES)

    def rows(self) -> list[tuple[Any, ...]]:
        self.db.expire_all()
        found = self.db.execute(
            select(
                DomainEsp.tenant_id,
                DomainEsp.domain_id,
                DomainEsp.esp_id,
                DomainEsp.return_path_host,
                DomainEsp.tracking_host,
            ).order_by(DomainEsp.id)
        ).all()
        return [tuple(r) for r in found]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "domain esps service", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str) -> Iterator[World]:
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        a, b = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        names = ("owner", "admin", "analyst", "viewer", "root", "b_owner")
        users = {n: User(email=f"{n}@example.com") for n in names}
        db.add_all([a, b, *users.values()])
        db.flush()
        domains = {
            "a": Domain(tenant_id=a.id, name="a.example"),
            "a2": Domain(tenant_id=a.id, name="a2.example"),
            "b": Domain(tenant_id=b.id, name="tenantb-secret.example"),
        }
        db.add_all(domains.values())
        db.commit()
        yield World(
            db,
            a.id,
            b.id,
            {n: u.id for n, u in users.items()},
            {n: d.id for n, d in domains.items()},
        )
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def repository_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fails the test if the service builds a repository."""
    calls: list[str] = []

    def build(*_a: Any, **_k: Any) -> Any:
        calls.append("repo_for")
        raise AssertionError("the repository was reached after a denial")

    monkeypatch.setattr(service_module, "repo_for", build)
    return calls


def _invoke(service: DomainEspService, verb: str, domain_id: object) -> Any:
    return {
        "catalogue": lambda: service.catalogue(),
        "list": lambda: service.list_for_domain(domain_id),
        "assign": lambda: service.assign(domain_id, ESP),
        "remove": lambda: service.remove(domain_id, ESP),
    }[verb]()


VERBS = ("catalogue", "list", "assign", "remove")
DOMAIN_VERBS = ("list", "assign", "remove")

# Decided by `can()` and the principal alone: no repository is built.
DENIED_BEFORE_REPOSITORY = [
    # Client viewers read but never write: on their assigned domain the write denial needs no
    # lookup (their `domain.read` is their own assignment).
    *[("viewer", "a", v, EspForbidden, None) for v in ("assign", "remove")],
    # Unassigned domain for a viewer: invisible, like the other domain routes.
    *[("viewer", "a2", v, EspNotFound, None) for v in DOMAIN_VERBS],
    # The instance admin flag adds nothing inside a tenant: no active tenant here.
    *[("root", "a", v, EspNotFound, None) for v in VERBS],
    # Per-user toggles deny as elsewhere, client viewers included.
    ("owner", "a", "catalogue", EspForbidden, {"domain.list": False}),
    ("viewer", "a", "catalogue", EspForbidden, {"domain.list": False}),
    ("viewer", "a", "list", EspNotFound, {"domain.read": False}),
    *[("owner", "a", v, EspNotFound, {"domain.read": False}) for v in DOMAIN_VERBS],
]


@pytest.mark.parametrize(("who", "domain", "verb", "error", "toggles"), DENIED_BEFORE_REPOSITORY)
def test_denied_before_any_repository(
    world: World,
    repository_spy: list[str],
    who: str,
    domain: str,
    verb: str,
    error: type[Exception],
    toggles: dict[str, Any] | None,
) -> None:
    with pytest.raises(error):
        _invoke(world.service(who, toggles), verb, world.domains[domain])
    assert repository_spy == []


@pytest.mark.parametrize("bad_id", [None, 0, -1, "1", 2**31, True, 1.0])
@pytest.mark.parametrize("verb", DOMAIN_VERBS)
def test_malformed_domain_id_is_not_found_before_any_repository(
    world: World, repository_spy: list[str], verb: str, bad_id: object
) -> None:
    with pytest.raises(EspNotFound):
        _invoke(world.service("owner"), verb, bad_id)
    assert repository_spy == []


@pytest.mark.parametrize("verb", ["assign", "remove"])
def test_analyst_write_is_forbidden_and_never_reaches_the_esp_repository(
    world: World, monkeypatch: pytest.MonkeyPatch, verb: str
) -> None:
    """`domain.update` is decided by `can()` first; the domain lookup only chooses 404 vs 403."""
    touched: list[str] = []
    for name in ("list_for_domain", "list_for_domains", "add", "update_hosts", "remove"):
        monkeypatch.setattr(
            DomainEspRepository, name, lambda *_a, _n=name, **_k: touched.append(_n)
        )
    with pytest.raises(EspForbidden):
        _invoke(world.service("analyst"), verb, world.domains["a"])
    assert touched == []


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_readers_list_and_see_the_catalogue(world: World, who: str) -> None:
    world.service("owner").assign(world.domains["a"], ESP, return_path_host="bounce.a.example")
    records = world.service(who).list_for_domain(world.domains["a"])
    assert [(r.esp_id, r.return_path_host) for r in records] == [(ESP, "bounce.a.example")]
    assert [p.id for p in world.service(who).catalogue()] == [ESP, OTHER]


@pytest.mark.parametrize("who", ["owner", "admin"])
def test_writers_assign_and_remove(world: World, who: str) -> None:
    service = world.service(who)
    result = service.assign(world.domains["a"], ESP)
    assert result.created
    service.remove(world.domains["a"], ESP)
    assert world.rows() == []


# --- tenancy ------------------------------------------------------------------------------------


@pytest.mark.parametrize("verb", DOMAIN_VERBS)
@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_domain_of_another_tenant_is_not_found(world: World, verb: str, who: str) -> None:
    world.b_service().assign(world.domains["b"], ESP, return_path_host=SECRET_HOST)
    before = world.rows()
    with pytest.raises(EspNotFound):
        _invoke(world.service(who), verb, world.domains["b"])
    assert world.rows() == before


def test_missing_domain_is_not_found(world: World) -> None:
    with pytest.raises(EspNotFound):
        world.service("owner").list_for_domain(999_999)


def test_rows_carry_the_context_tenant(world: World) -> None:
    world.service("owner").assign(world.domains["a"], ESP)
    world.b_service().assign(world.domains["b"], ESP, return_path_host=SECRET_HOST)
    assert {(r[0], r[1]) for r in world.rows()} == {
        (world.tenant_a, world.domains["a"]),
        (world.tenant_b, world.domains["b"]),
    }
    assert world.service("owner").list_for_domain(world.domains["a"])[0].return_path_host is None


# --- PUT semantics ------------------------------------------------------------------------------


def test_duplicate_assign_is_idempotent(world: World) -> None:
    service = world.service("owner")
    first = service.assign(world.domains["a"], ESP, return_path_host="bounce.a.example")
    second = service.assign(world.domains["a"], ESP, return_path_host="bounce.a.example")
    assert first.created and not second.created
    assert second.record == first.record
    assert len(world.rows()) == 1


def test_reassign_with_other_hosts_updates_them(world: World) -> None:
    """Not the repository's idempotent add, which keeps the old hosts: PUT sets them."""
    service = world.service("owner")
    service.assign(world.domains["a"], ESP, return_path_host="bounce.a.example")
    result = service.assign(
        world.domains["a"], ESP, return_path_host="RP.A.Example.", tracking_host="t.a.example"
    )
    assert not result.created
    assert (result.record.return_path_host, result.record.tracking_host) == (
        "rp.a.example",
        "t.a.example",
    )
    cleared = service.assign(world.domains["a"], ESP)
    assert (cleared.record.return_path_host, cleared.record.tracking_host) == (None, None)
    assert len(world.rows()) == 1


def test_concurrent_duplicate_add_is_not_a_500(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another request added the pair between the existence check and the flush: the unique
    constraint fires, the session rolls back and the retry updates the existing row."""
    world.service("owner").assign(world.domains["a"], ESP, return_path_host="old.a.example")
    hidden = {"left": 1}
    original_list = DomainEspRepository.list_for_domain
    original_get = DomainEspRepository._get

    def stale_list(self: DomainEspRepository, domain_id: object) -> Any:
        if hidden["left"]:
            return []
        return original_list(self, domain_id)

    def stale_get(self: DomainEspRepository, domain_id: int, esp_id: str) -> Any:
        if hidden["left"]:
            hidden["left"] -= 1
            return None
        return original_get(self, domain_id, esp_id)

    monkeypatch.setattr(DomainEspRepository, "list_for_domain", stale_list)
    monkeypatch.setattr(DomainEspRepository, "_get", stale_get)
    result = world.service("owner").assign(
        world.domains["a"], ESP, return_path_host="new.a.example"
    )
    assert not result.created
    assert result.record.return_path_host == "new.a.example"
    assert len(world.rows()) == 1


def test_persistent_integrity_error_is_a_conflict(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.service("owner").assign(world.domains["a"], ESP)
    monkeypatch.setattr(DomainEspRepository, "list_for_domain", lambda *_a: [])
    monkeypatch.setattr(DomainEspRepository, "_get", lambda *_a: None)
    with pytest.raises(EspConflict):
        world.service("owner").assign(world.domains["a"], ESP)
    assert len(world.rows()) == 1
    # The session is usable afterwards.
    monkeypatch.undo()
    assert world.service("owner").list_for_domain(world.domains["a"])[0].esp_id == ESP


# --- validation ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "esp_id", ["not-loaded", "EXAMPLE-ESP", "", " example-esp", "example-esp\x00", 7, None]
)
def test_esp_id_must_name_a_loaded_profile(world: World, esp_id: object) -> None:
    with pytest.raises(EspFieldInvalid) as caught:
        world.service("owner").assign(world.domains["a"], esp_id)
    assert (caught.value.field, caught.value.reason, caught.value.key) == (
        "esp_id",
        "unknown",
        "api.domain_esps.error.unknown_esp",
    )
    assert world.rows() == []


HOSTS = [
    ("return_path_host", "bounce.other.example", "not_in_domain", "host_outside_domain"),
    ("return_path_host", "evila.example", "not_in_domain", "host_outside_domain"),
    ("tracking_host", "tenantb-secret.example", "not_in_domain", "host_outside_domain"),
    ("tracking_host", "bücher.a.example", "not_ascii", "invalid_host"),
    ("tracking_host", "192.0.2.1", None, "invalid_host"),
    ("return_path_host", "a" * 300 + ".a.example", None, "invalid_host"),
    ("return_path_host", "bad\x00.a.example", None, "invalid_host"),
    ("return_path_host", "", None, "invalid_host"),
    ("tracking_host", 42, "not_a_string", "invalid_host"),
]


@pytest.mark.parametrize(("field", "value", "reason", "key"), HOSTS)
def test_hosts_are_validated_by_the_repository_rules(
    world: World, field: str, value: object, reason: str | None, key: str
) -> None:
    with pytest.raises(EspFieldInvalid) as caught:
        world.service("owner").assign(world.domains["a"], ESP, **{field: value})
    assert caught.value.field == field
    if reason is not None:
        assert caught.value.reason == reason
    assert caught.value.key == f"api.domain_esps.error.{key}"
    if value:
        assert str(value) not in str(caught.value)
    assert world.rows() == []


def test_invalid_host_on_update_keeps_the_stored_hosts(world: World) -> None:
    service = world.service("owner")
    service.assign(world.domains["a"], ESP, return_path_host="bounce.a.example")
    with pytest.raises(EspFieldInvalid):
        service.assign(world.domains["a"], ESP, return_path_host="bounce.other.example")
    assert world.rows()[0][3] == "bounce.a.example"


def test_cap_is_too_many(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    ids = [f"esp-{n}" for n in range(MAX_ESPS_PER_DOMAIN + 1)]
    profiles = [dataclasses.replace(PROFILES[0], id=i) for i in ids]
    service = DomainEspService(
        world.db,
        TenantContext(world.tenant_a, world.users["owner"]),
        world.principal("owner"),
        lambda: profiles,
    )
    for esp_id in ids[:-1]:
        service.assign(world.domains["a"], esp_id)
    with pytest.raises(EspFieldInvalid) as caught:
        service.assign(world.domains["a"], ids[-1])
    assert (caught.value.reason, caught.value.key) == ("too_many", "api.domain_esps.error.too_many")
    assert len(world.rows()) == MAX_ESPS_PER_DOMAIN


# --- remove -------------------------------------------------------------------------------------


@pytest.mark.parametrize("esp_id", ["other-esp", "not-loaded", "BAD", "", 3, None])
def test_remove_of_an_unassigned_pair_is_not_found(world: World, esp_id: object) -> None:
    world.service("owner").assign(world.domains["a"], ESP)
    with pytest.raises(EspNotFound):
        world.service("owner").remove(world.domains["a"], esp_id)
    assert len(world.rows()) == 1


def test_remove_works_for_a_profile_no_longer_loaded(world: World) -> None:
    world.service("owner").assign(world.domains["a"], ESP)
    gone = DomainEspService(
        world.db,
        TenantContext(world.tenant_a, world.users["owner"]),
        world.principal("owner"),
        lambda: (),
    )
    assert gone.list_for_domain(world.domains["a"])[0].esp_id == ESP
    gone.remove(world.domains["a"], ESP)
    assert world.rows() == []


def test_remove_of_another_tenants_assignment_is_not_found(world: World) -> None:
    world.b_service().assign(world.domains["b"], ESP, return_path_host=SECRET_HOST)
    with pytest.raises(EspNotFound):
        world.service("owner").remove(world.domains["b"], ESP)
    assert len(world.rows()) == 1


def test_field_key_table() -> None:
    assert field_key("esp_id", "unknown") == "api.domain_esps.error.unknown_esp"
    assert field_key("esp_id", "too_many") == "api.domain_esps.error.too_many"
    assert field_key("tracking_host", "not_in_domain").endswith("host_outside_domain")
    assert field_key("tracking_host", "too_long").endswith("invalid_host")


def test_audit_logs_ids_only(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO", logger="app.domain_esps")
    world.service("owner").assign(world.domains["a"], ESP, return_path_host="secret-rp.a.example")
    world.service("owner").remove(world.domains["a"], ESP)
    events = [r.__dict__.get("event") for r in caplog.records]
    assert events == ["domain_esps.created", "domain_esps.deleted"]
    assert "secret-rp" not in caplog.text
    assert all("secret-rp" not in str(r.__dict__) for r in caplog.records)


def test_row_count(world: World) -> None:
    """Sanity: the fixture starts empty (guards the row-based assertions above)."""
    assert int(world.db.scalar(select(func.count()).select_from(DomainEsp)) or 0) == 0


# --- broken profiles and domain runs (M6-06) ----------------------------------------------------


def _broken() -> Any:
    raise EspProfileError("profile directory not found")


def _unexpected() -> Any:
    raise AssertionError("profiles loaded for a domain without ESPs")


def _with_profiles(service: DomainEspService, source: Any) -> DomainEspService:
    service._profiles = source
    return service


@pytest.mark.parametrize("verb", ["catalogue", "names", "assign"])
def test_broken_profiles_raise_unavailable(
    world: World, verb: str, caplog: pytest.LogCaptureFixture
) -> None:
    """`names` is the profile lookup of the list route (the list itself reads only the DB)."""
    caplog.set_level("WARNING", logger="app.domain_esps")
    service = _with_profiles(world.service("owner"), _broken)
    with pytest.raises(EspProfilesUnavailable) as exc:
        if verb == "names":
            service.profile_names()
        else:
            _invoke(service, verb, world.domains["a"])
    assert (exc.value.status, exc.value.key) == (503, PROFILES_UNAVAILABLE_KEY)
    assert [r.__dict__.get("event") for r in caplog.records] == ["domain_esps.profiles_unreadable"]
    assert world.rows() == []


def test_broken_profiles_still_allow_remove(world: World) -> None:
    world.service("owner").assign(world.domains["a"], ESP)
    _with_profiles(world.service("owner"), _broken).remove(world.domains["a"], ESP)
    assert world.rows() == []


def _ctx(world: World, tenant: str = "a") -> TenantContext:
    if tenant == "b":
        return TenantContext(world.tenant_b, world.users["b_owner"])
    return TenantContext(world.tenant_a, world.users["owner"])


async def _run(run: EspRun, domain: str) -> CheckResult:
    ctx = CheckContext(resolver=_NxResolver())
    return await run.check.run(ctx, Target(domain=domain))


class _NxResolver:
    """Every name is NXDOMAIN: no network."""

    identity = "nx"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        return DnsResult(question=question, state=ResultState.nxdomain, rcode=3)


def test_run_without_assignment_never_loads_profiles(world: World) -> None:
    run = resolve_esp_run(_ctx(world), world.db, world.domains["a"], _unexpected)
    assert run.assigned is False
    assert run.check.id == "esp"


def test_run_of_tenant_a_never_sees_tenant_b_assignments(world: World) -> None:
    world.b_service().assign(world.domains["b"], ESP, return_path_host=SECRET_HOST)
    # Tenant A asking for tenant B's domain id gets nothing, not B's row.
    foreign = resolve_esp_run(_ctx(world), world.db, world.domains["b"], lambda: PROFILES)
    assert foreign.assigned is False
    own_a = resolve_esp_run(_ctx(world), world.db, world.domains["a"], lambda: PROFILES)
    assert own_a.assigned is False
    own_b = resolve_esp_run(_ctx(world, "b"), world.db, world.domains["b"], lambda: PROFILES)
    assert own_b.assigned is True


RUN_CASES = [
    # (assigned esp ids, profile source, expected code set, unavailable)
    ((ESP,), lambda: PROFILES, None, None),
    ((ESP, "gone-esp"), lambda: PROFILES, {"ESP_PROFILE_UNAVAILABLE"}, ["gone-esp"]),
    (("gone-esp",), lambda: PROFILES, {"ESP_PROFILE_UNAVAILABLE"}, ["gone-esp"]),
    ((ESP,), _broken, {"CHECK_INTERNAL_ERROR"}, None),
    ((ESP,), lambda: (*PROFILES, PROFILES[0]), None, None),  # duplicate from a raw source
]


@pytest.mark.parametrize(("esp_ids", "source", "codes", "unavailable"), RUN_CASES)
async def test_run_outcomes(
    world: World, esp_ids: tuple[str, ...], source: Any, codes: Any, unavailable: Any
) -> None:
    repo = DomainEspRepository(_ctx(world), world.db)
    for esp_id in esp_ids:
        repo.add(world.domains["a"], esp_id)
    world.db.commit()
    run = resolve_esp_run(_ctx(world), world.db, world.domains["a"], source)
    assert run.assigned is True
    result = await _run(run, "a.example")
    found = {f.code for f in result.findings}
    if codes is None:
        assert "ESP_PROFILE_UNAVAILABLE" not in found and "CHECK_INTERNAL_ERROR" not in found
    else:
        assert result.status == "error"
        assert codes <= found
    assert result.data.get("unavailable") == unavailable


def test_run_repository_failure_is_error(
    world: World, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class Broken:
        def list_for_domain(self, _domain_id: object) -> Any:
            raise OperationalError("SELECT", {}, Exception("connection lost"))

    class Repos:
        domain_esps = Broken()

    monkeypatch.setattr(service_module, "repo_for", lambda _ctx, _db: Repos())
    caplog.set_level("WARNING", logger="app.domain_esps")
    run = resolve_esp_run(_ctx(world), world.db, world.domains["a"], _unexpected)
    assert run.assigned is True
    assert "domain_esps.assignments_unreadable" in [r.__dict__.get("event") for r in caplog.records]


def test_run_real_statement_failure_leaves_rollback_to_the_caller(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real failed statement (no monkeypatched exception): the run is `error`-ready, and after
    the caller's rollback the session works again (on PostgreSQL the transaction was aborted)."""
    repo = DomainEspRepository(_ctx(world), world.db)
    repo.add(world.domains["a"], ESP)
    world.db.commit()

    def broken(self: DomainEspRepository, _domain_id: object) -> Any:
        return self._session.execute(text("SELECT * FROM m6_06c_no_such_table")).all()

    with monkeypatch.context() as patch:
        patch.setattr(DomainEspRepository, "list_for_domain", broken)
        failed = resolve_esp_run(_ctx(world), world.db, world.domains["a"], _unexpected)
    assert failed.assigned is True
    assert isinstance(failed.check, service_module._UnavailableEspCheck)
    world.db.rollback()
    again = resolve_esp_run(_ctx(world), world.db, world.domains["a"], lambda: PROFILES)
    assert again.assigned is True
    assert not isinstance(again.check, service_module._UnavailableEspCheck)


@pytest.mark.parametrize("lang", ["en", "it"])
def test_run_finding_keys_exist_in_both_languages(lang: str) -> None:
    for code in service_module.CODES:
        for part in ("title", "detail", "remediation"):
            key = f"finding.{code}.{part}"
            assert t(key, lang) != key
