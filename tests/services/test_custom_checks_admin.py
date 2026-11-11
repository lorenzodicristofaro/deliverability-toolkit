"""M5-23 custom checks admin service: authorization, scope, validation mapping, dry run, and the
custom checks of a domain run.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL. Fake resolvers only; no
network.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checks.custom import RUN_BUDGET_S
from app.checks.models import CheckContext, Target
from app.core.db import create_db_engine, create_session_factory
from app.core.permissions import MembershipGrant, Principal, RuleScope
from app.core.tenancy import TenantContext
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.models import CustomCheck, Domain, MembershipRole, Tenant, User
from app.repositories import GlobalCustomCheckRepository, repo_for
from app.services import custom_checks_admin as admin
from app.services.custom_checks_admin import (
    DUPLICATE_KEY,
    INVALID_DEFINITION_KEY,
    KIND_UNAVAILABLE_KEY,
    MAX_RUN_CUSTOM_CHECKS,
    NAME_TOO_LONG_KEY,
    CheckKeyConflict,
    CustomCheckFieldInvalid,
    CustomCheckNotFound,
    CustomChecksAdminError,
    CustomChecksAdminService,
    DomainRefused,
    ScopeForbidden,
    run_checks_for,
)
from tests.support.socket_guard import db_endpoint, install

GLOBAL = RuleScope.GLOBAL
TENANT = RuleScope.TENANT
TEXT = {"en": "Publish the record.", "it": "Pubblica il record."}
CATALOGUE_KEY = "api.rules.error.not_found"  # lowercase and present in en and it
NOW = datetime(2026, 11, 10, tzinfo=UTC)


def check(**overrides: Any) -> dict[str, Any]:
    return {
        "check_key": "acme.verify",
        "name": "Verification record",
        "kind": "dns_exists",
        "definition": {"name": "_acme.{domain}", "rrtype": "TXT"},
        "severity": "medium",
        "remediation_text": dict(TEXT),
        **overrides,
    }


@dataclass
class World:
    db: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]

    def principal(self, who: str) -> Principal:
        roles = {
            "owner": MembershipRole.OWNER,
            "admin": MembershipRole.ADMIN,
            "analyst": MembershipRole.ANALYST,
            "viewer": MembershipRole.CLIENT_VIEWER,
        }
        if who == "root":
            return Principal(self.users["root"], True, is_instance_admin=True)
        grant = MembershipGrant(self.tenant_a, roles[who], frozenset({self.domains["a"]}))
        return Principal(self.users[who], True, False, self.tenant_a, (grant,))

    def service(self, who: str) -> CustomChecksAdminService:
        ctx = None if who == "root" else TenantContext(self.tenant_a, self.users[who])
        return CustomChecksAdminService(self.db, ctx, self.principal(who))

    def b_service(self) -> CustomChecksAdminService:
        grant = MembershipGrant(self.tenant_b, MembershipRole.OWNER)
        principal = Principal(self.users["b_owner"], True, False, self.tenant_b, (grant,))
        ctx = TenantContext(self.tenant_b, self.users["b_owner"])
        return CustomChecksAdminService(self.db, ctx, principal)

    def rows(self) -> int:
        self.db.expire_all()
        return int(self.db.scalar(select(func.count()).select_from(CustomCheck)) or 0)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "custom checks admin", db_endpoint())


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
            "b": Domain(tenant_id=b.id, name="b.example"),
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
    """Records every repository, domain service or evaluator built by the service."""
    calls: list[str] = []

    def spy(name: str) -> Any:
        def build(*_a: Any, **_k: Any) -> Any:
            calls.append(name)
            raise AssertionError("reached after a denial")

        return build

    for name in ("repo_for", "GlobalCustomCheckRepository", "DomainService", "CustomDnsCheck"):
        monkeypatch.setattr(admin, name, spy(name))
    return calls


def dry(world: World, domain: str = "a", **overrides: Any) -> dict[str, Any]:
    body = {
        "domain_id": world.domains[domain],
        "kind": "dns_exists",
        "definition": {"name": "_acme.{domain}", "rrtype": "TXT"},
    }
    return {**body, **overrides}


# --- authorization -------------------------------------------------------------------------------

VERBS = ("list", "get", "create", "update", "delete", "test")


def _invoke(world: World, service: CustomChecksAdminService, verb: str, scope: RuleScope) -> Any:
    return {
        "list": lambda: service.list_checks(scope),
        "get": lambda: service.get_check(scope, 1),
        "create": lambda: service.create(scope, check()),
        "update": lambda: service.update(scope, 1, {"enabled": False}),
        "delete": lambda: service.delete(scope, 1),
        "test": lambda: service.prepare_test(dry(world)),
    }[verb]()


DENIED = [
    *[("analyst", TENANT, v, ScopeForbidden) for v in ("create", "update", "delete")],
    *[("viewer", TENANT, v, ScopeForbidden) for v in VERBS],
    *[
        (who, GLOBAL, v, ScopeForbidden)
        for who in ("owner", "admin", "analyst", "viewer")
        for v in VERBS
        if v != "test"
    ],
    # The instance admin flag adds nothing on a tenant path: there is no active tenant here.
    *[("root", TENANT, v, CustomCheckNotFound) for v in VERBS],
]


@pytest.mark.parametrize(("who", "scope", "verb", "error"), DENIED)
def test_denial_never_reaches_a_repository_dns_or_the_evaluator(
    world: World,
    repository_spy: list[str],
    who: str,
    scope: RuleScope,
    verb: str,
    error: type[CustomChecksAdminError],
) -> None:
    with pytest.raises(error):
        _invoke(world, world.service(who), verb, scope)
    assert repository_spy == []


@pytest.mark.parametrize("verb", VERBS)
def test_inactive_user_is_denied_before_any_repository(
    world: World, repository_spy: list[str], verb: str
) -> None:
    grant = MembershipGrant(world.tenant_a, MembershipRole.OWNER)
    principal = Principal(world.users["owner"], False, False, world.tenant_a, (grant,))
    ctx = TenantContext(world.tenant_a, world.users["owner"])
    with pytest.raises(ScopeForbidden):
        _invoke(world, CustomChecksAdminService(world.db, ctx, principal), verb, TENANT)
    assert repository_spy == []


@pytest.mark.parametrize("toggle", ["rules.manage", "rules.read"])
def test_feature_toggle_denies_before_any_repository(
    world: World, repository_spy: list[str], toggle: str
) -> None:
    grant = MembershipGrant(world.tenant_a, MembershipRole.OWNER, feature_toggles={toggle: False})
    principal = Principal(world.users["owner"], True, False, world.tenant_a, (grant,))
    service = CustomChecksAdminService(
        world.db, TenantContext(world.tenant_a, world.users["owner"]), principal
    )
    with pytest.raises(ScopeForbidden):
        if toggle == "rules.manage":
            service.create(TENANT, check())
        else:
            service.list_checks(TENANT)
    assert repository_spy == []


ALLOWED = [
    *[(who, TENANT, v) for who in ("owner", "admin") for v in VERBS],
    *[("analyst", TENANT, v) for v in ("list", "get", "test")],
    *[("root", GLOBAL, v) for v in VERBS if v != "test"],
]


@pytest.mark.parametrize(("who", "scope", "verb"), ALLOWED)
def test_allowed_verbs_per_role(world: World, who: str, scope: RuleScope, verb: str) -> None:
    writer = world.service("root" if scope is GLOBAL else "owner")
    target = writer.create(scope, check())
    service = world.service(who)
    if verb == "list":
        assert [r.id for r in service.list_checks(scope)] == [target.id]
    elif verb == "get":
        assert service.get_check(scope, target.id) == target
    elif verb == "create":
        assert service.create(scope, check(check_key="other")).scope == scope.value
    elif verb == "update":
        assert service.update(scope, target.id, {"enabled": False}).enabled is False
    elif verb == "delete":
        service.delete(scope, target.id)
        assert world.rows() == 0
    else:
        assert service.prepare_test(dry(world)).check.id == "custom:tenant:dry-run"


def test_stale_context_for_another_tenant_is_denied(
    world: World, repository_spy: list[str]
) -> None:
    ctx = TenantContext(world.tenant_b, world.users["owner"])
    service = CustomChecksAdminService(world.db, ctx, world.principal("owner"))
    with pytest.raises(ScopeForbidden):
        service.create(TENANT, check())
    with pytest.raises(ScopeForbidden):
        service.prepare_test(dry(world, "b"))
    assert repository_spy == []


# --- scope and tenancy ---------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin"])
def test_tenant_check_takes_its_tenant_from_the_context(world: World, who: str) -> None:
    record = world.service(who).create(TENANT, check())
    assert (record.scope, record.tenant_id, record.created_by) == (
        "tenant",
        world.tenant_a,
        world.users[who],
    )


@pytest.mark.parametrize("name", ["tenant_id", "scope", "id", "created_by", "updated_at"])
@pytest.mark.parametrize("verb", ["create", "update"])
def test_reserved_fields_are_rejected(world: World, verb: str, name: str) -> None:
    service = world.service("owner")
    target = service.create(TENANT, check())
    before = world.rows()
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        if verb == "create":
            service.create(TENANT, check(check_key="x", **{name: world.tenant_b}))
        else:
            service.update(TENANT, target.id, {name: world.tenant_b})
    assert (caught.value.field, caught.value.reason) == ("body", "unknown_field")
    assert caught.value.key == INVALID_DEFINITION_KEY
    assert world.rows() == before
    assert service.get_check(TENANT, target.id).tenant_id == world.tenant_a


@pytest.mark.parametrize("verb", ["get", "update", "delete"])
@pytest.mark.parametrize("target", ["foreign", "missing", "malformed", "out_of_range"])
def test_foreign_or_missing_check_is_not_found(world: World, verb: str, target: str) -> None:
    foreign = world.b_service().create(TENANT, check(name="B private"))
    check_id: object = {
        "foreign": foreign.id,
        "missing": 999_999,
        "malformed": None,
        "out_of_range": 2**31,
    }[target]
    service = world.service("owner")
    with pytest.raises(CustomCheckNotFound):
        if verb == "get":
            service.get_check(TENANT, check_id)
        elif verb == "update":
            service.update(TENANT, check_id, {"enabled": False})
        else:
            service.delete(TENANT, check_id)
    assert world.b_service().get_check(TENANT, foreign.id) == foreign


def test_tenant_lists_global_and_own_rows_only(world: World) -> None:
    own = world.service("owner").create(TENANT, check())
    shared = world.service("root").create(GLOBAL, check())
    world.b_service().create(TENANT, check(check_key="b.only"))
    assert {r.id for r in world.service("analyst").list_checks(TENANT)} == {own.id, shared.id}
    assert [r.id for r in world.service("root").list_checks(GLOBAL)] == [shared.id]


@pytest.mark.parametrize("verb", ["update", "delete"])
def test_tenant_path_cannot_change_a_global_check(world: World, verb: str) -> None:
    shared = world.service("root").create(GLOBAL, check())
    service = world.service("owner")
    with pytest.raises(ScopeForbidden):
        if verb == "update":
            service.update(TENANT, shared.id, {"enabled": False})
        else:
            service.delete(TENANT, shared.id)
    assert world.service("root").get_check(GLOBAL, shared.id) == shared


def test_global_path_does_not_reach_tenant_rows(world: World) -> None:
    own = world.service("owner").create(TENANT, check())
    with pytest.raises(CustomCheckNotFound):
        world.service("root").get_check(GLOBAL, own.id)


# --- validation ----------------------------------------------------------------------------------

INVALID = [
    ("bad template", {"definition": {"name": "{domain}.evil.example", "rrtype": "TXT"}}),
    ("unknown definition key", {"definition": {"name": "{domain}", "rrtype": "A", "x": 1}}),
    (
        "range on MX",
        {
            "kind": "dns_value_range",
            "definition": {"name": "{domain}", "rrtype": "MX", "min": 0, "max": 1},
        },
    ),
    (
        "bad regex",
        {
            "kind": "dns_matches",
            "definition": {"name": "{domain}", "rrtype": "TXT", "pattern": "(a"},
        },
    ),
    (
        "oversize regex",
        {
            "kind": "dns_matches",
            "definition": {"name": "{domain}", "rrtype": "TXT", "pattern": "a" * 1025},
        },
    ),
    ("unknown kind", {"kind": "glob"}),
    ("severity outside the schema", {"severity": "critical"}),
    ("no remediation", {"remediation_text": None}),
    ("one language", {"remediation_text": {"en": "x"}}),
    ("bad check key", {"check_key": "Upper Case"}),
    ("definition not an object", {"definition": ["x"]}),
    ("nul in name", {"name": "a\x00b"}),
]


@pytest.mark.parametrize(("case", "values"), INVALID, ids=[c[0] for c in INVALID])
def test_invalid_definition_is_422_and_stores_nothing(
    world: World, case: str, values: dict[str, Any]
) -> None:
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        world.service("owner").create(TENANT, check(**values))
    assert caught.value.key == INVALID_DEFINITION_KEY
    assert caught.value.status == 422
    assert world.rows() == 0


@pytest.mark.parametrize(
    "values",
    [
        {"kind": "http_fetch", "definition": {"url": "https://x.example"}},
        {"kind": "http_fetch", "definition": {}, "name": "n" * 500, "severity": "nope"},
    ],
)
@pytest.mark.parametrize("scope", [TENANT, GLOBAL])
def test_http_fetch_is_kind_unavailable(
    world: World, values: dict[str, Any], scope: RuleScope
) -> None:
    service = world.service("root" if scope is GLOBAL else "owner")
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        service.create(scope, check(**values))
    assert (caught.value.field, caught.value.key) == ("kind", KIND_UNAVAILABLE_KEY)
    target = service.create(scope, check())
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        service.update(scope, target.id, {"kind": "http_fetch"})
    assert caught.value.key == KIND_UNAVAILABLE_KEY
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        world.service("owner").prepare_test(dry(world, kind="http_fetch"))
    assert caught.value.key == KIND_UNAVAILABLE_KEY


def test_name_too_long_has_its_own_key(world: World) -> None:
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        world.service("owner").create(TENANT, check(name="n" * 201))
    assert (caught.value.field, caught.value.reason, caught.value.key) == (
        "name",
        "too_long",
        NAME_TOO_LONG_KEY,
    )


def test_update_revalidates_the_definition(world: World) -> None:
    service = world.service("owner")
    target = service.create(TENANT, check())
    with pytest.raises(CustomCheckFieldInvalid):
        service.update(TENANT, target.id, {"kind": "dns_matches"})  # pattern now required
    assert service.get_check(TENANT, target.id) == target


@pytest.mark.parametrize("scope", [TENANT, GLOBAL])
def test_duplicate_check_key_is_409(world: World, scope: RuleScope) -> None:
    service = world.service("root" if scope is GLOBAL else "owner")
    service.create(scope, check())
    with pytest.raises(CheckKeyConflict) as caught:
        service.create(scope, check())
    assert (caught.value.status, caught.value.key) == (409, DUPLICATE_KEY)


def test_same_key_in_global_and_tenant_scope_is_allowed(world: World) -> None:
    world.service("root").create(GLOBAL, check())
    world.service("owner").create(TENANT, check())
    world.b_service().create(TENANT, check())
    assert world.rows() == 3


# --- remediation key (M5-22 QA item 1) -----------------------------------------------------------


def test_tenant_cannot_set_a_remediation_key(world: World) -> None:
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        world.service("owner").create(
            TENANT, check(remediation_text=None, remediation_key=CATALOGUE_KEY)
        )
    assert caught.value.reason == "unknown_field"


@pytest.mark.parametrize(
    ("key", "reason"),
    [
        ("custom_check.missing.remediation", "unknown_key"),
        ("Bad.Key", "invalid_format"),
        (7, "not_a_string"),
    ],
)
def test_global_key_must_render(world: World, key: object, reason: str) -> None:
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        world.service("root").create(GLOBAL, check(remediation_text=None, remediation_key=key))
    assert (caught.value.field, caught.value.reason) == ("remediation_key", reason)
    assert world.rows() == 0


def test_global_key_only_row_carries_the_key_into_the_run(world: World) -> None:
    world.service("root").create(
        GLOBAL, check(remediation_text=None, remediation_key=CATALOGUE_KEY)
    )
    ctx = TenantContext(world.tenant_a, world.users["owner"])
    (custom,) = run_checks_for(ctx, world.db)
    result = asyncio.run(
        custom.run(CheckContext(resolver=Fake(ResultState.nxdomain)), Target(domain="a.example"))
    )
    assert result.status == "warn"
    assert result.findings[0].remediation_key == CATALOGUE_KEY


# --- domain run ----------------------------------------------------------------------------------


class Fake:
    identity = "fake"

    def __init__(self, state: ResultState = ResultState.ok, values: tuple[str, ...] = ()) -> None:
        self.state, self.values = state, values
        self.questions: list[DnsQuestion] = []

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.questions.append(question)
        records = tuple(DnsRecord(question.name, question.rdtype, 60, v) for v in self.values)
        return DnsResult(question, self.state, records)


def test_run_has_enabled_global_and_own_checks_only(world: World) -> None:
    world.service("root").create(GLOBAL, check(check_key="shared"))
    world.service("root").create(GLOBAL, check(check_key="off", enabled=False))
    world.service("owner").create(TENANT, check(check_key="own"))
    world.service("owner").create(TENANT, check(check_key="own.off", enabled=False))
    world.b_service().create(TENANT, check(check_key="b.secret"))
    ctx = TenantContext(world.tenant_a, None)
    assert [c.id for c in run_checks_for(ctx, world.db)] == [
        "custom:global:shared",
        "custom:tenant:own",
    ]
    b_ctx = TenantContext(world.tenant_b, None)
    assert [c.id for c in run_checks_for(b_ctx, world.db)] == [
        "custom:global:shared",
        "custom:tenant:b.secret",
    ]


def test_run_with_no_custom_checks_is_empty(world: World) -> None:
    assert run_checks_for(TenantContext(world.tenant_a, None), world.db) == []


def test_checks_past_the_cap_report_error_without_dns(world: World) -> None:
    repository = repo_for(TenantContext(world.tenant_a, world.users["owner"]), world.db)
    for n in range(MAX_RUN_CUSTOM_CHECKS + 3):
        repository.custom_checks.create(check(check_key=f"c{n:03d}"))
    world.db.commit()
    checks = run_checks_for(TenantContext(world.tenant_a, None), world.db)
    assert len(checks) == MAX_RUN_CUSTOM_CHECKS + 3
    dns = Fake(values=("x",))

    async def run_all() -> list[Any]:
        ctx = CheckContext(resolver=dns, clock=lambda: NOW)
        return [await c.run(ctx, Target(domain="a.example")) for c in checks]

    results = asyncio.run(run_all())
    assert [r.status for r in results[:MAX_RUN_CUSTOM_CHECKS]] == ["ok"] * MAX_RUN_CUSTOM_CHECKS
    assert [r.data["reason"] for r in results[MAX_RUN_CUSTOM_CHECKS:]] == [
        "run_budget_exceeded"
    ] * 3
    assert len(dns.questions) == MAX_RUN_CUSTOM_CHECKS


def test_run_checks_share_one_budget(world: World) -> None:
    world.service("root").create(GLOBAL, check(check_key="shared"))
    world.service("owner").create(TENANT, check(check_key="own"))
    first, second = run_checks_for(TenantContext(world.tenant_a, None), world.db)
    assert first._budget is second._budget
    assert first._budget.remaining() <= RUN_BUDGET_S


# --- dry run -------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin", "analyst"])
def test_dry_run_stores_nothing(world: World, who: str) -> None:
    prepared = world.service(who).prepare_test(dry(world))
    assert (prepared.tenant_id, prepared.domain_id, prepared.domain_name) == (
        world.tenant_a,
        world.domains["a"],
        "a.example",
    )
    assert world.rows() == 0


@pytest.mark.parametrize(
    ("domain_id", "status"),
    [
        ("b", 404),
        (999_999, 404),
        (2**31, 404),
        (True, 404),
        ("1", 404),
        (None, 404),
    ],
)
def test_dry_run_domain_must_be_visible(world: World, domain_id: object, status: int) -> None:
    value = world.domains["b"] if domain_id == "b" else domain_id
    with pytest.raises(DomainRefused) as caught:
        world.service("owner").prepare_test({**dry(world), "domain_id": value})
    assert (caught.value.status, caught.value.key) == (status, "api.error.not_found")


def test_dry_run_needs_check_run_on_the_domain(world: World) -> None:
    grant = MembershipGrant(
        world.tenant_a, MembershipRole.ANALYST, feature_toggles={"check.run": False}
    )
    principal = Principal(world.users["analyst"], True, False, world.tenant_a, (grant,))
    service = CustomChecksAdminService(
        world.db, TenantContext(world.tenant_a, world.users["analyst"]), principal
    )
    with pytest.raises(DomainRefused) as caught:
        service.prepare_test(dry(world))
    assert caught.value.status == 403


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"definition": {"name": "evil.example", "rrtype": "TXT"}}, "definition.name"),
        ({"definition": None}, "definition"),
        ({"severity": "critical"}, "severity"),
        ({"remediation_text": {"en": "only"}}, "remediation_text"),
        ({"tenant_id": 1}, "body"),
        ({"check_key": "x"}, "body"),
    ],
)
def test_dry_run_invalid_body_is_422(world: World, overrides: dict[str, Any], field: str) -> None:
    with pytest.raises(CustomCheckFieldInvalid) as caught:
        world.service("owner").prepare_test(dry(world, **overrides))
    assert caught.value.field == field


def test_dry_run_dns_failure_is_error(world: World) -> None:
    prepared = world.service("owner").prepare_test(dry(world))
    result = asyncio.run(
        prepared.check.run(
            CheckContext(resolver=Fake(ResultState.servfail)), Target(domain=prepared.domain_name)
        )
    )
    assert result.status == "error"
    assert result.data["reason"] == "dns_servfail"


# --- audit ---------------------------------------------------------------------------------------


def test_writes_are_audited_without_the_definition(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="app.rules")
    service = world.service("owner")
    secret = "_secret-marker.{domain}"
    record = service.create(TENANT, check(definition={"name": secret, "rrtype": "TXT"}))
    service.update(TENANT, record.id, {"enabled": False})
    service.delete(TENANT, record.id)
    events = [r.__dict__.get("event") for r in caplog.records]
    assert events == ["custom_checks.created", "custom_checks.updated", "custom_checks.deleted"]
    assert "secret-marker" not in caplog.text
    assert GlobalCustomCheckRepository(world.db).count() == 0
