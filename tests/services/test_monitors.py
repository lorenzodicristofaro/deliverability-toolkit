"""M7-11 monitor target service: per-user DomainAccess enforced above the repository, the
permission order (404 before 403), the per-tenant cap, duplicates (also a lost race at flush),
the first `next_run_at`, the interval/next-run rule on update, and audit lines.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL. No network.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.permissions import MembershipGrant, Principal
from app.core.tenancy import TenantContext
from app.models import Domain, MembershipRole, MonitorTarget, Tenant, User
from app.repositories import repo_for
from app.repositories.monitor_targets import MonitorTargetRepository
from app.services.monitors import (
    MonitorConflict,
    MonitorExists,
    MonitorFieldInvalid,
    MonitorForbidden,
    MonitorNotFound,
    MonitorService,
    field_key,
)
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 17, 9, 0, tzinfo=UTC)
SECRET = "tenantb-secret.example"


class FixedClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value


@dataclass
class World:
    db: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]
    clock: FixedClock

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

    def service(
        self, who: str, toggles: dict[str, Any] | None = None, cap: int = 100
    ) -> MonitorService:
        ctx = None if who == "root" else TenantContext(self.tenant_a, self.users[who])
        return MonitorService(
            self.db, ctx, self.principal(who, toggles), max_targets=cap, clock=self.clock
        )

    def b_service(self) -> MonitorService:
        grant = MembershipGrant(self.tenant_b, MembershipRole.OWNER)
        principal = Principal(self.users["b_owner"], True, False, self.tenant_b, (grant,))
        ctx = TenantContext(self.tenant_b, self.users["b_owner"])
        return MonitorService(self.db, ctx, principal, max_targets=100, clock=self.clock)

    def rows(self) -> list[tuple[Any, ...]]:
        self.db.expire_all()
        found = self.db.execute(
            select(
                MonitorTarget.tenant_id,
                MonitorTarget.domain_id,
                MonitorTarget.check_ids,
                MonitorTarget.interval_seconds,
                MonitorTarget.enabled,
                MonitorTarget.next_run_at,
            ).order_by(MonitorTarget.id)
        ).all()
        self.db.rollback()
        return [tuple(r) for r in found]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "monitors service", db_endpoint())


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
            "a3": Domain(tenant_id=a.id, name="a3.example"),
            "b": Domain(tenant_id=b.id, name=SECRET),
        }
        db.add_all(domains.values())
        db.commit()
        yield World(
            db,
            a.id,
            b.id,
            {n: u.id for n, u in users.items()},
            {n: d.id for n, d in domains.items()},
            FixedClock(),
        )
    finally:
        db.close()
        engine.dispose()


def create(svc: MonitorService, domain_id: object, **overrides: Any) -> Any:
    fields: dict[str, Any] = {"check_ids": ["spf"], "interval_seconds": 3600, "enabled": True}
    fields.update(overrides)
    return svc.create(domain_id, **fields)


# --- authorization ------------------------------------------------------------------------------

ROLES = ("owner", "admin", "analyst", "viewer")


@pytest.mark.parametrize("who", ROLES)
def test_assigned_domain_read_for_every_role(world: World, who: str) -> None:
    create(world.service("owner"), world.domains["a"])
    assert world.service(who).get(world.domains["a"]).domain_id == world.domains["a"]


@pytest.mark.parametrize(
    ("who", "expected"),
    [("owner", None), ("admin", None), ("analyst", None), ("viewer", MonitorNotFound)],
)
def test_unassigned_domain_needs_domain_access(
    world: World, who: str, expected: type[Exception] | None
) -> None:
    create(world.service("owner"), world.domains["a2"])
    if expected is None:
        assert world.service(who).get(world.domains["a2"]).domain_id == world.domains["a2"]
    else:
        with pytest.raises(expected):
            world.service(who).get(world.domains["a2"])


@pytest.mark.parametrize("domain", ["a", "a2"])
def test_viewer_never_manages(world: World, domain: str) -> None:
    viewer = world.service("viewer", {"monitor.manage": True})
    expected = MonitorForbidden if domain == "a" else MonitorNotFound
    with pytest.raises(expected):
        create(viewer, world.domains[domain])
    assert world.rows() == []


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_foreign_domain_is_not_found_for_every_role(world: World, who: str) -> None:
    create(world.b_service(), world.domains["b"])
    before = world.rows()
    svc = world.service(who)
    for call in (
        lambda: svc.get(world.domains["b"]),
        lambda: create(svc, world.domains["b"]),
        lambda: svc.update(world.domains["b"], enabled=False),
        lambda: svc.delete(world.domains["b"]),
    ):
        with pytest.raises(MonitorNotFound):
            call()
    assert world.rows() == before
    assert svc.list_targets() == []


@pytest.mark.parametrize("raw", [None, 0, -1, True, "1", 1.0, 2**63, object()])
def test_malformed_domain_id_is_not_found(world: World, raw: object) -> None:
    with pytest.raises(MonitorNotFound):
        world.service("owner").get(raw)
    with pytest.raises(MonitorNotFound):
        create(world.service("owner"), raw)


def test_no_active_tenant_is_not_found(world: World) -> None:
    svc = world.service("root")
    with pytest.raises(MonitorNotFound):
        svc.list_targets()
    with pytest.raises(MonitorNotFound):
        create(svc, world.domains["a"])


def test_missing_domain_is_404_before_the_permission_403(world: World) -> None:
    """A role without monitor.read still gets 404 for a domain that does not exist."""
    svc = world.service("analyst", {"monitor.read": False})
    with pytest.raises(MonitorNotFound):
        svc.get(999_999)
    with pytest.raises(MonitorForbidden):
        svc.get(world.domains["a"])


@pytest.mark.parametrize(
    ("toggles", "read", "manage"),
    [
        ({"monitor.read": False}, MonitorForbidden, MonitorForbidden),
        ({"monitor.manage": False}, None, MonitorForbidden),
        ({"domain.read": False}, MonitorNotFound, MonitorNotFound),
        ({"check.run": False}, None, None),
        ({"monitor.read": True, "monitor.manage": True}, None, None),
    ],
)
def test_toggles(
    world: World,
    toggles: dict[str, Any],
    read: type[Exception] | None,
    manage: type[Exception] | None,
) -> None:
    create(world.service("owner"), world.domains["a"])
    svc = world.service("analyst", toggles)
    if read is None:
        assert svc.get(world.domains["a"]) is not None
    else:
        with pytest.raises(read):
            svc.get(world.domains["a"])
    if manage is None:
        assert svc.update(world.domains["a"], enabled=False).enabled is False
    else:
        with pytest.raises(manage):
            svc.update(world.domains["a"], enabled=False)


def test_list_filters_per_domain_access_and_toggles(world: World) -> None:
    for name in ("a", "a2"):
        create(world.service("owner"), world.domains[name])
    create(world.b_service(), world.domains["b"])

    def ids(svc: MonitorService) -> list[int]:
        return [r.domain_id for r in svc.list_targets()]

    assert ids(world.service("analyst")) == [world.domains["a"], world.domains["a2"]]
    assert ids(world.service("viewer")) == [world.domains["a"]]
    assert ids(world.service("viewer", {"monitor.read": False})) == []
    assert ids(world.service("analyst", {"domain.read": False})) == []
    with pytest.raises(MonitorForbidden):
        world.service("analyst", {"domain.list": False}).list_targets()


def test_authorization_happens_before_any_target_access(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    touched: list[str] = []
    for name in ("get_for_domain", "list", "create", "update", "delete"):
        original = getattr(MonitorTargetRepository, name)

        def spy(self: Any, *args: Any, _n: str = name, _o: Any = original, **kw: Any) -> Any:
            touched.append(_n)
            return _o(self, *args, **kw)

        monkeypatch.setattr(MonitorTargetRepository, name, spy)
    viewer = world.service("viewer")
    for call in (
        lambda: viewer.get(world.domains["a2"]),
        lambda: create(viewer, world.domains["a"]),
        lambda: viewer.update(world.domains["a"], enabled=False),
        lambda: viewer.delete(world.domains["a"]),
    ):
        with pytest.raises((MonitorNotFound, MonitorForbidden)):
            call()
    assert touched == []


# --- create -------------------------------------------------------------------------------------


def test_create_sets_first_run_now_and_commits(world: World) -> None:
    record = create(world.service("analyst"), world.domains["a"], check_ids=["spf", "dkim"])
    assert record.next_run_at == NOW
    assert record.check_ids == ("dkim", "spf")
    assert world.rows()[0][:5] == (world.tenant_a, world.domains["a"], ["dkim", "spf"], 3600, True)


def test_duplicate_is_typed(world: World) -> None:
    create(world.service("owner"), world.domains["a"])
    with pytest.raises(MonitorExists) as exc:
        create(world.service("admin"), world.domains["a"], interval_seconds=86400)
    assert exc.value.status == 409 and exc.value.key == "monitor.error.exists"
    assert len(world.rows()) == 1


def test_lost_race_at_flush_is_typed(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """Another request creates the target between the existence check and the insert."""
    original = MonitorTargetRepository.create

    def racing(self: Any, domain_id: object, **kw: Any) -> Any:
        # The other writer's row is committed; this insert then fails on the unique domain.
        row = MonitorTarget(
            tenant_id=world.tenant_a,
            domain_id=domain_id,
            check_ids=["dmarc"],
            interval_seconds=3600,
            enabled=True,
            next_run_at=NOW,
        )
        world.db.add(row)
        world.db.flush()
        world.db.commit()
        world.db.expunge_all()
        monkeypatch.setattr(MonitorTargetRepository, "create", original)
        raise IntegrityError("insert", {}, Exception("unique"))

    monkeypatch.setattr(MonitorTargetRepository, "create", racing)
    with pytest.raises(MonitorExists):
        create(world.service("owner"), world.domains["a"])
    assert [r[2] for r in world.rows()] == [["dmarc"]]


def test_integrity_error_without_a_target_is_a_conflict(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(self: Any, domain_id: object, **kw: Any) -> Any:
        raise IntegrityError("insert", {}, Exception("fk"))

    monkeypatch.setattr(MonitorTargetRepository, "create", failing)
    with pytest.raises(MonitorConflict):
        create(world.service("owner"), world.domains["a"])
    assert world.rows() == []


def test_domain_gone_before_insert_is_not_found(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MonitorTargetRepository, "create", lambda self, d, **kw: None)
    with pytest.raises(MonitorNotFound):
        create(world.service("owner"), world.domains["a"])


@pytest.mark.parametrize(
    ("fields", "field", "reason", "key"),
    [
        ({"interval_seconds": 60}, "interval_seconds", "not_allowed", "invalid_interval"),
        ({"interval_seconds": "3600"}, "interval_seconds", "not_an_int", "invalid_interval"),
        ({"interval_seconds": True}, "interval_seconds", "not_an_int", "invalid_interval"),
        ({"check_ids": ["custom:tenant:x"]}, "check_ids", "unknown_check", "unknown_check"),
        ({"check_ids": []}, "check_ids", "empty", "invalid_checks"),
        ({"check_ids": "spf"}, "check_ids", "not_a_list", "invalid_checks"),
        ({"check_ids": [1]}, "check_ids", "not_a_string", "invalid_checks"),
        ({"check_ids": ["spf", "spf"]}, "check_ids", "duplicate", "invalid_checks"),
        ({"enabled": "yes"}, "enabled", "not_a_bool", None),
    ],
)
def test_rejected_values(
    world: World, fields: dict[str, Any], field: str, reason: str, key: str | None
) -> None:
    with pytest.raises(MonitorFieldInvalid) as exc:
        create(world.service("owner"), world.domains["a"], **fields)
    assert (exc.value.field, exc.value.reason) == (field, reason)
    assert exc.value.key == (f"monitor.error.{key}" if key else "api.error.invalid_request")
    assert "custom:tenant" not in str(exc.value)
    assert world.rows() == []


def test_cap_counts_the_tenant_only(world: World) -> None:
    create(world.b_service(), world.domains["b"])
    owner = world.service("owner", cap=2)
    create(owner, world.domains["a"])
    create(owner, world.domains["a2"])
    with pytest.raises(MonitorFieldInvalid) as exc:
        create(owner, world.domains["a3"])
    assert (exc.value.field, exc.value.reason, exc.value.key) == (
        "target",
        "limit_reached",
        "monitor.error.limit_reached",
    )
    assert len(world.rows()) == 3


def test_lowering_the_cap_removes_nothing(world: World) -> None:
    for name in ("a", "a2"):
        create(world.service("owner"), world.domains[name])
    owner = world.service("owner", cap=1)
    with pytest.raises(MonitorFieldInvalid):
        create(owner, world.domains["a3"])
    assert len(owner.list_targets()) == 2
    assert owner.update(world.domains["a"], enabled=False).enabled is False


# --- update / delete ----------------------------------------------------------------------------


def _with_next_run(world: World, at: datetime) -> None:
    repo = repo_for(TenantContext(world.tenant_a, None), world.db).monitor_targets
    current = repo.get_for_domain(world.domains["a"])
    assert current is not None
    repo.update(current.id, next_run_at=at)
    world.db.commit()


@pytest.mark.parametrize(
    ("planned", "interval", "expected"),
    [
        # shorter: pulled forward to now + new interval
        (NOW + timedelta(days=1), 3600, NOW + timedelta(hours=1)),
        # already sooner than now + interval: kept
        (NOW + timedelta(minutes=5), 3600, NOW + timedelta(minutes=5)),
        # overdue: kept (the scheduler picks it up at once)
        (NOW - timedelta(hours=2), 3600, NOW - timedelta(hours=2)),
        # longer: kept
        (NOW + timedelta(hours=1), 86400, NOW + timedelta(hours=1)),
        # unchanged interval: kept
        (NOW + timedelta(days=1), 43200, NOW + timedelta(days=1)),
    ],
)
def test_interval_change_moves_next_run_only_forward(
    world: World, planned: datetime, interval: int, expected: datetime
) -> None:
    create(world.service("owner"), world.domains["a"], interval_seconds=43200)
    _with_next_run(world, planned)
    record = world.service("analyst").update(world.domains["a"], interval_seconds=interval)
    assert record.next_run_at == expected
    assert record.interval_seconds == interval


def test_invalid_interval_on_update_changes_nothing(world: World) -> None:
    create(world.service("owner"), world.domains["a"])
    before = world.rows()
    for bad in (7200, 10**30, -1, 3600.0, None):
        with pytest.raises(MonitorFieldInvalid):
            world.service("owner").update(world.domains["a"], interval_seconds=bad)
    assert world.rows() == before


def test_update_rejects_fields_outside_the_api(world: World) -> None:
    create(world.service("owner"), world.domains["a"])
    before = world.rows()
    for name in ("next_run_at", "last_status", "last_run_at", "domain_id", "tenant_id"):
        with pytest.raises(MonitorFieldInvalid) as exc:
            world.service("owner").update(world.domains["a"], **{name: None})
        assert exc.value.reason == "unknown_field"
    assert world.rows() == before


def test_update_and_delete_without_target_are_not_found(world: World) -> None:
    with pytest.raises(MonitorNotFound):
        world.service("owner").update(world.domains["a"], enabled=False)
    with pytest.raises(MonitorNotFound):
        world.service("owner").delete(world.domains["a"])


def test_delete_removes_only_that_target(world: World) -> None:
    create(world.service("owner"), world.domains["a"])
    create(world.service("owner"), world.domains["a2"])
    create(world.b_service(), world.domains["b"])
    world.service("analyst").delete(world.domains["a"])
    assert [r[1] for r in world.rows()] == [world.domains["a2"], world.domains["b"]]


# --- audit and keys -----------------------------------------------------------------------------


def test_writes_are_logged_without_values(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.monitors")
    svc = world.service("analyst")
    record = create(svc, world.domains["a"])
    svc.update(world.domains["a"], enabled=False)
    svc.delete(world.domains["a"])
    events = [(r.event, r.actor, r.domain_id, r.target_id) for r in caplog.records]  # type: ignore[attr-defined]
    assert events == [
        (f"monitors.{e}", world.users["analyst"], world.domains["a"], record.id)
        for e in ("created", "updated", "deleted")
    ]
    assert "spf" not in caplog.text and SECRET not in caplog.text


def test_refused_writes_are_not_logged(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.monitors")
    with pytest.raises(MonitorForbidden):
        create(world.service("viewer"), world.domains["a"])
    with pytest.raises(MonitorFieldInvalid):
        create(world.service("owner"), world.domains["a"], interval_seconds=1)
    assert caplog.records == []


@pytest.mark.parametrize(
    ("field", "reason", "key"),
    [
        ("check_ids", "unknown_check", "monitor.error.unknown_check"),
        ("check_ids", "empty", "monitor.error.invalid_checks"),
        ("check_ids", "anything", "monitor.error.invalid_checks"),
        ("interval_seconds", "not_allowed", "monitor.error.invalid_interval"),
        ("target", "limit_reached", "monitor.error.limit_reached"),
        ("target", "other", "api.error.invalid_request"),
        ("enabled", "not_a_bool", "api.error.invalid_request"),
        ("", "", "api.error.invalid_request"),
    ],
)
def test_field_key(field: str, reason: str, key: str) -> None:
    assert field_key(field, reason) == key
    for lang in ("en", "it"):
        assert t(key, lang) != key
