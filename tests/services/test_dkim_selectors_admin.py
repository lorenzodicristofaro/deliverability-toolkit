"""M5-20 DKIM selectors admin service: authorization, seed semantics, audit.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL. No network.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app.core.db import create_db_engine, create_session_factory
from app.core.permissions import MembershipGrant, Principal, RuleScope
from app.core.tenancy import TenantContext
from app.models import MembershipRole, Tenant, User
from app.models.dkim_selector import DkimSelector
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.repositories.dkim_selectors import _DkimSelectorStore
from app.services import dkim_selectors_admin as admin
from app.services.dkim_selectors_admin import (
    DkimSelectorsAdminService,
    ScopeForbidden,
    SeededSelectorNotDeletable,
    SelectorConflict,
    SelectorFieldInvalid,
    SelectorNotFound,
)
from app.services.seed_sync import sync_dkim_selectors
from tests.support.socket_guard import db_endpoint, install

SEED_KEY = "selector1"
SECRET = "SECRET-NOTE-7301"
GLOBAL = RuleScope.GLOBAL
TENANT = RuleScope.TENANT


@dataclass
class World:
    db: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]

    def principal(self, who: str) -> Principal:
        roles = {
            "owner": MembershipRole.OWNER,
            "admin": MembershipRole.ADMIN,
            "analyst": MembershipRole.ANALYST,
            "viewer": MembershipRole.CLIENT_VIEWER,
        }
        if who == "root":
            return Principal(self.users["root"], True, is_instance_admin=True)
        grant = MembershipGrant(self.tenant_a, roles[who])
        return Principal(self.users[who], True, False, self.tenant_a, (grant,))

    def service(self, who: str) -> DkimSelectorsAdminService:
        ctx = None if who == "root" else TenantContext(self.tenant_a, self.users[who])
        return DkimSelectorsAdminService(self.db, ctx, self.principal(who))

    def b_service(self) -> DkimSelectorsAdminService:
        grant = MembershipGrant(self.tenant_b, MembershipRole.OWNER)
        principal = Principal(self.users["b_owner"], True, False, self.tenant_b, (grant,))
        ctx = TenantContext(self.tenant_b, self.users["b_owner"])
        return DkimSelectorsAdminService(self.db, ctx, principal)

    def seeded(self) -> Any:
        self.db.expire_all()
        for record in GlobalDkimSelectorRepository(self.db).list_seeded():
            if record.seed_key == SEED_KEY:
                return record
        raise AssertionError("seeded selector missing")

    def rows(self) -> int:
        self.db.expire_all()
        return int(self.db.scalar(select(func.count()).select_from(DkimSelector)) or 0)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "dkim selectors admin", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str) -> Iterator[World]:
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        a, b = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        names = ("owner", "admin", "analyst", "viewer", "root", "b_owner")
        users = {n: User(email=f"{n}@example.com") for n in names}
        db.add_all([a, b, *users.values()])
        db.commit()
        sync_dkim_selectors(db)
        db.commit()
        yield World(db, a.id, b.id, {n: u.id for n, u in users.items()})
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def repository_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fails the test if the service builds a repository."""
    calls: list[str] = []

    def spy(name: str) -> Any:
        def build(*_a: Any, **_k: Any) -> Any:
            calls.append(name)
            raise AssertionError("the repository was reached after a denial")

        return build

    monkeypatch.setattr(admin, "repo_for", spy("repo_for"))
    monkeypatch.setattr(admin, "GlobalDkimSelectorRepository", spy("global"))
    return calls


# --- authorization -------------------------------------------------------------------------------

VERBS = ("list", "get", "create", "update", "delete")


def _invoke(service: DkimSelectorsAdminService, verb: str, scope: RuleScope) -> Any:
    return {
        "list": lambda: service.list_selectors(scope),
        "get": lambda: service.get_selector(scope, 1),
        "create": lambda: service.create(scope, {"selector": "x"}),
        "update": lambda: service.update(scope, 1, {"notes": "x"}),
        "delete": lambda: service.delete(scope, 1),
    }[verb]()


DENIED = [
    *[("analyst", TENANT, v, ScopeForbidden) for v in ("create", "update", "delete")],
    *[("viewer", TENANT, v, ScopeForbidden) for v in VERBS],
    *[(who, GLOBAL, v, ScopeForbidden) for who in ("owner", "admin", "analyst") for v in VERBS],
    # The instance admin flag adds nothing on a tenant path: there is no active tenant here.
    *[("root", TENANT, v, SelectorNotFound) for v in VERBS],
]


@pytest.mark.parametrize(("who", "scope", "verb", "error"), DENIED)
def test_denied_before_any_repository(
    world: World,
    repository_spy: list[str],
    who: str,
    scope: RuleScope,
    verb: str,
    error: type[Exception],
) -> None:
    with pytest.raises(error):
        _invoke(world.service(who), verb, scope)
    assert repository_spy == []


@pytest.mark.parametrize("who", ["owner", "admin", "analyst"])
def test_tenant_readers_see_global_and_own_rows(world: World, who: str) -> None:
    mine = world.service("owner").create(TENANT, {"selector": "mine"})
    world.b_service().create(TENANT, {"selector": "theirs"})
    names = {r.selector for r in world.service(who).list_selectors(TENANT, limit=1000)}
    assert {"mine", SEED_KEY} <= names
    assert "theirs" not in names
    assert world.service(who).get_selector(TENANT, mine.id).id == mine.id


@pytest.mark.parametrize("verb", ["get", "update", "delete"])
def test_foreign_tenant_row_is_not_found(world: World, verb: str) -> None:
    foreign = world.b_service().create(TENANT, {"selector": "theirs", "notes": SECRET})
    before = world.rows()
    service = world.service("owner")
    with pytest.raises(SelectorNotFound):
        if verb == "get":
            service.get_selector(TENANT, foreign.id)
        elif verb == "update":
            service.update(TENANT, foreign.id, {"notes": "stolen"})
        else:
            service.delete(TENANT, foreign.id)
    assert world.rows() == before
    assert world.b_service().get_selector(TENANT, foreign.id).notes == SECRET


@pytest.mark.parametrize("bad_id", [None, 0, -1, "1", 2**31, True])
def test_malformed_id_is_not_found(world: World, bad_id: object) -> None:
    with pytest.raises(SelectorNotFound):
        world.service("owner").get_selector(TENANT, bad_id)


def test_global_scope_reaches_only_global_rows(world: World) -> None:
    tenant_row = world.service("owner").create(TENANT, {"selector": "mine"})
    root = world.service("root")
    assert {r.scope for r in root.list_selectors(GLOBAL, limit=1000)} == {"global"}
    with pytest.raises(SelectorNotFound):
        root.get_selector(GLOBAL, tenant_row.id)
    with pytest.raises(SelectorNotFound):
        root.update(GLOBAL, tenant_row.id, {"notes": "x"})
    with pytest.raises(SelectorNotFound):
        root.delete(GLOBAL, tenant_row.id)


@pytest.mark.parametrize("verb", ["update", "delete"])
def test_tenant_path_write_to_a_global_row_is_forbidden(world: World, verb: str) -> None:
    target = world.seeded()
    service = world.service("owner")
    with pytest.raises(ScopeForbidden):
        if verb == "update":
            service.update(TENANT, target.id, {"notes": "x"})
        else:
            service.delete(TENANT, target.id)
    assert world.seeded() == target


def test_tenant_id_comes_from_the_context(world: World) -> None:
    record = world.service("owner").create(TENANT, {"selector": "mine"})
    assert (record.scope, record.tenant_id) == ("tenant", world.tenant_a)
    assert record.created_by == world.users["owner"]


@pytest.mark.parametrize(
    "smuggled",
    ["scope", "tenant_id", "seed_key", "locally_modified", "status", "sources", "verified_on"],
)
@pytest.mark.parametrize("who_scope", [("owner", TENANT), ("root", GLOBAL)])
def test_body_cannot_set_reserved_fields(
    world: World, who_scope: tuple[str, RuleScope], smuggled: str
) -> None:
    who, scope = who_scope
    before = world.rows()
    with pytest.raises(SelectorFieldInvalid) as exc:
        world.service(who).create(scope, {"selector": "mine", smuggled: "x"})
    assert (exc.value.field, exc.value.reason) == ("body", "unknown_field")
    assert world.rows() == before


# --- validation ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "field", "reason", "key"),
    [
        ({"selector": ""}, "selector", "empty", "invalid_selector"),
        ({"selector": None}, "selector", "not_a_string", "invalid_selector"),
        ({"selector": 5}, "selector", "not_a_string", "invalid_selector"),
        ({"selector": "a.b"}, "selector", "not_a_label", "invalid_selector"),
        ({"selector": "UPPER"}, "selector", "invalid_label", "invalid_selector"),
        ({"selector": "caffè"}, "selector", "invalid_label", "invalid_selector"),
        ({"selector": "a b"}, "selector", "invalid_label", "invalid_selector"),
        ({"selector": " a"}, "selector", "whitespace", "invalid_selector"),
        ({"selector": "a\x00b"}, "selector", "nul", "invalid_selector"),
        ({"selector": "a\ud800"}, "selector", "surrogate", "invalid_selector"),
        ({"selector": "a\nb"}, "selector", "control_char", "invalid_selector"),
        ({"selector": "a" * 64}, "selector", "too_long", "too_long"),
        ({"notes": "x"}, "selector", "required", "invalid_selector"),
        ({"selector": "ok", "provider": "x" * 65}, "provider", "too_long", "too_long"),
        (
            {"selector": "ok", "provider": "Not A Slug"},
            "provider",
            "invalid_format",
            "invalid_field",
        ),
        ({"selector": "ok", "provider": "a\x00"}, "provider", "nul", "invalid_field"),
        ({"selector": "ok", "provider": "\udfff"}, "provider", "surrogate", "invalid_field"),
        ({"selector": "ok", "notes": "x" * 501}, "notes", "too_long", "too_long"),
        ({"selector": "ok", "notes": ""}, "notes", "empty", "invalid_field"),
        ({"selector": "ok", "notes": "a\x00b"}, "notes", "nul", "invalid_field"),
        ({"selector": "ok", "notes": "\ud83d"}, "notes", "surrogate", "invalid_field"),
        ({"selector": "ok", "record_type": "mx"}, "record_type", "invalid_choice", "invalid_field"),
        ({"selector": "ok", "record_type": []}, "record_type", "invalid_choice", "invalid_field"),
        ({"selector": "ok", "enabled": "yes"}, "enabled", "not_a_bool", "invalid_field"),
        ({"selector": "ok", "enabled": None}, "enabled", "not_a_bool", "invalid_field"),
        ({}, "body", "empty", "invalid_field"),
    ],
)
@pytest.mark.parametrize("who_scope", [("owner", TENANT), ("root", GLOBAL)])
def test_create_validation(
    world: World,
    who_scope: tuple[str, RuleScope],
    data: dict[str, Any],
    field: str,
    reason: str,
    key: str,
) -> None:
    who, scope = who_scope
    before = world.rows()
    with pytest.raises(SelectorFieldInvalid) as exc:
        world.service(who).create(scope, data)
    assert (exc.value.field, exc.value.reason) == (field, reason)
    assert exc.value.key == f"api.dkim_selectors.error.{key}"
    assert world.rows() == before


def test_update_validation_leaves_the_row_alone(world: World) -> None:
    record = world.service("owner").create(TENANT, {"selector": "mine", "notes": "keep"})
    for data in ({"notes": "a\x00"}, {"selector": "a.b"}, {}, {"tenant_id": 1}):
        with pytest.raises(SelectorFieldInvalid):
            world.service("owner").update(TENANT, record.id, data)
    assert world.service("owner").get_selector(TENANT, record.id).notes == "keep"


def test_duplicate_in_the_same_scope_conflicts(world: World) -> None:
    service = world.service("owner")
    other = service.create(TENANT, {"selector": "other"})
    service.create(TENANT, {"selector": "mine"})
    before = world.rows()
    with pytest.raises(SelectorConflict):
        service.create(TENANT, {"selector": "mine"})
    with pytest.raises(SelectorConflict):
        service.update(TENANT, other.id, {"selector": "mine"})
    with pytest.raises(SelectorConflict):
        world.service("root").create(GLOBAL, {"selector": SEED_KEY})
    assert world.rows() == before


def test_same_selector_is_allowed_in_other_scopes(world: World) -> None:
    world.service("owner").create(TENANT, {"selector": SEED_KEY})
    world.b_service().create(TENANT, {"selector": SEED_KEY})


# --- seed semantics ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [{"enabled": False}, {"notes": "local note"}, {"enabled": False, "notes": "both"}],
)
def test_global_edit_sets_locally_modified_and_survives_sync(
    world: World, change: dict[str, Any]
) -> None:
    target = world.seeded()
    assert target.locally_modified is False
    updated = world.service("root").update(GLOBAL, target.id, change)
    assert updated.locally_modified is True
    sync_dkim_selectors(world.db)
    world.db.commit()
    after = world.seeded()
    assert after.locally_modified is True
    for name, value in change.items():
        assert getattr(after, name) == value


def test_identical_edit_still_sets_locally_modified(world: World) -> None:
    target = world.seeded()
    updated = world.service("root").update(GLOBAL, target.id, {"enabled": target.enabled})
    assert updated.locally_modified is True


def test_edit_of_an_unseeded_global_row_sets_locally_modified(world: World) -> None:
    root = world.service("root")
    created = root.create(GLOBAL, {"selector": "instance-only"})
    assert created.locally_modified is False
    assert root.update(GLOBAL, created.id, {"notes": "x"}).locally_modified is True


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ({"selector": "renamed"}, "selector"),
        ({"provider": "other_provider"}, "provider"),
        ({"record_type": "txt"}, "record_type"),
    ],
)
def test_seed_managed_field_of_a_seeded_row_is_refused(
    world: World, change: dict[str, Any], field: str
) -> None:
    target = world.seeded()
    with pytest.raises(SelectorFieldInvalid) as exc:
        world.service("root").update(GLOBAL, target.id, {**change, "notes": "x"})
    assert (exc.value.field, exc.value.reason) == (field, "seed_managed")
    assert world.seeded() == target


def test_resending_the_seed_managed_values_is_accepted(world: World) -> None:
    target = world.seeded()
    updated = world.service("root").update(
        GLOBAL,
        target.id,
        {
            "selector": target.selector,
            "provider": target.provider,
            "record_type": target.record_type,
            "notes": "edited",
        },
    )
    assert updated.notes == "edited"
    assert updated.selector == target.selector


def test_unseeded_global_row_can_change_every_field(world: World) -> None:
    root = world.service("root")
    created = root.create(GLOBAL, {"selector": "instance-only"})
    updated = root.update(
        GLOBAL,
        created.id,
        {"selector": "renamed", "provider": "acme", "record_type": "txt"},
    )
    assert (updated.selector, updated.provider, updated.record_type) == ("renamed", "acme", "txt")


def test_seeded_row_cannot_be_deleted(world: World) -> None:
    target = world.seeded()
    with pytest.raises(SeededSelectorNotDeletable):
        world.service("root").delete(GLOBAL, target.id)
    assert world.seeded() == target


def test_unseeded_global_and_tenant_rows_are_deleted(world: World) -> None:
    root = world.service("root")
    created = root.create(GLOBAL, {"selector": "instance-only"})
    root.delete(GLOBAL, created.id)
    with pytest.raises(SelectorNotFound):
        root.get_selector(GLOBAL, created.id)
    owner = world.service("owner")
    mine = owner.create(TENANT, {"selector": "mine"})
    owner.delete(TENANT, mine.id)
    with pytest.raises(SelectorNotFound):
        owner.get_selector(TENANT, mine.id)


# --- concurrency and audit -----------------------------------------------------------------------


@pytest.mark.parametrize("verb", ["update", "delete"])
def test_stale_row_is_not_found(world: World, monkeypatch: pytest.MonkeyPatch, verb: str) -> None:
    record = world.service("owner").create(TENANT, {"selector": "mine"})

    def stale(*_a: Any, **_k: Any) -> Any:
        raise StaleDataError("row went away")

    monkeypatch.setattr(_DkimSelectorStore, verb, stale)
    with pytest.raises(SelectorNotFound):
        if verb == "update":
            world.service("owner").update(TENANT, record.id, {"notes": "x"})
        else:
            world.service("owner").delete(TENANT, record.id)


def test_concurrent_delete_on_update_is_not_found(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = world.service("owner").create(TENANT, {"selector": "mine"})
    monkeypatch.setattr(_DkimSelectorStore, "update", lambda *_a, **_k: None)
    with pytest.raises(SelectorNotFound):
        world.service("owner").update(TENANT, record.id, {"notes": "x"})


def test_concurrent_delete_on_delete_is_not_found(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = world.service("owner").create(TENANT, {"selector": "mine"})
    monkeypatch.setattr(_DkimSelectorStore, "delete", lambda *_a, **_k: False)
    with pytest.raises(SelectorNotFound):
        world.service("owner").delete(TENANT, record.id)


def test_audit_logs_actor_id_and_scope_only(world: World, caplog: pytest.LogCaptureFixture) -> None:
    service = world.service("owner")
    with caplog.at_level(logging.INFO, logger="app.dkim_selectors"):
        record = service.create(TENANT, {"selector": "secret-sel", "notes": SECRET})
        service.update(TENANT, record.id, {"notes": f"{SECRET}-2"})
        service.delete(TENANT, record.id)
    events = [r for r in caplog.records if r.name == "app.dkim_selectors"]
    assert [r.event for r in events] == [
        "dkim_selectors.created",
        "dkim_selectors.updated",
        "dkim_selectors.deleted",
    ]
    for entry in events:
        assert entry.actor == world.users["owner"]
        assert entry.selector_id == record.id
        assert entry.selector_scope == "tenant"
    assert SECRET not in caplog.text
    assert "secret-sel" not in caplog.text


def test_repository_path_stays_tenant_scoped(world: World) -> None:
    """The rows written through the service are reachable only by their own tenant's repository."""
    record = world.service("owner").create(TENANT, {"selector": "mine"})
    other = repo_for(TenantContext(world.tenant_b, world.users["b_owner"]), world.db).dkim_selectors
    assert other.get(record.id) is None
