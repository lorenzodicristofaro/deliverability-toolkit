"""M7-11 monitor target routes through the real app and middleware: `/api/v1/monitors` and
`/api/v1/domains/{id}/monitor`.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role, per-verb table, toggles, error
bodies, the per-tenant cap and the wire format. No network.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1._common import MAX_BODY_BYTES
from app.api.v1.monitors import monitor_clock
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import Domain, Membership, MonitorTarget, User
from app.repositories import repo_for
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _seed, call
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 17, 9, 30, tzinfo=UTC)
LIST = "/api/v1/monitors"
BODY = {"check_ids": ["spf", "dmarc"], "interval_seconds": 86400}
NOT_FOUND = {"detail": t("monitor.error.not_found", "en")}
FORBIDDEN = {"detail": t("api.error.forbidden", "en")}
INVALID = {"detail": t("api.error.invalid_request", "en")}
CAP = 3


class _FixedClock:
    def now(self) -> datetime:
        return NOW


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "monitors API", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    root = User(email="root@example.com", is_instance_admin=True)
    db.add(root)
    db.commit()
    users["root"] = root.id
    settings = Settings(
        database_url=migrated_db_url,
        secret_key=KEY,
        encryption_key=KEY,
        monitor_max_targets_per_tenant=CAP,
    )
    application = create_app(settings)
    application.dependency_overrides[monitor_clock] = _FixedClock
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- helpers ------------------------------------------------------------------------------------


def rows(db: Session) -> list[tuple[Any, ...]]:
    """Ground truth: every monitor target (all tenants)."""
    db.expire_all()
    db.rollback()
    found = db.execute(
        select(
            MonitorTarget.tenant_id,
            MonitorTarget.domain_id,
            MonitorTarget.check_ids,
            MonitorTarget.interval_seconds,
            MonitorTarget.enabled,
        ).order_by(MonitorTarget.id)
    ).all()
    db.rollback()
    return [tuple(r) for r in found]


def one(w: World, domain: str = "assigned") -> str:
    return f"/api/v1/domains/{w.domains[domain]}/monitor"


def seed_target(w: World, domain: str = "assigned", tenant: str = "a") -> int:
    """A target written straight through the tenant repository (not through the API)."""
    ctx = TenantContext(w.tenant_id(tenant), None)
    record = repo_for(ctx, w.db).monitor_targets.create(
        w.domains[domain],
        check_ids=["spf"],
        interval_seconds=3600,
        next_run_at=NOW + timedelta(hours=1),
    )
    assert record is not None
    w.db.commit()
    return record.id


def extra_domain(w: World, name: str, tenant: str = "a") -> int:
    domain = Domain(tenant_id=w.tenant_id(tenant), name=name)
    w.db.add(domain)
    w.db.commit()
    w.domains[name] = domain.id
    return domain.id


def set_toggles(w: World, who: str, toggles: dict[str, Any]) -> None:
    membership = w.db.scalars(select(Membership).where(Membership.user_id == w.users[who])).one()
    membership.feature_toggles = toggles
    w.db.commit()


def assert_problem(response: Any, key: str, field: str, reason: str) -> None:
    assert response.status_code == 422, response.text
    assert response.json()["detail"] == {
        "key": key,
        "message": t(key, "en"),
        "field": field,
        "reason": reason,
    }


# --- roles and verbs ----------------------------------------------------------------------------

# "root" is an instance admin with no membership in tenant A: no active tenant, so 404.
READ = {"anon": 401, "owner": 200, "admin": 200, "analyst": 200, "viewer": 200, "root": 404}
MANAGE = {"anon": 401, "owner": 0, "admin": 0, "analyst": 0, "viewer": 403, "root": 404}


@pytest.mark.parametrize(("who", "status"), READ.items())
def test_list_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "GET", LIST)
    assert response.status_code == status
    if status == 404:
        assert response.json() == NOT_FOUND


@pytest.mark.parametrize(("who", "status"), READ.items())
def test_get_per_role(world: World, who: str, status: int) -> None:
    seed_target(world)
    response = call(world, who, "GET", one(world))
    assert response.status_code == status
    if status == 200:
        assert response.json()["domain_id"] == world.domains["assigned"]


@pytest.mark.parametrize(("who", "status"), MANAGE.items())
def test_create_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "POST", one(world), json=BODY)
    assert response.status_code == (status or 201)
    assert len(rows(world.db)) == (1 if status == 0 else 0)


@pytest.mark.parametrize(("who", "status"), MANAGE.items())
def test_update_per_role(world: World, who: str, status: int) -> None:
    seed_target(world)
    before = rows(world.db)
    response = call(world, who, "PATCH", one(world), json={"enabled": False})
    assert response.status_code == (status or 200)
    after = rows(world.db)
    assert after == before if status else after[0][4] is False


@pytest.mark.parametrize(("who", "status"), MANAGE.items())
def test_delete_per_role(world: World, who: str, status: int) -> None:
    seed_target(world)
    response = call(world, who, "DELETE", one(world))
    assert response.status_code == (status or 204)
    assert len(rows(world.db)) == (0 if status == 0 else 1)


def test_viewer_write_is_403_with_the_forbidden_body(world: World) -> None:
    seed_target(world)
    for method, body in (("POST", BODY), ("PATCH", {"enabled": False}), ("DELETE", None)):
        response = call(world, "viewer", method, one(world), json=body)
        assert response.status_code == 403
        assert response.json() == FORBIDDEN
    assert len(rows(world.db)) == 1


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
def test_viewer_unassigned_domain_is_404(world: World, method: str) -> None:
    seed_target(world, "unassigned")
    before = rows(world.db)
    response = call(world, "viewer", method, one(world, "unassigned"), json=BODY)
    assert response.status_code == 404
    assert response.json() == NOT_FOUND
    assert rows(world.db) == before


def test_viewer_list_shows_assigned_domains_only(world: World) -> None:
    seed_target(world, "assigned")
    seed_target(world, "unassigned")
    viewer = call(world, "viewer", "GET", LIST).json()["items"]
    assert [i["domain_id"] for i in viewer] == [world.domains["assigned"]]
    analyst = call(world, "analyst", "GET", LIST).json()["items"]
    assert {i["domain_id"] for i in analyst} == {
        world.domains["assigned"],
        world.domains["unassigned"],
    }


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_foreign_domain_is_404_and_unchanged(world: World, method: str, who: str) -> None:
    seed_target(world, "other", tenant="b")
    before = rows(world.db)
    response = call(world, who, method, one(world, "other"), json=BODY)
    assert response.status_code == 404
    assert response.json() == NOT_FOUND
    assert B_SECRET_NAME not in response.text
    assert rows(world.db) == before


def test_foreign_target_never_listed(world: World) -> None:
    seed_target(world, "other", tenant="b")
    for who in ("owner", "admin", "analyst", "viewer"):
        assert call(world, who, "GET", LIST).json() == {"items": []}
    b_items = call(world, "b_owner", "GET", LIST, tenant="b").json()["items"]
    assert [i["domain_id"] for i in b_items] == [world.domains["other"]]


@pytest.mark.parametrize("method", ["LIST", "GET", "POST", "PATCH", "DELETE"])
def test_session_in_a_foreign_tenant_gets_404(world: World, method: str) -> None:
    """Owner of A with a session whose active tenant is B (not a member there)."""
    seed_target(world)
    before = rows(world.db)
    verb, path = ("GET", LIST) if method == "LIST" else (method, one(world))
    response = call(world, "owner", verb, path, json=BODY, tenant="b")
    assert response.status_code == 404
    assert response.json() == NOT_FOUND
    assert rows(world.db) == before


def test_tenant_comes_from_the_session(world: World) -> None:
    """A tenant_id in the body is an unknown field (422), never a way to address tenant B."""
    response = call(world, "owner", "POST", one(world), json={**BODY, "tenant_id": world.tenant_b})
    assert response.status_code == 422
    assert response.json() == INVALID
    assert rows(world.db) == []


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "1.5", "99999999999999999999", "%C2%B2"])
@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
def test_malformed_domain_id_is_a_404(world: World, method: str, raw: str) -> None:
    response = call(world, "owner", method, f"/api/v1/domains/{raw}/monitor", json=BODY)
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


def test_missing_target_is_404(world: World) -> None:
    for method in ("GET", "PATCH", "DELETE"):
        response = call(world, "owner", method, one(world), json={"enabled": True})
        assert response.status_code == 404
        assert response.json() == NOT_FOUND


# --- toggles ------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_monitor_read_toggle_off_denies_everything(world: World, who: str) -> None:
    seed_target(world)
    set_toggles(world, who, {"monitor.read": False})
    before = rows(world.db)
    assert call(world, who, "GET", LIST).json() == {"items": []}
    for method, body in (
        ("GET", None),
        ("POST", BODY),
        ("PATCH", {"enabled": False}),
        ("DELETE", None),
    ):
        response = call(world, who, method, one(world), json=body)
        assert response.status_code == 403, method
        assert response.json() == FORBIDDEN
    assert rows(world.db) == before


@pytest.mark.parametrize("who", ["owner", "admin", "analyst"])
def test_monitor_manage_toggle_off_denies_writes_only(world: World, who: str) -> None:
    seed_target(world)
    set_toggles(world, who, {"monitor.manage": False})
    before = rows(world.db)
    assert call(world, who, "GET", one(world)).status_code == 200
    assert len(call(world, who, "GET", LIST).json()["items"]) == 1
    for method, body in (("POST", BODY), ("PATCH", {"enabled": False}), ("DELETE", None)):
        assert call(world, who, method, one(world), json=body).status_code == 403, method
    assert rows(world.db) == before


def test_viewer_manage_toggle_true_grants_nothing(world: World) -> None:
    set_toggles(world, "viewer", {"monitor.manage": True, "monitor.read": True})
    assert call(world, "viewer", "POST", one(world), json=BODY).status_code == 403
    assert rows(world.db) == []


def test_check_run_toggle_does_not_switch_off_monitoring(world: World) -> None:
    set_toggles(world, "analyst", {"check.run": False})
    assert call(world, "analyst", "POST", one(world), json=BODY).status_code == 201


def test_domain_read_toggle_off_is_404(world: World) -> None:
    seed_target(world)
    set_toggles(world, "analyst", {"domain.read": False})
    response = call(world, "analyst", "GET", one(world))
    assert response.status_code == 404
    assert call(world, "analyst", "GET", LIST).json() == {"items": []}


# --- CSRF and auth ------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE"])
def test_mutation_without_csrf_is_refused(world: World, method: str) -> None:
    seed_target(world, "unassigned")
    before = rows(world.db)
    response = call(world, "owner", method, one(world, "unassigned"), json=BODY, csrf=False)
    assert response.status_code == 403
    assert response.json() == {"detail": t("csrf.invalid", "en")}
    assert rows(world.db) == before


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE"])
def test_anonymous_mutation_is_refused(world: World, method: str) -> None:
    assert call(world, "anon", method, one(world), json=BODY, csrf=False).status_code == 403
    assert call(world, "anon", method, one(world), json=BODY).status_code == 401
    assert rows(world.db) == []


def test_denied_caller_gets_403_whatever_the_body(world: World) -> None:
    response = call(world, "viewer", "POST", one(world), content=b"{not json")
    assert response.status_code == 403


def test_missing_domain_with_malformed_body_is_404(world: World) -> None:
    response = call(world, "owner", "POST", "/api/v1/domains/999999/monitor", content=b"{x")
    assert response.status_code == 404


# --- create / update / delete round trip --------------------------------------------------------


def test_round_trip_and_wire_format(world: World) -> None:
    created = call(world, "analyst", "POST", one(world), json=BODY)
    assert created.status_code == 201
    payload = created.json()
    assert set(payload) == {
        "id",
        "domain_id",
        "check_ids",
        "interval_seconds",
        "enabled",
        "next_run_at",
        "last_run_at",
        "last_status",
        "created_at",
        "updated_at",
    }
    assert payload["domain_id"] == world.domains["assigned"]
    assert payload["check_ids"] == ["dmarc", "spf"]  # stored sorted
    assert payload["interval_seconds"] == 86400
    assert payload["enabled"] is True
    assert payload["next_run_at"] == NOW.isoformat()  # first run due at once
    assert payload["last_run_at"] is None and payload["last_status"] is None
    assert "tenant" not in created.text
    assert call(world, "viewer", "GET", one(world)).json() == payload
    assert call(world, "owner", "GET", LIST).json() == {"items": [payload]}

    patched = call(world, "owner", "PATCH", one(world), json={"check_ids": ["dnsbl"]})
    assert patched.status_code == 200
    assert patched.json()["check_ids"] == ["dnsbl"]
    assert patched.json()["interval_seconds"] == 86400  # untouched
    assert call(world, "admin", "DELETE", one(world)).status_code == 204
    assert rows(world.db) == []
    assert call(world, "owner", "GET", one(world)).status_code == 404


def test_create_disabled(world: World) -> None:
    response = call(world, "owner", "POST", one(world), json={**BODY, "enabled": False})
    assert response.status_code == 201
    assert response.json()["enabled"] is False


def test_duplicate_create_is_a_typed_409(world: World) -> None:
    assert call(world, "owner", "POST", one(world), json=BODY).status_code == 201
    before = rows(world.db)
    response = call(world, "admin", "POST", one(world), json={**BODY, "interval_seconds": 3600})
    assert response.status_code == 409
    assert response.json() == {"detail": t("monitor.error.exists", "en")}
    assert rows(world.db) == before


def test_shorter_interval_pulls_the_next_run_forward(world: World) -> None:
    created = call(world, "owner", "POST", one(world), json=BODY).json()
    # Move the planned slot far away, as the scheduler's claim would.
    later = NOW + timedelta(days=1)
    ctx = TenantContext(world.tenant_a, None)
    repo_for(ctx, world.db).monitor_targets.update(created["id"], next_run_at=later)
    world.db.commit()
    shorter = call(world, "owner", "PATCH", one(world), json={"interval_seconds": 3600}).json()
    assert shorter["next_run_at"] == (NOW + timedelta(hours=1)).isoformat()
    longer = call(world, "owner", "PATCH", one(world), json={"interval_seconds": 43200}).json()
    assert longer["next_run_at"] == shorter["next_run_at"]  # a longer interval keeps the slot


def test_empty_patch_changes_nothing(world: World) -> None:
    seed_target(world)
    before = rows(world.db)
    response = call(world, "owner", "PATCH", one(world), json={})
    assert response.status_code == 200
    assert rows(world.db) == before


# --- validation ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "key", "field", "reason"),
    [
        (
            {"check_ids": ["spf"], "interval_seconds": 60},
            "monitor.error.invalid_interval",
            "interval_seconds",
            "not_allowed",
        ),
        (
            {"check_ids": ["spf"], "interval_seconds": 7200},
            "monitor.error.invalid_interval",
            "interval_seconds",
            "not_allowed",
        ),
        (
            {"check_ids": ["spf"], "interval_seconds": 10**30},
            "monitor.error.invalid_interval",
            "interval_seconds",
            "not_allowed",
        ),
        (
            {"check_ids": ["nope"], "interval_seconds": 3600},
            "monitor.error.unknown_check",
            "check_ids",
            "unknown_check",
        ),
        (
            {"check_ids": ["custom:tenant:x"], "interval_seconds": 3600},
            "monitor.error.unknown_check",
            "check_ids",
            "unknown_check",
        ),
        (
            {"check_ids": ["esp"], "interval_seconds": 3600},
            "monitor.error.unknown_check",
            "check_ids",
            "unknown_check",
        ),
        (
            {"check_ids": [], "interval_seconds": 3600},
            "monitor.error.invalid_checks",
            "check_ids",
            "empty",
        ),
        (
            {"check_ids": ["spf", "spf"], "interval_seconds": 3600},
            "monitor.error.invalid_checks",
            "check_ids",
            "duplicate",
        ),
    ],
)
def test_rejected_fields_have_the_problem_shape(
    world: World, body: dict[str, Any], key: str, field: str, reason: str
) -> None:
    response = call(world, "owner", "POST", one(world), json=body)
    assert_problem(response, key, field, reason)
    assert "nope" not in response.text and "custom:tenant" not in response.text
    assert rows(world.db) == []


def test_patch_rejects_bad_fields_and_changes_nothing(world: World) -> None:
    seed_target(world)
    before = rows(world.db)
    response = call(world, "owner", "PATCH", one(world), json={"interval_seconds": 1})
    assert_problem(response, "monitor.error.invalid_interval", "interval_seconds", "not_allowed")
    response = call(world, "owner", "PATCH", one(world), json={"check_ids": ["zzz"]})
    assert_problem(response, "monitor.error.unknown_check", "check_ids", "unknown_check")
    assert rows(world.db) == before


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b"null",
        b'{"check_ids": ["spf"]}',
        b'{"interval_seconds": 3600}',
        b'{"check_ids": "spf", "interval_seconds": 3600}',
        b'{"check_ids": [1], "interval_seconds": 3600}',
        b'{"check_ids": ["spf"], "interval_seconds": "3600"}',
        b'{"check_ids": ["spf"], "interval_seconds": 3600.0}',
        b'{"check_ids": ["spf"], "interval_seconds": true}',
        b'{"check_ids": ["spf"], "interval_seconds": NaN}',
        b'{"check_ids": ["spf"], "interval_seconds": 3600, "enabled": "yes"}',
        b'{"check_ids": ["spf"], "interval_seconds": 3600, "enabled": 1}',
        b'{"check_ids": ["spf"], "interval_seconds": 3600, "next_run_at": "2020-01-01"}',
        b'{"check_ids": ["spf"], "interval_seconds": 3600, "interval_seconds": 86400}',
        b'{"check_ids": ["spf"], "interval_seconds": 3600, "domain_id": 1}',
        b"\xff\xfe",
    ],
)
def test_malformed_create_bodies_are_422(world: World, raw: bytes) -> None:
    response = call(world, "owner", "POST", one(world), content=raw)
    assert response.status_code == 422
    assert response.json() == INVALID
    assert rows(world.db) == []


def test_too_many_check_ids_is_422(world: World) -> None:
    body = {"check_ids": [f"c{i}" for i in range(65)], "interval_seconds": 3600}
    response = call(world, "owner", "POST", one(world), json=body)
    assert response.status_code == 422
    assert response.json() == INVALID


@pytest.mark.parametrize(
    "raw",
    [
        b'{"enabled": null}',
        b'{"check_ids": null}',
        b'{"interval_seconds": null}',
        b'{"enabled": "false"}',
        b'{"last_status": "ok"}',
        b'{"next_run_at": "2020-01-01T00:00:00Z"}',
        b"[]",
    ],
)
def test_malformed_patch_bodies_are_422(world: World, raw: bytes) -> None:
    seed_target(world)
    before = rows(world.db)
    response = call(world, "owner", "PATCH", one(world), content=raw)
    assert response.status_code == 422
    assert response.json() == INVALID
    assert rows(world.db) == before


def test_non_json_content_type_is_415(world: World) -> None:
    response = call(
        world,
        "owner",
        "POST",
        one(world),
        content=b"x",
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 415


def test_oversized_body_is_413(world: World) -> None:
    raw = b'{"check_ids": ["' + b"a" * (MAX_BODY_BYTES + 1) + b'"], "interval_seconds": 3600}'
    response = call(world, "owner", "POST", one(world), content=raw)
    assert response.status_code == 413
    assert rows(world.db) == []


# --- per-tenant cap -----------------------------------------------------------------------------


def test_cap_is_enforced_per_tenant(world: World) -> None:
    names = [f"cap{i}.example" for i in range(CAP + 1)]
    for name in names:
        extra_domain(world, name)
    for name in names[:CAP]:
        assert call(world, "owner", "POST", one(world, name), json=BODY).status_code == 201
    response = call(world, "owner", "POST", one(world, names[CAP]), json=BODY)
    assert_problem(response, "monitor.error.limit_reached", "target", "limit_reached")
    assert len(rows(world.db)) == CAP
    # Tenant B has its own budget.
    assert (
        call(world, "b_owner", "POST", one(world, "other"), json=BODY, tenant="b").status_code
        == 201
    )
    # Removing one frees a slot.
    assert call(world, "owner", "DELETE", one(world, names[0])).status_code == 204
    assert call(world, "owner", "POST", one(world, names[CAP]), json=BODY).status_code == 201


def test_duplicate_wins_over_the_cap(world: World) -> None:
    """At the cap, re-creating an existing target still answers the typed 409."""
    names = [f"cap{i}.example" for i in range(CAP)]
    for name in names:
        extra_domain(world, name)
        assert call(world, "owner", "POST", one(world, name), json=BODY).status_code == 201
    response = call(world, "owner", "POST", one(world, names[0]), json=BODY)
    assert response.status_code == 409


# --- i18n ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["en", "it"])
def test_keys_exist_in_both_languages(lang: str) -> None:
    for key in (
        "monitor.error.not_found",
        "monitor.error.exists",
        "monitor.error.limit_reached",
        "monitor.error.invalid_interval",
        "monitor.error.unknown_check",
        "monitor.error.invalid_checks",
        "permission.monitor.read",
        "permission.monitor.manage",
    ):
        assert t(key, lang) != key


def test_errors_are_localized(world: World) -> None:
    response = call(world, "owner", "GET", one(world), headers={"Accept-Language": "it"})
    assert response.status_code == 404
    assert response.json() == {"detail": t("monitor.error.not_found", "it")}
