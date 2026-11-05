"""M1 acceptance (TODO.md): named end-to-end tests for tenant isolation and client-viewer scope,
plus the session/switch guarantees and the single source of domain-restricted roles (M1-19 QA).

Uses the shared `world` from tests/tenancy/conftest.py (SQLite; PostgreSQL with
TEST_DATABASE_URL). No network.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest

from app.core import permissions
from app.core.permissions import Action, DomainResource, can, is_domain_restricted
from app.core.security import SESSION_COOKIE_NAME
from app.models import MembershipRole
from app.services.auth import SessionPolicy, resolve_session
from app.web import deps
from tests.tenancy.conftest import ROLES, World, leaks

ROOT = Path(__file__).resolve().parents[2]
ROW = re.compile(r'<tr data-domain-id="(\d+)">')


def _b_reads(w: World) -> list[str]:
    """Every read route addressing tenant B data by id."""
    reads = []
    for key in ("secret", "idn"):
        d = w.domains[key]
        reads += [
            f"/api/v1/domains/{d}",
            f"/domains/{d}",
            f"/domains/{d}/rename",
            f"/domains/{d}/delete",
        ]
    return reads


@pytest.mark.parametrize("role", ROLES)
def test_user_from_tenant_a_cannot_read_tenant_b_data(
    world: World, logs: pytest.LogCaptureFixture, role: str
) -> None:
    for tenant in ("a", "b"):  # own session, and a session forged to tenant B
        for path in _b_reads(world):
            response = world.send(role, "GET", path, tenant=tenant)
            assert response.status_code == 404, (tenant, path)
            assert leaks(world, response, logs) == [], (tenant, path)
        listing = world.send(role, "GET", "/api/v1/domains", tenant=tenant)
        landing = world.send(role, "GET", "/", tenant=tenant)
        assert landing.status_code == 200
        assert leaks(world, listing, logs) == []
        assert leaks(world, landing, logs) == []
        b_ids = {world.domains["secret"], world.domains["idn"]}
        if tenant == "a":
            assert listing.status_code == 200
            assert not {i["id"] for i in listing.json()["items"]} & b_ids
        else:
            assert listing.status_code == 404
        assert not {int(m) for m in ROW.findall(landing.text)} & b_ids


def test_client_viewer_limited_to_assigned_domains(
    world: World, logs: pytest.LogCaptureFixture
) -> None:
    assigned, unassigned = world.domains["assigned"], world.domains["unassigned"]
    listing = world.send("viewer", "GET", "/api/v1/domains")
    assert listing.status_code == 200
    assert [item["id"] for item in listing.json()["items"]] == [assigned]
    landing = world.send("viewer", "GET", "/")
    assert [int(m) for m in ROW.findall(landing.text)] == [assigned]
    assert "unassigned.example" not in landing.text
    assert "unassigned.example" not in listing.text
    assert world.send("viewer", "GET", f"/api/v1/domains/{assigned}").status_code == 200
    assert world.send("viewer", "GET", f"/domains/{assigned}").status_code == 200
    for path in (f"/api/v1/domains/{unassigned}", f"/domains/{unassigned}"):
        response = world.send("viewer", "GET", path)
        assert response.status_code == 404, path
        assert "unassigned.example" not in response.text
    assert leaks(world, landing, logs) == []
    # Analysts of the same tenant see both: the restriction is the viewer's role, not the data.
    analyst = world.send("analyst", "GET", "/api/v1/domains")
    assert {assigned, unassigned} <= {i["id"] for i in analyst.json()["items"]}


@pytest.mark.parametrize("role", ROLES)
def test_session_of_user_a_never_resolves_tenant_b_context(world: World, role: str) -> None:
    cookie = world.new_cookie(role, "b")
    resolved = resolve_session(
        world.db,
        cookie,
        world.settings.secret_key,
        policy=SessionPolicy.from_settings(world.settings),
    )
    assert resolved is not None and resolved.active_tenant_id == world.tenants["b"]
    auth = deps._build(world.db, world.user(role), resolved.session_id, resolved.active_tenant_id)
    assert auth.active_tenant_id is None
    assert auth.principal.active_tenant_id is None
    assert auth.principal.memberships == ()
    with pytest.raises(Exception) as excinfo:
        deps.tenant_ctx(auth)
    assert getattr(excinfo.value, "status_code", None) == 404
    for key in ("secret", "idn"):
        assert not can(
            auth.principal,
            Action.DOMAIN_READ,
            DomainResource(world.tenants["b"], world.domains[key]),
        )


@pytest.mark.parametrize("role", ROLES)
def test_switching_to_a_non_member_tenant_fails(
    world: World, logs: pytest.LogCaptureFixture, role: str
) -> None:
    cookie = world.new_cookie(role, "a")
    response = world.send(
        role,
        "POST",
        "/tenants/switch",
        fresh=True,
        form={"tenant_id": str(world.tenants["b"]), "next": "/"},
    )
    assert response.status_code == 404
    assert SESSION_COOKIE_NAME not in response.headers.get("set-cookie", "")
    assert leaks(world, response, logs) == []
    # The session the user already had still resolves tenant A, not B.
    resolved = resolve_session(
        world.db,
        cookie,
        world.settings.secret_key,
        policy=SessionPolicy.from_settings(world.settings),
    )
    assert resolved is not None and resolved.active_tenant_id == world.tenants["a"]


# --- domain-restricted roles: single source (M1-19 QA follow-up) ------------------------------


@pytest.mark.parametrize(
    ("role", "restricted"),
    [
        (MembershipRole.OWNER, False),
        (MembershipRole.ADMIN, False),
        (MembershipRole.ANALYST, False),
        (MembershipRole.CLIENT_VIEWER, True),
        ("client_viewer", True),
        ("analyst", False),
        # malformed / unknown: fail closed (treated as restricted)
        ("CLIENT_VIEWER", True),
        ("superuser", True),
        ("", True),
        (None, True),
        (1, True),
        (True, True),
        (object(), True),
    ],
)
def test_is_domain_restricted(role: Any, restricted: bool) -> None:
    assert is_domain_restricted(role) is restricted


def test_is_domain_restricted_matches_the_role_set() -> None:
    assert {r for r in MembershipRole if is_domain_restricted(r)} == set(
        permissions._DOMAIN_RESTRICTED_ROLES
    )


def test_deps_names_no_role_constant() -> None:
    tree = ast.parse((ROOT / "app" / "web" / "deps.py").read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "MembershipRole" not in names
    assert not {r.name for r in MembershipRole} & attrs


def test_deps_follows_the_restricted_role_set(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Making analysts domain-restricted in permissions.py alone changes what deps loads: the
    analyst (no DomainAccess rows) then reads no domain. Proves deps has no role of its own."""
    cookie = world.new_cookie("analyst", "a")
    resolved = resolve_session(
        world.db,
        cookie,
        world.settings.secret_key,
        policy=SessionPolicy.from_settings(world.settings),
    )
    assert resolved is not None
    a, d = world.tenants["a"], world.domains["unassigned"]
    analyst = world.user("analyst")
    before = deps._build(world.db, analyst, resolved.session_id, a)
    assert can(before.principal, Action.DOMAIN_READ, DomainResource(a, d))
    monkeypatch.setattr(
        permissions,
        "_DOMAIN_RESTRICTED_ROLES",
        frozenset({MembershipRole.CLIENT_VIEWER, MembershipRole.ANALYST}),
    )
    after = deps._build(world.db, analyst, resolved.session_id, a)
    assert after.principal.memberships[0].domain_ids == frozenset()
    assert not can(after.principal, Action.DOMAIN_READ, DomainResource(a, d))
