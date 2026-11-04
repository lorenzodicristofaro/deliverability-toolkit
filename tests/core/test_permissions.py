"""M1-11 permission layer. The expected matrix below is written out by hand from SPEC section 3
and ARCHITECTURE section 4 (not derived from app code) and expanded over every principal kind x
action x resource situation. No DB, no network."""

import itertools
from types import MappingProxyType
from typing import Any

import pytest

from app.core.permissions import (
    Action,
    DomainResource,
    InstanceResource,
    MembershipGrant,
    PermissionDenied,
    Principal,
    TenantResource,
    can,
    principal_from_models,
    require,
)
from app.models import DomainAccess, Membership, MembershipRole, User

A, B = 1, 2  # active tenant A, other tenant B
ASSIGNED, UNASSIGNED = 10, 11  # domains in tenant A; the viewer is assigned only ASSIGNED

SITUATIONS: dict[str, object] = {
    "instance": InstanceResource(),
    "own_tenant": TenantResource(A),
    "other_tenant": TenantResource(B),
    "own_assigned_domain": DomainResource(A, ASSIGNED),
    "own_unassigned_domain": DomainResource(A, UNASSIGNED),
    # Same domain id as an assigned one, but in tenant B: must never pass.
    "other_tenant_domain": DomainResource(B, ASSIGNED),
}

ACT = Action
TENANT_LEVEL = {"own_tenant"}
DOMAIN_ALL = {"own_assigned_domain", "own_unassigned_domain"}

# role -> {action: allowed situations}; missing action means denied everywhere.
ROLE_EXPECTED: dict[str, dict[Action, set[str]]] = {
    "owner": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.TENANT_MANAGE: TENANT_LEVEL,
        ACT.USER_MANAGE: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_CREATE: TENANT_LEVEL,
        ACT.DOMAIN_READ: DOMAIN_ALL,
        ACT.DOMAIN_UPDATE: DOMAIN_ALL,
        ACT.DOMAIN_DELETE: DOMAIN_ALL,
    },
    "admin": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.USER_MANAGE: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_CREATE: TENANT_LEVEL,
        ACT.DOMAIN_READ: DOMAIN_ALL,
        ACT.DOMAIN_UPDATE: DOMAIN_ALL,
        ACT.DOMAIN_DELETE: DOMAIN_ALL,
    },
    "analyst": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_READ: DOMAIN_ALL,
    },
    "client_viewer": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_READ: {"own_assigned_domain"},
    },
    "none": {},
}
INSTANCE_ADMIN_EXTRA: dict[Action, set[str]] = {ACT.INSTANCE_MANAGE: {"instance"}}


def _grant(role: str, tenant: int = A, toggles: dict[str, Any] | None = None) -> MembershipGrant:
    return MembershipGrant(
        tenant_id=tenant,
        role=MembershipRole(role),
        domain_ids=frozenset({ASSIGNED}),
        feature_toggles=MappingProxyType(toggles or {}),
    )


def _principal(role: str, *, admin: bool = False, active: bool = True) -> Principal:
    # Every principal also holds a membership in B (agency scenario) with the same role, so
    # cross-tenant denial is tested against a user who IS a member of B, just not active there.
    memberships = () if role == "none" else (_grant(role, A), _grant(role, B))
    return Principal(
        user_id=1,
        is_active=active,
        is_instance_admin=admin,
        active_tenant_id=A,
        memberships=memberships,
    )


def _expected(role: str, admin: bool, active: bool, action: Action, situation: str) -> bool:
    if not active:
        return False
    allowed = dict(ROLE_EXPECTED[role])
    if admin:
        allowed |= INSTANCE_ADMIN_EXTRA
    return situation in allowed.get(action, set())


MATRIX = [
    pytest.param(
        role, admin, active, action, situation, id=f"{role}-{admin=}-{active=}-{action}-{situation}"
    )
    for role, admin, active, action, situation in itertools.product(
        ROLE_EXPECTED, (False, True), (True, False), list(Action), SITUATIONS
    )
]


def test_matrix_size() -> None:
    # 5 role kinds x admin flag x active flag x 9 actions x 6 situations.
    assert len(MATRIX) == 5 * 2 * 2 * 9 * 6 == 1080


@pytest.mark.parametrize(("role", "admin", "active", "action", "situation"), MATRIX)
def test_matrix(role: str, admin: bool, active: bool, action: Action, situation: str) -> None:
    principal = _principal(role, admin=admin, active=active)
    resource = SITUATIONS[situation]
    expected = _expected(role, admin, active, action, situation)
    assert can(principal, action, resource) is expected
    assert can(principal, action.value, resource) is expected  # string form behaves the same
    if expected:
        require(principal, action, resource)
    else:
        with pytest.raises(PermissionDenied) as exc:
            require(principal, action, resource)
        assert exc.value.code == "permission_denied"


def test_action_list_is_the_m1_set() -> None:
    assert {a.value for a in Action} == {
        "tenant.read",
        "tenant.manage",
        "user.manage",
        "domain.list",
        "domain.read",
        "domain.create",
        "domain.update",
        "domain.delete",
        "instance.manage",
    }


@pytest.mark.parametrize(
    "action",
    [
        "domain.run_check",
        "",
        "DOMAIN.READ",
        " domain.read",
        "admin",
        None,
        1,
        object(),
        b"tenant.read",
    ],
)
def test_unknown_or_malformed_action_denied(action: object) -> None:
    owner = _principal("owner", admin=True)
    for resource in SITUATIONS.values():
        assert can(owner, action, resource) is False


@pytest.mark.parametrize(
    "resource",
    [
        None,
        "own_tenant",
        A,
        {"tenant_id": A},
        TenantResource(0),
        TenantResource(-1),
        TenantResource(True),  # type: ignore[arg-type]
        TenantResource("1"),  # type: ignore[arg-type]
        DomainResource(A, 0),
        DomainResource(A, None),  # type: ignore[arg-type]
        DomainResource(None, ASSIGNED),  # type: ignore[arg-type]
    ],
)
def test_malformed_resource_denied(resource: object) -> None:
    owner = _principal("owner", admin=True)
    for action in Action:
        assert can(owner, action, resource) is False


def _p(**kwargs: Any) -> Principal:
    base: dict[str, Any] = {
        "user_id": 1,
        "is_active": True,
        "is_instance_admin": False,
        "active_tenant_id": A,
        "memberships": (_grant("owner"),),
    }
    base.update(kwargs)
    return Principal(**base)


@pytest.mark.parametrize(
    ("label", "principal"),
    [
        ("not a principal", None),
        ("dict", {"user_id": 1, "is_active": True}),
        ("is_active truthy non-bool", _p(is_active=1)),
        ("is_active string", _p(is_active="yes")),
        ("no active tenant", _p(active_tenant_id=None)),
        ("active tenant bool", _p(active_tenant_id=True)),
        ("active tenant not a member", _p(active_tenant_id=B)),
        ("memberships as list", _p(memberships=[_grant("owner")])),
        ("membership not a grant", _p(memberships=({"tenant_id": A, "role": "owner"},))),
        ("duplicate membership", _p(memberships=(_grant("owner"), _grant("analyst")))),
        ("unknown role", _p(memberships=(MembershipGrant(A, "superuser"),))),  # type: ignore[arg-type]
        ("role None", _p(memberships=(MembershipGrant(A, None),))),  # type: ignore[arg-type]
        (
            "toggles not a mapping",
            _p(memberships=(MembershipGrant(A, MembershipRole.OWNER, feature_toggles=None),)),
        ),  # type: ignore[arg-type]
    ],
)
def test_malformed_principal_denied_for_tenant_actions(label: str, principal: object) -> None:
    for action, situation in itertools.product(Action, SITUATIONS):
        if situation == "instance":
            continue
        assert can(principal, action, SITUATIONS[situation]) is False, label


def test_role_given_as_string_is_accepted() -> None:
    p = _p(memberships=(MembershipGrant(A, "owner"),))  # type: ignore[arg-type]
    assert can(p, Action.TENANT_MANAGE, TenantResource(A)) is True


def test_instance_admin_flag_must_be_exactly_true() -> None:
    assert can(_p(is_instance_admin=1), Action.INSTANCE_MANAGE, InstanceResource()) is False
    assert can(_p(is_instance_admin=True), Action.INSTANCE_MANAGE, InstanceResource()) is True


@pytest.mark.parametrize(
    ("role", "toggles", "action", "resource", "expected"),
    [
        (
            "client_viewer",
            {"domain.read": False},
            ACT.DOMAIN_READ,
            DomainResource(A, ASSIGNED),
            False,
        ),
        (
            "client_viewer",
            {"domain.read": True},
            ACT.DOMAIN_READ,
            DomainResource(A, ASSIGNED),
            True,
        ),
        (
            "client_viewer",
            {"domain.read": "false"},
            ACT.DOMAIN_READ,
            DomainResource(A, ASSIGNED),
            False,
        ),
        (
            "client_viewer",
            {"domain.read": None},
            ACT.DOMAIN_READ,
            DomainResource(A, ASSIGNED),
            False,
        ),
        ("client_viewer", {"domain.list": False}, ACT.DOMAIN_LIST, TenantResource(A), False),
        (
            "client_viewer",
            {"domain.list": False},
            ACT.DOMAIN_READ,
            DomainResource(A, ASSIGNED),
            True,
        ),
        # Toggles never grant: True on an action the role lacks, or on an unassigned domain.
        (
            "client_viewer",
            {"domain.delete": True},
            ACT.DOMAIN_DELETE,
            DomainResource(A, ASSIGNED),
            False,
        ),
        (
            "client_viewer",
            {"domain.read": True},
            ACT.DOMAIN_READ,
            DomainResource(A, UNASSIGNED),
            False,
        ),
        ("analyst", {"user.manage": True}, ACT.USER_MANAGE, TenantResource(A), False),
        # Unknown toggle keys are ignored.
        (
            "client_viewer",
            {"content.analysis": False},
            ACT.DOMAIN_READ,
            DomainResource(A, ASSIGNED),
            True,
        ),
        # Toggles apply to every role (deny only).
        (
            "owner",
            {"domain.delete": False},
            ACT.DOMAIN_DELETE,
            DomainResource(A, UNASSIGNED),
            False,
        ),
        ("admin", {"user.manage": False}, ACT.USER_MANAGE, TenantResource(A), False),
    ],
)
def test_feature_toggles_only_deny(
    role: str, toggles: dict[str, Any], action: Action, resource: object, expected: bool
) -> None:
    p = _p(memberships=(_grant(role, toggles=toggles),))
    assert can(p, action, resource) is expected


def test_toggle_in_other_tenant_membership_does_not_leak() -> None:
    p = _p(
        memberships=(_grant("client_viewer"), _grant("client_viewer", B, {"domain.read": False}))
    )
    assert can(p, Action.DOMAIN_READ, DomainResource(A, ASSIGNED)) is True


def test_principal_from_models_builds_grants_without_queries() -> None:
    user = User(id=7, email="u@example.com", is_active=True, is_instance_admin=False)
    mine = Membership(
        id=1,
        user_id=7,
        tenant_id=A,
        role=MembershipRole.CLIENT_VIEWER,
        feature_toggles={"domain.read": True},
    )
    other_tenant = Membership(
        id=2, user_id=7, tenant_id=B, role=MembershipRole.OWNER, feature_toggles={}
    )
    someone_else = Membership(
        id=3, user_id=8, tenant_id=A, role=MembershipRole.OWNER, feature_toggles={}
    )
    access = [
        DomainAccess(membership_id=1, domain_id=ASSIGNED, tenant_id=A),
        DomainAccess(membership_id=1, domain_id=99, tenant_id=B),  # tenant mismatch: ignored
        DomainAccess(membership_id=3, domain_id=UNASSIGNED, tenant_id=A),  # other user: ignored
    ]
    p = principal_from_models(user, [mine, other_tenant, someone_else], access, active_tenant_id=A)
    assert p.user_id == 7 and p.active_tenant_id == A
    assert [(g.tenant_id, g.role) for g in p.memberships] == [
        (A, MembershipRole.CLIENT_VIEWER),
        (B, MembershipRole.OWNER),
    ]
    assert p.memberships[0].domain_ids == frozenset({ASSIGNED})
    assert can(p, Action.DOMAIN_READ, DomainResource(A, ASSIGNED)) is True
    assert can(p, Action.DOMAIN_READ, DomainResource(A, UNASSIGNED)) is False
    assert can(p, Action.DOMAIN_DELETE, DomainResource(B, 99)) is False  # owner in B, active A


def test_principal_from_models_inactive_user_denied() -> None:
    user = User(id=7, email="u@example.com", is_active=False, is_instance_admin=True)
    m = Membership(id=1, user_id=7, tenant_id=A, role=MembershipRole.OWNER, feature_toggles={})
    p = principal_from_models(user, [m], [], active_tenant_id=A)
    for action, resource in itertools.product(Action, SITUATIONS.values()):
        assert can(p, action, resource) is False
