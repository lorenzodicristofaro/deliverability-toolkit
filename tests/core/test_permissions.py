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
    require,
)
from app.models import MembershipRole

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
        ACT.DNS_TOOLS: TENANT_LEVEL,
    },
    "admin": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.USER_MANAGE: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_CREATE: TENANT_LEVEL,
        ACT.DOMAIN_READ: DOMAIN_ALL,
        ACT.DOMAIN_UPDATE: DOMAIN_ALL,
        ACT.DOMAIN_DELETE: DOMAIN_ALL,
        ACT.DNS_TOOLS: TENANT_LEVEL,
    },
    "analyst": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_READ: DOMAIN_ALL,
        ACT.DNS_TOOLS: TENANT_LEVEL,
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
    # 5 role kinds x admin flag x active flag x 10 actions x 6 situations.
    assert len(MATRIX) == 5 * 2 * 2 * 10 * 6 == 1200


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


def test_action_list_is_the_m1_set_plus_dns_tools() -> None:
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
        "dns.tools",  # M2-11
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
        TenantResource(1.0),  # type: ignore[arg-type]
        DomainResource(A, 10.0),  # type: ignore[arg-type]
        DomainResource(1.0, ASSIGNED),  # type: ignore[arg-type]
        DomainResource(A, -1),
        DomainResource(A, "10"),  # type: ignore[arg-type]
        DomainResource(-1, ASSIGNED),
        DomainResource(A, True),  # type: ignore[arg-type]
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


def test_instance_admin_with_membership_tenant_none_gets_no_tenant_data() -> None:
    p = _p(
        is_instance_admin=True,
        memberships=(MembershipGrant(None, MembershipRole.OWNER),),  # type: ignore[arg-type]
    )
    for action, situation in itertools.product(Action, SITUATIONS):
        expected = action is Action.INSTANCE_MANAGE and situation == "instance"
        assert can(p, action, SITUATIONS[situation]) is expected


@pytest.mark.parametrize(
    ("domain_ids", "domain_id", "expected"),
    [
        (frozenset({True}), 1, False),  # bool must not match domain 1
        (frozenset({1.0}), 1, False),
        (frozenset({"1"}), 1, False),
        (frozenset({0, -1}), 1, False),
        ([1], 1, False),  # not a set
        (frozenset({1}), 1, True),
        ({1}, 1, True),
    ],
)
def test_client_viewer_domain_ids_are_validated(
    domain_ids: object, domain_id: int, expected: bool
) -> None:
    grant = MembershipGrant(A, MembershipRole.CLIENT_VIEWER, domain_ids=domain_ids)  # type: ignore[arg-type]
    assert (
        can(_p(memberships=(grant,)), Action.DOMAIN_READ, DomainResource(A, domain_id)) is expected
    )


# --- M2-11: dns.tools (GM decision 2026-11-05) -----------------------------------------------
# owner/admin/analyst only; client viewer denied by role and never grantable; anonymous (no
# principal / no active membership) denied; the instance admin flag adds nothing.

DNS_ROLES_EXPECTED = {"owner": True, "admin": True, "analyst": True, "client_viewer": False}
DNS_TOGGLES: dict[str, dict[str, Any]] = {
    "none": {},
    "dns_true": {"dns.tools": True},
    "dns_false": {"dns.tools": False},
    "dns_none": {"dns.tools": None},
    "dns_str_true": {"dns.tools": "true"},
    "dns_one": {"dns.tools": 1},
    "unrelated_false": {"domain.read": False},
}
DNS_STATES = ("member", "instance_admin_member", "inactive_user", "active_elsewhere")


def _dns_principal(role: str, toggles: dict[str, Any], state: str) -> Principal:
    return Principal(
        user_id=1,
        is_active=state != "inactive_user",
        is_instance_admin=state == "instance_admin_member",
        # "active_elsewhere": the membership exists but its tenant is not the active one.
        active_tenant_id=B if state == "active_elsewhere" else A,
        memberships=(_grant(role, toggles=toggles),),
    )


@pytest.mark.parametrize(
    ("role", "toggle", "state"),
    [
        pytest.param(r, t, st, id=f"{r}-{t}-{st}")
        for r, t, st in itertools.product(DNS_ROLES_EXPECTED, DNS_TOGGLES, DNS_STATES)
    ],
)
def test_dns_tools_roles_x_toggles_x_states(role: str, toggle: str, state: str) -> None:
    p = _dns_principal(role, DNS_TOGGLES[toggle], state)
    expected = (
        DNS_ROLES_EXPECTED[role]
        and state in {"member", "instance_admin_member"}
        and toggle in {"none", "dns_true", "unrelated_false"}
    )
    assert can(p, Action.DNS_TOOLS, TenantResource(A)) is expected
    assert can(p, "dns.tools", TenantResource(A)) is expected
    # Only the principal's own active tenant, and only the tenant-level resource kind.
    for resource in (
        TenantResource(B),
        InstanceResource(),
        DomainResource(A, ASSIGNED),
        DomainResource(A, UNASSIGNED),
    ):
        assert can(p, Action.DNS_TOOLS, resource) is False


@pytest.mark.parametrize(
    ("label", "principal"),
    [
        ("anonymous", None),
        ("no memberships", _p(memberships=())),
        ("no active tenant", _p(active_tenant_id=None)),
        ("instance admin, no membership", _p(is_instance_admin=True, memberships=())),
        ("instance admin, no active tenant", _p(is_instance_admin=True, active_tenant_id=None)),
        ("instance admin, inactive", _p(is_instance_admin=True, is_active=False)),
    ],
)
def test_dns_tools_denied_without_active_membership(label: str, principal: object) -> None:
    for resource in SITUATIONS.values():
        assert can(principal, Action.DNS_TOOLS, resource) is False, label


_ALL_TOGGLES_TRUE = {a.value: True for a in Action}


@pytest.mark.parametrize(
    ("label", "grant", "admin"),
    [
        ("plain", _grant("client_viewer"), False),
        ("toggle dns.tools true", _grant("client_viewer", toggles={"dns.tools": True}), False),
        ("every toggle true", _grant("client_viewer", toggles=_ALL_TOGGLES_TRUE), False),
        (
            "every domain assigned",
            MembershipGrant(A, MembershipRole.CLIENT_VIEWER, domain_ids=frozenset(range(1, 50))),
            False,
        ),
        (
            "every domain + every toggle",
            MembershipGrant(
                A,
                MembershipRole.CLIENT_VIEWER,
                domain_ids=frozenset({ASSIGNED, UNASSIGNED}),
                feature_toggles=MappingProxyType(_ALL_TOGGLES_TRUE),
            ),
            False,
        ),
        ("instance admin flag", _grant("client_viewer", toggles={"dns.tools": True}), True),
        ("role as string", MembershipGrant(A, "client_viewer"), False),  # type: ignore[arg-type]
    ],
)
def test_client_viewer_never_gets_dns_tools(
    label: str, grant: MembershipGrant, admin: bool
) -> None:
    p = _p(is_instance_admin=admin, memberships=(grant,))
    for resource in SITUATIONS.values():
        assert can(p, Action.DNS_TOOLS, resource) is False, label
        with pytest.raises(PermissionDenied):
            require(p, Action.DNS_TOOLS, resource)


def test_owner_role_in_other_tenant_does_not_leak_dns_tools() -> None:
    # Owner in B must not leak dns.tools into A, where the user is only a client viewer.
    p = _p(memberships=(_grant("client_viewer"), _grant("owner", B)))
    assert can(p, Action.DNS_TOOLS, TenantResource(A)) is False
    assert can(p, Action.DNS_TOOLS, TenantResource(B)) is False  # B is not the active tenant
