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
    RuleScope,
    RuleScopeResource,
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
    # M5-04 rule scopes.
    "global_rules": RuleScopeResource(RuleScope.GLOBAL),
    "own_tenant_rules": RuleScopeResource(RuleScope.TENANT, A),
    "other_tenant_rules": RuleScopeResource(RuleScope.TENANT, B),
}

ACT = Action
TENANT_LEVEL = {"own_tenant"}
DOMAIN_ALL = {"own_assigned_domain", "own_unassigned_domain"}
OWN_RULES = {"own_tenant_rules"}

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
        ACT.CHECK_RUN: DOMAIN_ALL,
        ACT.MESSAGE_ANALYZE: TENANT_LEVEL,
        ACT.CONTENT_ANALYZE: TENANT_LEVEL,
        ACT.RULES_READ: TENANT_LEVEL,
        ACT.RULES_MANAGE: OWN_RULES,
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
        ACT.CHECK_RUN: DOMAIN_ALL,
        ACT.MESSAGE_ANALYZE: TENANT_LEVEL,
        ACT.CONTENT_ANALYZE: TENANT_LEVEL,
        ACT.RULES_READ: TENANT_LEVEL,
        ACT.RULES_MANAGE: OWN_RULES,
    },
    "analyst": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_READ: DOMAIN_ALL,
        ACT.DNS_TOOLS: TENANT_LEVEL,
        ACT.CHECK_RUN: DOMAIN_ALL,
        ACT.MESSAGE_ANALYZE: TENANT_LEVEL,
        ACT.CONTENT_ANALYZE: TENANT_LEVEL,
        ACT.RULES_READ: TENANT_LEVEL,
    },
    "client_viewer": {
        ACT.TENANT_READ: TENANT_LEVEL,
        ACT.DOMAIN_LIST: TENANT_LEVEL,
        ACT.DOMAIN_READ: {"own_assigned_domain"},
        ACT.CHECK_RUN: {"own_assigned_domain"},
    },
    "none": {},
}
# The instance admin flag adds instance-level grants only, whatever the role (or none).
INSTANCE_ADMIN_EXTRA: dict[Action, set[str]] = {
    ACT.INSTANCE_MANAGE: {"instance"},
    ACT.RULES_MANAGE: {"global_rules"},
}


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
    allowed = set(ROLE_EXPECTED[role].get(action, set()))
    if admin:
        allowed |= INSTANCE_ADMIN_EXTRA.get(action, set())  # union: owner keeps own_tenant_rules
    return situation in allowed


MATRIX = [
    pytest.param(
        role, admin, active, action, situation, id=f"{role}-{admin=}-{active=}-{action}-{situation}"
    )
    for role, admin, active, action, situation in itertools.product(
        ROLE_EXPECTED, (False, True), (True, False), list(Action), SITUATIONS
    )
]


def test_matrix_size() -> None:
    # 5 role kinds x admin flag x active flag x 15 actions x 9 situations.
    assert len(MATRIX) == 5 * 2 * 2 * 15 * 9 == 2700


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


def test_action_list_is_the_m1_set_plus_later_milestone_actions() -> None:
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
        "check.run",  # M3-14
        "message.analyze",  # M4-06
        "content.analyze",  # M5-04
        "rules.read",  # M5-04
        "rules.manage",  # M5-04
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
        expected = (action is Action.INSTANCE_MANAGE and situation == "instance") or (
            action is Action.RULES_MANAGE and situation == "global_rules"
        )
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


# --- M3-14: check.run (GM decision, ticket M3-14) ---------------------------------------------
# Domain-level. owner/admin/analyst on every domain of the active tenant; client viewer only on
# assigned domains. Toggles deny only; the instance admin flag adds nothing.

CHECK_ROLES = ("owner", "admin", "analyst", "client_viewer")
CHECK_TOGGLES: dict[str, dict[str, Any]] = {
    "none": {},
    "check_true": {"check.run": True},
    "check_false": {"check.run": False},
    "check_none": {"check.run": None},
    "check_str_true": {"check.run": "true"},
    "check_one": {"check.run": 1},
    "unrelated_false": {"domain.read": False, "dns.tools": False},
}
CHECK_STATES = (
    "member",
    "instance_admin_member",
    "inactive_user",
    "active_elsewhere",
    "no_membership",
    "instance_admin_no_membership",
)
CHECK_RESOURCES: dict[str, object] = {
    "assigned": DomainResource(A, ASSIGNED),
    "unassigned": DomainResource(A, UNASSIGNED),
    "other_tenant_domain": DomainResource(B, ASSIGNED),
    "own_tenant": TenantResource(A),
    "instance": InstanceResource(),
}


def _check_principal(role: str, toggles: dict[str, Any], state: str) -> Principal:
    no_membership = state in {"no_membership", "instance_admin_no_membership"}
    return Principal(
        user_id=1,
        is_active=state != "inactive_user",
        is_instance_admin=state in {"instance_admin_member", "instance_admin_no_membership"},
        # "active_elsewhere": the membership exists but its tenant is not the active one.
        active_tenant_id=B if state == "active_elsewhere" else A,
        memberships=() if no_membership else (_grant(role, toggles=toggles),),
    )


def _check_expected(role: str, toggle: str, state: str, resource: str) -> bool:
    if state not in {"member", "instance_admin_member"}:
        return False
    if toggle not in {"none", "check_true", "unrelated_false"}:
        return False
    if role == "client_viewer":
        return resource == "assigned"
    return resource in {"assigned", "unassigned"}


@pytest.mark.parametrize(
    ("role", "toggle", "state", "resource"),
    [
        pytest.param(r, t, st, res, id=f"{r}-{t}-{st}-{res}")
        for r, t, st, res in itertools.product(
            CHECK_ROLES, CHECK_TOGGLES, CHECK_STATES, CHECK_RESOURCES
        )
    ],
)
def test_check_run_roles_x_toggles_x_states(
    role: str, toggle: str, state: str, resource: str
) -> None:
    p = _check_principal(role, CHECK_TOGGLES[toggle], state)
    expected = _check_expected(role, toggle, state, resource)
    res = CHECK_RESOURCES[resource]
    assert can(p, Action.CHECK_RUN, res) is expected
    assert can(p, "check.run", res) is expected
    if not expected:
        with pytest.raises(PermissionDenied):
            require(p, Action.CHECK_RUN, res)


@pytest.mark.parametrize(
    ("label", "grant", "admin", "domain_id", "expected"),
    [
        ("plain, assigned", _grant("client_viewer"), False, ASSIGNED, True),
        ("plain, unassigned", _grant("client_viewer"), False, UNASSIGNED, False),
        (
            "toggle true does not widen to unassigned",
            _grant("client_viewer", toggles={"check.run": True}),
            False,
            UNASSIGNED,
            False,
        ),
        (
            "every toggle true does not widen to unassigned",
            _grant("client_viewer", toggles=_ALL_TOGGLES_TRUE),
            False,
            UNASSIGNED,
            False,
        ),
        (
            "instance admin flag does not widen to unassigned",
            _grant("client_viewer"),
            True,
            UNASSIGNED,
            False,
        ),
        (
            "no assignments",
            MembershipGrant(A, MembershipRole.CLIENT_VIEWER),
            False,
            ASSIGNED,
            False,
        ),
        (
            "domain ids not a set",
            MembershipGrant(A, MembershipRole.CLIENT_VIEWER, domain_ids=[ASSIGNED]),  # type: ignore[arg-type]
            False,
            ASSIGNED,
            False,
        ),
        (
            "bool domain id",
            MembershipGrant(A, MembershipRole.CLIENT_VIEWER, domain_ids=frozenset({True})),
            False,
            1,
            False,
        ),
        (
            "toggles not a mapping",
            MembershipGrant(
                A,
                MembershipRole.CLIENT_VIEWER,
                domain_ids=frozenset({ASSIGNED}),
                feature_toggles=None,  # type: ignore[arg-type]
            ),
            False,
            ASSIGNED,
            False,
        ),
        (
            "role as string",
            MembershipGrant(A, "client_viewer", frozenset({ASSIGNED})),
            False,
            ASSIGNED,
            True,
        ),  # type: ignore[arg-type]
    ],
)
def test_check_run_client_viewer_assigned_domains_only(
    label: str, grant: MembershipGrant, admin: bool, domain_id: int, expected: bool
) -> None:
    p = _p(is_instance_admin=admin, memberships=(grant,))
    assert can(p, Action.CHECK_RUN, DomainResource(A, domain_id)) is expected, label


@pytest.mark.parametrize(
    ("label", "principal"),
    [
        ("anonymous", None),
        ("no active tenant", _p(active_tenant_id=None)),
        ("instance admin, inactive", _p(is_instance_admin=True, is_active=False)),
        ("duplicate membership", _p(memberships=(_grant("owner"), _grant("analyst")))),
        ("unknown role", _p(memberships=(MembershipGrant(A, "superuser"),))),  # type: ignore[arg-type]
    ],
)
def test_check_run_denied_for_malformed_principal(label: str, principal: object) -> None:
    for resource in CHECK_RESOURCES.values():
        assert can(principal, Action.CHECK_RUN, resource) is False, label


def test_check_run_role_in_other_tenant_does_not_leak() -> None:
    # Owner in B must not widen A, where the user is only a client viewer on ASSIGNED.
    p = _p(memberships=(_grant("client_viewer"), _grant("owner", B)))
    assert can(p, Action.CHECK_RUN, DomainResource(A, ASSIGNED)) is True
    assert can(p, Action.CHECK_RUN, DomainResource(A, UNASSIGNED)) is False
    assert can(p, Action.CHECK_RUN, DomainResource(B, UNASSIGNED)) is False


def test_check_run_toggle_is_independent_of_dns_tools() -> None:
    # Denying check.run leaves dns.tools and domain.read untouched, and vice versa.
    p = _p(memberships=(_grant("analyst", toggles={"check.run": False}),))
    assert can(p, Action.CHECK_RUN, DomainResource(A, ASSIGNED)) is False
    assert can(p, Action.DNS_TOOLS, TenantResource(A)) is True
    assert can(p, Action.DOMAIN_READ, DomainResource(A, ASSIGNED)) is True
    q = _p(memberships=(_grant("analyst", toggles={"dns.tools": False}),))
    assert can(q, Action.CHECK_RUN, DomainResource(A, UNASSIGNED)) is True


# --- M4-06: message.analyze (ticket M4-06) ----------------------------------------------------
# Tenant-level, owner/admin/analyst only; client viewer denied by role and never grantable;
# no active membership denied; the instance admin flag adds nothing; toggles only deny.

MSG_ROLES_EXPECTED = {"owner": True, "admin": True, "analyst": True, "client_viewer": False}
MSG_TOGGLES: dict[str, dict[str, Any]] = {
    "none": {},
    "msg_true": {"message.analyze": True},
    "msg_false": {"message.analyze": False},
    "msg_none": {"message.analyze": None},
    "msg_str_yes": {"message.analyze": "yes"},
    "msg_str_true": {"message.analyze": "true"},
    "msg_zero": {"message.analyze": 0},
    "msg_one": {"message.analyze": 1},
    "unrelated_false": {"dns.tools": False, "check.run": False, "domain.read": False},
}
MSG_ALLOWING_TOGGLES = {"none", "msg_true", "unrelated_false"}


@pytest.mark.parametrize(
    ("role", "toggle", "state"),
    [
        pytest.param(r, t, st, id=f"{r}-{t}-{st}")
        for r, t, st in itertools.product(MSG_ROLES_EXPECTED, MSG_TOGGLES, DNS_STATES)
    ],
)
def test_message_analyze_roles_x_toggles_x_states(role: str, toggle: str, state: str) -> None:
    p = _dns_principal(role, MSG_TOGGLES[toggle], state)
    expected = (
        MSG_ROLES_EXPECTED[role]
        and state in {"member", "instance_admin_member"}
        and toggle in MSG_ALLOWING_TOGGLES
    )
    assert can(p, Action.MESSAGE_ANALYZE, TenantResource(A)) is expected
    assert can(p, "message.analyze", TenantResource(A)) is expected
    if not expected:
        with pytest.raises(PermissionDenied):
            require(p, Action.MESSAGE_ANALYZE, TenantResource(A))
    # Only the principal's own active tenant, and only the tenant-level resource kind: a
    # DomainResource (even in the own tenant) or an InstanceResource is denied.
    for resource in (
        TenantResource(B),
        InstanceResource(),
        DomainResource(A, ASSIGNED),
        DomainResource(A, UNASSIGNED),
    ):
        assert can(p, Action.MESSAGE_ANALYZE, resource) is False


@pytest.mark.parametrize(
    ("label", "principal"),
    [
        ("anonymous", None),
        ("not a principal", object()),
        ("dict principal", {"user_id": 1, "is_active": True, "active_tenant_id": A}),
        ("inactive user", _p(is_active=False)),
        ("is_active truthy non-bool", _p(is_active=1)),
        ("no memberships", _p(memberships=())),
        ("no active tenant", _p(active_tenant_id=None)),
        ("active tenant not an id", _p(active_tenant_id="1")),
        ("active tenant bool", _p(active_tenant_id=True)),
        ("memberships not a tuple", _p(memberships=[_grant("owner")])),
        ("membership not a grant", _p(memberships=({"tenant_id": A, "role": "owner"},))),
        ("duplicate membership", _p(memberships=(_grant("owner"), _grant("analyst")))),
        ("unknown role", _p(memberships=(MembershipGrant(A, "superuser"),))),  # type: ignore[arg-type]
        ("role not a string", _p(memberships=(MembershipGrant(A, 1),))),  # type: ignore[arg-type]
        (
            "toggles not a mapping",
            _p(memberships=(MembershipGrant(A, MembershipRole.OWNER, feature_toggles=None),)),  # type: ignore[arg-type]
        ),
        ("instance admin, no membership", _p(is_instance_admin=True, memberships=())),
        ("instance admin, no active tenant", _p(is_instance_admin=True, active_tenant_id=None)),
        ("instance admin, inactive", _p(is_instance_admin=True, is_active=False)),
    ],
)
def test_message_analyze_denied_for_malformed_or_inactive_principal(
    label: str, principal: object
) -> None:
    for resource in SITUATIONS.values():
        assert can(principal, Action.MESSAGE_ANALYZE, resource) is False, label


@pytest.mark.parametrize(
    "resource",
    [
        TenantResource(B),
        TenantResource(0),
        TenantResource(-1),
        TenantResource(True),  # True == 1 must not match tenant A
        TenantResource("1"),  # type: ignore[arg-type]
        DomainResource(A, ASSIGNED),
        InstanceResource(),
        None,
        A,
        {"tenant_id": A},
    ],
)
def test_message_analyze_wrong_tenant_or_resource_denied(resource: object) -> None:
    p = _p(is_instance_admin=True)  # owner in A; the instance flag must not help
    assert can(p, Action.MESSAGE_ANALYZE, resource) is False
    assert can(p, Action.MESSAGE_ANALYZE, TenantResource(A)) is True


@pytest.mark.parametrize(
    ("label", "grant", "admin"),
    [
        ("plain", _grant("client_viewer"), False),
        (
            "toggle message.analyze true",
            _grant("client_viewer", toggles={"message.analyze": True}),
            False,
        ),
        ("every toggle true", _grant("client_viewer", toggles=_ALL_TOGGLES_TRUE), False),
        (
            "every domain + every toggle",
            MembershipGrant(
                A,
                MembershipRole.CLIENT_VIEWER,
                domain_ids=frozenset(range(1, 50)),
                feature_toggles=MappingProxyType(_ALL_TOGGLES_TRUE),
            ),
            False,
        ),
        (
            "instance admin flag",
            _grant("client_viewer", toggles={"message.analyze": True}),
            True,
        ),
        ("role as string", MembershipGrant(A, "client_viewer"), False),  # type: ignore[arg-type]
    ],
)
def test_client_viewer_never_gets_message_analyze(
    label: str, grant: MembershipGrant, admin: bool
) -> None:
    p = _p(is_instance_admin=admin, memberships=(grant,))
    for resource in SITUATIONS.values():
        assert can(p, Action.MESSAGE_ANALYZE, resource) is False, label
        with pytest.raises(PermissionDenied):
            require(p, Action.MESSAGE_ANALYZE, resource)


def test_message_analyze_role_in_other_tenant_does_not_leak() -> None:
    # Owner in B must not leak message.analyze into A, where the user is only a client viewer.
    p = _p(memberships=(_grant("client_viewer"), _grant("owner", B)))
    assert can(p, Action.MESSAGE_ANALYZE, TenantResource(A)) is False
    assert can(p, Action.MESSAGE_ANALYZE, TenantResource(B)) is False  # B is not active


def test_message_analyze_toggle_is_independent_of_dns_tools_and_check_run() -> None:
    # Denying dns.tools must not switch off the offline analyzer, and vice versa.
    p = _p(memberships=(_grant("analyst", toggles={"dns.tools": False, "check.run": False}),))
    assert can(p, Action.MESSAGE_ANALYZE, TenantResource(A)) is True
    assert can(p, Action.DNS_TOOLS, TenantResource(A)) is False
    q = _p(memberships=(_grant("analyst", toggles={"message.analyze": False}),))
    assert can(q, Action.MESSAGE_ANALYZE, TenantResource(A)) is False
    assert can(q, Action.DNS_TOOLS, TenantResource(A)) is True
    assert can(q, Action.CHECK_RUN, DomainResource(A, ASSIGNED)) is True


# --- M5-04: content.analyze, rules.read, rules.manage (ticket M5-04) -------------------------
# content.analyze / rules.read: tenant-level, owner/admin/analyst, never client viewers, toggles
# only deny. rules.manage: scope `global` -> only the instance admin flag (no membership needed,
# tenant role irrelevant, toggles do not apply); scope `tenant` -> owner/admin of that same,
# active tenant, toggles deny, the instance flag adds nothing.

TENANT_LEVEL_M5 = (Action.CONTENT_ANALYZE, Action.RULES_READ)
M5_ROLES_TENANT_LEVEL = {"owner": True, "admin": True, "analyst": True, "client_viewer": False}
M5_ROLES_MANAGE_TENANT = {"owner": True, "admin": True, "analyst": False, "client_viewer": False}
M5_STATES = (
    "member",
    "instance_admin_member",
    "inactive_user",
    "inactive_instance_admin",
    "active_elsewhere",
    "no_active_tenant",
    "no_membership",
    "instance_admin_no_membership",
)
M5_RESOURCES: dict[str, object] = {
    "global_rules": RuleScopeResource(RuleScope.GLOBAL),
    "global_rules_str": RuleScopeResource("global"),  # type: ignore[arg-type]
    "own_tenant_rules": RuleScopeResource(RuleScope.TENANT, A),
    "own_tenant_rules_str": RuleScopeResource("tenant", A),  # type: ignore[arg-type]
    "other_tenant_rules": RuleScopeResource(RuleScope.TENANT, B),
    "own_tenant": TenantResource(A),
    "other_tenant": TenantResource(B),
    "own_domain": DomainResource(A, ASSIGNED),
    "instance": InstanceResource(),
}
M5_TOGGLE_KINDS = (
    "none",
    "true",
    "false",
    "none_value",
    "str_yes",
    "str_true",
    "zero",
    "one",
    "unrelated_false",
)
ALLOWING_TOGGLES = {"none", "true", "unrelated_false"}


def _toggles_for(action: Action, kind: str) -> dict[str, Any]:
    v = action.value
    return {
        "none": {},
        "true": {v: True},
        "false": {v: False},
        "none_value": {v: None},
        "str_yes": {v: "yes"},
        "str_true": {v: "true"},
        "zero": {v: 0},
        "one": {v: 1},
        "unrelated_false": {
            k: False for k in ("message.analyze", "dns.tools", "check.run", "domain.read")
        },
    }[kind]


def _m5_principal(role: str, toggles: dict[str, Any], state: str) -> Principal:
    no_membership = state in {"no_membership", "instance_admin_no_membership"}
    return Principal(
        user_id=1,
        is_active=state not in {"inactive_user", "inactive_instance_admin"},
        is_instance_admin=state
        in {"instance_admin_member", "inactive_instance_admin", "instance_admin_no_membership"},
        active_tenant_id={"active_elsewhere": B, "no_active_tenant": None}.get(state, A),
        memberships=() if no_membership else (_grant(role, toggles=toggles),),
    )


def _m5_expected(action: Action, role: str, toggle: str, state: str, resource: str) -> bool:
    if state in {"inactive_user", "inactive_instance_admin"}:
        return False
    if action is Action.RULES_MANAGE and resource.startswith("global_rules"):
        # Global scope: the instance flag alone decides; role and toggles are irrelevant.
        return state in {"instance_admin_member", "instance_admin_no_membership"}
    if state not in {"member", "instance_admin_member"} or toggle not in ALLOWING_TOGGLES:
        return False
    if action is Action.RULES_MANAGE:
        return M5_ROLES_MANAGE_TENANT[role] and resource.startswith("own_tenant_rules")
    return M5_ROLES_TENANT_LEVEL[role] and resource == "own_tenant"


@pytest.mark.parametrize(
    ("action", "role", "toggle", "state", "resource"),
    [
        pytest.param(a, r, t, st, res, id=f"{a}-{r}-{t}-{st}-{res}")
        for a, r, t, st, res in itertools.product(
            (*TENANT_LEVEL_M5, Action.RULES_MANAGE),
            M5_ROLES_TENANT_LEVEL,
            M5_TOGGLE_KINDS,
            M5_STATES,
            M5_RESOURCES,
        )
    ],
)
def test_m5_actions_roles_x_toggles_x_states(
    action: Action, role: str, toggle: str, state: str, resource: str
) -> None:
    p = _m5_principal(role, _toggles_for(action, toggle), state)
    expected = _m5_expected(action, role, toggle, state, resource)
    res = M5_RESOURCES[resource]
    assert can(p, action, res) is expected
    assert can(p, action.value, res) is expected
    if not expected:
        with pytest.raises(PermissionDenied):
            require(p, action, res)


@pytest.mark.parametrize(
    "resource",
    [
        RuleScopeResource("Global"),  # type: ignore[arg-type]
        RuleScopeResource(" global"),  # type: ignore[arg-type]
        RuleScopeResource("GLOBAL"),  # type: ignore[arg-type]
        RuleScopeResource(""),  # type: ignore[arg-type]
        RuleScopeResource("instance"),  # type: ignore[arg-type]
        RuleScopeResource("tenant ", A),  # type: ignore[arg-type]
        RuleScopeResource("Tenant", A),  # type: ignore[arg-type]
        RuleScopeResource(None),  # type: ignore[arg-type]
        RuleScopeResource(1),  # type: ignore[arg-type]
        RuleScopeResource(b"global"),  # type: ignore[arg-type]
        RuleScopeResource(RuleScope.GLOBAL, A),  # global with a tenant id is ambiguous
        RuleScopeResource(RuleScope.GLOBAL, 0),
        RuleScopeResource(RuleScope.TENANT),  # tenant scope without a tenant
        RuleScopeResource(RuleScope.TENANT, 0),
        RuleScopeResource(RuleScope.TENANT, -1),
        RuleScopeResource(RuleScope.TENANT, True),  # True == 1 must not match tenant A
        RuleScopeResource(RuleScope.TENANT, "1"),  # type: ignore[arg-type]
        RuleScopeResource(RuleScope.TENANT, 1.0),  # type: ignore[arg-type]
        None,
        "global",
        {"scope": "global"},
    ],
)
def test_rules_manage_malformed_scope_denied(resource: object) -> None:
    # Owner of A who is also instance admin: the strongest principal still gets nothing.
    p = _p(is_instance_admin=True)
    for action in Action:
        assert can(p, action, resource) is False


@pytest.mark.parametrize(
    ("action", "resource"),
    [
        (Action.RULES_MANAGE, TenantResource(A)),
        (Action.RULES_MANAGE, InstanceResource()),
        (Action.RULES_MANAGE, DomainResource(A, ASSIGNED)),
        (Action.RULES_READ, RuleScopeResource(RuleScope.TENANT, A)),
        (Action.RULES_READ, RuleScopeResource(RuleScope.GLOBAL)),
        (Action.RULES_READ, InstanceResource()),
        (Action.CONTENT_ANALYZE, RuleScopeResource(RuleScope.TENANT, A)),
        (Action.CONTENT_ANALYZE, DomainResource(A, ASSIGNED)),
        (Action.CONTENT_ANALYZE, InstanceResource()),
        (Action.INSTANCE_MANAGE, RuleScopeResource(RuleScope.GLOBAL)),
        (Action.TENANT_MANAGE, RuleScopeResource(RuleScope.TENANT, A)),
    ],
)
def test_m5_wrong_resource_type_denied(action: Action, resource: object) -> None:
    p = _p(is_instance_admin=True)
    assert can(p, action, resource) is False


@pytest.mark.parametrize(
    ("label", "principal"),
    [
        ("anonymous", None),
        ("not a principal", object()),
        ("dict principal", {"user_id": 1, "is_active": True, "is_instance_admin": True}),
        ("inactive instance admin", _p(is_instance_admin=True, is_active=False)),
        ("is_active truthy non-bool", _p(is_instance_admin=True, is_active=1)),
        ("instance flag truthy non-bool", _p(is_instance_admin=1, memberships=())),
        ("instance flag string", _p(is_instance_admin="true", memberships=())),
        ("duplicate membership", _p(memberships=(_grant("owner"), _grant("admin")))),
        ("unknown role", _p(memberships=(MembershipGrant(A, "superuser"),))),  # type: ignore[arg-type]
        ("role not a string", _p(memberships=(MembershipGrant(A, 1),))),  # type: ignore[arg-type]
        ("memberships not a tuple", _p(memberships=[_grant("owner")])),
        (
            "toggles not a mapping",
            _p(memberships=(MembershipGrant(A, MembershipRole.OWNER, feature_toggles=None),)),  # type: ignore[arg-type]
        ),
    ],
)
def test_m5_actions_denied_for_malformed_principal(label: str, principal: object) -> None:
    for action, resource in itertools.product(
        (Action.CONTENT_ANALYZE, Action.RULES_READ, Action.RULES_MANAGE), M5_RESOURCES.values()
    ):
        assert can(principal, action, resource) is False, label


def test_tenant_admin_cannot_manage_other_tenant_or_global_rules() -> None:
    # Admin of A, also owner of B (agency): only A's tenant rules while A is active.
    p = _p(memberships=(_grant("admin"), _grant("owner", B)))
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.TENANT, A)) is True
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.TENANT, B)) is False
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.GLOBAL)) is False
    # Every toggle true still never grants global.
    q = _p(memberships=(_grant("owner", toggles=_ALL_TOGGLES_TRUE),))
    assert can(q, Action.RULES_MANAGE, RuleScopeResource(RuleScope.GLOBAL)) is False


def test_instance_admin_without_membership_gets_global_rules_only() -> None:
    # Rule (existing model, maintainer decision 2026-11-04): the instance flag grants
    # instance-level resources only; inside a tenant it has no membership, so nothing.
    for active in (A, None):
        p = _p(is_instance_admin=True, memberships=(), active_tenant_id=active)
        for action, resource in itertools.product(Action, M5_RESOURCES.values()):
            expected = (
                action is Action.RULES_MANAGE
                and isinstance(resource, RuleScopeResource)
                and resource.tenant_id is None
            ) or (action is Action.INSTANCE_MANAGE and isinstance(resource, InstanceResource))
            assert can(p, action, resource) is expected, (active, action, resource)


def test_instance_admin_with_viewer_role_gets_global_but_not_tenant_rules() -> None:
    p = _p(is_instance_admin=True, memberships=(_grant("client_viewer"),))
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.GLOBAL)) is True
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.TENANT, A)) is False
    assert can(p, Action.RULES_READ, TenantResource(A)) is False
    assert can(p, Action.CONTENT_ANALYZE, TenantResource(A)) is False


def test_rules_manage_toggle_does_not_touch_global_scope() -> None:
    # A per-membership toggle in the active tenant denies tenant rules, not global ones.
    p = _p(is_instance_admin=True, memberships=(_grant("owner", toggles={"rules.manage": False}),))
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.TENANT, A)) is False
    assert can(p, Action.RULES_MANAGE, RuleScopeResource(RuleScope.GLOBAL)) is True


@pytest.mark.parametrize("action", [Action.CONTENT_ANALYZE, Action.RULES_READ, Action.RULES_MANAGE])
def test_client_viewer_never_gets_m5_actions(action: Action) -> None:
    grants = (
        _grant("client_viewer"),
        _grant("client_viewer", toggles=_ALL_TOGGLES_TRUE),
        MembershipGrant(
            A,
            MembershipRole.CLIENT_VIEWER,
            domain_ids=frozenset(range(1, 50)),
            feature_toggles=MappingProxyType(_ALL_TOGGLES_TRUE),
        ),
        MembershipGrant(A, "client_viewer"),  # type: ignore[arg-type]
    )
    for grant in grants:
        p = _p(memberships=(grant,))
        for resource in M5_RESOURCES.values():
            assert can(p, action, resource) is False


def test_m5_toggles_are_independent() -> None:
    # content.analyze and message.analyze have separate toggle keys; so do rules.read and
    # rules.manage.
    p = _p(memberships=(_grant("owner", toggles={"message.analyze": False}),))
    assert can(p, Action.CONTENT_ANALYZE, TenantResource(A)) is True
    q = _p(memberships=(_grant("owner", toggles={"content.analyze": False}),))
    assert can(q, Action.CONTENT_ANALYZE, TenantResource(A)) is False
    assert can(q, Action.MESSAGE_ANALYZE, TenantResource(A)) is True
    r = _p(memberships=(_grant("owner", toggles={"rules.manage": False}),))
    assert can(r, Action.RULES_READ, TenantResource(A)) is True
    assert can(r, Action.RULES_MANAGE, RuleScopeResource(RuleScope.TENANT, A)) is False
    s = _p(memberships=(_grant("owner", toggles={"rules.read": False}),))
    assert can(s, Action.RULES_READ, TenantResource(A)) is False
    assert can(s, Action.RULES_MANAGE, RuleScopeResource(RuleScope.TENANT, A)) is True
