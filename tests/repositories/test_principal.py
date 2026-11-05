"""`principal_from_models` (moved from app.core.permissions by the M1-12 isolation fix): builds a
permission Principal from already-loaded ORM rows. No DB, no network."""

import itertools

import pytest

from app.core.permissions import Action, DomainResource, InstanceResource, TenantResource, can
from app.models import DomainAccess, Membership, MembershipRole, User
from app.repositories import principal_from_models

A, B = 1, 2  # active tenant A, other tenant B
ASSIGNED, UNASSIGNED = 10, 11  # domains in tenant A; the viewer is assigned only ASSIGNED

SITUATIONS: dict[str, object] = {
    "instance": InstanceResource(),
    "own_tenant": TenantResource(A),
    "other_tenant": TenantResource(B),
    "own_assigned_domain": DomainResource(A, ASSIGNED),
    "own_unassigned_domain": DomainResource(A, UNASSIGNED),
    "other_tenant_domain": DomainResource(B, ASSIGNED),
}


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


def test_principal_from_models_ignores_access_for_unknown_membership() -> None:
    user = User(id=7, email="u@example.com", is_active=True, is_instance_admin=False)
    m = Membership(
        id=1, user_id=7, tenant_id=A, role=MembershipRole.CLIENT_VIEWER, feature_toggles={}
    )
    access = [
        DomainAccess(membership_id=42, domain_id=ASSIGNED, tenant_id=None),
        DomainAccess(membership_id=None, domain_id=ASSIGNED, tenant_id=None),
    ]
    p = principal_from_models(user, [m], access, active_tenant_id=A)
    assert p.memberships[0].domain_ids == frozenset()
    assert can(p, Action.DOMAIN_READ, DomainResource(A, ASSIGNED)) is False


@pytest.mark.parametrize("toggles", [["ab"], "ab", 1, None])
def test_principal_from_models_non_mapping_toggles_deny_all(toggles: object) -> None:
    user = User(id=7, email="u@example.com", is_active=True, is_instance_admin=False)
    m = Membership(id=1, user_id=7, tenant_id=A, role=MembershipRole.OWNER)
    m.feature_toggles = toggles  # type: ignore[assignment]
    p = principal_from_models(user, [m], [], active_tenant_id=A)
    assert p.memberships[0].feature_toggles == toggles  # passed through, not coerced
    for action, situation in itertools.product(Action, SITUATIONS):
        if situation != "instance":
            assert can(p, action, SITUATIONS[situation]) is False
