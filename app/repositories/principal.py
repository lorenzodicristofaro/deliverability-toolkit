"""Build a permission `Principal` from already-loaded ORM rows (M1-11, moved here by M1-12).

Lives in `app.repositories` because it reads tenant models (Membership, DomainAccess), which only
`app.models` and `app.repositories` may reference. `app.core.permissions` stays model-free.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from app.core.permissions import MembershipGrant, Principal

if TYPE_CHECKING:
    from app.models.membership import DomainAccess, Membership
    from app.models.user import User


def _freeze_toggles(toggles: object) -> Any:
    """Read-only copy of a mapping; anything else is passed through unchanged so that `can`
    denies every action for it (fail closed, no coercion)."""
    if isinstance(toggles, Mapping):
        return MappingProxyType(dict(toggles))
    return toggles


def principal_from_models(
    user: User,
    memberships: Iterable[Membership],
    domain_access: Iterable[DomainAccess],
    active_tenant_id: int | None,
) -> Principal:
    """Build a Principal from already-loaded ORM rows (no queries). Memberships of other users
    and DomainAccess rows whose tenant does not match their membership are ignored."""
    own = [m for m in memberships if m.user_id == user.id]
    tenant_of = {m.id: m.tenant_id for m in own}
    domains: dict[int, set[int]] = {m.id: set() for m in own}
    for da in domain_access:
        if da.membership_id in domains and tenant_of[da.membership_id] == da.tenant_id:
            domains[da.membership_id].add(da.domain_id)
    grants = tuple(
        MembershipGrant(
            tenant_id=m.tenant_id,
            role=m.role,
            domain_ids=frozenset(domains[m.id]),
            feature_toggles=_freeze_toggles(m.feature_toggles),
        )
        for m in own
    )
    return Principal(
        user_id=user.id,
        is_active=user.is_active,
        is_instance_admin=user.is_instance_admin,
        active_tenant_id=active_tenant_id,
        memberships=grants,
    )
