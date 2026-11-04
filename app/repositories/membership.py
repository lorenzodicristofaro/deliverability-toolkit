"""User-scoped (NOT tenant-scoped) membership queries.

Why this module does not take a TenantContext: listing the tenants a user belongs to, or finding
the user's membership in a tenant they ask to enter, happens *before* a tenant is chosen. It is
what builds the TenantContext in the first place, so it cannot be filtered by one. It is scoped by
the user instead: every query filters on the user id given at construction, and results are
read-only value objects (no ORM rows that could be modified or re-used outside a tenant scope).

Use it only for login/tenant selection and context resolution; everything that reads or writes a
tenant's data goes through `app.repositories.repo_for(ctx, session)`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from sqlalchemy import Row, Select, select
from sqlalchemy.orm import Session

from app.models import Membership, MembershipRole, Tenant
from app.repositories.base import coerce_id


@dataclass(frozen=True, slots=True)
class UserTenantMembership:
    membership_id: int
    tenant_id: int
    tenant_name: str
    tenant_slug: str
    role: MembershipRole


def _to_value(row: Row[int, int, str, str, MembershipRole]) -> UserTenantMembership:
    membership_id, tenant_id, tenant_name, tenant_slug, role = row
    return UserTenantMembership(membership_id, tenant_id, tenant_name, tenant_slug, role)


class UserMembershipsRepository:
    """The memberships of one user across tenants (user-scoped, see module docstring)."""

    __slots__ = ("_session", "_user_id")

    def __init__(self, session: Session, user_id: int) -> None:
        uid = coerce_id(user_id)
        if uid is None:
            raise ValueError("UserMembershipsRepository requires a positive integer user_id")
        self._session = session
        self._user_id = uid

    def _select(self) -> Select[int, int, str, str, MembershipRole]:
        return (
            select(Membership.id, Membership.tenant_id, Tenant.name, Tenant.slug, Membership.role)
            .join(Tenant, Tenant.id == Membership.tenant_id)
            .where(Membership.user_id == self._user_id)
        )

    def list(self) -> Sequence[UserTenantMembership]:
        """All tenants the user is a member of, ordered by tenant name then id."""
        rows = self._session.execute(self._select().order_by(Tenant.name, Tenant.id)).all()
        return [_to_value(row) for row in rows]

    def get_for_tenant(self, tenant_id: object) -> UserTenantMembership | None:
        """The user's membership in `tenant_id`; None if not a member or the id is malformed."""
        tid = coerce_id(tenant_id)
        if tid is None:
            return None
        row = self._session.execute(self._select().where(Membership.tenant_id == tid)).first()
        return None if row is None else _to_value(row)
