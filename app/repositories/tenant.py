"""Tenant-scoped repositories for the core tenancy tables: the context's own tenant row and the
memberships of that tenant. Obtain them through `app.repositories.repo_for`."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.models import Membership, Tenant
from app.repositories.base import TenantScopedRepository, coerce_id


class CurrentTenantRepository:
    """Read access to the context's own `tenants` row only (a tenant has no `tenant_id`; its own
    id is the scope). Other tenants are never reachable from here."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    def get(self) -> Tenant | None:
        stmt = select(Tenant).where(Tenant.id == self._ctx.tenant_id)
        return self._session.scalars(stmt).one_or_none()


class TenantMembershipRepository(TenantScopedRepository[Membership]):
    """Memberships of the context tenant (members list, roles)."""

    model = Membership

    def get_by_user(self, user_id: object) -> Membership | None:
        """The membership of `user_id` in the context tenant; None if none/malformed."""
        uid = coerce_id(user_id)
        if uid is None:
            return None
        return self._session.scalars(self._where(Membership.user_id == uid)).one_or_none()
