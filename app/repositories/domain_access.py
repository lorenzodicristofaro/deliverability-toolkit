"""Tenant-scoped repository for DomainAccess (which client viewers may read which domain, M1-18).

`domain_access` has a composite primary key (membership_id, domain_id), so it does not use
`TenantScopedRepository`, but follows the same rules: built only with a `TenantContext`, every
query filtered on `tenant_id = ctx.tenant_id`, rows written with the context tenant only, and a
membership or domain of another tenant behaves exactly like a missing one (False / empty).
The composite FKs (M1-10) additionally make cross-tenant rows impossible in the database.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence

from sqlalchemy import ColumnElement, Select, select
from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.models import Domain, DomainAccess, Membership
from app.repositories.base import coerce_id

MAX_ASSIGNMENTS = 1000


class DomainAccessRepository:
    """DomainAccess rows of the context tenant."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _select(self, *criteria: ColumnElement[bool]) -> Select[DomainAccess]:
        return select(DomainAccess).where(DomainAccess.tenant_id == self._ctx.tenant_id, *criteria)

    def _membership_exists(self, membership_id: int) -> bool:
        stmt = select(Membership.id).where(
            Membership.id == membership_id, Membership.tenant_id == self._ctx.tenant_id
        )
        return self._session.scalar(stmt) is not None

    def _domain_exists(self, domain_id: int) -> bool:
        stmt = select(Domain.id).where(
            Domain.id == domain_id, Domain.tenant_id == self._ctx.tenant_id
        )
        return self._session.scalar(stmt) is not None

    def _get(self, membership_id: int, domain_id: int) -> DomainAccess | None:
        stmt = self._select(
            DomainAccess.membership_id == membership_id, DomainAccess.domain_id == domain_id
        )
        return self._session.scalars(stmt).one_or_none()

    # --- reads ------------------------------------------------------------------------------

    def domain_ids_for_membership(self, membership_id: object) -> frozenset[int]:
        """Ids of the domains assigned to the membership (empty if missing/foreign/malformed)."""
        mid = coerce_id(membership_id)
        if mid is None:
            return frozenset()
        stmt = select(DomainAccess.domain_id).where(
            DomainAccess.tenant_id == self._ctx.tenant_id, DomainAccess.membership_id == mid
        )
        return frozenset(self._session.scalars(stmt).all())

    def domain_ids_for_user(self, user_id: object) -> frozenset[int]:
        """Ids of the domains assigned to the user's membership in the context tenant."""
        uid = coerce_id(user_id)
        if uid is None:
            return frozenset()
        stmt = (
            select(DomainAccess.domain_id)
            .join(Membership, Membership.id == DomainAccess.membership_id)
            .where(
                DomainAccess.tenant_id == self._ctx.tenant_id,
                Membership.tenant_id == self._ctx.tenant_id,
                Membership.user_id == uid,
            )
        )
        return frozenset(self._session.scalars(stmt).all())

    def membership_ids_for_domain(self, domain_id: object) -> Sequence[int]:
        """Membership ids with access to the domain, ascending (empty if missing/foreign)."""
        did = coerce_id(domain_id)
        if did is None:
            return []
        stmt = (
            select(DomainAccess.membership_id)
            .where(DomainAccess.tenant_id == self._ctx.tenant_id, DomainAccess.domain_id == did)
            .order_by(DomainAccess.membership_id)
        )
        return self._session.scalars(stmt).all()

    # --- writes -----------------------------------------------------------------------------

    def assign(self, membership_id: object, domain_id: object) -> bool:
        """Grant access (idempotent). False if the membership or domain is missing, foreign or
        malformed (nothing is written)."""
        mid, did = coerce_id(membership_id), coerce_id(domain_id)
        if mid is None or did is None:
            return False
        if not self._membership_exists(mid) or not self._domain_exists(did):
            return False
        if self._get(mid, did) is None:
            self._session.add(
                DomainAccess(membership_id=mid, domain_id=did, tenant_id=self._ctx.tenant_id)
            )
            self._session.flush()
        return True

    def unassign(self, membership_id: object, domain_id: object) -> bool:
        """Revoke access. False if there was no such row in the context tenant."""
        mid, did = coerce_id(membership_id), coerce_id(domain_id)
        if mid is None or did is None:
            return False
        row = self._get(mid, did)
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True

    def replace_for_domain(
        self, domain_id: object, membership_ids: Collection[object]
    ) -> Sequence[int] | None:
        """Make `membership_ids` the exact set with access to the domain. None (nothing changes)
        if the domain or any membership is missing, foreign or malformed, or the set is larger
        than MAX_ASSIGNMENTS. Returns the resulting membership ids, ascending."""
        did = coerce_id(domain_id)
        if did is None or not self._domain_exists(did) or len(membership_ids) > MAX_ASSIGNMENTS:
            return None
        wanted: set[int] = set()
        for value in membership_ids:
            mid = coerce_id(value)
            if mid is None or not self._membership_exists(mid):
                return None
            wanted.add(mid)
        current = set(self.membership_ids_for_domain(did))
        for mid in sorted(current - wanted):
            row = self._get(mid, did)
            if row is not None:
                self._session.delete(row)
        for mid in sorted(wanted - current):
            self._session.add(
                DomainAccess(membership_id=mid, domain_id=did, tenant_id=self._ctx.tenant_id)
            )
        self._session.flush()
        return sorted(wanted)
