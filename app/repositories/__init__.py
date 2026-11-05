"""Repositories: the ONLY place with queries on tenant-owned tables (CLAUDE.md, ARCHITECTURE 4).

Entry points:
- `repo_for(ctx, session)` is the sole way routers, services, CLI and jobs reach tenant data. It
  takes a `TenantContext` and returns repositories bound to that tenant; callers never query a
  raw session for tenant data and never construct tenant repositories themselves.
- `UserMembershipsRepository` (app.repositories.membership) is user-scoped, not tenant-scoped:
  it lists a user's tenants and resolves the membership used to build a TenantContext.
- `principal_from_models` (app.repositories.principal) builds a permission `Principal` from
  already-loaded user, membership and DomainAccess rows (no queries).

Cross-tenant ids behave exactly like missing ids (None/False), so upstream maps them to 404.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.repositories.base import TenantScopedRepository, TenantScopeError
from app.repositories.membership import UserMembershipsRepository, UserTenantMembership
from app.repositories.principal import principal_from_models
from app.repositories.tenant import CurrentTenantRepository, TenantMembershipRepository


@dataclass(frozen=True, slots=True)
class TenantRepositories:
    """Repositories bound to one tenant (add new tenant repositories here, e.g. domains M1-18)."""

    ctx: TenantContext
    tenant: CurrentTenantRepository
    memberships: TenantMembershipRepository


def repo_for(ctx: TenantContext, session: Session) -> TenantRepositories:
    """Build the repositories for `ctx.tenant_id` on `session` (the sole entry to tenant data)."""
    if not isinstance(ctx, TenantContext):
        raise TypeError("repo_for requires a TenantContext")
    return TenantRepositories(
        ctx=ctx,
        tenant=CurrentTenantRepository(ctx, session),
        memberships=TenantMembershipRepository(ctx, session),
    )


__all__ = [
    "CurrentTenantRepository",
    "TenantMembershipRepository",
    "TenantRepositories",
    "TenantScopeError",
    "TenantScopedRepository",
    "UserMembershipsRepository",
    "UserTenantMembership",
    "principal_from_models",
    "repo_for",
]
