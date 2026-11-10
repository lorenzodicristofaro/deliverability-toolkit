"""Repositories: the ONLY place with queries on tenant-owned tables (CLAUDE.md, ARCHITECTURE 4).

Entry points:
- `repo_for(ctx, session)` is the sole way routers, services, CLI and jobs reach tenant data. It
  takes a `TenantContext` and returns repositories bound to that tenant; callers never query a
  raw session for tenant data and never construct tenant repositories themselves.
- `UserMembershipsRepository` (app.repositories.membership) is user-scoped, not tenant-scoped:
  it lists a user's tenants and resolves the membership used to build a TenantContext.
- `principal_from_models` (app.repositories.principal) builds a permission `Principal` from
  already-loaded user, membership and DomainAccess rows (no queries).
- `GlobalContentRuleRepository` (app.repositories.content_rules) is the instance-admin entry
  point for global content rules; it is deliberately not part of `repo_for`, and callers must
  have passed the M5-04 global `rules.manage` check (or be seed sync) before building it.
- `GlobalDkimSelectorRepository` (app.repositories.dkim_selectors) is the same kind of
  instance-admin entry point for global DKIM selectors (admin service and seed sync only).
- `GlobalCustomCheckRepository` (app.repositories.custom_checks) is the same kind of
  instance-admin entry point for global custom checks (admin service only).

Cross-tenant ids behave exactly like missing ids (None/False), so upstream maps them to 404.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.repositories.base import TenantScopedRepository, TenantScopeError
from app.repositories.content_rules import ContentRuleRepository, GlobalContentRuleRepository
from app.repositories.custom_checks import CustomCheckRepository, GlobalCustomCheckRepository
from app.repositories.dkim_selectors import DkimSelectorRepository, GlobalDkimSelectorRepository
from app.repositories.domain import DomainRepository
from app.repositories.domain_access import DomainAccessRepository
from app.repositories.domain_esps import DomainEspRepository
from app.repositories.membership import UserMembershipsRepository, UserTenantMembership
from app.repositories.principal import principal_from_models
from app.repositories.tenant import CurrentTenantRepository, TenantMembershipRepository


@dataclass(frozen=True, slots=True)
class TenantRepositories:
    """Repositories bound to one tenant (add new tenant repositories here)."""

    ctx: TenantContext
    tenant: CurrentTenantRepository
    memberships: TenantMembershipRepository
    domains: DomainRepository
    domain_access: DomainAccessRepository
    domain_esps: DomainEspRepository
    content_rules: ContentRuleRepository
    dkim_selectors: DkimSelectorRepository
    custom_checks: CustomCheckRepository


def repo_for(ctx: TenantContext, session: Session) -> TenantRepositories:
    """Build the repositories for `ctx.tenant_id` on `session` (the sole entry to tenant data)."""
    if not isinstance(ctx, TenantContext):
        raise TypeError("repo_for requires a TenantContext")
    return TenantRepositories(
        ctx=ctx,
        tenant=CurrentTenantRepository(ctx, session),
        memberships=TenantMembershipRepository(ctx, session),
        domains=DomainRepository(ctx, session),
        domain_access=DomainAccessRepository(ctx, session),
        domain_esps=DomainEspRepository(ctx, session),
        content_rules=ContentRuleRepository(ctx, session),
        dkim_selectors=DkimSelectorRepository(ctx, session),
        custom_checks=CustomCheckRepository(ctx, session),
    )


__all__ = [
    "ContentRuleRepository",
    "CurrentTenantRepository",
    "CustomCheckRepository",
    "DkimSelectorRepository",
    "DomainAccessRepository",
    "DomainEspRepository",
    "DomainRepository",
    "GlobalContentRuleRepository",
    "GlobalCustomCheckRepository",
    "GlobalDkimSelectorRepository",
    "TenantMembershipRepository",
    "TenantRepositories",
    "TenantScopeError",
    "TenantScopedRepository",
    "UserMembershipsRepository",
    "UserTenantMembership",
    "principal_from_models",
    "repo_for",
]
