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
- `DnsblEnablementRepository` (app.repositories.dnsbl_enablement) holds the instance-level DNSBL
  list enablement (M7-05c): written only by the instance-admin service, its enabled ids read by
  every DNSBL check run. Not part of `repo_for` (no tenant data).
- `MonitorSchedulerRepository` (app.repositories.monitor_targets, M7-06) is the scheduler's
  system entry point: its `due_targets` is the only cross-tenant read of monitor targets. Not part
  of `repo_for`; tenant access to targets is `repo_for(ctx).monitor_targets`.
- `CheckRunRetentionRepository` (app.repositories.check_runs, M7-07) is the retention system entry
  point: its `prune_all_tenants` is the only cross-tenant access to check runs. Not part of
  `repo_for`; tenant access is `repo_for(ctx).check_runs`.
- `DnsSnapshotRetentionRepository` (app.repositories.dns_snapshots, M7-08) is the retention system
  entry point for DNS snapshots: its `prune_all_tenants` is the only cross-tenant access to them.
  Not part of `repo_for`; tenant access is `repo_for(ctx).dns_snapshots`.
- `AlertDispatchRepository` (app.repositories.alert_channels, M7-15) is the delivery loop's system
  entry point: its `tenants_with_due` is the only cross-tenant read of alert deliveries (tenant
  ids only). `AlertChannelSecretRotation.rotate_all` re-encrypts every stored channel secret
  after a key rotation. Neither is part of `repo_for`; tenant access to channels is
  `repo_for(ctx).alert_channels`.

Cross-tenant ids behave exactly like missing ids (None/False), so upstream maps them to 404.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.repositories.alert_channels import (
    AlertChannelRepository,
    AlertChannelSecretRotation,
    AlertDispatchRepository,
)
from app.repositories.alerts import (
    AlertDeliveryRepository,
    AlertRepository,
    AlertRuleRepository,
)
from app.repositories.base import TenantScopedRepository, TenantScopeError
from app.repositories.check_runs import CheckRunRepository, CheckRunRetentionRepository
from app.repositories.content_rules import ContentRuleRepository, GlobalContentRuleRepository
from app.repositories.custom_checks import CustomCheckRepository, GlobalCustomCheckRepository
from app.repositories.dkim_selectors import DkimSelectorRepository, GlobalDkimSelectorRepository
from app.repositories.dns_snapshots import DnsSnapshotRepository, DnsSnapshotRetentionRepository
from app.repositories.dnsbl_enablement import DnsblEnablementRepository
from app.repositories.domain import DomainRepository
from app.repositories.domain_access import DomainAccessRepository
from app.repositories.domain_esps import DomainEspRepository
from app.repositories.membership import UserMembershipsRepository, UserTenantMembership
from app.repositories.monitor_targets import MonitorSchedulerRepository, MonitorTargetRepository
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
    monitor_targets: MonitorTargetRepository
    check_runs: CheckRunRepository
    dns_snapshots: DnsSnapshotRepository
    alerts: AlertRepository
    alert_deliveries: AlertDeliveryRepository
    alert_rules: AlertRuleRepository
    alert_channels: AlertChannelRepository


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
        monitor_targets=MonitorTargetRepository(ctx, session),
        check_runs=CheckRunRepository(ctx, session),
        dns_snapshots=DnsSnapshotRepository(ctx, session),
        alerts=AlertRepository(ctx, session),
        alert_deliveries=AlertDeliveryRepository(ctx, session),
        alert_rules=AlertRuleRepository(ctx, session),
        alert_channels=AlertChannelRepository(ctx, session),
    )


__all__ = [
    "AlertChannelRepository",
    "AlertChannelSecretRotation",
    "AlertDeliveryRepository",
    "AlertDispatchRepository",
    "AlertRepository",
    "AlertRuleRepository",
    "CheckRunRepository",
    "CheckRunRetentionRepository",
    "ContentRuleRepository",
    "CurrentTenantRepository",
    "CustomCheckRepository",
    "DkimSelectorRepository",
    "DnsSnapshotRepository",
    "DnsSnapshotRetentionRepository",
    "DnsblEnablementRepository",
    "DomainAccessRepository",
    "DomainEspRepository",
    "DomainRepository",
    "GlobalContentRuleRepository",
    "GlobalCustomCheckRepository",
    "GlobalDkimSelectorRepository",
    "MonitorSchedulerRepository",
    "MonitorTargetRepository",
    "TenantMembershipRepository",
    "TenantRepositories",
    "TenantScopeError",
    "TenantScopedRepository",
    "UserMembershipsRepository",
    "UserTenantMembership",
    "principal_from_models",
    "repo_for",
]
