"""Retention of raw check run history (M7-07) and DNS snapshots (M7-08), ARCHITECTURE section 5.

`prune_check_runs(session, now, policy)` deletes raw `check_runs` older than the policy's window,
for every tenant, through the explicitly named system repository
(`CheckRunRetentionRepository.prune_all_tenants`); `prune_dns_snapshots` does the same for
`dns_snapshots` through `DnsSnapshotRetentionRepository` (the newest snapshot of each domain is
always kept). Snapshots are kept longer than runs: the snapshot window is never shorter than the
run window. The clock is a parameter (`now`), never read here, so tests use a fake clock.
Aggregates are not pruned by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import (
    CHECK_RUN_RETENTION_DAYS_MAX,
    CHECK_RUN_RETENTION_DAYS_MIN,
    DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS,
    DNS_SNAPSHOT_RETENTION_DAYS_MAX,
    DNS_SNAPSHOT_RETENTION_DAYS_MIN,
    Settings,
)
from app.repositories.check_runs import CheckRunRetentionRepository
from app.repositories.dns_snapshots import DnsSnapshotRetentionRepository


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """How long raw check runs and DNS snapshots are kept, in days (bounded like the settings).
    `dns_snapshot_days` defaults to the default snapshot window, raised to `check_run_days` if
    that is longer; an explicit value shorter than `check_run_days` is rejected."""

    check_run_days: int
    dns_snapshot_days: int | None = None

    def __post_init__(self) -> None:
        days = self.check_run_days
        if (
            type(days) is not int
            or not CHECK_RUN_RETENTION_DAYS_MIN <= days <= CHECK_RUN_RETENTION_DAYS_MAX
        ):
            raise ValueError(
                f"check_run_days must be an int between {CHECK_RUN_RETENTION_DAYS_MIN} "
                f"and {CHECK_RUN_RETENTION_DAYS_MAX}"
            )
        snaps = self.dns_snapshot_days
        if snaps is None:
            object.__setattr__(
                self, "dns_snapshot_days", max(DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS, days)
            )
        elif (
            type(snaps) is not int
            or not DNS_SNAPSHOT_RETENTION_DAYS_MIN <= snaps <= DNS_SNAPSHOT_RETENTION_DAYS_MAX
            or snaps < days
        ):
            raise ValueError(
                f"dns_snapshot_days must be an int between {DNS_SNAPSHOT_RETENTION_DAYS_MIN} "
                f"and {DNS_SNAPSHOT_RETENTION_DAYS_MAX}, and not below check_run_days"
            )


def policy_from_settings(settings: Settings) -> RetentionPolicy:
    return RetentionPolicy(
        check_run_days=settings.check_run_retention_days,
        dns_snapshot_days=max(
            settings.dns_snapshot_retention_days, settings.check_run_retention_days
        ),
    )


def prune_check_runs(session: Session, now: datetime, policy: RetentionPolicy) -> int:
    """Delete raw runs of every tenant that started before `now - policy.check_run_days`.
    Returns the number deleted. `now` must be timezone-aware. Flushed, not committed."""
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("policy must be a RetentionPolicy")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    cutoff = now - timedelta(days=policy.check_run_days)
    return CheckRunRetentionRepository(session).prune_all_tenants(cutoff)


def prune_dns_snapshots(session: Session, now: datetime, policy: RetentionPolicy) -> int:
    """Delete snapshots of every tenant taken before `now - policy.dns_snapshot_days`, except the
    newest snapshot of each domain. Returns the number deleted. `now` must be timezone-aware.
    Flushed, not committed."""
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("policy must be a RetentionPolicy")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    assert policy.dns_snapshot_days is not None  # resolved by RetentionPolicy
    cutoff = now - timedelta(days=policy.dns_snapshot_days)
    return DnsSnapshotRetentionRepository(session).prune_all_tenants(cutoff)
