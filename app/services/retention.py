"""Retention of raw check run history (M7-07, ARCHITECTURE section 5).

`prune_check_runs(session, now, policy)` deletes raw `check_runs` older than the policy's window,
for every tenant, through the explicitly named system repository
(`CheckRunRetentionRepository.prune_all_tenants`). The clock is a parameter (`now`), never read
here, so tests use a fake clock. Aggregates and DNS snapshots are not pruned by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import (
    CHECK_RUN_RETENTION_DAYS_MAX,
    CHECK_RUN_RETENTION_DAYS_MIN,
    Settings,
)
from app.repositories.check_runs import CheckRunRetentionRepository


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """How long raw check runs are kept, in days (bounded like the setting)."""

    check_run_days: int

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


def policy_from_settings(settings: Settings) -> RetentionPolicy:
    return RetentionPolicy(check_run_days=settings.check_run_retention_days)


def prune_check_runs(session: Session, now: datetime, policy: RetentionPolicy) -> int:
    """Delete raw runs of every tenant that started before `now - policy.check_run_days`.
    Returns the number deleted. `now` must be timezone-aware. Flushed, not committed."""
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("policy must be a RetentionPolicy")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    cutoff = now - timedelta(days=policy.check_run_days)
    return CheckRunRetentionRepository(session).prune_all_tenants(cutoff)
