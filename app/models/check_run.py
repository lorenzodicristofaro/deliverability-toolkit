"""Check run history (M7-07): one row per executed check on a tenant domain.

ARCHITECTURE section 5: this single table `check_runs` holds the raw per-check results (there is
no separate `check_results` table) and is the raw history that retention prunes. A row stores
the outcome of one check run: `status` is exactly the Check contract's `Status` (ok, info, warn,
fail, error), `source` is `scheduled` or `manual`.

`findings` holds stable finding codes and their params only (a JSON list of
`{"code": ..., "params": {...}}`), never rendered text, so i18n applies at display time. It is
bounded (`MAX_FINDINGS`, `MAX_FINDINGS_BYTES` measured on the stored JSON text); when the run had
more, the stored list is a prefix and `findings_truncated` is true. `findings_hash` is a SHA-256
over the canonical full list, so two runs with the same findings share a hash even when truncated.

The row carries `tenant_id` and a composite FK (domain_id, tenant_id) -> domains(id, tenant_id),
like `monitor_targets`: a run of another tenant's domain is rejected by the database. Deleting the
domain or the tenant cascades. Access goes only through `app.repositories.check_runs`.
"""

from datetime import datetime
from typing import Final

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    false,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

STATUSES: Final[tuple[str, ...]] = ("ok", "info", "warn", "fail", "error")
SOURCES: Final[tuple[str, ...]] = ("scheduled", "manual")
# Built-in ids are short slugs; custom checks are `custom:{scope}:{key}` (app.checks.custom) with
# a key up to `custom_check.MAX_KEY_LENGTH` (64), so up to 79 characters with the longest scope
# label ("invalid", the fallback for a bad scope). Rounded up; a test ties it to those constants.
# Migration 0012 hardcodes the same width.
MAX_CHECK_ID_LENGTH: Final = 96
MAX_STATUS_LENGTH: Final = 8
MAX_SOURCE_LENGTH: Final = 16
HASH_LENGTH: Final = 64
MAX_FINDINGS: Final = 100
MAX_FINDINGS_BYTES: Final = 16384
MAX_DURATION_MS: Final = 2**31 - 1


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


class CheckRun(Base):
    __tablename__ = "check_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(_in("status", STATUSES), name="status_known"),
        CheckConstraint(_in("source", SOURCES), name="source_known"),
        CheckConstraint("duration_ms >= 0", name="duration_non_negative"),
        # Serves the history list and latest-per-check (tenant, domain, check, newest first).
        Index(
            "ix_check_runs_tenant_domain_check_started",
            "tenant_id",
            "domain_id",
            "check_id",
            "started_at",
        ),
        # Serves retention (delete by age across tenants).
        Index("ix_check_runs_started_at", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    check_id: Mapped[str] = mapped_column(String(MAX_CHECK_ID_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(String(MAX_STATUS_LENGTH), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(MAX_SOURCE_LENGTH), nullable=False)
    findings: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    findings_truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false(), default=False
    )
    findings_hash: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
