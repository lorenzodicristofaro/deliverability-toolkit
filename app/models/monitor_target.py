"""Monitor targets (M7-06): which checks run on a tenant domain, how often, and when next.

One row per (tenant, domain). `check_ids` is a JSON list of ids from the check registry (the
repository validates them against `app.checks.registry`; the registry lives in code, so no FK).
`interval_seconds` is one of `ALLOWED_INTERVALS_SECONDS`, never below `MIN_INTERVAL_SECONDS`
(the database enforces the minimum, the repository the exact set). `last_status` is NULL until
the first run, then one of `LAST_STATUSES` (the check `Status` values).

The row carries `tenant_id` and a composite FK (domain_id, tenant_id) -> domains(id, tenant_id),
so a target pointing at another tenant's domain is rejected by the database (same technique as
`domain_esps`). Deleting the domain or the tenant cascades. Access goes only through
`app.repositories.monitor_targets`.
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
    UniqueConstraint,
    func,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

MIN_INTERVAL_SECONDS: Final = 3600
ALLOWED_INTERVALS_SECONDS: Final[tuple[int, ...]] = (3600, 21600, 43200, 86400)
LAST_STATUSES: Final[tuple[str, ...]] = ("ok", "warn", "fail", "info", "error")
MAX_STATUS_LENGTH: Final = 8


class MonitorTarget(Base):
    __tablename__ = "monitor_targets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "domain_id"),
        ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"interval_seconds >= {MIN_INTERVAL_SECONDS}", name="interval_min"),
        CheckConstraint(
            "last_status IS NULL OR last_status IN ("
            + ", ".join(f"'{s}'" for s in LAST_STATUSES)
            + ")",
            name="last_status_known",
        ),
        # Serves due_targets: enabled rows by next_run_at.
        Index("ix_monitor_targets_enabled_next_run_at", "enabled", "next_run_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    check_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=true(), default=True
    )
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(MAX_STATUS_LENGTH), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
