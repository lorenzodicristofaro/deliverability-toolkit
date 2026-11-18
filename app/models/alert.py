"""Alerts, their per-channel deliveries and the tenant's alert rules (M7-14).

ARCHITECTURE section 6 ("Alerts") holds the design; in short:
- `alerts`: one row per (tenant, fingerprint, state_hash). `fingerprint` is the change event's
  (`app.services.change_detect`: kind, domain, subject, new state); `state_hash` adds the position
  in the event's stream (the id of the previous alert of the same stream), so a later, truly new
  transition to the same state is a new row while a replay of the same transition hits the UNIQUE
  constraint, which is the dedup point (INSERT .. ON CONFLICT DO NOTHING, never check-then-insert).
  `stream` is SHA-256 of (family, domain, subject): the alerts of one DNS entry, one DNSBL list,
  one check's policy or one check's errors. `suppressed` rows (min re-alert interval) are kept
  for the UI and get no deliveries. The payload is a code plus bounded params, never text.
- `alert_deliveries`: one row per (alert, channel), status pending|sent|failed|abandoned,
  `attempts`, `next_attempt_at`, `last_error` (a stable code only, never a body or secret).
- `alert_rules`: which event kinds go to which channel of the tenant; none means no delivery.

`channel_id` has no FK yet: the channels table comes with M7-15, which adds it.
Composite FKs keep every row inside its tenant: alerts -> domains(id, tenant_id), deliveries ->
alerts(id, tenant_id); deleting the domain, the alert or the tenant cascades. Access goes only
through `app.repositories.alerts`.
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
    false,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# The event kinds of app.services.change_detect.EventKind (a test ties the two).
KINDS: Final[tuple[str, ...]] = (
    "record_changed",
    "new_listing",
    "listing_cleared",
    "policy_regression",
    "check_error_started",
    "check_error_cleared",
)
DELIVERY_STATUSES: Final[tuple[str, ...]] = ("pending", "sent", "failed", "abandoned")
MAX_KIND_LENGTH: Final = 32
MAX_CODE_LENGTH: Final = 64
MAX_ERROR_LENGTH: Final = 64
MAX_STATUS_LENGTH: Final = 16
HASH_LENGTH: Final = 64


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            ondelete="CASCADE",
        ),
        # The dedup point: a replayed transition conflicts here.
        UniqueConstraint("tenant_id", "fingerprint", "state_hash"),
        # Target of the composite FK from alert_deliveries (redundant with the PK on purpose).
        UniqueConstraint("id", "tenant_id"),
        CheckConstraint(_in("kind", KINDS), name="kind_known"),
        # Serves the latest alert of a stream.
        Index("ix_alerts_tenant_domain_stream_id", "tenant_id", "domain_id", "stream", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(MAX_KIND_LENGTH), nullable=False)
    stream: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    state_hash: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    code: Mapped[str] = mapped_column(String(MAX_CODE_LENGTH), nullable=False)
    params: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    suppressed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false(), default=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AlertDelivery(Base):
    __tablename__ = "alert_deliveries"
    __table_args__ = (
        ForeignKeyConstraint(
            ["alert_id", "tenant_id"],
            ["alerts.id", "alerts.tenant_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("alert_id", "channel_id"),
        CheckConstraint(_in("status", DELIVERY_STATUSES), name="status_known"),
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        # Serves the due deliveries of a tenant.
        Index("ix_alert_deliveries_tenant_status_next", "tenant_id", "status", "next_attempt_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    alert_id: Mapped[int] = mapped_column(Integer, nullable=False)
    channel_id: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(MAX_STATUS_LENGTH), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(MAX_ERROR_LENGTH))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "kind", "channel_id"),
        CheckConstraint(_in("kind", KINDS), name="kind_known"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(MAX_KIND_LENGTH), nullable=False)
    channel_id: Mapped[int] = mapped_column(Integer, nullable=False)
