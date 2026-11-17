"""DNS snapshots (M7-08): the normalised monitored records of a tenant domain at one moment.

ARCHITECTURE section 5: `dns_snapshots` holds what the diff (`app.services.dns_diff`) compares.
A row is stored in full only when it differs from the previous one or a heartbeat interval has
passed (`app.services.dns_snapshot`), so history stays small.

`entries` is a JSON list, one item per monitored (name, type): `name` is RELATIVE to the domain
(`@`, `_dmarc`, `<selector>._domainkey`; at most 75 characters, so no column width depends on the
253-character DNS name limit and a domain rename does not change the snapshot), `type`, `state`
(ok, nxdomain, nodata or error; an `error` is never "removed") and the sorted normalised values
as `{"h": sha256, "v": bounded text}`. `content_hash` is a SHA-256 over the full normalised
content (before any truncation), so it is stable across truncation. The stored JSON text is
capped (`MAX_ENTRIES_BYTES`, measured on what is stored: SQLAlchemy's default `json.dumps`).

The row carries `tenant_id` and a composite FK (domain_id, tenant_id) -> domains(id, tenant_id)
like `check_runs`: a snapshot of another tenant's domain is rejected by the database; deleting the
domain or the tenant cascades. Access goes only through `app.repositories.dns_snapshots`.
"""

from datetime import datetime
from typing import Final

from sqlalchemy import (
    JSON,
    Boolean,
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

HASH_LENGTH: Final = 64
# Entries: apex SPF, _dmarc, MX, NS plus the configured DKIM selectors (seed cap 200, plus tenant
# ones), so a generous ceiling.
MAX_ENTRIES: Final = 300
# Measured on the stored JSON text. Worst case after the value texts are dropped is far below.
MAX_ENTRIES_BYTES: Final = 524288


class DnsSnapshot(Base):
    __tablename__ = "dns_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            ondelete="CASCADE",
        ),
        # Serves latest-per-domain and history (tenant, domain, newest first).
        Index("ix_dns_snapshots_tenant_domain_taken", "tenant_id", "domain_id", "taken_at"),
        # Serves retention (delete by age across tenants).
        Index("ix_dns_snapshots_taken_at", "taken_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(HASH_LENGTH), nullable=False)
    entries: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    truncated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false(), default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
