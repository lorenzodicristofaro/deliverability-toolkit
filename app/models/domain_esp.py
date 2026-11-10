"""ESP assignments of a domain (M6-02): which ESP profiles a tenant domain sends through.

`esp_id` is the slug of an ESP profile. Profiles live in YAML files (`profiles/esp/`, M6-01), not
in the database, so there is no foreign key on it; the slug format is enforced by the repository
(and its length and case by CHECK constraints). `return_path_host` and `tracking_host` are
optional per-assignment host names; the repository normalises them like domain names and requires
them to equal or end with `.<domain name>`.

The row carries `tenant_id` and a composite FK (domain_id, tenant_id) -> domains(id, tenant_id),
so a row pointing at another tenant's domain is rejected by the database (same technique as
`domain_access`, M1-10). Deleting the domain or the tenant cascades. Access goes only through
`app.repositories.domain_esps`.
"""

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

MAX_ESP_ID_LENGTH = 40  # slug `[a-z0-9][a-z0-9-]{0,39}` (M6-01)
MAX_HOST_LENGTH = 253


def _host_checks(column: str) -> tuple[CheckConstraint, CheckConstraint]:
    return (
        CheckConstraint(
            f"{column} IS NULL OR (length({column}) BETWEEN 1 AND {MAX_HOST_LENGTH})",
            name=f"{column}_length",
        ),
        CheckConstraint(f"{column} IS NULL OR {column} = lower({column})", name=f"{column}_lower"),
    )


class DomainEsp(Base):
    __tablename__ = "domain_esps"
    __table_args__ = (
        UniqueConstraint("domain_id", "esp_id"),
        ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(f"length(esp_id) BETWEEN 1 AND {MAX_ESP_ID_LENGTH}", name="esp_id_length"),
        CheckConstraint("esp_id = lower(esp_id)", name="esp_id_lower"),
        *_host_checks("return_path_host"),
        *_host_checks("tracking_host"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    esp_id: Mapped[str] = mapped_column(String(MAX_ESP_ID_LENGTH), nullable=False)
    return_path_host: Mapped[str | None] = mapped_column(String(MAX_HOST_LENGTH), nullable=True)
    tracking_host: Mapped[str | None] = mapped_column(String(MAX_HOST_LENGTH), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
