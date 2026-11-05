"""Domains, owned by one tenant. Names are stored normalised (ASCII/A-label, lowercase, no
trailing dot); the same name may exist in several tenants but only once per tenant."""

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.models.base import Base

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
# LDH plus "_" (seen in service labels); anything else is rejected rather than guessed at.
_ALLOWED_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def normalize_domain_name(name: str) -> str:
    """Strip, drop one trailing dot, lowercase; reject empty/oversized names and labels.

    Only ASCII (A-label) names are accepted: U-label to A-label conversion (IDNA 2008 / UTS 46)
    is the caller's job until a vetted IDNA dependency is added (stdlib codec is IDNA 2003)."""
    value = name.strip()
    if value.endswith("."):
        value = value[:-1]
    value = value.lower()
    if not value or len(value) > MAX_DOMAIN_LENGTH or not value.isascii():
        raise ValueError("invalid domain name")
    if any(not label or len(label) > MAX_LABEL_LENGTH for label in value.split(".")):
        raise ValueError("invalid domain name")
    if not set(value) <= _ALLOWED_CHARS:
        raise ValueError("invalid domain name")
    return value


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name"),
        # Target of the composite FK from domain_access (redundant with the PK on purpose).
        UniqueConstraint("id", "tenant_id"),
        CheckConstraint("name = lower(name)", name="name_lowercase"),
        CheckConstraint("name <> ''", name="name_not_empty"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(MAX_DOMAIN_LENGTH), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    @validates("name")
    def _normalize_name(self, _key: str, value: str) -> str:
        return normalize_domain_name(value)
