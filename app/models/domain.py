"""Domains, owned by one tenant. Names are stored normalised (ASCII/A-label, lowercase, no
trailing dot); the same name may exist in several tenants but only once per tenant.

Ownership verification (M7-21a, migration 0015): `verification_status` is `unverified` until a
tenant owner/admin proves control; `verified_at` / `verification_method` say when and how. A
pending DNS challenge is stored only as the SHA-256 hex of its token plus its expiry, never the
token itself. The CHECKs are single-column on purpose: SQLite adds them with ADD COLUMN, so the
table (target of many foreign keys) is never rebuilt. `email` is accepted as a method for M7-21b
but nothing writes it yet."""

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


VERIFICATION_STATUSES = ("unverified", "verified")
VERIFICATION_METHODS = ("dns_txt", "email")
TOKEN_HASH_LENGTH = 64  # SHA-256, hex


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name"),
        # Target of the composite FK from domain_access (redundant with the PK on purpose).
        UniqueConstraint("id", "tenant_id"),
        CheckConstraint("name = lower(name)", name="name_lowercase"),
        CheckConstraint("name <> ''", name="name_not_empty"),
        CheckConstraint(
            "verification_status IN ('unverified', 'verified')", name="verification_status_valid"
        ),
        CheckConstraint(
            "verification_method IS NULL OR verification_method IN ('dns_txt', 'email')",
            name="verification_method_valid",
        ),
        CheckConstraint(
            "verification_token_hash IS NULL OR length(verification_token_hash) = 64",
            name="verification_token_hash_length",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(MAX_DOMAIN_LENGTH), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    verification_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unverified", server_default="unverified"
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verification_token_hash: Mapped[str | None] = mapped_column(
        String(TOKEN_HASH_LENGTH), nullable=True
    )
    verification_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @validates("name")
    def _normalize_name(self, _key: str, value: str) -> str:
        return normalize_domain_name(value)
