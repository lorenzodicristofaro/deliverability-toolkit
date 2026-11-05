"""Users. Instance admin is `is_instance_admin` (M1-01 Q4a); per ARCHITECTURE section 4 item 6 the
flag grants no access to tenant data by itself."""

import unicodedata
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.models.base import Base

# RFC 5321 caps a forward path at 256 octets including the angle brackets, so an address is at
# most 254 characters (the column stays String(320); this is the stricter, enforced limit).
MAX_EMAIL_LENGTH = 254
# Control characters (Cc: NUL, C0, DEL, C1) and lone surrogates (Cs) never belong in an address;
# PostgreSQL text rejects NUL and unencodable surrogates outright (DataError).
_REJECTED_CATEGORIES = frozenset({"Cc", "Cs"})


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Case-insensitive uniqueness, enforced by the DB on SQLite and PostgreSQL.
        Index("uq_users_email_lower", func.lower(text("email")), unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    language: Mapped[str] = mapped_column(String(8), nullable=False, server_default="en")
    is_instance_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    @validates("email")
    def _normalize_email(self, _key: str, value: str) -> str:
        return normalize_email(value)


def normalize_email(email: str) -> str:
    """Strip and lowercase (str.lower, matching the lower(email) index; casefold would rewrite
    e.g. "ß" to "ss"). Lowercasing in Python also covers non-ASCII, which SQLite's lower() does
    not. Only a minimal shape check: one "@" with non-empty local part and domain, at most
    MAX_EMAIL_LENGTH characters after stripping, no whitespace, control character or surrogate."""
    value = email.strip().lower()
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain or len(value) > MAX_EMAIL_LENGTH:
        raise ValueError("invalid email address")
    if any(c.isspace() or unicodedata.category(c) in _REJECTED_CATEGORIES for c in value):
        raise ValueError("invalid email address")
    return value
