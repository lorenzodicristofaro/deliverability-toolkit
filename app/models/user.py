"""Users. Instance admin is `is_instance_admin` (M1-01 Q4a); per ARCHITECTURE section 4 item 6 the
flag grants no access to tenant data by itself."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.models.base import Base


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
    not. Only a minimal shape check: one "@" with non-empty local part and domain."""
    value = email.strip().lower()
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain or any(c.isspace() for c in value):
        raise ValueError("invalid email address")
    return value
