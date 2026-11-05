"""Server-side login sessions (M1-13, GM decision Q3).

A row per login. Only the SHA-256 digest of the opaque session token is stored (`token_hash`);
the token itself lives only in the signed cookie. `expires_at` is the absolute expiry, set at
creation; idle expiry is `last_seen_at` + the idle timeout. `revoked_at` marks logout/revocation.
`active_tenant_id` is the tenant the user is working in (M1-01 Q4a); it is not a tenant scope:
sessions are user-owned, and tenant access is still resolved through memberships.
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    active_tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
