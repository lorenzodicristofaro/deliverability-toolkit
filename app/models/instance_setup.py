"""First-run setup state (M1-17, GM decision Q6): a singleton row.

The database enforces the single-admin guarantee of the setup wizard:
- `ck_instance_setup_singleton` (CHECK id = 1) plus the primary key allow exactly one row.
- Completing setup is one conditional UPDATE of that row
  (`... WHERE id = 1 AND completed_at IS NULL AND token_hash = :hash`) in the same transaction
  that creates the admin. The database serialises concurrent UPDATEs of the row (PostgreSQL row
  lock, SQLite write lock), so exactly one transaction sees rowcount 1; every other one sees 0
  and rolls back its user insert.
- `ck_instance_setup_token_cleared`: a completed setup has no token hash, so the one-time token
  cannot outlive setup.

Only the SHA-256 digest of the one-time setup token is stored, never the token itself.
"""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

SINGLETON_ID = 1


class InstanceSetup(Base):
    __tablename__ = "instance_setup"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
        CheckConstraint("completed_at IS NULL OR token_hash IS NULL", name="token_cleared"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    token_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    admin_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
