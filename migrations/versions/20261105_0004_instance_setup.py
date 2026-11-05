"""First-run setup state (M1-17, GM decision Q6): singleton row with the setup token hash.

CHECK id = 1 keeps it a singleton; completing setup is a conditional UPDATE of that row, so the
database lets exactly one concurrent setup create the instance admin. A completed setup must
have cleared its token hash.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "instance_setup",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("token_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("admin_user_id", sa.Integer(), nullable=True),
        sa.CheckConstraint("id = 1", name=op.f("ck_instance_setup_singleton")),
        sa.CheckConstraint(
            "completed_at IS NULL OR token_hash IS NULL",
            name=op.f("ck_instance_setup_token_cleared"),
        ),
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            ["users.id"],
            name=op.f("fk_instance_setup_admin_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_instance_setup")),
    )


def downgrade() -> None:
    op.drop_table("instance_setup")
