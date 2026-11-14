"""dnsbl_list_enablements (M7-05c): DNSBL lists enabled by the instance admin.

Instance-level (no tenant_id). Integer `id` key, unique `list_id`: one row per enabled list;
disabling deletes the row. `list_id` is a slug of `seeds/dnsbl.yaml` (no FK: lists live in YAML).
CHECK constraints keep the list id lowercase and 1 to 40 characters (`length()` counts characters
on SQLite and PostgreSQL alike) and refuse a row without the usage-policy acknowledgement.
`enabled_by` becomes NULL when the user is deleted.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dnsbl_list_enablements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("list_id", sa.String(length=40), nullable=False),
        sa.Column("enabled_by", sa.Integer(), nullable=True),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("policy_acknowledged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("unverified_confirmed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.CheckConstraint(
            "length(list_id) BETWEEN 1 AND 40",
            name=op.f("ck_dnsbl_list_enablements_list_id_length"),
        ),
        sa.CheckConstraint(
            "list_id = lower(list_id)", name=op.f("ck_dnsbl_list_enablements_list_id_lower")
        ),
        sa.CheckConstraint(
            "policy_acknowledged = true",
            name=op.f("ck_dnsbl_list_enablements_policy_acknowledged"),
        ),
        sa.ForeignKeyConstraint(
            ["enabled_by"],
            ["users.id"],
            name=op.f("fk_dnsbl_list_enablements_enabled_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dnsbl_list_enablements")),
        sa.UniqueConstraint("list_id", name=op.f("uq_dnsbl_list_enablements_list_id")),
    )


def downgrade() -> None:
    op.drop_table("dnsbl_list_enablements")
