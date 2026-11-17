"""monitor_targets (M7-06): scheduled checks per tenant domain.

One row per (tenant, domain), unique. A composite FK (domain_id, tenant_id) ->
domains(id, tenant_id) makes a cross-tenant row impossible (as in domain_esps); deleting the
domain or the tenant cascades. CHECK constraints keep `interval_seconds` at or above the minimum
(3600) and `last_status` to the known check statuses; the repository validates the exact interval
set and the check ids (registry in code, no FK). Index on (enabled, next_run_at) for the
scheduler's due query.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "monitor_targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("check_ids", sa.JSON(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=8), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "interval_seconds >= 3600", name=op.f("ck_monitor_targets_interval_min")
        ),
        sa.CheckConstraint(
            "last_status IS NULL OR last_status IN ('ok', 'warn', 'fail', 'info', 'error')",
            name=op.f("ck_monitor_targets_last_status_known"),
        ),
        sa.ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            name=op.f("fk_monitor_targets_domain_id_tenant_id_domains"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_monitor_targets_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_monitor_targets")),
        sa.UniqueConstraint(
            "tenant_id", "domain_id", name=op.f("uq_monitor_targets_tenant_id_domain_id")
        ),
    )
    op.create_index(op.f("ix_monitor_targets_tenant_id"), "monitor_targets", ["tenant_id"])
    op.create_index(
        "ix_monitor_targets_enabled_next_run_at", "monitor_targets", ["enabled", "next_run_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_monitor_targets_enabled_next_run_at", table_name="monitor_targets")
    op.drop_index(op.f("ix_monitor_targets_tenant_id"), table_name="monitor_targets")
    op.drop_table("monitor_targets")
