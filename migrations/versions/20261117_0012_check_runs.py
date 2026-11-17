"""check_runs (M7-07): raw check run history per tenant domain.

Composite FK (domain_id, tenant_id) -> domains(id, tenant_id) as in monitor_targets: a run of
another tenant's domain is impossible; deleting the domain or the tenant cascades. CHECK
constraints keep `status` to the Check contract statuses, `source` to scheduled|manual and
`duration_ms` non-negative. Index (tenant_id, domain_id, check_id, started_at) for the history
queries and (started_at) for retention.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "check_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("check_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("findings_truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("findings_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('ok', 'info', 'warn', 'fail', 'error')",
            name=op.f("ck_check_runs_status_known"),
        ),
        sa.CheckConstraint(
            "source IN ('scheduled', 'manual')", name=op.f("ck_check_runs_source_known")
        ),
        sa.CheckConstraint("duration_ms >= 0", name=op.f("ck_check_runs_duration_non_negative")),
        sa.ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            name=op.f("fk_check_runs_domain_id_tenant_id_domains"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_check_runs_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_check_runs")),
    )
    op.create_index(
        "ix_check_runs_tenant_domain_check_started",
        "check_runs",
        ["tenant_id", "domain_id", "check_id", "started_at"],
    )
    op.create_index("ix_check_runs_started_at", "check_runs", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_check_runs_started_at", table_name="check_runs")
    op.drop_index("ix_check_runs_tenant_domain_check_started", table_name="check_runs")
    op.drop_table("check_runs")
