"""dns_snapshots (M7-08): normalised monitored DNS records per tenant domain, for diffing.

Composite FK (domain_id, tenant_id) -> domains(id, tenant_id) as in check_runs: a snapshot of
another tenant's domain is impossible; deleting the domain or the tenant cascades. Index
(tenant_id, domain_id, taken_at) for latest/history and (taken_at) for retention. The entries are
a JSON list with relative names (no column depends on the 253-character name limit).

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dns_snapshots",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
        # app.models.dns_snapshot.HASH_LENGTH (hex SHA-256).
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("entries", sa.JSON(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            name=op.f("fk_dns_snapshots_domain_id_tenant_id_domains"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_dns_snapshots_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dns_snapshots")),
    )
    op.create_index(
        "ix_dns_snapshots_tenant_domain_taken",
        "dns_snapshots",
        ["tenant_id", "domain_id", "taken_at"],
    )
    op.create_index("ix_dns_snapshots_taken_at", "dns_snapshots", ["taken_at"])


def downgrade() -> None:
    op.drop_index("ix_dns_snapshots_taken_at", table_name="dns_snapshots")
    op.drop_index("ix_dns_snapshots_tenant_domain_taken", table_name="dns_snapshots")
    op.drop_table("dns_snapshots")
