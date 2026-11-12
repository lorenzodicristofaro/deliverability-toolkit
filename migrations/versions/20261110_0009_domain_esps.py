"""domain_esps (M6-02): ESP profile assignments of a tenant domain.

`esp_id` is a profile slug (profiles live in YAML, so no FK). A composite FK
(domain_id, tenant_id) -> domains(id, tenant_id) makes a cross-tenant row impossible (as in
domain_access); deleting the domain or the tenant cascades. Unique (domain_id, esp_id). CHECK
constraints bound the lengths (`length()` counts characters on SQLite and PostgreSQL alike) and
keep esp_id and the optional hosts lowercase; the repository validates their format.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_esps",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("esp_id", sa.String(length=40), nullable=False),
        sa.Column("return_path_host", sa.String(length=253), nullable=True),
        sa.Column("tracking_host", sa.String(length=253), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(esp_id) BETWEEN 1 AND 40", name=op.f("ck_domain_esps_esp_id_length")
        ),
        sa.CheckConstraint("esp_id = lower(esp_id)", name=op.f("ck_domain_esps_esp_id_lower")),
        sa.CheckConstraint(
            "return_path_host IS NULL OR (length(return_path_host) BETWEEN 1 AND 253)",
            name=op.f("ck_domain_esps_return_path_host_length"),
        ),
        sa.CheckConstraint(
            "return_path_host IS NULL OR return_path_host = lower(return_path_host)",
            name=op.f("ck_domain_esps_return_path_host_lower"),
        ),
        sa.CheckConstraint(
            "tracking_host IS NULL OR (length(tracking_host) BETWEEN 1 AND 253)",
            name=op.f("ck_domain_esps_tracking_host_length"),
        ),
        sa.CheckConstraint(
            "tracking_host IS NULL OR tracking_host = lower(tracking_host)",
            name=op.f("ck_domain_esps_tracking_host_lower"),
        ),
        sa.ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            name=op.f("fk_domain_esps_domain_id_tenant_id_domains"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_domain_esps_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_domain_esps")),
        sa.UniqueConstraint("domain_id", "esp_id", name=op.f("uq_domain_esps_domain_id_esp_id")),
    )
    op.create_index(op.f("ix_domain_esps_tenant_id"), "domain_esps", ["tenant_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_domain_esps_tenant_id"), table_name="domain_esps")
    op.drop_table("domain_esps")
