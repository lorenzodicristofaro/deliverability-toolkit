"""Core tenancy tables: users, tenants, memberships, domains, domain_access.

domain_access carries tenant_id and composite FKs to memberships(id, tenant_id) and
domains(id, tenant_id), so a cross-tenant grant is rejected by the database (SQLite and
PostgreSQL). Deleting a tenant or a user cascades to the rows that depend on it.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLES = ("owner", "admin", "analyst", "client_viewer")


def _created_at() -> sa.Column[sa.DateTime]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column("language", sa.String(length=8), server_default="en", nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("slug", name=op.f("uq_tenants_slug")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("language", sa.String(length=8), server_default="en", nullable=False),
        sa.Column(
            "is_instance_admin", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index("uq_users_email_lower", "users", [sa.func.lower(sa.text("email"))], unique=True)
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        _created_at(),
        sa.CheckConstraint("name <> ''", name=op.f("ck_domains_name_not_empty")),
        sa.CheckConstraint("name = lower(name)", name=op.f("ck_domains_name_lowercase")),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_domains_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_domains")),
        sa.UniqueConstraint("id", "tenant_id", name=op.f("uq_domains_id")),
        sa.UniqueConstraint("tenant_id", "name", name=op.f("uq_domains_tenant_id")),
    )
    op.create_table(
        "memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                *ROLES,
                name="membership_role",
                native_enum=False,
                create_constraint=True,
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("feature_toggles", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
        _created_at(),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_memberships_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_memberships_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.UniqueConstraint("id", "tenant_id", name=op.f("uq_memberships_id")),
        sa.UniqueConstraint("user_id", "tenant_id", name=op.f("uq_memberships_user_id")),
    )
    op.create_index(op.f("ix_memberships_tenant_id"), "memberships", ["tenant_id"])
    op.create_table(
        "domain_access",
        sa.Column("membership_id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            name=op.f("fk_domain_access_domain_id_domains"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["membership_id", "tenant_id"],
            ["memberships.id", "memberships.tenant_id"],
            name=op.f("fk_domain_access_membership_id_memberships"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_domain_access_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("membership_id", "domain_id", name=op.f("pk_domain_access")),
    )
    op.create_index(op.f("ix_domain_access_domain_id"), "domain_access", ["domain_id"])
    op.create_index(op.f("ix_domain_access_tenant_id"), "domain_access", ["tenant_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_domain_access_tenant_id"), table_name="domain_access")
    op.drop_index(op.f("ix_domain_access_domain_id"), table_name="domain_access")
    op.drop_table("domain_access")
    op.drop_index(op.f("ix_memberships_tenant_id"), table_name="memberships")
    op.drop_table("memberships")
    op.drop_table("domains")
    op.drop_index("uq_users_email_lower", table_name="users")
    op.drop_table("users")
    op.drop_table("tenants")
