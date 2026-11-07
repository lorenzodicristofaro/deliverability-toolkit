"""DKIM selectors (M5-06): global rows (scope 'global', tenant_id NULL) and tenant rows.

CHECK constraints enforce the scope/tenant pairing, the record_type and status enumerations,
every string length (`length()` counts characters on SQLite and PostgreSQL alike), a lowercase
selector and seed_key only on global rows. The selector is unique among global rows (partial
unique index) and per tenant (unique (tenant_id, selector); NULL tenant_id never collides);
seed_key is unique where set.
`sources` is a JSON list of URLs, validated by the repository.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GLOBAL = "scope = 'global'"
_SEEDED = "seed_key IS NOT NULL"


def upgrade() -> None:
    op.create_table(
        "dkim_selectors",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("selector", sa.String(length=63), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column(
            "record_type", sa.String(length=16), server_default=sa.text("'either'"), nullable=False
        ),
        sa.Column("notes", sa.String(length=500), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("sources", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("verified_on", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=True),
        sa.Column("seed_key", sa.String(length=63), nullable=True),
        sa.Column(
            "locally_modified", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
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
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "scope IN ('global', 'tenant')", name=op.f("ck_dkim_selectors_scope_valid")
        ),
        sa.CheckConstraint(
            "(scope = 'global' AND tenant_id IS NULL)"
            " OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name=op.f("ck_dkim_selectors_scope_tenant"),
        ),
        sa.CheckConstraint(
            "record_type IN ('txt', 'cname', 'either')",
            name=op.f("ck_dkim_selectors_record_type_valid"),
        ),
        sa.CheckConstraint(
            "status IS NULL OR status IN ('verified', 'unverified')",
            name=op.f("ck_dkim_selectors_status_valid"),
        ),
        sa.CheckConstraint(
            "length(selector) BETWEEN 1 AND 63", name=op.f("ck_dkim_selectors_selector_length")
        ),
        sa.CheckConstraint(
            "selector = lower(selector)", name=op.f("ck_dkim_selectors_selector_lower")
        ),
        sa.CheckConstraint(
            "provider IS NULL OR (length(provider) BETWEEN 1 AND 64)",
            name=op.f("ck_dkim_selectors_provider_length"),
        ),
        sa.CheckConstraint(
            "notes IS NULL OR (length(notes) BETWEEN 1 AND 500)",
            name=op.f("ck_dkim_selectors_notes_length"),
        ),
        sa.CheckConstraint(
            "seed_key IS NULL OR (length(seed_key) BETWEEN 1 AND 63)",
            name=op.f("ck_dkim_selectors_seed_key_length"),
        ),
        sa.CheckConstraint(
            "seed_key IS NULL OR scope = 'global'",
            name=op.f("ck_dkim_selectors_seed_key_global"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_dkim_selectors_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_dkim_selectors_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dkim_selectors")),
    )
    op.create_index(
        "uq_dkim_selectors_global_selector",
        "dkim_selectors",
        ["selector"],
        unique=True,
        sqlite_where=sa.text(_GLOBAL),
        postgresql_where=sa.text(_GLOBAL),
    )
    # Not partial: NULL tenant_id (global rows) never collides, and a partial tenant index next
    # to a plain tenant_id index trips an SQLite 3.53 query planner error (see the model).
    op.create_index(
        "uq_dkim_selectors_tenant_selector",
        "dkim_selectors",
        ["tenant_id", "selector"],
        unique=True,
    )
    op.create_index(
        "uq_dkim_selectors_global_seed_key",
        "dkim_selectors",
        ["seed_key"],
        unique=True,
        sqlite_where=sa.text(_SEEDED),
        postgresql_where=sa.text(_SEEDED),
    )


def downgrade() -> None:
    op.drop_index("uq_dkim_selectors_global_seed_key", table_name="dkim_selectors")
    op.drop_index("uq_dkim_selectors_tenant_selector", table_name="dkim_selectors")
    op.drop_index("uq_dkim_selectors_global_selector", table_name="dkim_selectors")
    op.drop_table("dkim_selectors")
