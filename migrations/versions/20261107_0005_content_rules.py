"""Content rules (M5-05): global rows (scope 'global', tenant_id NULL) and tenant rows.

CHECK constraints enforce the scope/tenant pairing, enumerations, weight and flag bounds and
every string length (`length()` counts characters on SQLite and PostgreSQL alike). seed_key is
unique among global rows and per tenant among tenant rows (partial unique indexes on both
backends). A rule without seed_key needs a title (seeded rules take their text from i18n keys
derived from seed_key). `sources` is a JSON list of URLs, validated by the repository. The flags
mask 346 is `app.core.safe_regex.ALLOWED_FLAGS` (pinned by a test).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GLOBAL_SEED = "scope = 'global' AND seed_key IS NOT NULL"
_TENANT_SEED = "scope = 'tenant' AND seed_key IS NOT NULL"


def upgrade() -> None:
    op.create_table(
        "content_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("pattern", sa.String(length=1024), nullable=False),
        sa.Column("flags", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("language", sa.String(length=16), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=True),
        sa.Column("advice", sa.String(length=2000), nullable=True),
        sa.Column("sources", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("verified_on", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=True),
        sa.Column("seed_key", sa.String(length=128), nullable=True),
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
            "scope IN ('global', 'tenant')", name=op.f("ck_content_rules_scope_valid")
        ),
        sa.CheckConstraint(
            "(scope = 'global' AND tenant_id IS NULL)"
            " OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name=op.f("ck_content_rules_scope_tenant"),
        ),
        sa.CheckConstraint(
            "kind IN ('regex', 'keyword')", name=op.f("ck_content_rules_kind_valid")
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name=op.f("ck_content_rules_severity_valid"),
        ),
        sa.CheckConstraint(
            "status IS NULL OR status IN ('verified', 'unverified')",
            name=op.f("ck_content_rules_status_valid"),
        ),
        sa.CheckConstraint("weight BETWEEN 0 AND 100", name=op.f("ck_content_rules_weight_range")),
        sa.CheckConstraint("(flags | 346) = 346", name=op.f("ck_content_rules_flags_allowed")),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 200", name=op.f("ck_content_rules_name_length")
        ),
        sa.CheckConstraint(
            "length(pattern) BETWEEN 1 AND 1024", name=op.f("ck_content_rules_pattern_length")
        ),
        sa.CheckConstraint(
            "length(category) BETWEEN 1 AND 64", name=op.f("ck_content_rules_category_length")
        ),
        sa.CheckConstraint(
            "language IS NULL OR (length(language) BETWEEN 1 AND 16)",
            name=op.f("ck_content_rules_language_length"),
        ),
        sa.CheckConstraint(
            "language IS NULL OR language = lower(language)",
            name=op.f("ck_content_rules_language_lower"),
        ),
        sa.CheckConstraint(
            "seed_key IS NULL OR (length(seed_key) BETWEEN 1 AND 128)",
            name=op.f("ck_content_rules_seed_key_length"),
        ),
        sa.CheckConstraint(
            "title IS NULL OR (length(title) BETWEEN 1 AND 200)",
            name=op.f("ck_content_rules_title_length"),
        ),
        sa.CheckConstraint(
            "advice IS NULL OR (length(advice) BETWEEN 1 AND 2000)",
            name=op.f("ck_content_rules_advice_length"),
        ),
        sa.CheckConstraint(
            "seed_key IS NOT NULL OR title IS NOT NULL",
            name=op.f("ck_content_rules_title_required"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_content_rules_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_content_rules_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_content_rules")),
    )
    op.create_index("ix_content_rules_tenant_id", "content_rules", ["tenant_id"])
    op.create_index(
        "uq_content_rules_global_seed_key",
        "content_rules",
        ["seed_key"],
        unique=True,
        sqlite_where=sa.text(_GLOBAL_SEED),
        postgresql_where=sa.text(_GLOBAL_SEED),
    )
    op.create_index(
        "uq_content_rules_tenant_seed_key",
        "content_rules",
        ["tenant_id", "seed_key"],
        unique=True,
        sqlite_where=sa.text(_TENANT_SEED),
        postgresql_where=sa.text(_TENANT_SEED),
    )


def downgrade() -> None:
    op.drop_index("uq_content_rules_tenant_seed_key", table_name="content_rules")
    op.drop_index("uq_content_rules_global_seed_key", table_name="content_rules")
    op.drop_index("ix_content_rules_tenant_id", table_name="content_rules")
    op.drop_table("content_rules")
