"""Custom checks (M5-07): global rows (scope 'global', tenant_id NULL) and tenant rows.

CHECK constraints enforce the scope/tenant pairing, the kind and severity enumerations (kind
excludes the reserved `http_fetch`, deferred to M7), every string length (`length()` counts
characters on SQLite and PostgreSQL alike), a lowercase check_key, a size cap on the JSON columns
(`length(CAST(col AS TEXT))`: both backends keep the ASCII text SQLAlchemy sent) and exactly one of
remediation_key / remediation_text. 48032 is `MAX_REMEDIATION_JSON_LENGTH` (pinned by a test).
check_key is unique among global rows (partial unique index) and per tenant (plain unique
(tenant_id, check_key); NULL tenant_id never collides). No partial tenant index: SQLite's planner
error with the tenant OR-filter (see 0007).

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GLOBAL = "scope = 'global'"


def _json_object(column: str, maximum: int, *, nullable: bool = False) -> str:
    as_text = f"CAST({column} AS TEXT)"
    bound = f"length({as_text}) BETWEEN 2 AND {maximum} AND substr({as_text}, 1, 1) = '{{'"
    return f"{column} IS NULL OR ({bound})" if nullable else bound


def upgrade() -> None:
    op.create_table(
        "custom_checks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("check_key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("definition", sa.JSON(none_as_null=True), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("remediation_key", sa.String(length=200), nullable=True),
        sa.Column("remediation_text", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
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
            "scope IN ('global', 'tenant')", name=op.f("ck_custom_checks_scope_valid")
        ),
        sa.CheckConstraint(
            "(scope = 'global' AND tenant_id IS NULL)"
            " OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name=op.f("ck_custom_checks_scope_tenant"),
        ),
        sa.CheckConstraint(
            "kind IN ('dns_exists', 'dns_matches', 'dns_value_range')",
            name=op.f("ck_custom_checks_kind_valid"),
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name=op.f("ck_custom_checks_severity_valid"),
        ),
        sa.CheckConstraint(
            "length(check_key) BETWEEN 1 AND 64", name=op.f("ck_custom_checks_check_key_length")
        ),
        sa.CheckConstraint(
            "check_key = lower(check_key)", name=op.f("ck_custom_checks_check_key_lower")
        ),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 200", name=op.f("ck_custom_checks_name_length")
        ),
        sa.CheckConstraint(
            "description IS NULL OR (length(description) BETWEEN 1 AND 2000)",
            name=op.f("ck_custom_checks_description_length"),
        ),
        sa.CheckConstraint(
            _json_object("definition", 16384), name=op.f("ck_custom_checks_definition_size")
        ),
        sa.CheckConstraint(
            "remediation_key IS NULL OR (length(remediation_key) BETWEEN 1 AND 200)",
            name=op.f("ck_custom_checks_remediation_key_length"),
        ),
        sa.CheckConstraint(
            _json_object("remediation_text", 48032, nullable=True),
            name=op.f("ck_custom_checks_remediation_text_size"),
        ),
        sa.CheckConstraint(
            "(remediation_key IS NOT NULL AND remediation_text IS NULL)"
            " OR (remediation_key IS NULL AND remediation_text IS NOT NULL)",
            name=op.f("ck_custom_checks_remediation_one"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_custom_checks_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_custom_checks_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custom_checks")),
    )
    op.create_index(
        "uq_custom_checks_global_check_key",
        "custom_checks",
        ["check_key"],
        unique=True,
        sqlite_where=sa.text(_GLOBAL),
        postgresql_where=sa.text(_GLOBAL),
    )
    op.create_index(
        "uq_custom_checks_tenant_check_key",
        "custom_checks",
        ["tenant_id", "check_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_custom_checks_tenant_check_key", table_name="custom_checks")
    op.drop_index("uq_custom_checks_global_check_key", table_name="custom_checks")
    op.drop_table("custom_checks")
