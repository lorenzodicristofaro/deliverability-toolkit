"""Content rules index rework (M5-05b), following 0006's dkim_selectors pattern.

0005's partial unique (tenant_id, seed_key) WHERE scope = 'tenant' next to the plain tenant_id
index makes SQLite (3.46, 3.53) raise "internal query planner error" for the tenant OR-filter
plus seed_key with bound parameters. The tenant index becomes a plain unique (tenant_id, seed_key):
NULLs never collide on SQLite or PostgreSQL, so global rows (tenant_id NULL) and rules without a
seed_key (seed_key NULL) are unaffected, and uniqueness stays exactly as before. It leads with
tenant_id, so it replaces ix_content_rules_tenant_id. The global partial seed_key index is kept.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_SEED = "scope = 'tenant' AND seed_key IS NOT NULL"


def upgrade() -> None:
    op.drop_index("uq_content_rules_tenant_seed_key", table_name="content_rules")
    op.drop_index("ix_content_rules_tenant_id", table_name="content_rules")
    op.create_index(
        "uq_content_rules_tenant_seed_key",
        "content_rules",
        ["tenant_id", "seed_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_content_rules_tenant_seed_key", table_name="content_rules")
    op.create_index("ix_content_rules_tenant_id", "content_rules", ["tenant_id"])
    op.create_index(
        "uq_content_rules_tenant_seed_key",
        "content_rules",
        ["tenant_id", "seed_key"],
        unique=True,
        sqlite_where=sa.text(_TENANT_SEED),
        postgresql_where=sa.text(_TENANT_SEED),
    )
