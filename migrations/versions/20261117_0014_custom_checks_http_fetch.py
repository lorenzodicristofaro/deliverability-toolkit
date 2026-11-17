"""custom_checks (M7-02): `http_fetch` becomes an accepted kind.

Only the `ck_custom_checks_kind_valid` CHECK changes. PostgreSQL drops and recreates it. SQLite
cannot alter a CHECK in place, so the table is rebuilt by Alembic batch mode (reflected columns,
constraints, foreign keys and both indexes, the partial global one included).

Downgrade refuses to run while any `http_fetch` row exists: deleting tenant data silently is not
acceptable, so the operator deletes (or exports) those rows first and runs it again.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-17
"""

import warnings
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NAME = "ck_custom_checks_kind_valid"
_UP = "kind IN ('dns_exists', 'dns_matches', 'dns_value_range', 'http_fetch')"
_DOWN = "kind IN ('dns_exists', 'dns_matches', 'dns_value_range')"


def _replace_kind_check(condition: str) -> None:
    name = op.f(_NAME)  # already the final name: no second naming-convention prefix
    if op.get_bind().dialect.name == "sqlite":
        # Reflecting the FK target `users` warns about its expression index; that table is not
        # rebuilt, so the warning says nothing about this migration.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=".*expression-based index.*")
            with op.batch_alter_table("custom_checks", recreate="always") as batch:
                batch.drop_constraint(name, type_="check")
                batch.create_check_constraint(name, condition)
        return
    op.drop_constraint(name, "custom_checks", type_="check")
    op.create_check_constraint(name, "custom_checks", condition)


def upgrade() -> None:
    _replace_kind_check(_UP)


def downgrade() -> None:
    count = op.get_bind().execute(
        sa.text("SELECT count(*) FROM custom_checks WHERE kind = 'http_fetch'")
    )
    if count.scalar_one():
        raise RuntimeError(
            "downgrade 0014 refused: custom_checks holds http_fetch rows; delete them first"
        )
    _replace_kind_check(_DOWN)
