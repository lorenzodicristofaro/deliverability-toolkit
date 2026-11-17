"""domains (M7-21a): ownership verification state.

Adds five nullable-or-defaulted columns to `domains`: `verification_status` (NOT NULL, default
`unverified`, so every existing domain migrates as unverified), `verified_at`,
`verification_method`, `verification_token_hash` (SHA-256 hex of the pending token, never the
token) and `verification_token_expires_at`.

The three CHECKs are single-column. PostgreSQL adds the columns, then the named constraints.
SQLite cannot add a constraint to an existing table, but `ALTER TABLE ... ADD COLUMN` accepts a
named column CHECK, so each checked column is added together with its CHECK: the `domains` table,
target of many foreign keys, is never rebuilt (a rebuild drops the parent table, which with
foreign keys on would cascade-delete child rows).

Downgrade drops the columns (and their constraints) on both backends; verification state is lost,
nothing else is. SQLite needs 3.35 or later for DROP COLUMN.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "domains"
# (column, SQL type, NOT NULL default or None, constraint name, condition)
_CHECKED = (
    (
        "verification_status",
        "VARCHAR(16)",
        "'unverified'",
        "ck_domains_verification_status_valid",
        "verification_status IN ('unverified', 'verified')",
    ),
    (
        "verification_method",
        "VARCHAR(16)",
        None,
        "ck_domains_verification_method_valid",
        "verification_method IS NULL OR verification_method IN ('dns_txt', 'email')",
    ),
    (
        "verification_token_hash",
        "VARCHAR(64)",
        None,
        "ck_domains_verification_token_hash_length",
        "verification_token_hash IS NULL OR length(verification_token_hash) = 64",
    ),
)
_DATES = ("verified_at", "verification_token_expires_at")
_ORDER = (
    "verification_status",
    "verified_at",
    "verification_method",
    "verification_token_hash",
    "verification_token_expires_at",
)


def upgrade() -> None:
    sqlite = op.get_bind().dialect.name == "sqlite"
    for column, sql_type, default, name, condition in _CHECKED:
        if sqlite:
            required = f" DEFAULT {default} NOT NULL" if default is not None else ""
            op.execute(
                f"ALTER TABLE {_TABLE} ADD COLUMN {column} {sql_type}{required} "
                f"CONSTRAINT {name} CHECK ({condition})"
            )
            continue
        length = int(sql_type.split("(")[1].rstrip(")"))
        op.add_column(
            _TABLE,
            sa.Column(
                column,
                sa.String(length),
                nullable=default is None,
                server_default=sa.text(default) if default is not None else None,
            ),
        )
        op.create_check_constraint(op.f(name), _TABLE, condition)
    for column in _DATES:
        op.add_column(_TABLE, sa.Column(column, sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    sqlite = op.get_bind().dialect.name == "sqlite"
    for column in reversed(_ORDER):
        if sqlite:
            op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN {column}")
        else:
            op.drop_column(_TABLE, column)  # drops the column's CHECK with it
