"""alert_channels (M7-15): a tenant's alert channels with encrypted secret settings.

`config` holds non-secret settings (JSON), `secret` the Fernet token of the secret ones
(`app.core.secrets_crypto`), `secret_fields` their names. UNIQUE (tenant_id, name), UNIQUE
(id, tenant_id) (target of a later composite FK), CHECK on `kind`; deleting the tenant cascades.

No FK from `alert_deliveries.channel_id` / `alert_rules.channel_id` is added here: the M7-14
tests and constraint fixtures use free channel ids, so the FK needs its own ticket. Until then
the repository deletes a channel's rules and deliveries with the channel.

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_channels",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("secret_fields", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('email', 'webhook', 'slack', 'teams')",
            name=op.f("ck_alert_channels_kind_known"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_alert_channels_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_channels")),
        sa.UniqueConstraint("id", "tenant_id", name=op.f("uq_alert_channels_id_tenant_id")),
        sa.UniqueConstraint("tenant_id", "name", name=op.f("uq_alert_channels_tenant_id_name")),
    )


def downgrade() -> None:
    op.drop_table("alert_channels")
