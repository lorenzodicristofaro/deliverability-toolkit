"""alerts, alert_deliveries, alert_rules (M7-14): alert state, dedup and delivery records.

`alerts` has UNIQUE (tenant_id, fingerprint, state_hash), the dedup point of alert creation
(INSERT .. ON CONFLICT DO NOTHING on SQLite and PostgreSQL), and UNIQUE (id, tenant_id) as the
target of the composite FK from `alert_deliveries`. Composite FK (domain_id, tenant_id) ->
domains(id, tenant_id); deleting the domain, the alert or the tenant cascades. `channel_id` has
no FK until the channels table (M7-15). CHECK constraints keep `kind` to the change event kinds
and the delivery `status` to pending|sent|failed|abandoned.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# app.models.alert.KINDS / DELIVERY_STATUSES at the time of this revision.
_KINDS = (
    "'record_changed', 'new_listing', 'listing_cleared', 'policy_regression', "
    "'check_error_started', 'check_error_cleared'"
)
_STATUSES = "'pending', 'sent', 'failed', 'abandoned'"


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("stream", sa.String(length=64), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("suppressed", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(f"kind IN ({_KINDS})", name=op.f("ck_alerts_kind_known")),
        sa.ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            name=op.f("fk_alerts_domain_id_tenant_id_domains"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_alerts_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.UniqueConstraint(
            "tenant_id",
            "fingerprint",
            "state_hash",
            name=op.f("uq_alerts_tenant_id_fingerprint_state_hash"),
        ),
        sa.UniqueConstraint("id", "tenant_id", name=op.f("uq_alerts_id_tenant_id")),
    )
    op.create_index(
        "ix_alerts_tenant_domain_stream_id",
        "alerts",
        ["tenant_id", "domain_id", "stream", "id"],
    )
    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("alert_id", sa.Integer(), nullable=False),
        sa.Column("channel_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=64), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            f"status IN ({_STATUSES})", name=op.f("ck_alert_deliveries_status_known")
        ),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_alert_deliveries_attempts_non_negative")),
        sa.ForeignKeyConstraint(
            ["alert_id", "tenant_id"],
            ["alerts.id", "alerts.tenant_id"],
            name=op.f("fk_alert_deliveries_alert_id_tenant_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_alert_deliveries_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_deliveries")),
        sa.UniqueConstraint(
            "alert_id", "channel_id", name=op.f("uq_alert_deliveries_alert_id_channel_id")
        ),
    )
    op.create_index(
        "ix_alert_deliveries_tenant_status_next",
        "alert_deliveries",
        ["tenant_id", "status", "next_attempt_at"],
    )
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("channel_id", sa.Integer(), nullable=False),
        sa.CheckConstraint(f"kind IN ({_KINDS})", name=op.f("ck_alert_rules_kind_known")),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_alert_rules_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_rules")),
        sa.UniqueConstraint(
            "tenant_id",
            "kind",
            "channel_id",
            name=op.f("uq_alert_rules_tenant_id_kind_channel_id"),
        ),
    )


def downgrade() -> None:
    op.drop_table("alert_rules")
    op.drop_index("ix_alert_deliveries_tenant_status_next", table_name="alert_deliveries")
    op.drop_table("alert_deliveries")
    op.drop_index("ix_alerts_tenant_domain_stream_id", table_name="alerts")
    op.drop_table("alerts")
