"""Alert channels of a tenant (M7-15): where alert deliveries go.

One row per configured channel: `kind` (email|webhook|slack|teams), a `name` unique in the
tenant, `enabled`, `config` (JSON, NON-secret settings only, e.g. email recipients) and `secret`
(the Fernet token of a JSON object holding the secret settings, e.g. a webhook URL or signing
secret; `app.core.secrets_crypto`, M7-14b). `secret_fields` lists the NAMES of the stored secret
settings, so the API can show which are set (masked) without decrypting anything. The plaintext
is decrypted only at send time and never stored, returned or logged.

UNIQUE (id, tenant_id) is the target for a future composite FK from `alert_deliveries` and
`alert_rules` (their `channel_id` has no FK yet, see `app.models.alert`); until then the
repository deletes a channel's rules and deliveries together with the channel. Deleting the
tenant cascades. Access goes only through `app.repositories.alert_channels`.
"""

from datetime import datetime
from typing import Final

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

CHANNEL_KINDS: Final[tuple[str, ...]] = ("email", "webhook", "slack", "teams")
MAX_CHANNEL_KIND_LENGTH: Final = 16
MAX_CHANNEL_NAME_LENGTH: Final = 100


class AlertChannel(Base):
    __tablename__ = "alert_channels"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name"),
        UniqueConstraint("id", "tenant_id"),
        CheckConstraint(
            "kind IN (" + ", ".join(f"'{k}'" for k in CHANNEL_KINDS) + ")", name="kind_known"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(MAX_CHANNEL_KIND_LENGTH), nullable=False)
    name: Mapped[str] = mapped_column(String(MAX_CHANNEL_NAME_LENGTH), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=true(), default=True
    )
    config: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_fields: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
