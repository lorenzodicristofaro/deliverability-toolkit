"""Instance-level DNSBL list enablement (M7-05c): one row per list the instance admin enabled.

A row means "enabled": disabling deletes it. The key is an integer `id` (the project's id rule);
`list_id` is unique. `list_id` is a list slug from `seeds/dnsbl.yaml`
(lists live in YAML, so no FK); the admin service accepts only ids present there. The table is
instance-level (no tenant_id): every tenant's runs read the same set. Access goes only through
`app.repositories.dnsbl_enablement.DnsblEnablementRepository`.

The database enforces what an enabled row must carry: an explicit usage-policy acknowledgement
(`ck_dnsbl_list_enablements_policy_acknowledged`) with its timestamp, a lowercase id of 1 to 40
characters. `enabled_by` survives the deletion of the user as NULL.
"""

from datetime import datetime
from typing import Final

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, false
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

MAX_LIST_ID_LENGTH: Final = 40


class DnsblListEnablement(Base):
    __tablename__ = "dnsbl_list_enablements"
    __table_args__ = (
        CheckConstraint(
            f"length(list_id) BETWEEN 1 AND {MAX_LIST_ID_LENGTH}", name="list_id_length"
        ),
        CheckConstraint("list_id = lower(list_id)", name="list_id_lower"),
        CheckConstraint("policy_acknowledged = true", name="policy_acknowledged"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    list_id: Mapped[str] = mapped_column(String(MAX_LIST_ID_LENGTH), nullable=False, unique=True)
    enabled_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    enabled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    policy_acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy_acknowledged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    unverified_confirmed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false(), default=False
    )
