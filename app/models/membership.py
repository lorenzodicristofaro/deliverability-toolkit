"""Memberships (user in tenant, with a role) and per-domain access for restricted members.

`domain_access` carries `tenant_id` and two composite FKs, (membership_id, tenant_id) ->
memberships(id, tenant_id) and (domain_id, tenant_id) -> domains(id, tenant_id), so the database
rejects a membership and a domain from different tenants on SQLite and PostgreSQL alike.
"""

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class MembershipRole(enum.StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    CLIENT_VIEWER = "client_viewer"


def _role_values(enum_cls: type[MembershipRole]) -> list[str]:
    return [member.value for member in enum_cls]


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id"),
        # Target of the composite FK from domain_access (redundant with the PK on purpose).
        UniqueConstraint("id", "tenant_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # RESTRICT: users are deactivated (is_active), not deleted, while they hold memberships.
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[MembershipRole] = mapped_column(
        Enum(
            MembershipRole,
            name="membership_role",
            native_enum=False,
            create_constraint=True,
            length=20,
            values_callable=_role_values,
            validate_strings=True,
        ),
        nullable=False,
    )
    feature_toggles: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class DomainAccess(Base):
    __tablename__ = "domain_access"
    __table_args__ = (
        ForeignKeyConstraint(
            ["membership_id", "tenant_id"],
            ["memberships.id", "memberships.tenant_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["domain_id", "tenant_id"],
            ["domains.id", "domains.tenant_id"],
            ondelete="CASCADE",
        ),
    )

    membership_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
