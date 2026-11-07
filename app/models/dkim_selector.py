"""DKIM selectors (M5-06): global rows (`scope = 'global'`, `tenant_id` NULL, seeded from
`seeds/dkim_selectors.yaml` or instance-managed) and tenant rows (`scope = 'tenant'`, `tenant_id`
set). The database enforces the scope/tenant pairing, the enumerations, every string length
(CHECK on `length()`, which counts characters on SQLite and PostgreSQL alike), a lowercase
selector, and that only global rows carry a seed_key.

`selector` is unique per scope: once among global rows (partial unique index, since NULL
tenant_id never collides in a plain one) and once per tenant (unique (tenant_id, selector)).

Access goes only through `app.repositories.dkim_selectors`; the repository also validates the
selector as a single DNS label (the M3 seed rule) and rejects NUL, surrogate and control
characters before the database.
"""

from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

SCOPES = ("global", "tenant")
RECORD_TYPES = ("txt", "cname", "either")
STATUSES = ("verified", "unverified")

MAX_SELECTOR_LENGTH = 63  # one DNS label
MAX_PROVIDER_LENGTH = 64
MAX_NOTES_LENGTH = 500
MAX_SEED_KEY_LENGTH = 63  # the seed key is the seed entry's selector name
MAX_SOURCES = 10
MAX_SOURCE_URL_LENGTH = 2048


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _len(column: str, maximum: int, *, nullable: bool = False) -> str:
    bound = f"length({column}) BETWEEN 1 AND {maximum}"
    return f"{column} IS NULL OR ({bound})" if nullable else bound


class DkimSelector(Base):
    __tablename__ = "dkim_selectors"
    __table_args__ = (
        CheckConstraint(_in("scope", SCOPES), name="scope_valid"),
        CheckConstraint(
            "(scope = 'global' AND tenant_id IS NULL)"
            " OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name="scope_tenant",
        ),
        CheckConstraint(_in("record_type", RECORD_TYPES), name="record_type_valid"),
        CheckConstraint(f"status IS NULL OR {_in('status', STATUSES)}", name="status_valid"),
        CheckConstraint(_len("selector", MAX_SELECTOR_LENGTH), name="selector_length"),
        CheckConstraint("selector = lower(selector)", name="selector_lower"),
        CheckConstraint(
            _len("provider", MAX_PROVIDER_LENGTH, nullable=True), name="provider_length"
        ),
        CheckConstraint(_len("notes", MAX_NOTES_LENGTH, nullable=True), name="notes_length"),
        CheckConstraint(
            _len("seed_key", MAX_SEED_KEY_LENGTH, nullable=True), name="seed_key_length"
        ),
        # Seed sync only manages global rows; tenant rows are tenant-entered selectors.
        CheckConstraint("seed_key IS NULL OR scope = 'global'", name="seed_key_global"),
        Index(
            "uq_dkim_selectors_global_selector",
            "selector",
            unique=True,
            sqlite_where=text("scope = 'global'"),
            postgresql_where=text("scope = 'global'"),
        ),
        # Plain unique index: global rows have tenant_id NULL and NULLs never collide (SQLite and
        # PostgreSQL default). It also serves tenant_id lookups. Not partial on purpose: SQLite
        # 3.53 raises "internal query planner error" for the tenant OR-filter with bound
        # parameters when a partial (tenant_id, ...) WHERE scope = 'tenant' index sits next to a
        # plain tenant_id index.
        Index("uq_dkim_selectors_tenant_selector", "tenant_id", "selector", unique=True),
        Index(
            "uq_dkim_selectors_global_seed_key",
            "seed_key",
            unique=True,
            sqlite_where=text("seed_key IS NOT NULL"),
            postgresql_where=text("seed_key IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    selector: Mapped[str] = mapped_column(String(MAX_SELECTOR_LENGTH), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(MAX_PROVIDER_LENGTH), nullable=True)
    record_type: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'either'")
    )
    notes: Mapped[str | None] = mapped_column(String(MAX_NOTES_LENGTH), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    # JSON list of https URLs from the seed entry (validated by the repository).
    sources: Mapped[list[str] | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    verified_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    seed_key: Mapped[str | None] = mapped_column(String(MAX_SEED_KEY_LENGTH), nullable=True)
    # Set when an instance admin edits a seeded row, so seed sync keeps the edit.
    locally_modified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
