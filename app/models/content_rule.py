"""Content rules (M5-05): global rules (`scope = 'global'`, `tenant_id` NULL, instance-managed or
seeded) and tenant rules (`scope = 'tenant'`, `tenant_id` set). The database enforces the
scope/tenant pairing, the enumerations, the bounds and every string length, identically on
SQLite and PostgreSQL (CHECK on `length()`, which counts characters on both).

Access goes only through `app.repositories.content_rules`; the repository also rejects NUL and
surrogate code points before the database (PostgreSQL refuses NUL in text, SQLite stores it).
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

from app.core.safe_regex import ALLOWED_FLAGS, MAX_PATTERN_LENGTH
from app.models.base import Base

SCOPES = ("global", "tenant")
KINDS = ("regex", "keyword")
SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("verified", "unverified")

MAX_NAME_LENGTH = 200
MAX_CATEGORY_LENGTH = 64
MAX_LANGUAGE_LENGTH = 16
MAX_SEED_KEY_LENGTH = 128
MAX_TITLE_LENGTH = 200
MAX_ADVICE_LENGTH = 2000
MAX_SOURCES = 10
MAX_SOURCE_URL_LENGTH = 2048
MIN_WEIGHT = 0
MAX_WEIGHT = 100

# Migration 0005 writes this literal; tests pin it to ALLOWED_FLAGS.
FLAGS_MASK = ALLOWED_FLAGS


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _len(column: str, maximum: int, *, nullable: bool = False) -> str:
    bound = f"length({column}) BETWEEN 1 AND {maximum}"
    return f"{column} IS NULL OR ({bound})" if nullable else bound


class ContentRule(Base):
    __tablename__ = "content_rules"
    __table_args__ = (
        CheckConstraint(_in("scope", SCOPES), name="scope_valid"),
        CheckConstraint(
            "(scope = 'global' AND tenant_id IS NULL)"
            " OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name="scope_tenant",
        ),
        CheckConstraint(_in("kind", KINDS), name="kind_valid"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity_valid"),
        CheckConstraint(f"status IS NULL OR {_in('status', STATUSES)}", name="status_valid"),
        CheckConstraint(f"weight BETWEEN {MIN_WEIGHT} AND {MAX_WEIGHT}", name="weight_range"),
        CheckConstraint(f"(flags | {FLAGS_MASK}) = {FLAGS_MASK}", name="flags_allowed"),
        CheckConstraint(_len("name", MAX_NAME_LENGTH), name="name_length"),
        CheckConstraint(_len("pattern", MAX_PATTERN_LENGTH), name="pattern_length"),
        CheckConstraint(_len("category", MAX_CATEGORY_LENGTH), name="category_length"),
        CheckConstraint(
            _len("language", MAX_LANGUAGE_LENGTH, nullable=True), name="language_length"
        ),
        CheckConstraint("language IS NULL OR language = lower(language)", name="language_lower"),
        CheckConstraint(
            _len("seed_key", MAX_SEED_KEY_LENGTH, nullable=True), name="seed_key_length"
        ),
        CheckConstraint(_len("title", MAX_TITLE_LENGTH, nullable=True), name="title_length"),
        CheckConstraint(_len("advice", MAX_ADVICE_LENGTH, nullable=True), name="advice_length"),
        # Seeded rules take their text from i18n keys derived from seed_key; any other rule
        # carries user-entered text and needs a title.
        CheckConstraint("seed_key IS NOT NULL OR title IS NOT NULL", name="title_required"),
        # seed_key is unique per scope: once among global rows, once per tenant among its rows.
        Index(
            "uq_content_rules_global_seed_key",
            "seed_key",
            unique=True,
            sqlite_where=text("scope = 'global' AND seed_key IS NOT NULL"),
            postgresql_where=text("scope = 'global' AND seed_key IS NOT NULL"),
        ),
        # Plain unique index (migration 0007): global rows have tenant_id NULL and rules without
        # a seed_key have seed_key NULL; NULLs never collide (SQLite and PostgreSQL default). It
        # also serves tenant_id lookups. Not partial on purpose: SQLite 3.46/3.53 raise "internal
        # query planner error" for the tenant OR-filter plus seed_key with bound parameters when
        # a partial (tenant_id, seed_key) WHERE scope = 'tenant' index sits next to a plain
        # tenant_id index.
        Index("uq_content_rules_tenant_seed_key", "tenant_id", "seed_key", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(MAX_NAME_LENGTH), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    pattern: Mapped[str] = mapped_column(String(MAX_PATTERN_LENGTH), nullable=False)
    flags: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    weight: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(MAX_CATEGORY_LENGTH), nullable=False)
    language: Mapped[str | None] = mapped_column(String(MAX_LANGUAGE_LENGTH), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # User-entered text of admin-authored rules, written in the rule's `language`.
    title: Mapped[str | None] = mapped_column(String(MAX_TITLE_LENGTH), nullable=True)
    advice: Mapped[str | None] = mapped_column(String(MAX_ADVICE_LENGTH), nullable=True)
    # JSON list of http(s) URLs (at most MAX_SOURCES); validated by the repository, the database
    # only stores it (no portable JSON CHECK on SQLite and PostgreSQL).
    sources: Mapped[list[str] | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    verified_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    seed_key: Mapped[str | None] = mapped_column(String(MAX_SEED_KEY_LENGTH), nullable=True)
    # Set when an admin edits a seed-derived row, so seed sync (M5-12) keeps the edit.
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
