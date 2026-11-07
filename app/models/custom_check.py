"""Custom checks (M5-07): global checks (`scope = 'global'`, `tenant_id` NULL, instance-managed)
and tenant checks (`scope = 'tenant'`, `tenant_id` set). The database enforces the scope/tenant
pairing, the enumerations, every string length (CHECK on `length()`, which counts characters on
SQLite and PostgreSQL alike), a size cap on the JSON columns and exactly one remediation source.

`kind` deliberately excludes `http_fetch` (reserved, deferred to M7 with the guarded outbound
client; see M5-22): the CHECK refuses it even for a raw insert.

`definition` is stored opaquely as a JSON object; its schema is validated by the M5-22 service
layer, not here. The JSON size CHECKs measure `CAST(column AS TEXT)`: both backends keep the
text SQLAlchemy sent (`json.dumps`, ASCII-only), so the repository measures exactly the same
length before the database.

`check_key` (a stable lowercase slug; not `key`, an SQL keyword) is unique per scope: once among
global rows (partial unique index, since NULL tenant_id never collides in a plain one) and once
per tenant (plain unique (tenant_id, check_key)).

Access goes only through `app.repositories.custom_checks`; the repository also rejects NUL,
surrogate and control characters before the database.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.i18n import SUPPORTED_LANGUAGES
from app.models.base import Base

SCOPES = ("global", "tenant")
KINDS = ("dns_exists", "dns_matches", "dns_value_range")
# Reserved for M7 (outbound HTTP through the guarded client); refused by the DB and repository.
RESERVED_KINDS = ("http_fetch",)
SEVERITIES = ("critical", "high", "medium", "low", "info")
# remediation_text carries one entry per supported language, all required.
REMEDIATION_LANGUAGES: tuple[str, ...] = tuple(SUPPORTED_LANGUAGES)

MAX_KEY_LENGTH = 64
MAX_NAME_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_REMEDIATION_KEY_LENGTH = 200
MAX_REMEDIATION_LENGTH = 2000  # characters per language
# Serialized (json.dumps, ASCII) length of `definition`; enforced exactly by repository and DB.
MAX_DEFINITION_LENGTH = 16384
MAX_DEFINITION_DEPTH = 16
# DB backstop for remediation_text: the worst case escapes one character as 12 ASCII characters
# (an astral code point becomes a \\uXXXX\\uXXXX pair); the repository enforces the exact
# per-language MAX_REMEDIATION_LENGTH. Migration 0008 hardcodes this value (pinned by a test).
MAX_REMEDIATION_JSON_LENGTH = len(REMEDIATION_LANGUAGES) * (12 * MAX_REMEDIATION_LENGTH + 16)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _len(column: str, maximum: int, *, nullable: bool = False) -> str:
    bound = f"length({column}) BETWEEN 1 AND {maximum}"
    return f"{column} IS NULL OR ({bound})" if nullable else bound


def _json_object(column: str, maximum: int, *, nullable: bool = False) -> str:
    as_text = f"CAST({column} AS TEXT)"
    bound = f"length({as_text}) BETWEEN 2 AND {maximum} AND substr({as_text}, 1, 1) = '{{'"
    return f"{column} IS NULL OR ({bound})" if nullable else bound


class CustomCheck(Base):
    __tablename__ = "custom_checks"
    __table_args__ = (
        CheckConstraint(_in("scope", SCOPES), name="scope_valid"),
        CheckConstraint(
            "(scope = 'global' AND tenant_id IS NULL)"
            " OR (scope = 'tenant' AND tenant_id IS NOT NULL)",
            name="scope_tenant",
        ),
        CheckConstraint(_in("kind", KINDS), name="kind_valid"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity_valid"),
        CheckConstraint(_len("check_key", MAX_KEY_LENGTH), name="check_key_length"),
        CheckConstraint("check_key = lower(check_key)", name="check_key_lower"),
        CheckConstraint(_len("name", MAX_NAME_LENGTH), name="name_length"),
        CheckConstraint(
            _len("description", MAX_DESCRIPTION_LENGTH, nullable=True), name="description_length"
        ),
        CheckConstraint(_json_object("definition", MAX_DEFINITION_LENGTH), name="definition_size"),
        CheckConstraint(
            _len("remediation_key", MAX_REMEDIATION_KEY_LENGTH, nullable=True),
            name="remediation_key_length",
        ),
        CheckConstraint(
            _json_object("remediation_text", MAX_REMEDIATION_JSON_LENGTH, nullable=True),
            name="remediation_text_size",
        ),
        # Exactly one remediation source: an i18n key, or admin-written text in every language.
        CheckConstraint(
            "(remediation_key IS NOT NULL AND remediation_text IS NULL)"
            " OR (remediation_key IS NULL AND remediation_text IS NOT NULL)",
            name="remediation_one",
        ),
        Index(
            "uq_custom_checks_global_check_key",
            "check_key",
            unique=True,
            sqlite_where=text("scope = 'global'"),
            postgresql_where=text("scope = 'global'"),
        ),
        # Plain unique index: global rows have tenant_id NULL and NULLs never collide (SQLite and
        # PostgreSQL default). It also serves tenant_id lookups. Not partial on purpose: SQLite
        # 3.46/3.53 raise "internal query planner error" for the tenant OR-filter plus check_key
        # with bound parameters when a partial (tenant_id, ...) WHERE scope = 'tenant' index
        # exists.
        Index("uq_custom_checks_tenant_check_key", "tenant_id", "check_key", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[int | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    check_key: Mapped[str] = mapped_column(String(MAX_KEY_LENGTH), nullable=False)
    name: Mapped[str] = mapped_column(String(MAX_NAME_LENGTH), nullable=False)
    description: Mapped[str | None] = mapped_column(String(MAX_DESCRIPTION_LENGTH), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON(none_as_null=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    remediation_key: Mapped[str | None] = mapped_column(
        String(MAX_REMEDIATION_KEY_LENGTH), nullable=True
    )
    # {"en": "...", "it": "..."}: admin-written remediation, every supported language required.
    remediation_text: Mapped[dict[str, str] | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
