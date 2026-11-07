"""Content rules repositories (M5-05). The only access path to `content_rules`.

Two entry points, never mixed:
- `ContentRuleRepository(ctx, session)` (via `repo_for(ctx, session).content_rules`): the tenant
  path. Reads return the global rows plus the context tenant's rows, nothing else. Writes
  (create/update/delete) touch only the context tenant's rows: `scope` is always 'tenant' and
  `tenant_id` comes from the context; a global or foreign id is "not found" (None/False), exactly
  like a missing or malformed id.
- `GlobalContentRuleRepository(session)`: the instance-admin entry point for global rows (admin
  service after the M5-04 `rules.manage` global-scope check, and seed sync). It never reads or
  writes tenant rows. It is NOT reachable through `repo_for`.

Callers get immutable `ContentRuleRecord`s, never ORM objects, so a row cannot be moved across
scopes or tenants by mutating a returned object. An attribute listener additionally refuses
changing `scope`/`tenant_id` of a persisted row anywhere in the process.

Validation before the database (identical outcome on SQLite and PostgreSQL): types, the same
length limits as the CHECK constraints, enumerations, weight and flag bounds, and NUL / lone
surrogate code points (PostgreSQL rejects them, SQLite would store them). Regex patterns are
also run through `app.core.safe_regex.compile_checked`; the service layer (M5-18) still owns the
user-facing validation and error messages. `ContentRuleInvalid` names the field and a stable
reason, never the value.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import ColumnElement, Select, and_, event, func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.base import NEVER_SET, NO_VALUE

from app.core.safe_regex import ALLOWED_FLAGS, MAX_PATTERN_LENGTH, RegexRuleError, compile_checked
from app.core.tenancy import TenantContext
from app.models.content_rule import (
    KINDS,
    MAX_ADVICE_LENGTH,
    MAX_CATEGORY_LENGTH,
    MAX_LANGUAGE_LENGTH,
    MAX_NAME_LENGTH,
    MAX_SEED_KEY_LENGTH,
    MAX_SOURCE_URL_LENGTH,
    MAX_SOURCES,
    MAX_TITLE_LENGTH,
    MAX_WEIGHT,
    MIN_WEIGHT,
    SEVERITIES,
    STATUSES,
    ContentRule,
)
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, TenantScopeError, coerce_id

GLOBAL: Final = "global"
TENANT: Final = "tenant"
GLOBAL_SEED_KEY_INDEX: Final = "uq_content_rules_global_seed_key"
TENANT_SEED_KEY_INDEX: Final = "uq_content_rules_tenant_seed_key"

# Lowercase slugs; category and seed_key are identifiers, not display text.
_SLUG = re.compile(r"[a-z0-9][a-z0-9_.-]*")
# BCP 47-ish short code: primary language subtag plus optional region/script subtags.
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[a-z0-9]{2,8})*")

# Fields a caller may set. scope, tenant_id, id, created_*, updated_at are repository-owned.
_COMMON_FIELDS: Final = frozenset(
    {
        "name",
        "kind",
        "pattern",
        "flags",
        "weight",
        "category",
        "language",
        "enabled",
        "severity",
        "title",
        "advice",
    }
)
_SEED_FIELDS: Final = frozenset({"sources", "verified_on", "status", "seed_key"})
TENANT_FIELDS: Final = _COMMON_FIELDS | {"seed_key"}
GLOBAL_FIELDS: Final = _COMMON_FIELDS | _SEED_FIELDS | {"locally_modified"}
_REQUIRED: Final = frozenset({"name", "kind", "pattern", "weight", "category", "severity"})


class ContentRuleInvalid(ValueError):
    """A field value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"content rule {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class SeedKeyTaken(Exception):
    """Another rule of the same scope (same tenant) already uses this seed_key. If raised by a
    flush, the session is unusable until the caller rolls it back."""


@dataclass(frozen=True, slots=True)
class ContentRuleRecord:
    id: int
    scope: str
    tenant_id: int | None
    name: str
    kind: str
    pattern: str
    flags: int
    weight: int
    category: str
    language: str | None
    enabled: bool
    severity: str
    title: str | None
    advice: str | None
    sources: tuple[str, ...] | None
    verified_on: date | None
    status: str | None
    seed_key: str | None
    locally_modified: bool
    created_at: datetime
    updated_at: datetime
    created_by: int | None

    @classmethod
    def from_model(cls, row: ContentRule) -> ContentRuleRecord:
        return cls(
            id=row.id,
            scope=row.scope,
            tenant_id=row.tenant_id,
            name=row.name,
            kind=row.kind,
            pattern=row.pattern,
            flags=row.flags,
            weight=row.weight,
            category=row.category,
            language=row.language,
            enabled=row.enabled,
            severity=row.severity,
            title=row.title,
            advice=row.advice,
            sources=None if row.sources is None else tuple(row.sources),
            verified_on=row.verified_on,
            status=row.status,
            seed_key=row.seed_key,
            locally_modified=row.locally_modified,
            created_at=row.created_at,
            updated_at=row.updated_at,
            created_by=row.created_by,
        )


# --- validation ----------------------------------------------------------------------------------


def _text(field: str, value: object, maximum: int) -> str:
    if not isinstance(value, str):
        raise ContentRuleInvalid(field, "not_a_string")
    if value == "":
        raise ContentRuleInvalid(field, "empty")
    if len(value) > maximum:
        raise ContentRuleInvalid(field, "too_long")
    if "\x00" in value:
        raise ContentRuleInvalid(field, "nul")
    if any(unicodedata.category(c) == "Cs" for c in value):
        raise ContentRuleInvalid(field, "surrogate")
    return value


def _label(field: str, value: object, maximum: int) -> str:
    """Single-line display text: no control characters at all."""
    result = _text(field, value, maximum)
    if any(unicodedata.category(c) == "Cc" for c in result):
        raise ContentRuleInvalid(field, "control_char")
    if result.strip() != result or not result.strip():
        raise ContentRuleInvalid(field, "whitespace")
    return result


def _paragraphs(field: str, value: object, maximum: int) -> str:
    """Multi-line display text: newlines and tabs allowed, other control characters not."""
    result = _text(field, value, maximum)
    if any(unicodedata.category(c) == "Cc" and c not in "\n\t" for c in result):
        raise ContentRuleInvalid(field, "control_char")
    if not result.strip():
        raise ContentRuleInvalid(field, "whitespace")
    return result


def _sources(value: object) -> list[str] | None:
    """None, or 1..MAX_SOURCES distinct absolute http(s) URLs without whitespace."""
    if value is None:
        return None
    if not isinstance(value, list | tuple):
        raise ContentRuleInvalid("sources", "not_a_list")
    if not value:
        raise ContentRuleInvalid("sources", "empty")
    if len(value) > MAX_SOURCES:
        raise ContentRuleInvalid("sources", "too_many")
    result: list[str] = []
    for item in value:
        url = _label("sources", item, MAX_SOURCE_URL_LENGTH)
        if any(c.isspace() for c in url):
            raise ContentRuleInvalid("sources", "invalid_url")
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            raise ContentRuleInvalid("sources", "invalid_url") from None
        if parts.scheme not in ("http", "https") or not host:
            raise ContentRuleInvalid("sources", "invalid_url")
        if url in result:
            raise ContentRuleInvalid("sources", "duplicate")
        result.append(url)
    return result


def _slug(field: str, value: object, maximum: int) -> str:
    result = _text(field, value, maximum)
    if not _SLUG.fullmatch(result):
        raise ContentRuleInvalid(field, "invalid_format")
    return result


def _int(field: str, value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContentRuleInvalid(field, "not_an_int")
    if not low <= value <= high:
        raise ContentRuleInvalid(field, "out_of_range")
    return value


def _bool(field: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise ContentRuleInvalid(field, "not_a_bool")
    return value


def _choice(field: str, value: object, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ContentRuleInvalid(field, "invalid_choice")
    return value


def _language(value: object) -> str | None:
    if value is None:
        return None
    result = _text("language", value, MAX_LANGUAGE_LENGTH)
    if not result.isascii():
        raise ContentRuleInvalid("language", "invalid_format")
    result = result.lower()
    if not _LANGUAGE.fullmatch(result):
        raise ContentRuleInvalid("language", "invalid_format")
    return result


def _flags(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContentRuleInvalid("flags", "not_an_int")
    if value < 0 or value & ~ALLOWED_FLAGS:
        raise ContentRuleInvalid("flags", "unsupported_flags")
    return value


def _clean(field: str, value: object) -> object:
    match field:
        case "name":
            return _label(field, value, MAX_NAME_LENGTH)
        case "kind":
            return _choice(field, value, KINDS)
        case "pattern":
            return _text(field, value, MAX_PATTERN_LENGTH)
        case "flags":
            return _flags(value)
        case "weight":
            return _int(field, value, MIN_WEIGHT, MAX_WEIGHT)
        case "category":
            return _slug(field, value, MAX_CATEGORY_LENGTH)
        case "language":
            return _language(value)
        case "enabled" | "locally_modified":
            return _bool(field, value)
        case "severity":
            return _choice(field, value, SEVERITIES)
        case "seed_key":
            return None if value is None else _slug(field, value, MAX_SEED_KEY_LENGTH)
        case "title":
            return None if value is None else _label(field, value, MAX_TITLE_LENGTH)
        case "advice":
            return None if value is None else _paragraphs(field, value, MAX_ADVICE_LENGTH)
        case "sources":
            return _sources(value)
        case "status":
            return None if value is None else _choice(field, value, STATUSES)
        case "verified_on":
            # datetime is a date subclass: refuse it, a timestamp is not a verification day.
            if value is None or (isinstance(value, date) and not isinstance(value, datetime)):
                return value
            raise ContentRuleInvalid(field, "not_a_date")
    raise ContentRuleInvalid(field, "unknown_field")


def _clean_values(values: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(values, Mapping):
        raise TypeError("values must be a mapping")
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key in ("scope", "tenant_id"):
            raise TenantScopeError(f"{key} is set by the repository")
        if not isinstance(key, str) or key not in allowed:
            raise ContentRuleInvalid(str(key)[:64], "unknown_field")
        cleaned[key] = _clean(key, value)
    return cleaned


def _check_pattern(kind: str, pattern: str, flags: int) -> None:
    """Regex patterns must compile through the safe_regex gate (never a hand-built rule)."""
    if kind != "regex":
        return
    try:
        compile_checked(pattern, flags)
    except RegexRuleError as exc:
        raise ContentRuleInvalid("pattern", exc.reason.value) from None


def _check_title(seed_key: str | None, title: str | None) -> None:
    """Rules without seed_key carry user-entered text: a title is required (DB CHECK too)."""
    if seed_key is None and title is None:
        raise ContentRuleInvalid("title", "required")


def _check_page(limit: object, offset: object) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an int between 0 and {MAX_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative int")


def is_seed_key_conflict(exc: IntegrityError) -> bool:
    """True only for a violation of one of the seed_key unique indexes. PostgreSQL names the
    index in `diag.constraint_name`; SQLite names only the columns of the index."""
    orig = exc.orig
    diag = getattr(orig, "diag", None)
    if diag is not None:
        return getattr(diag, "constraint_name", None) in (
            GLOBAL_SEED_KEY_INDEX,
            TENANT_SEED_KEY_INDEX,
        )
    if getattr(orig, "sqlite_errorname", None) == "SQLITE_CONSTRAINT_UNIQUE":
        return str(orig) in (
            "UNIQUE constraint failed: content_rules.seed_key",
            "UNIQUE constraint failed: content_rules.tenant_id, content_rules.seed_key",
        )
    return False


# --- scope guard -------------------------------------------------------------------------------


def _refuse_move(target: Any, value: Any, oldvalue: Any, _initiator: Any) -> Any:
    if not sa_inspect(target).has_identity:
        return value
    if oldvalue in (NO_VALUE, NEVER_SET) or value != oldvalue:
        raise TenantScopeError("scope/tenant_id of an existing content rule cannot be changed")
    return value


for _attr in (ContentRule.scope, ContentRule.tenant_id):
    if not event.contains(_attr, "set", _refuse_move):
        event.listen(_attr, "set", _refuse_move, active_history=True, retval=True)


# --- shared base ---------------------------------------------------------------------------------


class _ContentRuleStore:
    __slots__ = ("_session",)

    _fields: frozenset[str]

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("a Session is required")
        self._session = session

    # Visible rows (reads) and writable rows (writes); subclasses decide.
    def _visible(self) -> ColumnElement[bool]:
        raise NotImplementedError

    def _writable(self) -> ColumnElement[bool]:
        raise NotImplementedError

    def _select(self, criterion: ColumnElement[bool]) -> Select[ContentRule]:
        return select(ContentRule).where(criterion)

    def _load(self, id_: object, criterion: ColumnElement[bool]) -> ContentRule | None:
        pk = coerce_id(id_)
        if pk is None:
            return None
        stmt = self._select(criterion).where(ContentRule.id == pk)
        return self._session.scalars(stmt).one_or_none()

    def get(self, id_: object) -> ContentRuleRecord | None:
        """A visible rule by id; None if missing, not visible or malformed."""
        row = self._load(id_, self._visible())
        return None if row is None else ContentRuleRecord.from_model(row)

    def list(
        self, *, enabled_only: bool = False, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[ContentRuleRecord]:
        """Visible rules ordered by id."""
        _check_page(limit, offset)
        stmt = self._select(self._visible())
        if enabled_only:
            stmt = stmt.where(ContentRule.enabled.is_(True))
        stmt = stmt.order_by(ContentRule.id).limit(limit).offset(offset)
        return [ContentRuleRecord.from_model(r) for r in self._session.scalars(stmt).all()]

    def count(self) -> int:
        stmt = select(func.count()).select_from(ContentRule).where(self._visible())
        return int(self._session.scalar(stmt) or 0)

    def _seed_key_taken(self, seed_key: str | None, exclude_id: int | None = None) -> bool:
        if seed_key is None:
            return False
        stmt = self._select(self._writable()).where(ContentRule.seed_key == seed_key)
        if exclude_id is not None:
            stmt = stmt.where(ContentRule.id != exclude_id)
        return self._session.scalars(stmt.limit(1)).first() is not None

    def _check_seed_reference(self, seed_key: str | None) -> None:
        """Hook: the tenant path requires seed_key to name an existing global rule."""

    def _flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError as exc:
            if not is_seed_key_conflict(exc):
                raise
            raise SeedKeyTaken from exc

    def _insert(self, values: Mapping[str, Any], fixed: Mapping[str, Any]) -> ContentRuleRecord:
        cleaned = _clean_values(values, self._fields)
        missing = _REQUIRED - cleaned.keys()
        if missing:
            raise ContentRuleInvalid(sorted(missing)[0], "required")
        _check_pattern(cleaned["kind"], cleaned["pattern"], cleaned.get("flags", 0))
        _check_title(cleaned.get("seed_key"), cleaned.get("title"))
        self._check_seed_reference(cleaned.get("seed_key"))
        if self._seed_key_taken(cleaned.get("seed_key")):
            raise SeedKeyTaken
        row = ContentRule(**cleaned, **fixed)
        self._session.add(row)
        self._flush()
        return ContentRuleRecord.from_model(row)

    def update(self, id_: object, values: Mapping[str, Any]) -> ContentRuleRecord | None:
        """Change fields of a writable rule; None if missing, not writable or malformed."""
        cleaned = _clean_values(values, self._fields)
        row = self._load(id_, self._writable())
        if row is None:
            return None
        _check_pattern(
            cleaned.get("kind", row.kind),
            cleaned.get("pattern", row.pattern),
            cleaned.get("flags", row.flags),
        )
        _check_title(cleaned.get("seed_key", row.seed_key), cleaned.get("title", row.title))
        if "seed_key" in cleaned:
            self._check_seed_reference(cleaned["seed_key"])
        if "seed_key" in cleaned and self._seed_key_taken(cleaned["seed_key"], row.id):
            raise SeedKeyTaken
        for key, value in cleaned.items():
            setattr(row, key, value)
        self._flush()
        return ContentRuleRecord.from_model(row)

    def delete(self, id_: object) -> bool:
        """Delete a writable rule; False if missing, not writable or malformed."""
        row = self._load(id_, self._writable())
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True


def _global_criterion() -> ColumnElement[bool]:
    return and_(ContentRule.scope == GLOBAL, ContentRule.tenant_id.is_(None))


class ContentRuleRepository(_ContentRuleStore):
    """Tenant path: reads global + context tenant rows; writes only context tenant rows."""

    __slots__ = ("_ctx",)

    _fields = TENANT_FIELDS

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        super().__init__(session)
        self._ctx = ctx

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _writable(self) -> ColumnElement[bool]:
        return and_(ContentRule.scope == TENANT, ContentRule.tenant_id == self._ctx.tenant_id)

    def _visible(self) -> ColumnElement[bool]:
        return or_(_global_criterion(), self._writable())

    def _check_seed_reference(self, seed_key: str | None) -> None:
        # A tenant seed_key only overrides a seeded global rule; it never invents one.
        if seed_key is None:
            return
        stmt = self._select(_global_criterion()).where(ContentRule.seed_key == seed_key)
        if self._session.scalars(stmt.limit(1)).first() is None:
            raise ContentRuleInvalid("seed_key", "unknown")

    def create(self, values: Mapping[str, Any]) -> ContentRuleRecord:
        """Insert a tenant rule; scope, tenant_id and created_by come from the context."""
        return self._insert(
            values,
            {"scope": TENANT, "tenant_id": self._ctx.tenant_id, "created_by": self._ctx.principal},
        )


class GlobalContentRuleRepository(_ContentRuleStore):
    """Instance-admin entry point for global rows only (admin service after the M5-04 global
    `rules.manage` check, and seed sync). Not reachable through `repo_for`."""

    __slots__ = ()

    _fields = GLOBAL_FIELDS

    def _writable(self) -> ColumnElement[bool]:
        return _global_criterion()

    def _visible(self) -> ColumnElement[bool]:
        return _global_criterion()

    def get_by_seed_key(self, seed_key: str) -> ContentRuleRecord | None:
        if not isinstance(seed_key, str):
            return None
        stmt = self._select(self._visible()).where(ContentRule.seed_key == seed_key)
        row = self._session.scalars(stmt).one_or_none()
        return None if row is None else ContentRuleRecord.from_model(row)

    def create(self, values: Mapping[str, Any], *, actor: int | None) -> ContentRuleRecord:
        """Insert a global rule. `actor` is the instance admin's user id (None for seed sync)."""
        if actor is not None and coerce_id(actor) is None:
            raise ValueError("actor must be a positive integer user id or None")
        return self._insert(values, {"scope": GLOBAL, "tenant_id": None, "created_by": actor})
