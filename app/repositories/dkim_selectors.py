"""DKIM selector repositories (M5-06). The only access path to `dkim_selectors`.

Two entry points, never mixed (same rules as `app.repositories.content_rules`):
- `DkimSelectorRepository(ctx, session)` (via `repo_for(ctx, session).dkim_selectors`): the
  tenant path. Reads return the global rows plus the context tenant's rows, nothing else. Writes
  touch only the context tenant's rows: `scope` is always 'tenant' and `tenant_id` comes from the
  context; a global or foreign id is "not found" (None/False), exactly like a missing or
  malformed id. Tenant rows never carry seed fields (seed_key, status, verified_on, sources).
- `GlobalDkimSelectorRepository(session)`: the instance-admin entry point for global rows (admin
  service after the M5-04 global-scope check, and seed sync). It never reads or writes tenant
  rows. It is NOT reachable through `repo_for`.

Callers get immutable `DkimSelectorRecord`s, never ORM objects; an attribute listener refuses
changing `scope`/`tenant_id` of a persisted row anywhere in the process.

Validation before the database (identical outcome on SQLite and PostgreSQL): types, the same
length limits as the CHECK constraints, enumerations, NUL / lone surrogate / control
characters, and the selector as a single DNS label with the M3 seed rule
(`app.dns.types._validate_name` plus "no dot"). `DkimSelectorInvalid` names the field and a
stable reason, never the value.
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

from app.core.tenancy import TenantContext
from app.dns.types import _validate_name
from app.models.dkim_selector import (
    MAX_NOTES_LENGTH,
    MAX_PROVIDER_LENGTH,
    MAX_SEED_KEY_LENGTH,
    MAX_SELECTOR_LENGTH,
    MAX_SOURCE_URL_LENGTH,
    MAX_SOURCES,
    RECORD_TYPES,
    STATUSES,
    DkimSelector,
)
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, TenantScopeError, coerce_id

GLOBAL: Final = "global"
TENANT: Final = "tenant"
GLOBAL_SELECTOR_INDEX: Final = "uq_dkim_selectors_global_selector"
TENANT_SELECTOR_INDEX: Final = "uq_dkim_selectors_tenant_selector"
SEED_KEY_INDEX: Final = "uq_dkim_selectors_global_seed_key"

# Provider is an identifier (e.g. google_workspace), not display text.
_SLUG = re.compile(r"[a-z0-9][a-z0-9_.-]*")

TENANT_FIELDS: Final = frozenset({"selector", "provider", "record_type", "notes", "enabled"})
GLOBAL_FIELDS: Final = TENANT_FIELDS | {
    "sources",
    "verified_on",
    "status",
    "seed_key",
    "locally_modified",
}


class DkimSelectorInvalid(ValueError):
    """A field value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"dkim selector {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class SelectorTaken(Exception):
    """The selector (or seed_key) already exists in the same scope (same tenant). If raised by a
    flush, the session is unusable until the caller rolls it back."""


@dataclass(frozen=True, slots=True)
class DkimSelectorRecord:
    id: int
    scope: str
    tenant_id: int | None
    selector: str
    provider: str | None
    record_type: str
    notes: str | None
    enabled: bool
    sources: tuple[str, ...] | None
    verified_on: date | None
    status: str | None
    seed_key: str | None
    locally_modified: bool
    created_at: datetime
    updated_at: datetime
    created_by: int | None

    @classmethod
    def from_model(cls, row: DkimSelector) -> DkimSelectorRecord:
        return cls(
            id=row.id,
            scope=row.scope,
            tenant_id=row.tenant_id,
            selector=row.selector,
            provider=row.provider,
            record_type=row.record_type,
            notes=row.notes,
            enabled=row.enabled,
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


def _label(field: str, value: object, maximum: int) -> str:
    """Single-line text: no NUL, surrogates or control characters, no surrounding whitespace."""
    if not isinstance(value, str):
        raise DkimSelectorInvalid(field, "not_a_string")
    if value == "":
        raise DkimSelectorInvalid(field, "empty")
    if len(value) > maximum:
        raise DkimSelectorInvalid(field, "too_long")
    if "\x00" in value:
        raise DkimSelectorInvalid(field, "nul")
    if any(unicodedata.category(c) == "Cs" for c in value):
        raise DkimSelectorInvalid(field, "surrogate")
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise DkimSelectorInvalid(field, "control_char")
    if value.strip() != value:
        raise DkimSelectorInvalid(field, "whitespace")
    return value


def _dns_label(field: str, value: object) -> str:
    """A single DNS label, validated exactly like the M3 seed (lowercase ASCII, printable)."""
    result = _label(field, value, MAX_SELECTOR_LENGTH)
    try:
        _validate_name(result)
    except ValueError:
        raise DkimSelectorInvalid(field, "invalid_label") from None
    if "." in result:
        raise DkimSelectorInvalid(field, "not_a_label")
    return result


def _sources(value: object) -> list[str] | None:
    """None, or 1..MAX_SOURCES distinct absolute http(s) URLs without whitespace."""
    if value is None:
        return None
    if not isinstance(value, list | tuple):
        raise DkimSelectorInvalid("sources", "not_a_list")
    if not value:
        raise DkimSelectorInvalid("sources", "empty")
    if len(value) > MAX_SOURCES:
        raise DkimSelectorInvalid("sources", "too_many")
    result: list[str] = []
    for item in value:
        url = _label("sources", item, MAX_SOURCE_URL_LENGTH)
        if any(c.isspace() for c in url):
            raise DkimSelectorInvalid("sources", "invalid_url")
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            raise DkimSelectorInvalid("sources", "invalid_url") from None
        if parts.scheme not in ("http", "https") or not host:
            raise DkimSelectorInvalid("sources", "invalid_url")
        if url in result:
            raise DkimSelectorInvalid("sources", "duplicate")
        result.append(url)
    return result


def _choice(field: str, value: object, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise DkimSelectorInvalid(field, "invalid_choice")
    return value


def _bool(field: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise DkimSelectorInvalid(field, "not_a_bool")
    return value


def _clean(field: str, value: object) -> object:
    match field:
        case "selector":
            return _dns_label(field, value)
        case "provider":
            if value is None:
                return None
            result = _label(field, value, MAX_PROVIDER_LENGTH)
            if not _SLUG.fullmatch(result):
                raise DkimSelectorInvalid(field, "invalid_format")
            return result
        case "record_type":
            return _choice(field, value, RECORD_TYPES)
        case "notes":
            return None if value is None else _label(field, value, MAX_NOTES_LENGTH)
        case "enabled" | "locally_modified":
            return _bool(field, value)
        case "seed_key":
            if value is None:
                return None
            if isinstance(value, str) and len(value) > MAX_SEED_KEY_LENGTH:
                raise DkimSelectorInvalid(field, "too_long")
            return _dns_label(field, value)
        case "sources":
            return _sources(value)
        case "status":
            return None if value is None else _choice(field, value, STATUSES)
        case "verified_on":
            # datetime is a date subclass: refuse it, a timestamp is not a verification day.
            if value is None or (isinstance(value, date) and not isinstance(value, datetime)):
                return value
            raise DkimSelectorInvalid(field, "not_a_date")
    raise DkimSelectorInvalid(field, "unknown_field")


def _clean_values(values: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(values, Mapping):
        raise TypeError("values must be a mapping")
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key in ("scope", "tenant_id"):
            raise TenantScopeError(f"{key} is set by the repository")
        if not isinstance(key, str) or key not in allowed:
            raise DkimSelectorInvalid(str(key)[:64], "unknown_field")
        cleaned[key] = _clean(key, value)
    return cleaned


def clean_global_values(values: Mapping[str, Any]) -> dict[str, Any]:
    """Validate global-row values without touching the database (seed sync checks the whole
    seed this way before its first write, so a bad entry never leaves a partial sync)."""
    return _clean_values(values, GLOBAL_FIELDS)


def _check_page(limit: object, offset: object) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an int between 0 and {MAX_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative int")


def is_unique_conflict(exc: IntegrityError) -> bool:
    """True only for a violation of one of the dkim_selectors unique indexes. PostgreSQL names
    the index in `diag.constraint_name`; SQLite names only the columns of the index."""
    orig = exc.orig
    diag = getattr(orig, "diag", None)
    if diag is not None:
        return getattr(diag, "constraint_name", None) in (
            GLOBAL_SELECTOR_INDEX,
            TENANT_SELECTOR_INDEX,
            SEED_KEY_INDEX,
        )
    if getattr(orig, "sqlite_errorname", None) == "SQLITE_CONSTRAINT_UNIQUE":
        return str(orig) in (
            "UNIQUE constraint failed: dkim_selectors.selector",
            "UNIQUE constraint failed: dkim_selectors.tenant_id, dkim_selectors.selector",
            "UNIQUE constraint failed: dkim_selectors.seed_key",
        )
    return False


# --- scope guard -------------------------------------------------------------------------------


def _refuse_move(target: Any, value: Any, oldvalue: Any, _initiator: Any) -> Any:
    if not sa_inspect(target).has_identity:
        return value
    if oldvalue in (NO_VALUE, NEVER_SET) or value != oldvalue:
        raise TenantScopeError("scope/tenant_id of an existing dkim selector cannot be changed")
    return value


for _attr in (DkimSelector.scope, DkimSelector.tenant_id):
    if not event.contains(_attr, "set", _refuse_move):
        event.listen(_attr, "set", _refuse_move, active_history=True, retval=True)


# --- shared base ---------------------------------------------------------------------------------


def _global_criterion() -> ColumnElement[bool]:
    return and_(DkimSelector.scope == GLOBAL, DkimSelector.tenant_id.is_(None))


class _DkimSelectorStore:
    __slots__ = ("_session",)

    _fields: frozenset[str]

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("a Session is required")
        self._session = session

    def _visible(self) -> ColumnElement[bool]:
        raise NotImplementedError

    def _writable(self) -> ColumnElement[bool]:
        raise NotImplementedError

    def _select(self, criterion: ColumnElement[bool]) -> Select[DkimSelector]:
        return select(DkimSelector).where(criterion)

    def _load(self, id_: object, criterion: ColumnElement[bool]) -> DkimSelector | None:
        pk = coerce_id(id_)
        if pk is None:
            return None
        stmt = self._select(criterion).where(DkimSelector.id == pk)
        return self._session.scalars(stmt).one_or_none()

    def get(self, id_: object) -> DkimSelectorRecord | None:
        """A visible selector by id; None if missing, not visible or malformed."""
        row = self._load(id_, self._visible())
        return None if row is None else DkimSelectorRecord.from_model(row)

    def list(
        self, *, enabled_only: bool = False, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[DkimSelectorRecord]:
        """Visible selectors ordered by selector name, then id."""
        _check_page(limit, offset)
        stmt = self._select(self._visible())
        if enabled_only:
            stmt = stmt.where(DkimSelector.enabled.is_(True))
        stmt = stmt.order_by(DkimSelector.selector, DkimSelector.id).limit(limit).offset(offset)
        return [DkimSelectorRecord.from_model(r) for r in self._session.scalars(stmt).all()]

    def count(self) -> int:
        stmt = select(func.count()).select_from(DkimSelector).where(self._visible())
        return int(self._session.scalar(stmt) or 0)

    def _taken(self, column: Any, value: str | None, exclude_id: int | None = None) -> bool:
        if value is None:
            return False
        stmt = self._select(self._writable()).where(column == value)
        if exclude_id is not None:
            stmt = stmt.where(DkimSelector.id != exclude_id)
        return self._session.scalars(stmt.limit(1)).first() is not None

    def _check_unique(self, cleaned: Mapping[str, Any], exclude_id: int | None = None) -> None:
        if self._taken(DkimSelector.selector, cleaned.get("selector"), exclude_id):
            raise SelectorTaken
        if self._taken(DkimSelector.seed_key, cleaned.get("seed_key"), exclude_id):
            raise SelectorTaken

    def _flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError as exc:
            if not is_unique_conflict(exc):
                raise
            raise SelectorTaken from exc

    def _insert(self, values: Mapping[str, Any], fixed: Mapping[str, Any]) -> DkimSelectorRecord:
        cleaned = _clean_values(values, self._fields)
        if "selector" not in cleaned:
            raise DkimSelectorInvalid("selector", "required")
        self._check_unique(cleaned)
        row = DkimSelector(**cleaned, **fixed)
        self._session.add(row)
        self._flush()
        return DkimSelectorRecord.from_model(row)

    def update(self, id_: object, values: Mapping[str, Any]) -> DkimSelectorRecord | None:
        """Change fields of a writable selector; None if missing, not writable or malformed."""
        cleaned = _clean_values(values, self._fields)
        row = self._load(id_, self._writable())
        if row is None:
            return None
        self._check_unique(cleaned, row.id)
        for key, value in cleaned.items():
            setattr(row, key, value)
        self._flush()
        return DkimSelectorRecord.from_model(row)

    def delete(self, id_: object) -> bool:
        """Delete a writable selector; False if missing, not writable or malformed."""
        row = self._load(id_, self._writable())
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True


class DkimSelectorRepository(_DkimSelectorStore):
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
        return and_(DkimSelector.scope == TENANT, DkimSelector.tenant_id == self._ctx.tenant_id)

    def _visible(self) -> ColumnElement[bool]:
        return or_(_global_criterion(), self._writable())

    def create(self, values: Mapping[str, Any]) -> DkimSelectorRecord:
        """Insert a tenant selector; scope, tenant_id and created_by come from the context."""
        return self._insert(
            values,
            {"scope": TENANT, "tenant_id": self._ctx.tenant_id, "created_by": self._ctx.principal},
        )


class GlobalDkimSelectorRepository(_DkimSelectorStore):
    """Instance-admin entry point for global rows only (admin service after the M5-04 global
    check, and seed sync). Not reachable through `repo_for`."""

    __slots__ = ()

    _fields = GLOBAL_FIELDS

    def _writable(self) -> ColumnElement[bool]:
        return _global_criterion()

    def _visible(self) -> ColumnElement[bool]:
        return _global_criterion()

    def list_seeded(self) -> Sequence[DkimSelectorRecord]:
        """Every global row that came from the seed (seed_key set), enabled or not."""
        stmt = (
            self._select(self._visible())
            .where(DkimSelector.seed_key.is_not(None))
            .order_by(DkimSelector.id)
        )
        return [DkimSelectorRecord.from_model(r) for r in self._session.scalars(stmt).all()]

    def create(self, values: Mapping[str, Any], *, actor: int | None) -> DkimSelectorRecord:
        """Insert a global selector. `actor` is the instance admin's user id (None for seed
        sync)."""
        if actor is not None and coerce_id(actor) is None:
            raise ValueError("actor must be a positive integer user id or None")
        return self._insert(values, {"scope": GLOBAL, "tenant_id": None, "created_by": actor})
