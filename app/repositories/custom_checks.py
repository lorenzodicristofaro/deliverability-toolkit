"""Custom checks repositories (M5-07). The only access path to `custom_checks`.

Two entry points, never mixed:
- `CustomCheckRepository(ctx, session)` (via `repo_for(ctx, session).custom_checks`): the tenant
  path. Reads return the global rows plus the context tenant's rows, nothing else. Writes
  (create/update/delete) touch only the context tenant's rows: `scope` is always 'tenant' and
  `tenant_id` comes from the context; a global or foreign id is "not found" (None/False), exactly
  like a missing or malformed id.
- `GlobalCustomCheckRepository(session)`: the instance-admin entry point for global rows (admin
  service after the M5-04 global-scope permission check). It never reads or writes tenant rows.
  It is NOT reachable through `repo_for`.

Callers get immutable `CustomCheckRecord`s, never ORM objects: `definition` comes back deeply
frozen (read-only mappings, tuples) and `remediation_text` as a `LocalizedText`. An attribute
listener additionally refuses changing `scope`/`tenant_id` of a persisted row anywhere in the
process.

`definition` is stored opaquely: its schema per kind is validated by the M5-22 service layer
(any regex it carries must go through `app.core.safe_regex.compile_checked` there). Here it must
only be a non-empty JSON object of plain JSON values, at most MAX_DEFINITION_DEPTH deep and at
most MAX_DEFINITION_LENGTH characters once serialized with `json.dumps` (what SQLAlchemy sends on
SQLite and PostgreSQL, so the DB CHECK sees the same length), with no NUL, surrogate or control
characters (tab and newline allowed) in any string or key, and no NaN/infinity.

`http_fetch` is a reserved kind (M7, guarded outbound client): refused here with reason
"reserved" and by the DB CHECK. `CustomCheckInvalid` names the field and a stable reason, never
the value.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Final

from sqlalchemy import ColumnElement, Select, and_, event, func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.base import NEVER_SET, NO_VALUE

from app.core.tenancy import TenantContext
from app.models.custom_check import (
    KINDS,
    MAX_DEFINITION_DEPTH,
    MAX_DEFINITION_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    MAX_KEY_LENGTH,
    MAX_NAME_LENGTH,
    MAX_REMEDIATION_KEY_LENGTH,
    MAX_REMEDIATION_LENGTH,
    REMEDIATION_LANGUAGES,
    RESERVED_KINDS,
    SEVERITIES,
    CustomCheck,
)
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, TenantScopeError, coerce_id

GLOBAL: Final = "global"
TENANT: Final = "tenant"
GLOBAL_KEY_INDEX: Final = "uq_custom_checks_global_check_key"
TENANT_KEY_INDEX: Final = "uq_custom_checks_tenant_check_key"

# Lowercase slug; check_key is an identifier, not display text.
_SLUG = re.compile(r"[a-z0-9][a-z0-9_.-]*")
# Dotted i18n key, e.g. "custom_check.spf_include.remediation".
_I18N_KEY = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+")

# Fields a caller may set. scope, tenant_id, id, created_*, updated_at are repository-owned.
FIELDS: Final = frozenset(
    {
        "check_key",
        "name",
        "description",
        "kind",
        "definition",
        "severity",
        "remediation_key",
        "remediation_text",
        "enabled",
    }
)
_REQUIRED: Final = frozenset({"check_key", "name", "kind", "definition", "severity"})


class CustomCheckInvalid(ValueError):
    """A field value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"custom check {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class CheckKeyTaken(Exception):
    """Another check of the same scope (same tenant) already uses this check_key. If raised by a
    flush, the session is unusable until the caller rolls it back."""


@dataclass(frozen=True, slots=True)
class LocalizedText:
    """Admin-written text in every supported language (en, it)."""

    en: str
    it: str

    def as_dict(self) -> dict[str, str]:
        return {"en": self.en, "it": self.it}


@dataclass(frozen=True, slots=True)
class CustomCheckRecord:
    id: int
    scope: str
    tenant_id: int | None
    check_key: str
    name: str
    description: str | None
    kind: str
    definition: Mapping[str, Any]
    severity: str
    remediation_key: str | None
    remediation_text: LocalizedText | None
    enabled: bool
    created_at: datetime
    updated_at: datetime
    created_by: int | None

    @classmethod
    def from_model(cls, row: CustomCheck) -> CustomCheckRecord:
        text = row.remediation_text
        return cls(
            id=row.id,
            scope=row.scope,
            tenant_id=row.tenant_id,
            check_key=row.check_key,
            name=row.name,
            description=row.description,
            kind=row.kind,
            definition=_freeze(row.definition),
            severity=row.severity,
            remediation_key=row.remediation_key,
            remediation_text=None if text is None else LocalizedText(en=text["en"], it=text["it"]),
            enabled=row.enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
            created_by=row.created_by,
        )


def _freeze(value: Any) -> Any:
    """Deep read-only copy: dicts become MappingProxyType, lists become tuples."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    return value


# --- validation ----------------------------------------------------------------------------------


def _bad_chars(field: str, value: str, *, allowed_controls: str) -> None:
    if "\x00" in value:
        raise CustomCheckInvalid(field, "nul")
    if any(unicodedata.category(c) == "Cs" for c in value):
        raise CustomCheckInvalid(field, "surrogate")
    if any(unicodedata.category(c) == "Cc" and c not in allowed_controls for c in value):
        raise CustomCheckInvalid(field, "control_char")


def _text(field: str, value: object, maximum: int, *, allowed_controls: str = "") -> str:
    if not isinstance(value, str):
        raise CustomCheckInvalid(field, "not_a_string")
    if value == "":
        raise CustomCheckInvalid(field, "empty")
    if len(value) > maximum:
        raise CustomCheckInvalid(field, "too_long")
    _bad_chars(field, value, allowed_controls=allowed_controls)
    return value


def _label(field: str, value: object, maximum: int) -> str:
    """Single-line display text: no control characters, no surrounding whitespace."""
    result = _text(field, value, maximum)
    if result.strip() != result or not result.strip():
        raise CustomCheckInvalid(field, "whitespace")
    return result


def _paragraphs(field: str, value: object, maximum: int) -> str:
    """Multi-line display text: newlines and tabs allowed, other control characters not."""
    result = _text(field, value, maximum, allowed_controls="\n\t")
    if not result.strip():
        raise CustomCheckInvalid(field, "whitespace")
    return result


def _pattern(field: str, value: object, maximum: int, pattern: re.Pattern[str]) -> str:
    result = _text(field, value, maximum)
    if not pattern.fullmatch(result):
        raise CustomCheckInvalid(field, "invalid_format")
    return result


def _kind(value: object) -> str:
    if isinstance(value, str) and value in RESERVED_KINDS:
        raise CustomCheckInvalid("kind", "reserved")
    if not isinstance(value, str) or value not in KINDS:
        raise CustomCheckInvalid("kind", "invalid_choice")
    return value


def _choice(field: str, value: object, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise CustomCheckInvalid(field, "invalid_choice")
    return value


def _bool(field: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise CustomCheckInvalid(field, "not_a_bool")
    return value


def _json_value(value: object, depth: int) -> Any:
    """Plain JSON copy of `value` (lists for tuples, dicts for mappings) or CustomCheckInvalid."""
    if depth > MAX_DEFINITION_DEPTH:
        raise CustomCheckInvalid("definition", "too_deep")
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CustomCheckInvalid("definition", "not_finite")
        return value
    if isinstance(value, str):
        _bad_chars("definition", value, allowed_controls="\n\t")
        return value
    if isinstance(value, list | tuple):
        return [_json_value(v, depth + 1) for v in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CustomCheckInvalid("definition", "non_string_key")
            _bad_chars("definition", k, allowed_controls="")
            result[k] = _json_value(v, depth + 1)
        return result
    raise CustomCheckInvalid("definition", "not_json")


def _definition(value: object) -> dict[str, Any]:
    """A non-empty JSON object within the size and depth caps (content is opaque here)."""
    if not isinstance(value, Mapping):
        raise CustomCheckInvalid("definition", "not_an_object")
    if not value:
        raise CustomCheckInvalid("definition", "empty")
    result: dict[str, Any] = _json_value(value, 1)
    # json.dumps defaults are exactly what SQLAlchemy sends on SQLite and psycopg (ASCII only),
    # so this is the length the DB CHECK measures.
    if len(json.dumps(result)) > MAX_DEFINITION_LENGTH:
        raise CustomCheckInvalid("definition", "too_large")
    return result


def _remediation_text(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, LocalizedText):
        value = value.as_dict()
    if not isinstance(value, Mapping):
        raise CustomCheckInvalid("remediation_text", "not_an_object")
    if set(value.keys()) != set(REMEDIATION_LANGUAGES):
        raise CustomCheckInvalid("remediation_text", "languages")
    return {
        lang: _paragraphs("remediation_text", value[lang], MAX_REMEDIATION_LENGTH)
        for lang in REMEDIATION_LANGUAGES
    }


def _clean(field: str, value: object) -> object:
    match field:
        case "check_key":
            return _pattern(field, value, MAX_KEY_LENGTH, _SLUG)
        case "name":
            return _label(field, value, MAX_NAME_LENGTH)
        case "description":
            return None if value is None else _paragraphs(field, value, MAX_DESCRIPTION_LENGTH)
        case "kind":
            return _kind(value)
        case "definition":
            return _definition(value)
        case "severity":
            return _choice(field, value, SEVERITIES)
        case "remediation_key":
            if value is None:
                return None
            return _pattern(field, value, MAX_REMEDIATION_KEY_LENGTH, _I18N_KEY)
        case "remediation_text":
            return _remediation_text(value)
        case "enabled":
            return _bool(field, value)
    raise CustomCheckInvalid(field, "unknown_field")


def _clean_values(values: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(values, Mapping):
        raise TypeError("values must be a mapping")
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key in ("scope", "tenant_id"):
            raise TenantScopeError(f"{key} is set by the repository")
        if not isinstance(key, str) or key not in FIELDS:
            raise CustomCheckInvalid(str(key)[:64], "unknown_field")
        cleaned[key] = _clean(key, value)
    return cleaned


def _check_remediation(key: str | None, text: dict[str, str] | None) -> None:
    """Exactly one remediation source (DB CHECK too)."""
    if key is None and text is None:
        raise CustomCheckInvalid("remediation", "required")
    if key is not None and text is not None:
        raise CustomCheckInvalid("remediation", "both")


def _check_page(limit: object, offset: object) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an int between 0 and {MAX_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative int")


def is_check_key_conflict(exc: IntegrityError) -> bool:
    """True only for a violation of one of the check_key unique indexes. PostgreSQL names the
    index in `diag.constraint_name`; SQLite names only the columns of the index."""
    orig = exc.orig
    diag = getattr(orig, "diag", None)
    if diag is not None:
        return getattr(diag, "constraint_name", None) in (GLOBAL_KEY_INDEX, TENANT_KEY_INDEX)
    if getattr(orig, "sqlite_errorname", None) == "SQLITE_CONSTRAINT_UNIQUE":
        return str(orig) in (
            "UNIQUE constraint failed: custom_checks.check_key",
            "UNIQUE constraint failed: custom_checks.tenant_id, custom_checks.check_key",
        )
    return False


# --- scope guard -------------------------------------------------------------------------------


def _refuse_move(target: Any, value: Any, oldvalue: Any, _initiator: Any) -> Any:
    if not sa_inspect(target).has_identity:
        return value
    if oldvalue in (NO_VALUE, NEVER_SET) or value != oldvalue:
        raise TenantScopeError("scope/tenant_id of an existing custom check cannot be changed")
    return value


for _attr in (CustomCheck.scope, CustomCheck.tenant_id):
    if not event.contains(_attr, "set", _refuse_move):
        event.listen(_attr, "set", _refuse_move, active_history=True, retval=True)


# --- shared base ---------------------------------------------------------------------------------


class _CustomCheckStore:
    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("a Session is required")
        self._session = session

    # Visible rows (reads) and writable rows (writes); subclasses decide.
    def _visible(self) -> ColumnElement[bool]:
        raise NotImplementedError

    def _writable(self) -> ColumnElement[bool]:
        raise NotImplementedError

    def _select(self, criterion: ColumnElement[bool]) -> Select[CustomCheck]:
        return select(CustomCheck).where(criterion)

    def _load(self, id_: object, criterion: ColumnElement[bool]) -> CustomCheck | None:
        pk = coerce_id(id_)
        if pk is None:
            return None
        stmt = self._select(criterion).where(CustomCheck.id == pk)
        return self._session.scalars(stmt).one_or_none()

    def get(self, id_: object) -> CustomCheckRecord | None:
        """A visible check by id; None if missing, not visible or malformed."""
        row = self._load(id_, self._visible())
        return None if row is None else CustomCheckRecord.from_model(row)

    def list(
        self, *, enabled_only: bool = False, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[CustomCheckRecord]:
        """Visible checks ordered by id."""
        _check_page(limit, offset)
        stmt = self._select(self._visible())
        if enabled_only:
            stmt = stmt.where(CustomCheck.enabled.is_(True))
        stmt = stmt.order_by(CustomCheck.id).limit(limit).offset(offset)
        return [CustomCheckRecord.from_model(r) for r in self._session.scalars(stmt).all()]

    def count(self) -> int:
        stmt = select(func.count()).select_from(CustomCheck).where(self._visible())
        return int(self._session.scalar(stmt) or 0)

    def get_by_key(self, check_key: object) -> Sequence[CustomCheckRecord]:
        """Visible checks with this check_key, ordered by id (the tenant path can see a global
        and an own-tenant check sharing a key). Empty for a malformed key."""
        if not isinstance(check_key, str):
            return []
        stmt = (
            self._select(self._visible())
            .where(CustomCheck.check_key == check_key)
            .order_by(CustomCheck.id)
        )
        return [CustomCheckRecord.from_model(r) for r in self._session.scalars(stmt).all()]

    def _key_taken(self, check_key: str, exclude_id: int | None = None) -> bool:
        stmt = self._select(self._writable()).where(CustomCheck.check_key == check_key)
        if exclude_id is not None:
            stmt = stmt.where(CustomCheck.id != exclude_id)
        return self._session.scalars(stmt.limit(1)).first() is not None

    def _flush(self) -> None:
        try:
            self._session.flush()
        except IntegrityError as exc:
            if not is_check_key_conflict(exc):
                raise
            raise CheckKeyTaken from exc

    def _insert(self, values: Mapping[str, Any], fixed: Mapping[str, Any]) -> CustomCheckRecord:
        cleaned = _clean_values(values)
        missing = _REQUIRED - cleaned.keys()
        if missing:
            raise CustomCheckInvalid(sorted(missing)[0], "required")
        _check_remediation(cleaned.get("remediation_key"), cleaned.get("remediation_text"))
        if self._key_taken(cleaned["check_key"]):
            raise CheckKeyTaken
        row = CustomCheck(**cleaned, **fixed)
        self._session.add(row)
        self._flush()
        return CustomCheckRecord.from_model(row)

    def update(self, id_: object, values: Mapping[str, Any]) -> CustomCheckRecord | None:
        """Change fields of a writable check; None if missing, not writable or malformed."""
        cleaned = _clean_values(values)
        for field in _REQUIRED & cleaned.keys():
            if cleaned[field] is None:
                raise CustomCheckInvalid(field, "required")
        row = self._load(id_, self._writable())
        if row is None:
            return None
        _check_remediation(
            cleaned.get("remediation_key", row.remediation_key),
            cleaned.get("remediation_text", row.remediation_text),
        )
        if "check_key" in cleaned and self._key_taken(cleaned["check_key"], row.id):
            raise CheckKeyTaken
        for key, value in cleaned.items():
            setattr(row, key, value)
        self._flush()
        return CustomCheckRecord.from_model(row)

    def delete(self, id_: object) -> bool:
        """Delete a writable check; False if missing, not writable or malformed."""
        row = self._load(id_, self._writable())
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True


def _global_criterion() -> ColumnElement[bool]:
    return and_(CustomCheck.scope == GLOBAL, CustomCheck.tenant_id.is_(None))


class CustomCheckRepository(_CustomCheckStore):
    """Tenant path: reads global + context tenant rows; writes only context tenant rows."""

    __slots__ = ("_ctx",)

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        super().__init__(session)
        self._ctx = ctx

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _writable(self) -> ColumnElement[bool]:
        return and_(CustomCheck.scope == TENANT, CustomCheck.tenant_id == self._ctx.tenant_id)

    def _visible(self) -> ColumnElement[bool]:
        return or_(_global_criterion(), self._writable())

    def create(self, values: Mapping[str, Any]) -> CustomCheckRecord:
        """Insert a tenant check; scope, tenant_id and created_by come from the context."""
        return self._insert(
            values,
            {"scope": TENANT, "tenant_id": self._ctx.tenant_id, "created_by": self._ctx.principal},
        )


class GlobalCustomCheckRepository(_CustomCheckStore):
    """Instance-admin entry point for global rows only (admin service after the M5-04 global
    permission check). Not reachable through `repo_for`."""

    __slots__ = ()

    def _writable(self) -> ColumnElement[bool]:
        return _global_criterion()

    def _visible(self) -> ColumnElement[bool]:
        return _global_criterion()

    def create(self, values: Mapping[str, Any], *, actor: int | None) -> CustomCheckRecord:
        """Insert a global check. `actor` is the instance admin's user id (None for system)."""
        if actor is not None and coerce_id(actor) is None:
            raise ValueError("actor must be a positive integer user id or None")
        return self._insert(values, {"scope": GLOBAL, "tenant_id": None, "created_by": actor})
