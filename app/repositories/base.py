"""Tenant-scoped repository base (ARCHITECTURE section 4, item 2).

How the tenant filter is made hard to forget:
- A repository can only be constructed with a `TenantContext`; its tenant is fixed for life.
- Every read is built from `_select()`, which already carries `tenant_id = ctx.tenant_id`.
  Subclasses add criteria with `_where(...)`; they never call `select(Model)` themselves, and
  never use `Session.get` (the identity map would bypass the WHERE clause).
- `update` and `delete` first load the row through the scoped `get`, so a row of another tenant
  is simply "not found" (None / False), exactly like a missing id. Malformed ids behave the same.
- `add` forces `tenant_id` from the context; a different `tenant_id` on the object raises.
- `update` refuses `tenant_id` and the primary key, and an attribute listener installed for every
  repository model refuses changing `tenant_id` of a persisted object anywhere in the process.
- Values written by `add`/`update` must be plain Python values (allowlist). SQL expressions
  (literal_column, text, subqueries, func.*, bindparam, columns, anything with
  `__clause_element__`) are refused: a subquery value could read another tenant's rows.

Composite-key or tenant-less tables are not supported by this base on purpose.
"""

from __future__ import annotations

import datetime as dt
import enum
import uuid
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, cast

from sqlalchemy import ClauseElement, ColumnElement, Select, event, func, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import InstrumentedAttribute, Mapper, Session
from sqlalchemy.orm.base import NEVER_SET, NO_VALUE

from app.core.tenancy import TenantContext
from app.models.base import Base

# Every primary and foreign key id is an INTEGER column (signed 32-bit on PostgreSQL), where a
# larger bound value is a DataError, not a miss. Larger "ids" are malformed, not just missing.
# tests/tenancy/test_id_range.py checks this against the models and the migrated schema.
MAX_ID = 2**31 - 1
# Only bounds the work of `int()`: zero-padded ids up to this length stay valid.
_MAX_ID_DIGITS = 19
DEFAULT_LIMIT = 100
TENANT_ATTR = "tenant_id"
MAX_LIMIT = 1000


class TenantScopeError(ValueError):
    """Raised when a caller tries to write a row outside the repository's tenant."""


def coerce_id(value: object) -> int | None:
    """Return `value` as a primary-key id, or None if it cannot be a valid id.

    Only real ints in 1..MAX_ID are accepted (no bool, str, float or None): callers parse path
    parameters before reaching a repository, and a malformed id is treated as "not found"."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 1 or value > MAX_ID:
        return None
    return value


def parse_id(raw: str) -> int | None:
    """An id received as text (path segment, form field), or None if it cannot be a valid id."""
    if not raw.isascii() or not raw.isdigit() or len(raw) > _MAX_ID_DIGITS:
        return None
    return coerce_id(int(raw))


_PLAIN_SCALARS: tuple[type, ...] = (
    bool,
    int,
    float,
    str,
    bytes,
    Decimal,
    dt.datetime,
    dt.date,
    dt.time,
    dt.timedelta,
    uuid.UUID,
    enum.Enum,
)
_MAX_JSON_DEPTH = 32


def _is_sql_construct(value: object) -> bool:
    return isinstance(value, ClauseElement) or hasattr(value, "__clause_element__")


def is_plain_value(value: object, _depth: int = 0) -> bool:
    """True for plain Python column values: None, scalars in the allowlist, and JSON-like
    dict (str keys) / list trees of them. SQL constructs are never plain, even when they also
    subclass an allowed type."""
    if value is None:
        return True
    if _is_sql_construct(value) or _depth > _MAX_JSON_DEPTH:
        return False
    if isinstance(value, _PLAIN_SCALARS):
        return True
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and not _is_sql_construct(k) and is_plain_value(v, _depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return all(is_plain_value(v, _depth + 1) for v in value)
    return False


def _refuse_tenant_move(target: Any, value: Any, oldvalue: Any, _initiator: Any) -> Any:
    if not sa_inspect(target).has_identity:
        return value  # not persisted yet: add() decides the tenant
    if oldvalue in (NO_VALUE, NEVER_SET) or value != oldvalue:
        raise TenantScopeError("tenant_id of an existing row cannot be changed")
    return value


def _install_tenant_guard(attribute: InstrumentedAttribute[Any]) -> None:
    if not event.contains(attribute, "set", _refuse_tenant_move):
        # active_history: load the old value even if expired, so the guard cannot be skipped.
        event.listen(attribute, "set", _refuse_tenant_move, active_history=True, retval=True)


class TenantScopedRepository[ModelT: Base]:
    """Base for repositories over tenant-owned tables (non-null `tenant_id`, single-column PK).

    Subclasses set `model` and build every query from `_select()` / `_where()`."""

    model: type[ModelT]

    __slots__ = ("_ctx", "_session")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        model = cls.__dict__.get("model")
        if model is None:
            return  # intermediate abstract subclass
        mapper: Mapper[Any] = sa_inspect(model)
        tenant_column = mapper.columns.get(TENANT_ATTR)
        if tenant_column is None or tenant_column.nullable:
            raise TypeError(f"{model.__name__} has no non-null tenant_id column")
        if len(mapper.primary_key) != 1:
            raise TypeError(f"{model.__name__} must have a single-column primary key")
        _install_tenant_guard(getattr(model, TENANT_ATTR))

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        if getattr(type(self), "model", None) is None:
            raise TypeError(f"{type(self).__name__} does not declare a model")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    # --- query building (the only way subclasses should start a query) -------------------------

    @property
    def _tenant_column(self) -> InstrumentedAttribute[int]:
        column: InstrumentedAttribute[int] = getattr(self.model, TENANT_ATTR)
        return column

    @property
    def _pk_column(self) -> InstrumentedAttribute[Any]:
        mapper: Mapper[Any] = sa_inspect(self.model)
        column: InstrumentedAttribute[Any] = getattr(
            self.model, mapper.get_property_by_column(mapper.primary_key[0]).key
        )
        return column

    def _tenant_criterion(self) -> ColumnElement[bool]:
        return cast(ColumnElement[bool], self._tenant_column == self._ctx.tenant_id)

    def _select(self) -> Select[ModelT]:
        return select(self.model).where(self._tenant_criterion())

    def _where(self, *criteria: ColumnElement[bool]) -> Select[ModelT]:
        return self._select().where(*criteria)

    # --- base operations -------------------------------------------------------------------------

    def get(self, id_: object) -> ModelT | None:
        """The row with this id in the context tenant; None if missing, foreign or malformed."""
        pk = coerce_id(id_)
        if pk is None:
            return None
        return self._session.scalars(self._where(self._pk_column == pk)).one_or_none()

    def list(self, *, limit: int = DEFAULT_LIMIT, offset: int = 0) -> Sequence[ModelT]:
        """Rows of the context tenant ordered by primary key."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be an int between 0 and {MAX_LIMIT}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative int")
        stmt = self._select().order_by(self._pk_column).limit(limit).offset(offset)
        return self._session.scalars(stmt).all()

    def count(self) -> int:
        stmt = select(func.count()).select_from(self.model).where(self._tenant_criterion())
        return int(self._session.scalar(stmt) or 0)

    def add(self, obj: ModelT) -> ModelT:
        """Insert a new row in the context tenant (tenant_id is set from the context)."""
        if not isinstance(obj, self.model):
            raise TypeError(f"expected a {self.model.__name__} instance")
        state = sa_inspect(obj)
        if not state.transient:
            raise TenantScopeError("add() only accepts new objects")
        current = getattr(obj, TENANT_ATTR, None)
        if current is not None and current != self._ctx.tenant_id:
            raise TenantScopeError("object tenant_id does not match the repository tenant")
        mapper: Mapper[Any] = sa_inspect(self.model)
        for attr in mapper.column_attrs:
            if attr.key in state.dict and not is_plain_value(state.dict[attr.key]):
                raise TenantScopeError(f"{attr.key} must be a plain value, not a SQL expression")
        setattr(obj, TENANT_ATTR, self._ctx.tenant_id)
        self._session.add(obj)
        self._session.flush()
        return obj

    def update(self, id_: object, values: Mapping[str, Any]) -> ModelT | None:
        """Set column values on the row; None if missing/foreign/malformed (nothing changes).

        `tenant_id` and the primary key cannot be updated; unknown names are rejected; values
        must be plain Python values (SQL expressions raise TenantScopeError)."""
        mapper: Mapper[Any] = sa_inspect(self.model)
        allowed = {attr.key for attr in mapper.column_attrs}
        pk_key = self._pk_column.key
        for key in values:
            if key == TENANT_ATTR:
                raise TenantScopeError("tenant_id cannot be updated")
            if key == pk_key:
                raise TenantScopeError("the primary key cannot be updated")
            if key not in allowed:
                raise ValueError(f"unknown column for {self.model.__name__}: {key!r}")
            if not is_plain_value(values[key]):
                raise TenantScopeError(f"{key} must be a plain value, not a SQL expression")
        obj = self.get(id_)
        if obj is None:
            return None
        for key, value in values.items():
            setattr(obj, key, value)
        self._session.flush()
        return obj

    def delete(self, id_: object) -> bool:
        """Delete the row; False if missing/foreign/malformed (nothing is deleted)."""
        obj = self.get(id_)
        if obj is None:
            return False
        self._session.delete(obj)
        self._session.flush()
        return True
