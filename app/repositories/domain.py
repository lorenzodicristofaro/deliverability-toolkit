"""Tenant-scoped repository for domains (M1-18).

Names reaching this repository must already be validated at the edge
(`app.core.domain_names.to_ascii_domain`); the model validator normalises them once more and
rejects anything non-ASCII. Callers outside `app.repositories` never see the ORM class by name:
they read rows through `DomainRecord` (immutable value object).
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Table, UniqueConstraint
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError

from app.models import Domain
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, TenantScopedRepository, coerce_id

# The per-tenant unique name constraint (naming convention in app.models.base).
NAME_CONSTRAINT = "uq_domains_tenant_id_name"


def _name_constraint_columns() -> tuple[str, ...]:
    table = sa_inspect(Domain).local_table
    if not isinstance(table, Table):
        raise RuntimeError("the domains model is not mapped to a table")
    for constraint in table.constraints:
        if isinstance(constraint, UniqueConstraint) and constraint.name == NAME_CONSTRAINT:
            return tuple(column.name for column in constraint.columns)
    raise RuntimeError(f"{NAME_CONSTRAINT} is not defined on the domains table")


# SQLite does not report constraint names, only "UNIQUE constraint failed: <table>.<col>, ...".
_SQLITE_NAME_MESSAGE = "UNIQUE constraint failed: " + ", ".join(
    f"{Domain.__tablename__}.{column}" for column in _name_constraint_columns()
)


def is_name_conflict(exc: IntegrityError) -> bool:
    """True only if `exc` is a violation of NAME_CONSTRAINT. PostgreSQL (psycopg) names the
    constraint in `diag.constraint_name`; SQLite only names the columns, which are taken from the
    model's constraint definition. Any other IntegrityError (FK, check, other unique) is False."""
    orig = exc.orig
    diag = getattr(orig, "diag", None)
    if diag is not None:
        return getattr(diag, "constraint_name", None) == NAME_CONSTRAINT
    if getattr(orig, "sqlite_errorname", None) == "SQLITE_CONSTRAINT_UNIQUE":
        return str(orig) == _SQLITE_NAME_MESSAGE
    return False


class DomainNameTaken(Exception):
    """A domain with this name already exists in the context tenant. If raised by a flush, the
    session is unusable until the caller rolls it back."""


@dataclass(frozen=True, slots=True)
class DomainRecord:
    id: int
    name: str
    created_at: datetime

    @classmethod
    def from_model(cls, row: Domain) -> DomainRecord:
        return cls(id=row.id, name=row.name, created_at=row.created_at)


def _check_page(limit: object, offset: object) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an int between 0 and {MAX_LIMIT}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative int")


class DomainRepository(TenantScopedRepository[Domain]):
    """Domains of the context tenant."""

    model = Domain

    def get_by_name(self, name: str) -> Domain | None:
        return self._session.scalars(self._where(Domain.name == name)).one_or_none()

    def list_by_ids(
        self, ids: Collection[object], *, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[Domain]:
        """Domains of the context tenant whose id is in `ids` (malformed ids are ignored),
        ordered by id. Foreign ids simply match nothing."""
        _check_page(limit, offset)
        wanted = {pk for pk in (coerce_id(i) for i in ids) if pk is not None}
        if not wanted:
            return []
        stmt = (
            self._where(Domain.id.in_(sorted(wanted)))
            .order_by(Domain.id)
            .limit(limit)
            .offset(offset)
        )
        return self._session.scalars(stmt).all()

    def create(self, name: str) -> Domain:
        """Insert a domain in the context tenant; DomainNameTaken if the name exists there
        (checked first; a concurrent insert surfaces as DomainNameTaken from the flush)."""
        if self.get_by_name(name) is not None:
            raise DomainNameTaken
        try:
            return self.add(Domain(name=name))
        except IntegrityError as exc:
            if not is_name_conflict(exc):
                raise
            raise DomainNameTaken from exc

    def rename(self, id_: object, name: str) -> Domain | None:
        """Change the name; None if the domain is missing/foreign/malformed, DomainNameTaken if
        another domain of the tenant already has `name`."""
        current = self.get(id_)
        if current is None:
            return None
        other = self.get_by_name(name)
        if other is not None and other.id != current.id:
            raise DomainNameTaken
        try:
            return self.update(current.id, {"name": name})
        except IntegrityError as exc:
            if not is_name_conflict(exc):
                raise
            raise DomainNameTaken from exc
