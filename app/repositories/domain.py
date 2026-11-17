"""Tenant-scoped repository for domains (M1-18).

Names reaching this repository must already be validated at the edge
(`app.core.domain_names.to_ascii_domain`); the model validator normalises them once more and
rejects anything non-ASCII. Callers outside `app.repositories` never see the ORM class by name:
they read rows through `DomainRecord` (immutable value object).
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import CursorResult, Table, UniqueConstraint, update
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError

from app.models import Domain
from app.models.domain import normalize_domain_name
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


def _utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes for timezone-aware columns; they were stored as UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


# Every verification column back to "never verified, nothing pending" (rename, M7-21a).
_UNVERIFIED: dict[str, object] = {
    "verification_status": "unverified",
    "verified_at": None,
    "verification_method": None,
    "verification_token_hash": None,
    "verification_token_expires_at": None,
}


@dataclass(frozen=True, slots=True)
class DomainRecord:
    """A domain row. The pending token's hash is NOT here: only `pending_token_hash` reads it."""

    id: int
    name: str
    created_at: datetime
    verification_status: str = "unverified"
    verified_at: datetime | None = None
    verification_method: str | None = None
    token_expires_at: datetime | None = None

    @property
    def verified(self) -> bool:
        return self.verification_status == "verified"

    @classmethod
    def from_model(cls, row: Domain) -> DomainRecord:
        return cls(
            id=row.id,
            name=row.name,
            created_at=row.created_at,
            verification_status=row.verification_status,
            verified_at=_utc(row.verified_at),
            verification_method=row.verification_method,
            token_expires_at=_utc(row.verification_token_expires_at),
        )


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
        another domain of the tenant already has `name`. A changed name resets ownership
        verification (M7-21a): status `unverified`, pending token cleared; proof for the old
        name says nothing about the new one. The same name again changes nothing."""
        current = self.get(id_)
        if current is None:
            return None
        other = self.get_by_name(name)
        if other is not None and other.id != current.id:
            raise DomainNameTaken
        values: dict[str, object] = {"name": name}
        if normalize_domain_name(name) != current.name:
            values.update(_UNVERIFIED)
        try:
            return self.update(current.id, values)
        except IntegrityError as exc:
            if not is_name_conflict(exc):
                raise
            raise DomainNameTaken from exc

    # --- ownership verification (M7-21a) -------------------------------------------------------

    def pending_token_hash(self, id_: object) -> str | None:
        """The stored hash of the domain's pending token (None: none pending, or no domain)."""
        row = self.get(id_)
        return None if row is None else row.verification_token_hash

    def set_pending_token(self, id_: object, token_hash: str, expires_at: datetime) -> Domain | None:
        """Store a new pending token (its hash) and expiry, replacing any previous one; the
        status is unchanged. None if the domain is missing/foreign/malformed."""
        if len(token_hash) != 64 or expires_at.tzinfo is None:
            raise ValueError("token hash must be SHA-256 hex and expiry timezone-aware")
        return self.update(
            id_,
            {"verification_token_hash": token_hash, "verification_token_expires_at": expires_at},
        )

    def mark_verified(
        self, id_: object, *, name: str, token_hash: str, method: str, at: datetime
    ) -> bool:
        """Verified, by one conditional UPDATE: only while the row still has `name` and the
        pending `token_hash` (a rename or a re-issue since the DNS lookup wins). Clears the
        token. False if nothing matched."""
        pk = coerce_id(id_)
        if pk is None or at.tzinfo is None:
            return False
        stmt = (
            update(Domain)
            .where(
                self._tenant_criterion(),
                Domain.id == pk,
                Domain.name == name,
                Domain.verification_token_hash == token_hash,
            )
            .values(
                verification_status="verified",
                verified_at=at,
                verification_method=method,
                verification_token_hash=None,
                verification_token_expires_at=None,
            )
            .execution_options(synchronize_session="fetch")
        )
        result = self._session.execute(stmt)
        return int(cast(CursorResult[Any], result).rowcount) == 1
