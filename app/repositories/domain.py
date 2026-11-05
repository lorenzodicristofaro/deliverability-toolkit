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

from sqlalchemy.exc import IntegrityError

from app.models import Domain
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, TenantScopedRepository, coerce_id


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
            raise DomainNameTaken from exc
