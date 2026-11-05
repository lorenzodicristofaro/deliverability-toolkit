"""Domain use cases for the active tenant (M1-18): list, get, create, rename, delete, access.

Every read and write goes through `DomainRepository` / `DomainAccessRepository` bound to the
request's `TenantContext`, and every decision through `app.core.permissions.can()`:
- a domain that is missing, of another tenant, malformed, or not assigned to a client viewer is
  `NotFound` (404): indistinguishable from each other;
- a visible domain (or the tenant itself) the principal may not change is `Forbidden` (403).
Errors carry only an i18n key, never user input or data of another tenant.

The `Principal` comes from the auth dependencies (app.web.deps), which load a client viewer's
DomainAccess grants for the active tenant (M1-19); a principal without grants sees no domains
(fail closed).

TODO(M10): write audit log entries for create/rename/delete/access changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_display_name
from app.core.permissions import (
    Action,
    DomainResource,
    MembershipGrant,
    Principal,
    TenantResource,
    can,
)
from app.core.tenancy import TenantContext
from app.models.membership import MembershipRole
from app.repositories import repo_for
from app.repositories.base import DEFAULT_LIMIT
from app.repositories.domain import DomainNameTaken, DomainRecord
from app.repositories.domain_access import MAX_ASSIGNMENTS


class DomainServiceError(Exception):
    """Base error; `status` is the HTTP status and `key` the i18n key of the message."""

    status = 500
    key = "ui.error.server.detail"


class NotFound(DomainServiceError):
    status = 404
    key = "api.error.not_found"


class Forbidden(DomainServiceError):
    status = 403
    key = "api.error.forbidden"


class Conflict(DomainServiceError):
    status = 409
    key = "api.error.conflict"


class InvalidName(DomainServiceError):
    status = 422
    key = "domain.error.invalid_name"


class InvalidRequest(DomainServiceError):
    status = 422
    key = "api.error.invalid_request"


@dataclass(frozen=True, slots=True)
class DomainView:
    id: int
    name: str
    display_name: str
    created_at: datetime

    @classmethod
    def from_record(cls, record: DomainRecord) -> DomainView:
        return cls(record.id, record.name, to_display_name(record.name), record.created_at)


@dataclass(frozen=True, slots=True)
class DomainAccessView:
    domain_id: int
    user_ids: tuple[int, ...]


def _active_grant(principal: Principal, tenant_id: int) -> MembershipGrant | None:
    if principal.active_tenant_id != tenant_id:
        return None
    matches = [m for m in principal.memberships if m.tenant_id == tenant_id]
    return matches[0] if len(matches) == 1 else None


class DomainService:
    """Domain operations for one request: `ctx` scopes the data, `principal` the permissions."""

    def __init__(self, db: Session, ctx: TenantContext, principal: Principal) -> None:
        self._db = db
        self._ctx = ctx
        repos = repo_for(ctx, db)
        self._domains = repos.domains
        self._access = repos.domain_access
        self._memberships = repos.memberships
        self._principal = principal

    @property
    def principal(self) -> Principal:
        return self._principal

    # --- helpers ------------------------------------------------------------------------------

    def _tenant(self) -> TenantResource:
        return TenantResource(self._ctx.tenant_id)

    def _resource(self, domain_id: int) -> DomainResource:
        return DomainResource(self._ctx.tenant_id, domain_id)

    def _visible(self, domain_id: object) -> DomainRecord:
        row = self._domains.get(domain_id)
        if row is None or not can(self._principal, Action.DOMAIN_READ, self._resource(row.id)):
            raise NotFound
        return DomainRecord.from_model(row)

    def _allow(self, action: Action, resource: TenantResource | DomainResource) -> None:
        if not can(self._principal, action, resource):
            raise Forbidden

    @staticmethod
    def _name(value: object) -> str:
        try:
            return to_ascii_domain(value)
        except InvalidDomainName:
            raise InvalidName from None

    # --- use cases ----------------------------------------------------------------------------

    # Permission pre-checks: routers call these before parsing a body, so a caller who may not
    # act gets 403/404 regardless of what it sent. The use cases repeat the checks.

    def check_create(self) -> None:
        self._allow(Action.DOMAIN_CREATE, self._tenant())

    def check_update(self, domain_id: object) -> None:
        current = self._visible(domain_id)
        self._allow(Action.DOMAIN_UPDATE, self._resource(current.id))

    def check_set_access(self, domain_id: object) -> None:
        current = self._visible(domain_id)
        self._allow(Action.DOMAIN_UPDATE, self._resource(current.id))
        self._allow(Action.USER_MANAGE, self._tenant())

    def list(self, *, limit: int = DEFAULT_LIMIT, offset: int = 0) -> Sequence[DomainView]:
        self._allow(Action.DOMAIN_LIST, self._tenant())
        grant = _active_grant(self._principal, self._ctx.tenant_id)
        if grant is not None and grant.role == MembershipRole.CLIENT_VIEWER:
            rows = self._domains.list_by_ids(grant.domain_ids, limit=limit, offset=offset)
        else:
            rows = self._domains.list(limit=limit, offset=offset)
        return [
            DomainView.from_record(DomainRecord.from_model(row))
            for row in rows
            if can(self._principal, Action.DOMAIN_READ, self._resource(row.id))
        ]

    def get(self, domain_id: object) -> DomainView:
        return DomainView.from_record(self._visible(domain_id))

    def create(self, name: object) -> DomainView:
        self._allow(Action.DOMAIN_CREATE, self._tenant())
        ascii_name = self._name(name)
        try:
            row = self._domains.create(ascii_name)
        except DomainNameTaken:
            self._db.rollback()
            raise Conflict from None
        record = DomainRecord.from_model(row)
        self._db.commit()
        return DomainView.from_record(record)

    def rename(self, domain_id: object, name: object) -> DomainView:
        current = self._visible(domain_id)
        self._allow(Action.DOMAIN_UPDATE, self._resource(current.id))
        ascii_name = self._name(name)
        try:
            row = self._domains.rename(current.id, ascii_name)
        except DomainNameTaken:
            self._db.rollback()
            raise Conflict from None
        if row is None:  # deleted concurrently
            raise NotFound
        record = DomainRecord.from_model(row)
        self._db.commit()
        return DomainView.from_record(record)

    def delete(self, domain_id: object) -> None:
        current = self._visible(domain_id)
        self._allow(Action.DOMAIN_DELETE, self._resource(current.id))
        if not self._domains.delete(current.id):
            raise NotFound
        self._db.commit()

    def set_access(self, domain_id: object, user_ids: Sequence[int]) -> DomainAccessView:
        """Replace the client viewers with access to the domain (owner/admin: domain update
        plus user management). Unknown or foreign users are NotFound; members that are not
        client viewers are InvalidRequest (their role already decides what they see)."""
        current = self._visible(domain_id)
        self._allow(Action.DOMAIN_UPDATE, self._resource(current.id))
        self._allow(Action.USER_MANAGE, self._tenant())
        if len(user_ids) > MAX_ASSIGNMENTS:
            raise InvalidRequest
        membership_ids: list[int] = []
        for user_id in dict.fromkeys(user_ids):
            membership = self._memberships.get_by_user(user_id)
            if membership is None:
                raise NotFound
            if membership.role != MembershipRole.CLIENT_VIEWER:
                raise InvalidRequest
            membership_ids.append(membership.id)
        if self._access.replace_for_domain(current.id, membership_ids) is None:
            raise NotFound
        self._db.commit()
        return self.access_of(current.id)

    def access_of(self, domain_id: int) -> DomainAccessView:
        user_ids = []
        for membership_id in self._access.membership_ids_for_domain(domain_id):
            membership = self._memberships.get(membership_id)
            if membership is not None:
                user_ids.append(membership.user_id)
        return DomainAccessView(domain_id, tuple(sorted(user_ids)))
