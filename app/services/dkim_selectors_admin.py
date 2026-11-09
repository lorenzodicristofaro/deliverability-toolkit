"""DKIM selectors administration (M5-20): list, read, create, update, delete.

Same scopes and permissions as the content rules (`app.services.content_rules_admin`), authorized
with `can()` BEFORE any repository is built:
- `tenant` (default): reads need `rules.read` on the active tenant and see the global rows plus
  that tenant's rows; writes need `rules.manage` on the active tenant and reach only its rows.
  `tenant_id` always comes from the `TenantContext`, never from the request.
- `global`: every verb needs `rules.manage` on the global scope (the instance admin flag), needs
  no active tenant, and reaches only global rows.

Outcomes: a selector that is missing, of another tenant or malformed is `SelectorNotFound` (404),
as is a tenant-scoped call with no active tenant. A denied permission is `ScopeForbidden` (403),
and so is a tenant-path write to a global row: that row is visible to the caller, who may not
change it.

Deliberate seed semantics:
- Every accepted edit of a global row sets `locally_modified` (the repository's `update` does
  not), so the next seed sync keeps it. That includes a PATCH whose values equal the current ones.
- On a seeded row the sync keeps only `enabled` and `notes` (`DKIM_LOCAL_FIELDS`) and rewrites the
  other fields whatever `locally_modified` says, so a change to them is refused (422,
  `seed_managed`) instead of being accepted and silently undone. Resending the current value is
  allowed, so a form can post the whole row.
- A seeded global row cannot be deleted (`SeededSelectorNotDeletable`, 409): the seed sync would
  recreate it. Disabling it is the supported way to turn it off.

A selector must also be a name the probe can query: `<selector>._domainkey.example.com` has to pass
`to_dns_name` unchanged, and `*` is refused because it would ask DNS for a wildcard owner name. The
repository's own label rule is looser; such a row would fail as `invalid_name` on every run.

Caps, so the DNS use of a probe stays bounded: a create is refused (422, `too_many`) when the
scope already holds `MAX_TENANT_SELECTORS` rows of that tenant, or `MAX_SELECTORS` global rows.
Disabled rows count, so re-enabling one can never exceed the cap. Concurrent creates can overshoot
by a few rows; the probe has its own cap (`app.services.dkim_probe_selectors`).

Audit: writes log the actor, selector id and scope only. Field checks are the repository's own, so
its limits and reasons are not restated here.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final

from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app.checks.dkim_selectors import MAX_SELECTORS
from app.core.domain_names import InvalidDomainName, to_dns_name
from app.core.permissions import (
    Action,
    Principal,
    RuleScope,
    RuleScopeResource,
    TenantResource,
    can,
)
from app.core.tenancy import TenantContext
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.repositories.base import DEFAULT_LIMIT
from app.repositories.dkim_selectors import (
    TENANT_FIELDS,
    DkimSelectorInvalid,
    DkimSelectorRecord,
    DkimSelectorRepository,
    SelectorTaken,
    clean_global_values,
)
from app.services.dkim_probe_selectors import all_visible

logger = logging.getLogger("app.dkim_selectors")

# Seed-owned on a seeded row: everything the API may set except `DKIM_LOCAL_FIELDS`.
SEED_MANAGED_FIELDS: Final = frozenset({"selector", "provider", "record_type"})
MAX_TENANT_SELECTORS: Final = 50

INVALID_SELECTOR_KEY: Final = "api.dkim_selectors.error.invalid_selector"
TOO_LONG_KEY: Final = "api.dkim_selectors.error.too_long"
DUPLICATE_KEY: Final = "api.dkim_selectors.error.duplicate"
SCOPE_FORBIDDEN_KEY: Final = "api.dkim_selectors.error.scope_forbidden"
NOT_FOUND_KEY: Final = "api.dkim_selectors.error.not_found"
INVALID_FIELD_KEY: Final = "api.dkim_selectors.error.invalid_field"
SEEDED_DELETE_KEY: Final = "api.dkim_selectors.error.seeded_delete"
TOO_MANY_KEY: Final = "api.dkim_selectors.error.too_many"


def field_key(field: str, reason: str) -> str:
    """The i18n key of a rejected field."""
    if reason == "too_long":
        return TOO_LONG_KEY
    if reason == "too_many":
        return TOO_MANY_KEY
    return INVALID_SELECTOR_KEY if field == "selector" else INVALID_FIELD_KEY


class DkimSelectorsAdminError(Exception):
    """Base error. `status` is the HTTP status, `key` the i18n key; never carries user input."""

    status = 500
    key = "ui.error.server.detail"


class SelectorNotFound(DkimSelectorsAdminError):
    status = 404
    key = NOT_FOUND_KEY


class ScopeForbidden(DkimSelectorsAdminError):
    status = 403
    key = SCOPE_FORBIDDEN_KEY


class SelectorConflict(DkimSelectorsAdminError):
    status = 409
    key = DUPLICATE_KEY


class SeededSelectorNotDeletable(DkimSelectorsAdminError):
    status = 409
    key = SEEDED_DELETE_KEY


class SelectorFieldInvalid(DkimSelectorsAdminError):
    """A rejected field: its name and a stable reason code, never its value."""

    status = 422

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason
        self.key = field_key(field, reason)


class DkimSelectorsAdminService:
    """One request's selector operations. `ctx` is None when the session has no active tenant."""

    def __init__(self, db: Session, ctx: TenantContext | None, principal: Principal) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal

    # --- authorization ------------------------------------------------------------------------

    def _tenant_id(self) -> int:
        if self._ctx is None:
            raise SelectorNotFound
        return self._ctx.tenant_id

    def check_read(self, scope: RuleScope) -> None:
        """Global: `rules.manage` on the global scope. Tenant: `rules.read`. No repository use."""
        if scope is RuleScope.GLOBAL:
            self.check_manage(scope)
        elif not can(self._principal, Action.RULES_READ, TenantResource(self._tenant_id())):
            raise ScopeForbidden

    def check_manage(self, scope: RuleScope) -> None:
        """`rules.manage` on `scope`, the tenant always being the context's. No repository use."""
        tenant_id = None if scope is RuleScope.GLOBAL else self._tenant_id()
        if not can(self._principal, Action.RULES_MANAGE, RuleScopeResource(scope, tenant_id)):
            raise ScopeForbidden

    def check_write(self, scope: RuleScope, selector_id: object) -> None:
        """Router pre-check: the caller may change this selector, whatever the body says."""
        self._writable(scope, selector_id)

    # --- helpers ------------------------------------------------------------------------------

    def _tenant_store(self) -> DkimSelectorRepository:
        assert self._ctx is not None  # guaranteed by the permission checks
        return repo_for(self._ctx, self._db).dkim_selectors

    def _store(self, scope: RuleScope) -> DkimSelectorRepository | GlobalDkimSelectorRepository:
        if scope is RuleScope.GLOBAL:
            return GlobalDkimSelectorRepository(self._db)
        return self._tenant_store()

    def _writable(self, scope: RuleScope, selector_id: object) -> DkimSelectorRecord:
        self.check_manage(scope)
        current = self._store(scope).get(selector_id)
        if current is None:
            raise SelectorNotFound
        if scope is RuleScope.TENANT and current.scope != RuleScope.TENANT.value:
            raise ScopeForbidden
        return current

    @staticmethod
    def _payload(data: Mapping[str, Any]) -> dict[str, Any]:
        """Only fields the API may set, on either scope. Unknown names (scope, tenant_id,
        locally_modified, seed_key...) are rejected without being echoed."""
        if not data:
            raise SelectorFieldInvalid("body", "empty")
        if any(name not in TENANT_FIELDS for name in data):
            raise SelectorFieldInvalid("body", "unknown_field")
        return dict(data)

    @staticmethod
    def _check_selector(values: Mapping[str, Any]) -> None:
        """The repository's own reasons first, then the probe's rule. Stores nothing."""
        if "selector" not in values:
            return
        selector = values["selector"]
        try:
            clean_global_values({"selector": selector})
        except DkimSelectorInvalid as exc:
            raise SelectorFieldInvalid(exc.field, exc.reason) from None
        name = f"{selector}._domainkey.example.com"
        try:
            probeable = selector != "*" and to_dns_name(name) == name
        except InvalidDomainName:
            probeable = False
        if not probeable:
            raise SelectorFieldInvalid("selector", "invalid_label")

    def _check_capacity(self, scope: RuleScope) -> None:
        if scope is RuleScope.GLOBAL:
            full = GlobalDkimSelectorRepository(self._db).count() >= MAX_SELECTORS
        else:
            own = [r for r in all_visible(self._tenant_store()) if r.scope == scope.value]
            full = len(own) >= MAX_TENANT_SELECTORS
        if full:
            raise SelectorFieldInvalid("selector", "too_many")

    def _audit(self, event: str, selector_id: int, scope: RuleScope) -> None:
        logger.info(
            "dkim selector changed",
            extra={
                "event": f"dkim_selectors.{event}",
                "actor": self._principal.user_id,
                "selector_id": selector_id,
                "selector_scope": scope.value,
            },
        )

    # --- reads --------------------------------------------------------------------------------

    def list_selectors(
        self, scope: RuleScope, *, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[DkimSelectorRecord]:
        self.check_read(scope)
        return self._store(scope).list(limit=limit, offset=offset)

    def get_selector(self, scope: RuleScope, selector_id: object) -> DkimSelectorRecord:
        self.check_read(scope)
        record = self._store(scope).get(selector_id)
        if record is None:
            raise SelectorNotFound
        return record

    # --- writes -------------------------------------------------------------------------------

    def create(self, scope: RuleScope, data: Mapping[str, Any]) -> DkimSelectorRecord:
        self.check_manage(scope)
        values = self._payload(data)
        self._check_selector(values)
        self._check_capacity(scope)
        try:
            if scope is RuleScope.GLOBAL:
                record = GlobalDkimSelectorRepository(self._db).create(
                    values, actor=self._principal.user_id
                )
            else:
                record = self._tenant_store().create(values)
        except DkimSelectorInvalid as exc:
            self._db.rollback()
            raise SelectorFieldInvalid(exc.field, exc.reason) from None
        except SelectorTaken:
            self._db.rollback()
            raise SelectorConflict from None
        self._db.commit()
        self._audit("created", record.id, scope)
        return record

    def update(
        self, scope: RuleScope, selector_id: object, data: Mapping[str, Any]
    ) -> DkimSelectorRecord:
        current = self._writable(scope, selector_id)
        values = self._payload(data)
        if current.seed_key is not None:
            for name in sorted(SEED_MANAGED_FIELDS & values.keys()):
                if values[name] != getattr(current, name):
                    raise SelectorFieldInvalid(name, "seed_managed")
        self._check_selector(values)
        if scope is RuleScope.GLOBAL:
            values["locally_modified"] = True
        try:
            record = self._store(scope).update(current.id, values)
        except DkimSelectorInvalid as exc:
            self._db.rollback()
            raise SelectorFieldInvalid(exc.field, exc.reason) from None
        except SelectorTaken:
            self._db.rollback()
            raise SelectorConflict from None
        except StaleDataError:  # deleted concurrently, between the load and the flush
            self._db.rollback()
            raise SelectorNotFound from None
        if record is None:  # deleted concurrently
            raise SelectorNotFound
        self._db.commit()
        self._audit("updated", record.id, scope)
        return record

    def delete(self, scope: RuleScope, selector_id: object) -> None:
        current = self._writable(scope, selector_id)
        if current.seed_key is not None:
            raise SeededSelectorNotDeletable
        try:
            deleted = self._store(scope).delete(current.id)
        except StaleDataError:  # deleted concurrently, between the load and the flush
            self._db.rollback()
            raise SelectorNotFound from None
        if not deleted:
            raise SelectorNotFound
        self._db.commit()
        self._audit("deleted", current.id, scope)
