"""Custom checks administration (M5-23): list, read, create, update, delete, dry run; and the
custom checks of a domain run.

Same scopes and permissions as the content rules (`app.services.content_rules_admin`), authorized
with `can()` BEFORE any repository is built:
- `tenant` (default): reads need `rules.read` on the active tenant and see the global rows plus
  that tenant's rows; writes need `rules.manage` on the active tenant and reach only its rows.
  `tenant_id` always comes from the `TenantContext`, never from the request.
- `global`: every verb needs `rules.manage` on the global scope (the instance admin flag), needs
  no active tenant, and reaches only global rows.

Outcomes: a check that is missing, of another tenant or malformed is `CustomCheckNotFound` (404),
as is a tenant-scoped call with no active tenant. A denied permission is `ScopeForbidden` (403),
and so is a tenant-path write to a global row. A duplicate `check_key` in the scope is 409.

Validation is the repository's (field checks plus the M5-22 schema on every write path); this
service only maps its reasons to i18n keys. `http_fetch` is refused first, whatever else the body
holds, as `kind_unavailable` (422, M7). `remediation_key` is accepted on the global path only
and must name a message present in every catalogue (`validate_remediation_key`), so a finding
carrying it always renders.

Dry run (`test`): needs `rules.read` on the active tenant (so never a client viewer), then
`check.run` on the domain named in the body (`DomainService` visibility first: a foreign,
missing or out-of-range id is 404). The definition is validated like a stored one and evaluated
by the same evaluator and runner as a domain run, and is stored nowhere. Every permission
decision happens before the evaluator or any DNS query.

Domain runs (`run_checks_for`): the enabled global rows plus the context tenant's enabled rows,
read only through the tenant repository, so another tenant's checks never run on this tenant's
domains. All of them share one `RunBudget`. At most MAX_RUN_CUSTOM_CHECKS query DNS; any further
one gets a spent budget and reports `error` without a query, so a run's DNS use stays bounded and
no check silently disappears.

Audit: writes log the actor, check id and scope only; definitions are never logged.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from app.checks.custom import CustomDnsCheck, RunBudget
from app.core.custom_check_schema import (
    DefinitionInvalid,
    parse_definition,
    validate_remediation_key,
    validate_remediation_text,
    validate_severity,
)
from app.core.permissions import (
    Action,
    DomainResource,
    Principal,
    RuleScope,
    RuleScopeResource,
    TenantResource,
    can,
)
from app.core.tenancy import TenantContext
from app.models.custom_check import RESERVED_KINDS
from app.repositories import GlobalCustomCheckRepository, repo_for
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, coerce_id
from app.repositories.custom_checks import (
    FIELDS,
    CheckKeyTaken,
    CustomCheckInvalid,
    CustomCheckRecord,
    CustomCheckRepository,
)
from app.services.domains import DomainService, DomainServiceError

logger = logging.getLogger("app.rules")

MAX_RUN_CUSTOM_CHECKS: Final = 50
DRY_RUN_SLUG: Final = "dry-run"

TENANT_WRITE_FIELDS: Final = FIELDS - {"remediation_key"}
GLOBAL_WRITE_FIELDS: Final = FIELDS
TEST_FIELDS: Final = frozenset({"domain_id", "kind", "definition", "severity", "remediation_text"})
_DEFAULT_TEST_SEVERITY: Final = "medium"

INVALID_DEFINITION_KEY: Final = "api.custom_checks.error.invalid_definition"
KIND_UNAVAILABLE_KEY: Final = "api.custom_checks.error.kind_unavailable"
SCOPE_FORBIDDEN_KEY: Final = "api.custom_checks.error.scope_forbidden"
NOT_FOUND_KEY: Final = "api.custom_checks.error.not_found"
NAME_TOO_LONG_KEY: Final = "api.custom_checks.error.name_too_long"
DUPLICATE_KEY: Final = "api.custom_checks.error.duplicate"


def field_key(field: str, reason: str) -> str:
    """The i18n key of a rejected field."""
    if field == "kind" and reason in ("reserved", "kind_unavailable"):
        return KIND_UNAVAILABLE_KEY
    if field == "name" and reason == "too_long":
        return NAME_TOO_LONG_KEY
    return INVALID_DEFINITION_KEY


class CustomChecksAdminError(Exception):
    """Base error. `status` is the HTTP status, `key` the i18n key; never carries user input."""

    status = 500
    key = "ui.error.server.detail"


class CustomCheckNotFound(CustomChecksAdminError):
    status = 404
    key = NOT_FOUND_KEY


class ScopeForbidden(CustomChecksAdminError):
    status = 403
    key = SCOPE_FORBIDDEN_KEY


class CheckKeyConflict(CustomChecksAdminError):
    status = 409
    key = DUPLICATE_KEY


class DomainRefused(CustomChecksAdminError):
    """The dry run's domain is not visible (404) or not runnable (403): the domain service's own
    status and key, so it answers like the check routes."""

    def __init__(self, status: int, key: str) -> None:
        super().__init__(key)
        self.status = status
        self.key = key


class CustomCheckFieldInvalid(CustomChecksAdminError):
    """A rejected field: its name and a stable reason code, never its value."""

    status = 422

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason
        self.key = field_key(field, reason)


@dataclass(frozen=True, slots=True)
class DryRun:
    """What the router runs once the database is released: plain values only."""

    tenant_id: int
    domain_id: int
    domain_name: str
    check: CustomDnsCheck


def _record_check(record: CustomCheckRecord, budget: RunBudget) -> CustomDnsCheck:
    return CustomDnsCheck(
        check_key=record.check_key,
        kind=record.kind,
        definition=record.definition,
        severity=record.severity,
        remediation_text=record.remediation_text,
        remediation_key=record.remediation_key,
        scope=record.scope,
        budget=budget,
    )


def run_checks_for(ctx: TenantContext, db: Session) -> list[CustomDnsCheck]:
    """The custom checks of a domain run of `ctx`'s tenant, in id order (global and own rows)."""
    store = repo_for(ctx, db).custom_checks
    records: list[CustomCheckRecord] = []
    while True:
        page = store.list(enabled_only=True, limit=MAX_LIMIT, offset=len(records))
        records.extend(page)
        if len(page) < MAX_LIMIT:
            break
    shared = RunBudget()
    spent = RunBudget(0.0)
    return [
        _record_check(record, shared if n < MAX_RUN_CUSTOM_CHECKS else spent)
        for n, record in enumerate(records)
    ]


class CustomChecksAdminService:
    """One request's custom check operations. `ctx` is None when the session has no tenant."""

    def __init__(self, db: Session, ctx: TenantContext | None, principal: Principal) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal

    # --- authorization ------------------------------------------------------------------------

    def _tenant_id(self) -> int:
        if self._ctx is None:
            raise CustomCheckNotFound
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

    def check_write(self, scope: RuleScope, check_id: object) -> None:
        """Router pre-check: the caller may change this check, whatever the body says."""
        self._writable(scope, check_id)

    def check_test(self) -> None:
        """Dry run pre-check, before the body is read: `rules.read` on the active tenant."""
        self.check_read(RuleScope.TENANT)

    # --- helpers ------------------------------------------------------------------------------

    def _tenant_store(self) -> CustomCheckRepository:
        assert self._ctx is not None  # guaranteed by the permission checks
        return repo_for(self._ctx, self._db).custom_checks

    def _store(self, scope: RuleScope) -> CustomCheckRepository | GlobalCustomCheckRepository:
        if scope is RuleScope.GLOBAL:
            return GlobalCustomCheckRepository(self._db)
        return self._tenant_store()

    def _writable(self, scope: RuleScope, check_id: object) -> CustomCheckRecord:
        self.check_manage(scope)
        current = self._store(scope).get(check_id)
        if current is None:
            raise CustomCheckNotFound
        if scope is RuleScope.TENANT and current.scope != RuleScope.TENANT.value:
            raise ScopeForbidden
        return current

    @staticmethod
    def _payload(scope: RuleScope, data: Mapping[str, Any]) -> dict[str, Any]:
        """Only fields the API may set; unknown names (scope, tenant_id...) are not echoed.
        `http_fetch` is refused before anything else."""
        allowed = GLOBAL_WRITE_FIELDS if scope is RuleScope.GLOBAL else TENANT_WRITE_FIELDS
        if not data:
            raise CustomCheckFieldInvalid("body", "empty")
        if any(name not in allowed for name in data):
            raise CustomCheckFieldInvalid("body", "unknown_field")
        kind = data.get("kind")
        if isinstance(kind, str) and kind in RESERVED_KINDS:
            raise CustomCheckFieldInvalid("kind", "kind_unavailable")
        if data.get("remediation_key") is not None:
            try:
                validate_remediation_key(data["remediation_key"])
            except DefinitionInvalid as exc:
                raise CustomCheckFieldInvalid(exc.field, exc.reason) from None
        return dict(data)

    def _audit(self, event: str, check_id: int, scope: RuleScope) -> None:
        logger.info(
            "custom check changed",
            extra={
                "event": f"custom_checks.{event}",
                "actor": self._principal.user_id,
                "custom_check_id": check_id,
                "rule_scope": scope.value,
            },
        )

    # --- reads --------------------------------------------------------------------------------

    def list_checks(
        self, scope: RuleScope, *, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[CustomCheckRecord]:
        self.check_read(scope)
        return self._store(scope).list(limit=limit, offset=offset)

    def get_check(self, scope: RuleScope, check_id: object) -> CustomCheckRecord:
        self.check_read(scope)
        record = self._store(scope).get(check_id)
        if record is None:
            raise CustomCheckNotFound
        return record

    # --- writes -------------------------------------------------------------------------------

    def create(self, scope: RuleScope, data: Mapping[str, Any]) -> CustomCheckRecord:
        self.check_manage(scope)
        values = self._payload(scope, data)
        try:
            if scope is RuleScope.GLOBAL:
                record = GlobalCustomCheckRepository(self._db).create(
                    values, actor=self._principal.user_id
                )
            else:
                record = self._tenant_store().create(values)
        except CustomCheckInvalid as exc:
            self._db.rollback()
            raise CustomCheckFieldInvalid(exc.field, exc.reason) from None
        except CheckKeyTaken:
            self._db.rollback()
            raise CheckKeyConflict from None
        self._db.commit()
        self._audit("created", record.id, scope)
        return record

    def update(
        self, scope: RuleScope, check_id: object, data: Mapping[str, Any]
    ) -> CustomCheckRecord:
        current = self._writable(scope, check_id)
        values = self._payload(scope, data)
        try:
            record = self._store(scope).update(current.id, values)
        except CustomCheckInvalid as exc:
            self._db.rollback()
            raise CustomCheckFieldInvalid(exc.field, exc.reason) from None
        except CheckKeyTaken:
            self._db.rollback()
            raise CheckKeyConflict from None
        except StaleDataError:  # deleted concurrently, between the load and the flush
            self._db.rollback()
            raise CustomCheckNotFound from None
        if record is None:  # deleted concurrently
            raise CustomCheckNotFound
        self._db.commit()
        self._audit("updated", record.id, scope)
        return record

    def delete(self, scope: RuleScope, check_id: object) -> None:
        current = self._writable(scope, check_id)
        if not self._store(scope).delete(current.id):
            raise CustomCheckNotFound
        self._db.commit()
        self._audit("deleted", current.id, scope)

    # --- dry run ------------------------------------------------------------------------------

    def _test_domain(self, value: object) -> tuple[int, int, str]:
        """The visible domain the caller may run checks on (404 / 403 otherwise)."""
        assert self._ctx is not None  # check_test ran first
        domain_id = coerce_id(value)
        try:
            view = DomainService(self._db, self._ctx, self._principal).get(domain_id)
        except DomainServiceError as exc:
            raise DomainRefused(exc.status, exc.key) from None
        resource = DomainResource(self._ctx.tenant_id, view.id)
        if not can(self._principal, Action.CHECK_RUN, resource):
            raise DomainRefused(403, "api.error.forbidden")
        return self._ctx.tenant_id, view.id, view.name

    def prepare_test(self, data: Mapping[str, Any]) -> DryRun:
        """Authorize and validate a dry run; returns the check to run, touching no DNS."""
        self.check_test()
        if any(name not in TEST_FIELDS for name in data):
            raise CustomCheckFieldInvalid("body", "unknown_field")
        tenant_id, domain_id, name = self._test_domain(data.get("domain_id"))
        kind, definition = data.get("kind"), data.get("definition")
        severity = data.get("severity", _DEFAULT_TEST_SEVERITY)
        remediation = data.get("remediation_text")
        try:
            parse_definition(kind, definition)
            validate_severity(severity)
            if remediation is not None:
                validate_remediation_text(remediation)
        except DefinitionInvalid as exc:
            raise CustomCheckFieldInvalid(exc.field, exc.reason) from None
        check = CustomDnsCheck(
            check_key=DRY_RUN_SLUG,
            kind=kind,
            definition=definition,
            severity=severity,
            remediation_text=remediation,
            scope=RuleScope.TENANT.value,
            remediation_optional=True,
        )
        return DryRun(tenant_id, domain_id, name, check)
