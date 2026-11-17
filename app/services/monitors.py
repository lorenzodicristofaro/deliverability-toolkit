"""Monitor targets of tenant domains: list, read, create, change, delete (M7-11).

Authorization is decided with `can()` before any repository call; the repository
(`repo_for(ctx).monitor_targets`) filters on the tenant but does not know DomainAccess, so the
per-user domain rule is enforced here:
- every domain route first needs `domain.read` on the domain (a client viewer only on assigned
  domains, a toggle can switch it off): otherwise 404, exactly like a missing, malformed or
  foreign domain, so nothing tells an unassigned domain from a missing one;
- the domain must exist in the context tenant (`repo_for(ctx).domains.get`): otherwise 404;
- then `monitor.read` (read) or `monitor.read` + `monitor.manage` (writes; a write answers the
  target, so it needs read too): otherwise 403. Client viewers never hold `monitor.manage`.
- the tenant list needs `domain.list` on the active tenant (403 otherwise) and returns only the
  targets whose domain passes `domain.read` + `monitor.read` for the caller.
No active tenant: 404 everywhere.

Writes (each one transaction, committed here; rolled back on any refusal):
- create: a domain has at most one target (`MonitorExists`, 409, `monitor.error.exists`, also
  when a concurrent create wins the race at flush). A tenant holds at most `max_targets`
  (setting `MONITOR_MAX_TARGETS_PER_TENANT`): one more is `MonitorFieldInvalid("target",
  "limit_reached")` (422). The count is read before the insert, so two concurrent creates can
  pass it together and exceed the cap by the number of concurrent requests; the cap bounds work,
  it is not a security boundary. The first `next_run_at` is `clock.now()`: the scheduler runs
  the new target on its next tick, so the user gets a baseline right away (rate limits and the
  per-run jitter of later runs spread the load).
- update: only the given fields change. When `interval_seconds` changes, `next_run_at` becomes
  `min(next_run_at, now + interval)`, so shortening a daily schedule to hourly does not wait for
  the old daily slot; lengthening it keeps the slot already planned.
- delete: removes the target (its history, M7-12, is not touched here).
Field values are validated by the repository (built-in check ids only, interval from
`ALLOWED_INTERVALS_SECONDS`); a rejection is `MonitorFieldInvalid(field, reason)` (422) with an
i18n key, never the value.

Audit: no audit table exists yet (SPEC section 3 audit log is a later milestone; see
`app.services.domains`), so writes log a structured `monitors.<event>` line with the actor,
domain id and target id only, as the other admin services do.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import timedelta
from typing import Any, Final

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.permissions import Action, DomainResource, Principal, TenantResource, can
from app.core.tenancy import TenantContext
from app.models.monitor_target import ALLOWED_INTERVALS_SECONDS
from app.repositories import repo_for
from app.repositories.base import MAX_LIMIT, coerce_id
from app.repositories.monitor_targets import (
    MonitorTargetExists,
    MonitorTargetInvalid,
    MonitorTargetRecord,
    MonitorTargetRepository,
)
from app.services.clock import Clock, SystemClock

logger = logging.getLogger("app.monitors")

NOT_FOUND_KEY: Final = "monitor.error.not_found"
EXISTS_KEY: Final = "monitor.error.exists"
LIMIT_KEY: Final = "monitor.error.limit_reached"
INVALID_INTERVAL_KEY: Final = "monitor.error.invalid_interval"
UNKNOWN_CHECK_KEY: Final = "monitor.error.unknown_check"
INVALID_CHECKS_KEY: Final = "monitor.error.invalid_checks"
INVALID_REQUEST_KEY: Final = "api.error.invalid_request"
FORBIDDEN_KEY: Final = "api.error.forbidden"
CONFLICT_KEY: Final = "api.error.conflict"


def field_key(field: str, reason: str) -> str:
    """The i18n key of a rejected field."""
    if field == "check_ids":
        return UNKNOWN_CHECK_KEY if reason == "unknown_check" else INVALID_CHECKS_KEY
    if field == "interval_seconds":
        return INVALID_INTERVAL_KEY
    if field == "target" and reason == "limit_reached":
        return LIMIT_KEY
    return INVALID_REQUEST_KEY


class MonitorError(Exception):
    """Base error. `status` is the HTTP status, `key` the i18n key; never carries user input."""

    status = 500
    key = "ui.error.server.detail"


class MonitorNotFound(MonitorError):
    status = 404
    key = NOT_FOUND_KEY


class MonitorForbidden(MonitorError):
    status = 403
    key = FORBIDDEN_KEY


class MonitorExists(MonitorError):
    """The domain already has a monitor target."""

    status = 409
    key = EXISTS_KEY


class MonitorConflict(MonitorError):
    status = 409
    key = CONFLICT_KEY


class MonitorFieldInvalid(MonitorError):
    """A rejected field (or the tenant cap, field `target`): name and reason, never the value."""

    status = 422

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason
        self.key = field_key(field, reason)


class MonitorService:
    """One request's monitor operations. `ctx` is None when the session has no active tenant."""

    def __init__(
        self,
        db: Session,
        ctx: TenantContext | None,
        principal: Principal,
        *,
        max_targets: int,
        clock: Clock | None = None,
    ) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal
        self._max_targets = max_targets
        self._clock: Clock = clock if clock is not None else SystemClock()

    # --- authorization ------------------------------------------------------------------------

    def _context(self) -> TenantContext:
        if self._ctx is None:
            raise MonitorNotFound
        return self._ctx

    def _readable(self, ctx: TenantContext, domain_id: int) -> bool:
        resource = DomainResource(ctx.tenant_id, domain_id)
        return can(self._principal, Action.DOMAIN_READ, resource) and can(
            self._principal, Action.MONITOR_READ, resource
        )

    def _domain(self, domain_id: object, *, manage: bool) -> int:
        """The id of an existing domain of the context tenant the caller may read the target of
        (and manage, with `manage`). See the module docstring for the order of the answers."""
        ctx = self._context()
        did = coerce_id(domain_id)
        if did is None:
            raise MonitorNotFound
        resource = DomainResource(ctx.tenant_id, did)
        if not can(self._principal, Action.DOMAIN_READ, resource):
            raise MonitorNotFound
        if repo_for(ctx, self._db).domains.get(did) is None:
            raise MonitorNotFound
        if not can(self._principal, Action.MONITOR_READ, resource):
            raise MonitorForbidden
        if manage and not can(self._principal, Action.MONITOR_MANAGE, resource):
            raise MonitorForbidden
        return did

    def check_read(self, domain_id: object) -> int:
        return self._domain(domain_id, manage=False)

    def check_manage(self, domain_id: object) -> int:
        """Router pre-check (before the body is parsed)."""
        return self._domain(domain_id, manage=True)

    def _repo(self) -> MonitorTargetRepository:
        return repo_for(self._context(), self._db).monitor_targets

    def _audit(self, event: str, domain_id: int, target_id: int) -> None:
        logger.info(
            "monitor target changed",
            extra={
                "event": f"monitors.{event}",
                "actor": self._principal.user_id,
                "domain_id": domain_id,
                "target_id": target_id,
            },
        )

    # --- reads --------------------------------------------------------------------------------

    def list_targets(self) -> Sequence[MonitorTargetRecord]:
        """The targets of the active tenant on the domains the caller may read, ordered by id.
        One read: the per-tenant cap is at most MAX_LIMIT."""
        ctx = self._context()
        if not can(self._principal, Action.DOMAIN_LIST, TenantResource(ctx.tenant_id)):
            raise MonitorForbidden
        records = self._repo().list(limit=MAX_LIMIT)
        return [r for r in records if self._readable(ctx, r.domain_id)]

    def get(self, domain_id: object) -> MonitorTargetRecord:
        did = self.check_read(domain_id)
        record = self._repo().get_for_domain(did)
        if record is None:
            raise MonitorNotFound
        return record

    # --- writes -------------------------------------------------------------------------------

    def create(
        self, domain_id: object, *, check_ids: object, interval_seconds: object, enabled: object
    ) -> MonitorTargetRecord:
        did = self.check_manage(domain_id)
        repo = self._repo()
        if repo.get_for_domain(did) is not None:
            raise MonitorExists
        if len(repo.list(limit=self._max_targets)) >= self._max_targets:
            raise MonitorFieldInvalid("target", "limit_reached")
        try:
            record = repo.create(
                did,
                check_ids=check_ids,
                interval_seconds=interval_seconds,
                enabled=enabled,
                next_run_at=self._clock.now(),
            )
        except MonitorTargetInvalid as exc:
            self._db.rollback()
            raise MonitorFieldInvalid(exc.field, exc.reason) from None
        except MonitorTargetExists:
            self._db.rollback()
            raise MonitorExists from None
        except IntegrityError:
            # A concurrent create for the same domain (or the domain deleted meanwhile).
            self._db.rollback()
            if self._repo().get_for_domain(did) is not None:
                raise MonitorExists from None
            raise MonitorConflict from None
        if record is None:  # the domain vanished between the check and the insert
            self._db.rollback()
            raise MonitorNotFound
        self._db.commit()
        self._audit("created", did, record.id)
        return record

    def update(self, domain_id: object, /, **fields: object) -> MonitorTargetRecord:
        """Change the given fields (`check_ids`, `interval_seconds`, `enabled`) only."""
        did = self.check_manage(domain_id)
        unknown = set(fields) - {"check_ids", "interval_seconds", "enabled"}
        if unknown:
            raise MonitorFieldInvalid(sorted(unknown)[0], "unknown_field")
        repo = self._repo()
        current = repo.get_for_domain(did)
        if current is None:
            raise MonitorNotFound
        values: dict[str, Any] = dict(fields)
        interval = fields.get("interval_seconds", current.interval_seconds)
        # Only a valid new interval moves the slot; anything else is rejected by the repository.
        if (
            type(interval) is int
            and interval != current.interval_seconds
            and interval in ALLOWED_INTERVALS_SECONDS
        ):
            values["next_run_at"] = min(
                current.next_run_at, self._clock.now() + timedelta(seconds=interval)
            )
        try:
            record = repo.update(current.id, **values)
        except MonitorTargetInvalid as exc:
            self._db.rollback()
            raise MonitorFieldInvalid(exc.field, exc.reason) from None
        if record is None:  # deleted concurrently
            self._db.rollback()
            raise MonitorNotFound
        self._db.commit()
        self._audit("updated", did, record.id)
        return record

    def delete(self, domain_id: object) -> None:
        did = self.check_manage(domain_id)
        repo = self._repo()
        current = repo.get_for_domain(did)
        if current is None or not repo.delete(current.id):
            self._db.rollback()
            raise MonitorNotFound
        self._db.commit()
        self._audit("deleted", did, current.id)
