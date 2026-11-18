"""Monitor target repositories (M7-06). The only access path to `monitor_targets`.

Two classes, deliberately separate:

`MonitorTargetRepository` is tenant-scoped (reached through `repo_for`). Same rules as
`DomainEspRepository`: built only with a `TenantContext`; every query is filtered on
`tenant_id = ctx.tenant_id` and every row is written with the context tenant; a domain or a
target of another tenant behaves exactly like a missing or malformed one (None / False / empty);
the composite FK (domain_id, tenant_id) -> domains(id, tenant_id) makes a cross-tenant row
impossible in the database too. Not built on `TenantScopedRepository` because its generic
`add(obj)` / `update(id, values)` would bypass the validation below.

`MonitorSchedulerRepository` holds the ONLY cross-tenant methods of this module, the system entry
point of the scheduler (M7-09), like the `Global*` repositories for instance-level data: not part
of `repo_for`, never given a tenant or domain by its caller.
- `due_targets(now, limit)`: read-only; returns `DueTarget`s carrying `tenant_id` so the caller
  builds a `TenantContext` for the run and does every further read or write of tenant data
  (including `last_run_at`/`last_status`) through the tenant repository.
- `claim(target_id, expected_next_run_at, new_next_run_at)`: the one system write. A single
  conditional UPDATE of `next_run_at` on a target id the scheduler got from `due_targets`; it only
  succeeds while the row is enabled and still has the `next_run_at` that was read, so of several
  schedulers (or replicas) that read the same due target exactly one wins. It writes nothing else.

Validation before the database (same outcome on SQLite and PostgreSQL), raising
`MonitorTargetInvalid` with the field and a stable reason, never the value:
- `check_ids`: a non-empty list/tuple of distinct ids that all exist in the built-in check
  registry; stored sorted.
- `interval_seconds`: an int from `ALLOWED_INTERVALS_SECONDS` (never below
  `MIN_INTERVAL_SECONDS`).
- `enabled`: a real bool; datetimes must be timezone-aware (stored as UTC); `last_status` one of
  the check statuses.

A concurrent create for the same domain surfaces as an IntegrityError from the flush (the
session must roll back). Callers get immutable records, never ORM objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, cast

from sqlalchemy import ColumnElement, CursorResult, Select, select, update
from sqlalchemy.orm import Session

from app.checks.registry import load_builtin_checks
from app.core.tenancy import TenantContext
from app.models import Domain, MonitorTarget
from app.models.monitor_target import ALLOWED_INTERVALS_SECONDS, LAST_STATUSES
from app.repositories.base import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    _install_tenant_guard,
    coerce_id,
)

_install_tenant_guard(MonitorTarget.tenant_id)

_UNSET: Final[Any] = object()


class MonitorTargetInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"monitor target {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class MonitorTargetExists(Exception):
    """The domain already has a monitor target."""


def _utc(value: datetime) -> datetime:
    # SQLite returns naive datetimes: values are always written as UTC, so tag them back.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class MonitorTargetRecord:
    id: int
    domain_id: int
    check_ids: tuple[str, ...]
    interval_seconds: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, row: MonitorTarget) -> MonitorTargetRecord:
        return cls(
            id=row.id,
            domain_id=row.domain_id,
            check_ids=tuple(row.check_ids),
            interval_seconds=row.interval_seconds,
            enabled=row.enabled,
            next_run_at=_utc(row.next_run_at),
            last_run_at=None if row.last_run_at is None else _utc(row.last_run_at),
            last_status=row.last_status,
            created_at=_utc(row.created_at),
            updated_at=_utc(row.updated_at),
        )


@dataclass(frozen=True, slots=True)
class DueTarget:
    """What the scheduler needs to run a target: `tenant_id` rebuilds the `TenantContext`."""

    id: int
    tenant_id: int
    domain_id: int
    check_ids: tuple[str, ...]
    interval_seconds: int
    next_run_at: datetime


def known_check_ids() -> frozenset[str]:
    """The check ids a target may carry: the built-in registry."""
    return frozenset(load_builtin_checks().all_ids())


def validate_check_ids(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise MonitorTargetInvalid("check_ids", "not_a_list")
    if not value:
        raise MonitorTargetInvalid("check_ids", "empty")
    if not all(isinstance(v, str) for v in value):
        raise MonitorTargetInvalid("check_ids", "not_a_string")
    if len(set(value)) != len(value):
        raise MonitorTargetInvalid("check_ids", "duplicate")
    if not set(value) <= known_check_ids():
        raise MonitorTargetInvalid("check_ids", "unknown_check")
    return sorted(value)


def validate_interval(value: object) -> int:
    if type(value) is not int:
        raise MonitorTargetInvalid("interval_seconds", "not_an_int")
    if value not in ALLOWED_INTERVALS_SECONDS:
        raise MonitorTargetInvalid("interval_seconds", "not_allowed")
    return value


def _flag(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise MonitorTargetInvalid(field, "not_a_bool")
    return value


def _aware(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MonitorTargetInvalid(field, "not_aware")
    return value.astimezone(UTC)


def _status(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in LAST_STATUSES:
        raise MonitorTargetInvalid("last_status", "unknown_status")
    return value


class MonitorTargetRepository:
    """Monitor targets of the context tenant's domains."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _select(self, *criteria: ColumnElement[bool]) -> Select[MonitorTarget]:
        return select(MonitorTarget).where(
            MonitorTarget.tenant_id == self._ctx.tenant_id, *criteria
        )

    def _row(self, target_id: object) -> MonitorTarget | None:
        tid = coerce_id(target_id)
        if tid is None:
            return None
        return self._session.scalars(self._select(MonitorTarget.id == tid)).one_or_none()

    def _domain_exists(self, domain_id: int) -> bool:
        stmt = select(Domain.id).where(
            Domain.id == domain_id, Domain.tenant_id == self._ctx.tenant_id
        )
        return self._session.scalar(stmt) is not None

    # --- reads ------------------------------------------------------------------------------

    def get(self, target_id: object) -> MonitorTargetRecord | None:
        """The target; None if missing, foreign or malformed."""
        row = self._row(target_id)
        return None if row is None else MonitorTargetRecord.from_model(row)

    def lock_latest_run(self, target_id: object, last_run_at: object) -> bool:
        """True when the target's `last_run_at` is still `last_run_at` (no newer run stored
        since, by any worker); the target row then stays locked until the transaction ends, so a
        newer run cannot store (or emit with this guard) before this transaction commits.
        PostgreSQL: SELECT .. FOR UPDATE (after waiting for a concurrent store, the row is
        re-checked and no longer matches). SQLite: a no-op conditional UPDATE, which begins the
        write transaction and takes SQLite's single writer lock. False if the target is missing,
        foreign or malformed, or a newer run was stored. `last_run_at` must be timezone-aware."""
        at = _aware(last_run_at, "last_run_at")
        tid = coerce_id(target_id)
        if tid is None:
            return False
        match = (
            MonitorTarget.tenant_id == self._ctx.tenant_id,
            MonitorTarget.id == tid,
            MonitorTarget.last_run_at == at,
        )
        if self._session.get_bind().dialect.name == "postgresql":
            stmt = select(MonitorTarget.id).where(*match).with_for_update()
            return self._session.scalar(stmt) is not None
        touch = (
            update(MonitorTarget)
            .where(*match)
            .values(last_run_at=MonitorTarget.last_run_at, updated_at=MonitorTarget.updated_at)
            .execution_options(synchronize_session=False)
        )
        return int(cast(CursorResult[Any], self._session.execute(touch)).rowcount) == 1

    def get_for_domain(self, domain_id: object) -> MonitorTargetRecord | None:
        """The target of the domain; None if there is none or the domain is foreign/malformed."""
        did = coerce_id(domain_id)
        if did is None:
            return None
        row = self._session.scalars(self._select(MonitorTarget.domain_id == did)).one_or_none()
        return None if row is None else MonitorTargetRecord.from_model(row)

    def list(self, *, limit: int = DEFAULT_LIMIT, offset: int = 0) -> Sequence[MonitorTargetRecord]:
        """Targets of the context tenant ordered by id."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be an int between 0 and {MAX_LIMIT}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative int")
        stmt = self._select().order_by(MonitorTarget.id).limit(limit).offset(offset)
        return [MonitorTargetRecord.from_model(r) for r in self._session.scalars(stmt)]

    # --- writes (flushed, not committed) ------------------------------------------------------

    def create(
        self,
        domain_id: object,
        *,
        check_ids: object,
        interval_seconds: object,
        next_run_at: object,
        enabled: object = True,
    ) -> MonitorTargetRecord | None:
        """Create the domain's target. None (nothing written) if the domain is missing, foreign
        or malformed; MonitorTargetInvalid for a bad value; MonitorTargetExists if the domain
        already has a target."""
        checks = validate_check_ids(check_ids)
        interval = validate_interval(interval_seconds)
        is_enabled = _flag(enabled, "enabled")
        first_run = _aware(next_run_at, "next_run_at")
        did = coerce_id(domain_id)
        if did is None or not self._domain_exists(did):
            return None
        if self._session.scalar(self._select(MonitorTarget.domain_id == did)) is not None:
            raise MonitorTargetExists
        row = MonitorTarget(
            tenant_id=self._ctx.tenant_id,
            domain_id=did,
            check_ids=checks,
            interval_seconds=interval,
            enabled=is_enabled,
            next_run_at=first_run,
        )
        self._session.add(row)
        self._session.flush()
        self._session.refresh(row)
        return MonitorTargetRecord.from_model(row)

    def update(
        self,
        target_id: object,
        *,
        check_ids: object = _UNSET,
        interval_seconds: object = _UNSET,
        enabled: object = _UNSET,
        next_run_at: object = _UNSET,
        last_run_at: object = _UNSET,
        last_status: object = _UNSET,
    ) -> MonitorTargetRecord | None:
        """Change the given fields only. None (nothing changes) if the target is missing,
        foreign or malformed; MonitorTargetInvalid for a bad value. `tenant_id` and `domain_id`
        cannot be changed."""
        values: dict[str, Any] = {}
        if check_ids is not _UNSET:
            values["check_ids"] = validate_check_ids(check_ids)
        if interval_seconds is not _UNSET:
            values["interval_seconds"] = validate_interval(interval_seconds)
        if enabled is not _UNSET:
            values["enabled"] = _flag(enabled, "enabled")
        if next_run_at is not _UNSET:
            values["next_run_at"] = _aware(next_run_at, "next_run_at")
        if last_run_at is not _UNSET:
            values["last_run_at"] = _aware(last_run_at, "last_run_at")
        if last_status is not _UNSET:
            values["last_status"] = _status(last_status)
        row = self._row(target_id)
        if row is None:
            return None
        for key, value in values.items():
            setattr(row, key, value)
        self._session.flush()
        self._session.refresh(row)
        return MonitorTargetRecord.from_model(row)

    def delete(self, target_id: object) -> bool:
        """Delete the target; False if missing, foreign or malformed."""
        row = self._row(target_id)
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True


class MonitorSchedulerRepository:
    """System entry point of the scheduler (M7-09). Not part of `repo_for`.

    `due_targets` and `claim` are the only cross-tenant methods for monitor targets (see the
    module docstring).
    """

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    def due_targets(self, now: object, limit: object) -> list[DueTarget]:
        """Enabled targets of ANY tenant with `next_run_at <= now`, oldest first (ties by id),
        at most `limit` (1..MAX_LIMIT). Read-only. `now` must be timezone-aware."""
        moment = _aware(now, "now")
        if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be an int between 1 and {MAX_LIMIT}")
        stmt = (
            select(MonitorTarget)
            .where(MonitorTarget.enabled.is_(True), MonitorTarget.next_run_at <= moment)
            .order_by(MonitorTarget.next_run_at, MonitorTarget.id)
            .limit(limit)
        )
        return [
            DueTarget(
                id=r.id,
                tenant_id=r.tenant_id,
                domain_id=r.domain_id,
                check_ids=tuple(r.check_ids),
                interval_seconds=r.interval_seconds,
                next_run_at=_utc(r.next_run_at),
            )
            for r in self._session.scalars(stmt)
        ]

    def claim(
        self, target_id: object, expected_next_run_at: object, new_next_run_at: object
    ) -> bool:
        """Move an enabled target's `next_run_at` from `expected_next_run_at` (the value
        `due_targets` returned) to `new_next_run_at` in one conditional UPDATE. True only for the
        caller whose UPDATE changed the row; False if another claim got there first, the target
        was disabled, deleted or rescheduled meanwhile, or the id is malformed. Datetimes must be
        timezone-aware. Flushed, not committed: commit right away so other schedulers see it."""
        expected = _aware(expected_next_run_at, "expected_next_run_at")
        new = _aware(new_next_run_at, "new_next_run_at")
        tid = coerce_id(target_id)
        if tid is None:
            return False
        stmt = (
            update(MonitorTarget)
            .where(
                MonitorTarget.id == tid,
                MonitorTarget.next_run_at == expected,
                MonitorTarget.enabled.is_(True),
            )
            .values(next_run_at=new)
            .execution_options(synchronize_session=False)
        )
        result = self._session.execute(stmt)
        return int(cast(CursorResult[Any], result).rowcount) == 1
