"""Alert repositories (M7-14). The only access path to `alerts`, `alert_deliveries` and
`alert_rules`.

All three are tenant-scoped (reached through `repo_for`): built only with a `TenantContext`,
every query filtered on `tenant_id = ctx.tenant_id`, every row written with the context tenant.
An alert, delivery, rule or domain of another tenant behaves exactly like a missing or malformed
one (None / False / empty); composite FKs make a cross-tenant row impossible in the database too.
Not built on `TenantScopedRepository`: its generic `add` / `update` would bypass the rules below.

Idempotence (ARCHITECTURE section 6, "Alerts"):
- `AlertRepository.insert_if_absent` is a single INSERT .. ON CONFLICT (tenant_id, fingerprint,
  state_hash) DO NOTHING: of any number of concurrent or replayed inserts of the same alert one
  row exists and only its inserter gets a record back. There is no check-then-insert.
- `AlertDeliveryRepository.add_pending` is INSERT .. ON CONFLICT (alert_id, channel_id) DO
  NOTHING, so a replay never adds a second delivery.
- Delivery state changes are conditional UPDATEs on the attempt counter read by the caller
  (`claim`, `mark_sent`, `mark_failed`): of two workers on the same delivery one wins, and a stale
  worker can never move a `sent` delivery back.

Writes are flushed, not committed: the caller owns the transaction. Callers get immutable
records, never ORM objects. Values are validated before the database (same outcome on SQLite and
PostgreSQL) and rejected with `AlertInvalid(field, reason)`, never echoing the value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, cast

from sqlalchemy import ColumnElement, CursorResult, Insert, Select, Table, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.models import Alert, AlertDelivery, AlertRule, Domain
from app.models.alert import (
    HASH_LENGTH,
    KINDS,
    MAX_CODE_LENGTH,
    MAX_ERROR_LENGTH,
)
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, _install_tenant_guard, coerce_id

_install_tenant_guard(Alert.tenant_id)
_install_tenant_guard(AlertDelivery.tenant_id)
_install_tenant_guard(AlertRule.tenant_id)

_HASH = re.compile(r"\A[0-9a-f]{64}\Z")
_CODE = re.compile(r"\A[A-Z][A-Z0-9_]{0,63}\Z")
# Delivery error codes: short stable slugs (e.g. `timeout`, `http_5xx`), never a message.
_ERROR = re.compile(r"\A[a-z0-9][a-z0-9_.-]{0,63}\Z")
# Bounds of the stored params (keys and values); longer strings are cut by the service.
MAX_PARAMS: Final = 8
MAX_PARAM_KEY: Final = 32
MAX_PARAM_VALUE: Final = 512
INVALID_ERROR: Final = "invalid_error_code"
DUE_STATUSES: Final = ("pending", "failed")


class AlertInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"alert {field} rejected: {reason}")
        self.field = field
        self.reason = reason


def _utc(value: datetime) -> datetime:
    # SQLite returns naive datetimes: values are always written as UTC, so tag them back.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _aware(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AlertInvalid(field, "not_aware")
    return value.astimezone(UTC)


def _limit(limit: object) -> int:
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise AlertInvalid("limit", "out_of_range")
    return limit


def _kind(value: object) -> str:
    if not isinstance(value, str) or value not in KINDS:
        raise AlertInvalid("kind", "unknown_kind")
    return value


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != HASH_LENGTH or not _HASH.match(value):
        raise AlertInvalid(field, "not_a_sha256")
    return value


def _code(value: object) -> str:
    if not isinstance(value, str) or len(value) > MAX_CODE_LENGTH or not _CODE.match(value):
        raise AlertInvalid("code", "malformed")
    return value


def _params(value: object) -> dict[str, str]:
    """Flat, bounded {str: str} only: codes and short values, never rendered text."""
    if not isinstance(value, Mapping) or len(value) > MAX_PARAMS:
        raise AlertInvalid("params", "malformed")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > MAX_PARAM_KEY:
            raise AlertInvalid("params", "bad_key")
        if not isinstance(item, str) or len(item) > MAX_PARAM_VALUE:
            raise AlertInvalid("params", "bad_value")
        out[key] = item
    return out


def _channel(value: object) -> int:
    cid = coerce_id(value)
    if cid is None:
        raise AlertInvalid("channel_id", "malformed")
    return cid


def error_code(value: object) -> str:
    """A storable delivery error code: the value if it is a short slug, else a fixed code (so a
    message or a body can never be stored by mistake)."""
    if isinstance(value, str) and len(value) <= MAX_ERROR_LENGTH and _ERROR.match(value):
        return value
    return INVALID_ERROR


def _insert(session: Session, table: Table) -> Any:
    """The dialect's INSERT that supports ON CONFLICT DO NOTHING (SQLite and PostgreSQL only)."""
    name = session.get_bind().dialect.name
    if name == "postgresql":
        return postgresql.insert(table)
    if name == "sqlite":
        return sqlite.insert(table)
    raise NotImplementedError(f"ON CONFLICT is not supported on {name}")


# --- records -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AlertRecord:
    id: int
    domain_id: int
    kind: str
    stream: str
    fingerprint: str
    state_hash: str
    code: str
    params: Mapping[str, str]
    suppressed: bool
    created_at: datetime

    @classmethod
    def from_model(cls, row: Alert) -> AlertRecord:
        params = row.params if isinstance(row.params, dict) else {}
        return cls(
            id=row.id,
            domain_id=row.domain_id,
            kind=row.kind,
            stream=row.stream,
            fingerprint=row.fingerprint,
            state_hash=row.state_hash,
            code=row.code,
            params={str(k): str(v) for k, v in params.items()},
            suppressed=row.suppressed,
            created_at=_utc(row.created_at),
        )


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    id: int
    alert_id: int
    channel_id: int
    status: str
    attempts: int
    next_attempt_at: datetime | None
    last_error: str | None
    sent_at: datetime | None
    created_at: datetime

    @classmethod
    def from_model(cls, row: AlertDelivery) -> DeliveryRecord:
        return cls(
            id=row.id,
            alert_id=row.alert_id,
            channel_id=row.channel_id,
            status=row.status,
            attempts=row.attempts,
            next_attempt_at=None if row.next_attempt_at is None else _utc(row.next_attempt_at),
            last_error=row.last_error,
            sent_at=None if row.sent_at is None else _utc(row.sent_at),
            created_at=_utc(row.created_at),
        )


@dataclass(frozen=True, slots=True)
class AlertRuleRecord:
    id: int
    kind: str
    channel_id: int


class _TenantRepository:
    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx


# --- alerts ------------------------------------------------------------------------------------


class AlertRepository(_TenantRepository):
    """Alerts of the context tenant's domains."""

    __slots__ = ()

    def _select(self, *criteria: ColumnElement[bool]) -> Select[Alert]:
        return select(Alert).where(Alert.tenant_id == self._ctx.tenant_id, *criteria)

    def get(self, alert_id: object) -> AlertRecord | None:
        """The alert; None if missing, foreign or malformed."""
        aid = coerce_id(alert_id)
        if aid is None:
            return None
        row = self._session.scalars(self._select(Alert.id == aid)).one_or_none()
        return None if row is None else AlertRecord.from_model(row)

    def list_for_domain(
        self, domain_id: object, *, limit: int = DEFAULT_LIMIT
    ) -> list[AlertRecord]:
        """Newest first; empty for a missing, foreign or malformed domain."""
        size = _limit(limit)
        did = coerce_id(domain_id)
        if did is None:
            return []
        stmt = self._select(Alert.domain_id == did).order_by(Alert.id.desc()).limit(size)
        return [AlertRecord.from_model(r) for r in self._session.scalars(stmt)]

    def latest_in_stream(self, domain_id: object, stream: object) -> AlertRecord | None:
        """The newest alert (suppressed or not) of one stream of the domain."""
        did = coerce_id(domain_id)
        if did is None:
            return None
        key = _hash(stream, "stream")
        stmt = (
            self._select(Alert.domain_id == did, Alert.stream == key)
            .order_by(Alert.id.desc())
            .limit(1)
        )
        row = self._session.scalars(stmt).first()
        return None if row is None else AlertRecord.from_model(row)

    def last_unsuppressed_at(self, fingerprint: object) -> datetime | None:
        """Creation time of the newest NOT suppressed alert with this fingerprint (the start of
        its minimum re-alert interval); None if there is none."""
        fp = _hash(fingerprint, "fingerprint")
        stmt = (
            select(Alert.created_at)
            .where(
                Alert.tenant_id == self._ctx.tenant_id,
                Alert.fingerprint == fp,
                Alert.suppressed.is_(False),
            )
            .order_by(Alert.id.desc())
            .limit(1)
        )
        found = self._session.scalar(stmt)
        return None if found is None else _utc(found)

    def _domain_exists(self, domain_id: int) -> bool:
        stmt = select(Domain.id).where(
            Domain.id == domain_id, Domain.tenant_id == self._ctx.tenant_id
        )
        return self._session.scalar(stmt) is not None

    def insert_if_absent(
        self,
        domain_id: object,
        *,
        kind: object,
        stream: object,
        fingerprint: object,
        state_hash: object,
        code: object,
        params: object,
        suppressed: object,
        created_at: object,
    ) -> AlertRecord | None:
        """Insert the alert unless (tenant, fingerprint, state_hash) exists. The new record, or
        None when it already existed (inserted by a replay or a concurrent emitter, committed or
        not: PostgreSQL waits for the other transaction) or the domain is missing or foreign."""
        did = coerce_id(domain_id)
        if did is None or not self._domain_exists(did):
            return None
        if type(suppressed) is not bool:
            raise AlertInvalid("suppressed", "not_a_bool")
        values = {
            "tenant_id": self._ctx.tenant_id,
            "domain_id": did,
            "kind": _kind(kind),
            "stream": _hash(stream, "stream"),
            "fingerprint": _hash(fingerprint, "fingerprint"),
            "state_hash": _hash(state_hash, "state_hash"),
            "code": _code(code),
            "params": _params(params),
            "suppressed": suppressed,
            "created_at": _aware(created_at, "created_at"),
        }
        table = cast(Table, Alert.__table__)
        stmt = (
            _insert(self._session, table)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["tenant_id", "fingerprint", "state_hash"])
            .returning(table.c.id)
        )
        new_id = self._session.execute(stmt).scalar_one_or_none()
        if new_id is None:
            return None
        return self.get(new_id)


# --- deliveries --------------------------------------------------------------------------------


class AlertDeliveryRepository(_TenantRepository):
    """Per-channel delivery records of the context tenant's alerts."""

    __slots__ = ()

    def _select(self, *criteria: ColumnElement[bool]) -> Select[AlertDelivery]:
        return select(AlertDelivery).where(
            AlertDelivery.tenant_id == self._ctx.tenant_id, *criteria
        )

    def get(self, delivery_id: object) -> DeliveryRecord | None:
        did = coerce_id(delivery_id)
        if did is None:
            return None
        row = self._session.scalars(self._select(AlertDelivery.id == did)).one_or_none()
        return None if row is None else DeliveryRecord.from_model(row)

    def for_alert(self, alert_id: object) -> list[DeliveryRecord]:
        """The deliveries of one alert, by channel id; empty for a missing or foreign alert."""
        aid = coerce_id(alert_id)
        if aid is None:
            return []
        stmt = self._select(AlertDelivery.alert_id == aid).order_by(AlertDelivery.channel_id)
        return [DeliveryRecord.from_model(r) for r in self._session.scalars(stmt)]

    def add_pending(
        self, alert_id: object, channel_ids: Iterable[object], now: object
    ) -> list[DeliveryRecord]:
        """One `pending` delivery per channel, due at `now`; a channel that already has one for
        this alert is left as it is. Returns the deliveries created by THIS call."""
        aid = coerce_id(alert_id)
        at = _aware(now, "now")
        channels = sorted({_channel(c) for c in channel_ids})
        if aid is None or not channels:
            return []
        owned = select(Alert.id).where(Alert.id == aid, Alert.tenant_id == self._ctx.tenant_id)
        if self._session.scalar(owned) is None:
            return []
        table = cast(Table, AlertDelivery.__table__)
        created: list[int] = []
        for channel_id in channels:
            stmt: Insert = (
                _insert(self._session, table)
                .values(
                    tenant_id=self._ctx.tenant_id,
                    alert_id=aid,
                    channel_id=channel_id,
                    status="pending",
                    attempts=0,
                    next_attempt_at=at,
                    created_at=at,
                )
                .on_conflict_do_nothing(index_elements=["alert_id", "channel_id"])
                .returning(table.c.id)
            )
            new_id = self._session.execute(stmt).scalar_one_or_none()
            if new_id is not None:
                created.append(new_id)
        return [r for r in (self.get(i) for i in created) if r is not None]

    def due(self, now: object, *, limit: int = DEFAULT_LIMIT) -> list[DeliveryRecord]:
        """`pending` or `failed` deliveries with `next_attempt_at <= now`, oldest due first."""
        at = _aware(now, "now")
        stmt = (
            self._select(
                AlertDelivery.status.in_(DUE_STATUSES),
                AlertDelivery.next_attempt_at <= at,
            )
            .order_by(AlertDelivery.next_attempt_at, AlertDelivery.id)
            .limit(_limit(limit))
        )
        return [DeliveryRecord.from_model(r) for r in self._session.scalars(stmt)]

    def _conditional(
        self,
        delivery_id: object,
        expected_attempts: object,
        values: Mapping[str, Any],
        *criteria: ColumnElement[bool],
    ) -> bool:
        did = coerce_id(delivery_id)
        if did is None or type(expected_attempts) is not int or expected_attempts < 0:
            raise AlertInvalid("delivery", "malformed")
        stmt = (
            update(AlertDelivery)
            .where(
                AlertDelivery.id == did,
                AlertDelivery.tenant_id == self._ctx.tenant_id,
                AlertDelivery.status.in_(DUE_STATUSES),
                AlertDelivery.attempts == expected_attempts,
                *criteria,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        result = cast(CursorResult[Any], self._session.execute(stmt))
        return result.rowcount == 1

    def claim(
        self, delivery_id: object, expected_attempts: object, now: object, lease_until: object
    ) -> bool:
        """Start one attempt: attempts + 1 and `next_attempt_at = lease_until` (a crash during
        the send makes it due again then), only while the delivery is still due at `now` with
        the attempt count the caller read. True for exactly one of concurrent claimers."""
        at = _aware(now, "now")
        lease = _aware(lease_until, "lease_until")
        return self._conditional(
            delivery_id,
            expected_attempts,
            {"attempts": AlertDelivery.attempts + 1, "next_attempt_at": lease},
            AlertDelivery.next_attempt_at <= at,
        )

    def mark_sent(self, delivery_id: object, attempt: object, now: object) -> bool:
        """`sent` after attempt number `attempt` (the claimed count) succeeded."""
        return self._conditional(
            delivery_id,
            attempt,
            {
                "status": "sent",
                "sent_at": _aware(now, "now"),
                "next_attempt_at": None,
                "last_error": None,
            },
        )

    def mark_failed(
        self, delivery_id: object, attempt: object, error: object, retry_at: object
    ) -> bool:
        """`failed` with the next try at `retry_at`, or `abandoned` when `retry_at` is None.
        `error` is stored only as a code (`error_code`)."""
        values: dict[str, Any] = {"last_error": error_code(error)}
        if retry_at is None:
            values.update(status="abandoned", next_attempt_at=None)
        else:
            values.update(status="failed", next_attempt_at=_aware(retry_at, "retry_at"))
        return self._conditional(delivery_id, attempt, values)


# --- rules -------------------------------------------------------------------------------------


class AlertRuleRepository(_TenantRepository):
    """Which event kinds go to which channels of the context tenant."""

    __slots__ = ()

    def list_all(self) -> list[AlertRuleRecord]:
        stmt = (
            select(AlertRule)
            .where(AlertRule.tenant_id == self._ctx.tenant_id)
            .order_by(AlertRule.kind, AlertRule.channel_id)
        )
        return [AlertRuleRecord(r.id, r.kind, r.channel_id) for r in self._session.scalars(stmt)]

    def channels_for(self, kind: object) -> list[int]:
        """Channel ids for an event kind, sorted; empty when no rule matches (no delivery)."""
        k = _kind(kind)
        stmt = (
            select(AlertRule.channel_id)
            .where(AlertRule.tenant_id == self._ctx.tenant_id, AlertRule.kind == k)
            .order_by(AlertRule.channel_id)
        )
        return list(self._session.scalars(stmt))

    def add(self, kind: object, channel_id: object) -> AlertRuleRecord:
        """Idempotent: the existing rule when (kind, channel) is already routed."""
        k, cid = _kind(kind), _channel(channel_id)
        table = cast(Table, AlertRule.__table__)
        stmt = (
            _insert(self._session, table)
            .values(tenant_id=self._ctx.tenant_id, kind=k, channel_id=cid)
            .on_conflict_do_nothing(index_elements=["tenant_id", "kind", "channel_id"])
        )
        self._session.execute(stmt)
        row = self._session.scalars(
            select(AlertRule).where(
                AlertRule.tenant_id == self._ctx.tenant_id,
                AlertRule.kind == k,
                AlertRule.channel_id == cid,
            )
        ).one()
        return AlertRuleRecord(row.id, row.kind, row.channel_id)

    def remove(self, kind: object, channel_id: object) -> bool:
        k, cid = _kind(kind), _channel(channel_id)
        row = self._session.scalars(
            select(AlertRule).where(
                AlertRule.tenant_id == self._ctx.tenant_id,
                AlertRule.kind == k,
                AlertRule.channel_id == cid,
            )
        ).one_or_none()
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True


__all__ = [
    "AlertDeliveryRepository",
    "AlertInvalid",
    "AlertRecord",
    "AlertRepository",
    "AlertRuleRecord",
    "AlertRuleRepository",
    "DeliveryRecord",
    "error_code",
]
