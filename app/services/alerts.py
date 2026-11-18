"""Alert creation, dedup and delivery bookkeeping (M7-14). Design: ARCHITECTURE section 6, "Alerts".

`AlertService.emit(ctx, events)` takes the change events of a run (`app.services.change_detect`,
M7-10) and records alerts; it matches the `EventSink` signature of `app.services.monitor_run`.
`AlertService.deliver_due(ctx, send)` sends the due deliveries through an injected `Sender` (the
concrete channels are M7-16..19) and records each outcome. No network here; time comes from the
injected `Clock`. Every read and write goes through `repo_for(ctx, session)`.

Streams and true changes. Each event belongs to a stream of one domain: a DNS entry
(`record_changed`), a DNSBL list (`new_listing` / `listing_cleared`), a check's policy
(`policy_regression`) or a check's errors (`check_error_started` / `_cleared`). An event is a NEW
alert only when the stream's state truly changed since its latest alert:
- the latest alert of the stream has a different fingerprint (kind, subject or new state differ);
  so A -> B -> A -> B alerts every transition, while a replay, or the duplicate `new_listing` of
  a list that was re-enabled while still listed, matches the latest alert and is a duplicate;
- or, for `policy_regression` only (an improvement produces no event, so the stream cannot see
  it), a stored non-error run of that check with a better status than the regressed one started
  at or after the latest alert: ok -> warn, warn -> ok, ok -> warn alerts twice; a replay once.

Exactly once. `state_hash` = SHA-256 of (new state, id of the latest alert of the stream, 0 if
none): every emitter that read the same stream position computes the same key, and the INSERT ..
ON CONFLICT DO NOTHING on (tenant_id, fingerprint, state_hash) lets exactly one row exist, however
many emitters race or replay (two sessions, or a restart replaying the same run).

Flapping. A true change to a fingerprint that was alerted (not suppressed) less than
`min_realert` ago is still recorded, as a `suppressed` alert row: visible to the UI and counted,
never delivered. It is the stream's new latest alert, so the state stays exact. Once the window
has ended, `release_suppressed(ctx, now)` (called periodically, wiring M7-14c) turns a stream
whose latest alert is suppressed and differs from the last delivered state into one deliverable
alert, exactly once; when the final state equals the last delivered one, nothing is sent.

Delivery. A created, not suppressed alert gets one `pending` delivery per channel that the
tenant's alert rules route its kind to (no rule: none; the alert is still recorded). Delivery is
at-least-once per channel: a delivery is claimed (attempts + 1, due again after `lease`, which
is how a crash during a send resumes), sent under `send_timeout` (validated shorter than `lease`;
a send still running at the timeout is cancelled and is a retryable `timeout` failure, so no
live send outlasts its lease), and marked `sent` in its own transaction right after the send
returned, before anything else. A crash between the remote accepting the message and
that commit re-sends it once the lease expires: exactly-once AT THE REMOTE END cannot be
guaranteed; the guarantee is on alert creation. A failure is retried with exponential backoff
(`backoff_base` * 2^(attempt-1), capped at `backoff_cap`) and becomes `abandoned` after
`max_attempts`; a permanent failure (`DeliveryError(code, permanent=True)`) is `abandoned` at
once, under the same attempt guard as `mark_sent`. Timeouts are always retryable. Failures
are logged and stored as a stable code only (`DeliveryError.code`), never a message, a
response body or a secret.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy.orm import Session, sessionmaker

from app.core.tenancy import TenantContext
from app.models.alert import KINDS
from app.repositories import TenantRepositories, repo_for
from app.repositories.alerts import (
    MAX_PARAM_VALUE,
    AlertRecord,
    DeliveryRecord,
    error_code,
)
from app.repositories.base import MAX_LIMIT
from app.repositories.check_runs import CheckRunInvalid, RunCursor
from app.services.change_detect import STATUS_RANK, ChangeEvent
from app.services.clock import Clock

logger = logging.getLogger("app.alerts")

# Stream family of each event kind (the kinds of one family share one state).
FAMILIES: Final[Mapping[str, str]] = {
    "record_changed": "record",
    "new_listing": "listing",
    "listing_cleared": "listing",
    "policy_regression": "policy",
    "check_error_started": "check_error",
    "check_error_cleared": "check_error",
}
# Payload code of each kind; i18n keys are `alert.<CODE>.title` and `alert.<CODE>.detail`.
CODES: Final[Mapping[str, str]] = {
    "record_changed": "ALERT_RECORD_CHANGED",
    "new_listing": "ALERT_NEW_LISTING",
    "listing_cleared": "ALERT_LISTING_CLEARED",
    "policy_regression": "ALERT_POLICY_REGRESSION",
    "check_error_started": "ALERT_CHECK_ERROR",
    "check_error_cleared": "ALERT_CHECK_ERROR_CLEARED",
}
I18N_PREFIX: Final = "alert"
MAX_STATE_PARAM: Final = 128

DEFAULT_MIN_REALERT: Final = timedelta(hours=1)
DEFAULT_MAX_ATTEMPTS: Final = 5
DEFAULT_BACKOFF_BASE: Final = timedelta(minutes=1)
DEFAULT_BACKOFF_CAP: Final = timedelta(hours=1)
DEFAULT_LEASE: Final = timedelta(minutes=5)
DEFAULT_SEND_TIMEOUT: Final = timedelta(seconds=60)
DEFAULT_BATCH: Final = 50
INTERNAL_ERROR: Final = "internal_error"
SEND_TIMEOUT: Final = "timeout"
MAX_LOCK_RETRIES: Final = 5


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _canon(*parts: object) -> str:
    return json.dumps(list(parts), ensure_ascii=True, separators=(",", ":"))


def stream_key(event: ChangeEvent) -> str:
    """SHA-256 of (family, domain_id, subject): the stream the event belongs to."""
    return _sha(_canon(FAMILIES[event.kind], event.domain_id, event.subject))


def state_hash(event: ChangeEvent, previous_alert_id: int | None) -> str:
    """SHA-256 of (new state, id of the stream's latest alert or 0): the stream position."""
    return _sha(_canon(event.after, previous_alert_id or 0))


def _cut(value: str, size: int) -> str:
    return value if len(value) <= size else value[:size]


def payload(event: ChangeEvent) -> tuple[str, dict[str, str]]:
    """The stored code and bounded params (short state values only, never record text)."""
    params = {
        "subject": _cut(event.subject, MAX_PARAM_VALUE),
        "before": _cut(event.before or "", MAX_STATE_PARAM),
        "after": _cut(event.after, MAX_STATE_PARAM),
    }
    if event.check_id is not None:
        params["check_id"] = _cut(event.check_id, MAX_STATE_PARAM)
    return CODES[event.kind], params


def is_valid_event(event: object) -> bool:
    """A `ChangeEvent` with a known kind, an int domain id and string state values."""
    return (
        isinstance(event, ChangeEvent)
        and event.kind in KINDS
        and type(event.domain_id) is int
        and event.domain_id > 0
        and isinstance(event.subject, str)
        and bool(event.subject)
        and isinstance(event.after, str)
        and (event.before is None or isinstance(event.before, str))
        and (event.check_id is None or isinstance(event.check_id, str))
    )


def locked_head(repos: TenantRepositories, domain_id: int, stream: str) -> AlertRecord | None:
    """The stream's latest alert, row-locked for the rest of the transaction (PostgreSQL), so
    an emit and a release (or two emits) building on the same head take turns. After the lock
    the head is read again: if another writer committed a newer head while this one waited, the
    newer head is locked instead. None when the stream has no alert yet (then the UNIQUE key
    decides between concurrent first inserts)."""
    head = repos.alerts.latest_in_stream(domain_id, stream, lock=True)
    for _ in range(MAX_LOCK_RETRIES):
        if head is None:
            return None
        again = repos.alerts.latest_in_stream(domain_id, stream)
        if again is not None and again.id == head.id:
            return head
        head = repos.alerts.latest_in_stream(domain_id, stream, lock=True)
    raise RuntimeError("stream head kept moving")


# --- delivery contract -------------------------------------------------------------------------


class DeliveryError(Exception):
    """A channel could not deliver. `code` is a short stable slug (e.g. `timeout`,
    `http_5xx`); it is the only thing stored or logged, so never put a body or secret in it.
    `permanent=True` (e.g. a 4xx the remote will never accept) abandons the delivery at once
    instead of retrying it with backoff."""

    def __init__(self, code: str, *, permanent: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.permanent = permanent is True


@dataclass(frozen=True, slots=True)
class AlertMessage:
    """What a channel receives: codes and params; rendering (i18n) is the channel's job."""

    alert_id: int
    domain_id: int
    kind: str
    code: str
    params: Mapping[str, str]
    created_at: datetime

    @classmethod
    def of(cls, alert: AlertRecord) -> AlertMessage:
        return cls(
            alert.id, alert.domain_id, alert.kind, alert.code, alert.params, alert.created_at
        )


# (ctx, channel_id, message): returns when the channel accepted it, raises DeliveryError if not.
Sender = Callable[[TenantContext, int, AlertMessage], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class EmitResult:
    created: int = 0
    duplicates: int = 0
    suppressed: int = 0
    rejected: int = 0
    failed: int = 0
    deliveries: int = 0


@dataclass(frozen=True, slots=True)
class DeliveryReport:
    sent: int = 0
    failed: int = 0
    abandoned: int = 0
    skipped: int = 0


class EmitIncomplete(Exception):
    """Raised by the `EventSink` form when some events could not be recorded (`result.failed`);
    retrying the same batch is safe."""

    def __init__(self, result: EmitResult) -> None:
        super().__init__(f"{result.failed} change events not recorded")
        self.result = result


def _positive(value: object, name: str) -> timedelta:
    if not isinstance(value, timedelta) or value <= timedelta(0):
        raise ValueError(f"{name} must be a positive timedelta")
    return value


class AlertService:
    """Alert creation and delivery bookkeeping. Dependencies are injected (factory, clock)."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        clock: Clock,
        *,
        min_realert: timedelta = DEFAULT_MIN_REALERT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: timedelta = DEFAULT_BACKOFF_BASE,
        backoff_cap: timedelta = DEFAULT_BACKOFF_CAP,
        lease: timedelta = DEFAULT_LEASE,
        send_timeout: timedelta = DEFAULT_SEND_TIMEOUT,
    ) -> None:
        if not isinstance(min_realert, timedelta) or min_realert < timedelta(0):
            raise ValueError("min_realert must be a non-negative timedelta")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be an int between 1 and 100")
        self._factory = factory
        self._clock = clock
        self._min_realert = min_realert
        self._max_attempts = max_attempts
        self._backoff_base = _positive(backoff_base, "backoff_base")
        self._backoff_cap = _positive(backoff_cap, "backoff_cap")
        self._lease = _positive(lease, "lease")
        self._send_timeout = _positive(send_timeout, "send_timeout")
        if self._send_timeout >= self._lease:
            raise ValueError("send_timeout must be shorter than lease")

    # --- creation ------------------------------------------------------------------------------

    def __call__(self, ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        """`EventSink` form of `emit`. Raises `EmitIncomplete` when an event could not be
        recorded, so the caller can retry the batch (recorded events are duplicates then).
        Replay only the LATEST run's events: replaying an older run after newer transitions were
        recorded is a true change against the stream's latest alert and alerts again."""
        result = self.emit(ctx, events)
        if result.failed:
            raise EmitIncomplete(result)

    def emit(self, ctx: TenantContext, events: Sequence[ChangeEvent]) -> EmitResult:
        """Record the alerts of `events`, idempotently (module docstring). Each event has its own
        transaction: one that fails is logged and counted (`failed`), the others are still
        recorded. Only the latest run may be replayed (see `__call__`)."""
        if not isinstance(ctx, TenantContext):
            raise TypeError("emit requires a TenantContext")
        counts = {"created": 0, "duplicates": 0, "suppressed": 0, "rejected": 0, "failed": 0}
        deliveries = 0
        for event in events:
            if not is_valid_event(event):
                counts["rejected"] += 1
                logger.warning(
                    "change event rejected (malformed)",
                    extra={"event": "alerts.event_rejected", "tenant_id": ctx.tenant_id},
                )
                continue
            try:
                with self._factory.begin() as db:
                    outcome, added = self._emit_one(repo_for(ctx, db), event)
            except Exception as exc:  # noqa: BLE001 - one event never blocks the others
                counts["failed"] += 1
                logger.error(
                    "alert not recorded (%s)",
                    type(exc).__name__,
                    extra={"event": "alerts.emit_failed", "tenant_id": ctx.tenant_id},
                )
                continue
            counts[outcome] += 1
            deliveries += added
        return EmitResult(deliveries=deliveries, **counts)

    def _emit_one(self, repos: TenantRepositories, event: ChangeEvent) -> tuple[str, int]:
        now = self._clock.now()
        stream = stream_key(event)
        latest = locked_head(repos, event.domain_id, stream)
        if (
            latest is not None
            and latest.fingerprint == event.fingerprint
            and not self._changed_since(repos, event, latest)
        ):
            return "duplicates", 0
        suppressed = False
        if self._min_realert > timedelta(0):
            last = repos.alerts.last_unsuppressed_at(event.fingerprint)
            suppressed = last is not None and now - last < self._min_realert
        code, params = payload(event)
        alert = repos.alerts.insert_if_absent(
            event.domain_id,
            kind=event.kind,
            stream=stream,
            fingerprint=event.fingerprint,
            state_hash=state_hash(event, None if latest is None else latest.id),
            code=code,
            params=params,
            suppressed=suppressed,
            created_at=now,
        )
        if alert is None:
            return "duplicates", 0  # a replay or a concurrent emitter got there first
        logger.info(
            "alert %d recorded (%s%s)",
            alert.id,
            event.kind,
            ", suppressed" if suppressed else "",
            extra={"event": "alerts.created", "tenant_id": repos.ctx.tenant_id},
        )
        if suppressed:
            return "suppressed", 0
        channels = repos.alert_rules.channels_for(event.kind)
        return "created", len(repos.alert_deliveries.add_pending(alert.id, channels, now))

    @staticmethod
    def _changed_since(repos: TenantRepositories, event: ChangeEvent, latest: AlertRecord) -> bool:
        """Same fingerprint as the stream's latest alert: a true change only for a policy
        regression with a better non-error run of that check since that alert."""
        if event.kind != "policy_regression" or event.check_id is None:
            return False
        rank = STATUS_RANK.get(event.after)
        if rank is None:
            return False
        cursor: RunCursor | None = None
        try:
            while True:
                page = repos.check_runs.list_for_domain(
                    event.domain_id,
                    check_id=event.check_id,
                    since=latest.created_at,
                    limit=MAX_LIMIT,
                    cursor=cursor,
                )
                for run in page.items:
                    better = STATUS_RANK.get(run.status)
                    if better is not None and better < rank:
                        return True
                if page.next_cursor is None:
                    return False
                cursor = page.next_cursor
        except CheckRunInvalid:
            return False

    # --- release of suppressed state -----------------------------------------------------------

    def release_suppressed(
        self, ctx: TenantContext, now: datetime | None = None, *, limit: int = DEFAULT_BATCH
    ) -> int:
        """Make sure the tenant ends up notified of each stream's current state. For every
        stream whose latest alert is `suppressed`, whose fingerprint's `min_realert` window has
        ended at `now`, and whose state differs from the stream's last delivered (not
        suppressed) alert, record one deliverable alert of that state (with deliveries per the
        rules). Idempotent and race-safe: the new row's `state_hash` is derived from the
        suppressed head's id, so the UNIQUE constraint lets exactly one caller insert it, and it
        becomes the stream's latest alert. Returns the number of alerts released. Meant to be
        called periodically (wiring: M7-14c)."""
        if not isinstance(ctx, TenantContext):
            raise TypeError("release_suppressed requires a TenantContext")
        at = self._clock.now() if now is None else now
        released = 0
        after = 0
        while True:  # pages through every head: one still inside its window blocks nothing
            with self._factory.begin() as db:
                heads = repo_for(ctx, db).alerts.suppressed_stream_heads(
                    limit=limit, after_id=after
                )
            for head in heads:
                try:
                    with self._factory.begin() as db:
                        released += self._release_one(repo_for(ctx, db), head, at)
                except Exception as exc:  # noqa: BLE001 - one stream never blocks the others
                    logger.error(
                        "suppressed alert %d not released (%s)",
                        head.id,
                        type(exc).__name__,
                        extra={"event": "alerts.release_failed", "tenant_id": ctx.tenant_id},
                    )
            if len(heads) < limit:
                return released
            after = heads[-1].id

    def _release_one(self, repos: TenantRepositories, head: AlertRecord, now: datetime) -> int:
        latest = locked_head(repos, head.domain_id, head.stream)
        if latest is None or latest.id != head.id or not latest.suppressed:
            return 0  # the stream moved on since the read
        last = repos.alerts.last_unsuppressed_at(head.fingerprint)
        if last is not None and now - last < self._min_realert:
            return 0  # still inside the window: a later call releases it
        delivered = repos.alerts.latest_unsuppressed_in_stream(head.domain_id, head.stream)
        if delivered is not None and delivered.fingerprint == head.fingerprint:
            return 0  # the tenant already knows this state
        alert = repos.alerts.insert_if_absent(
            head.domain_id,
            kind=head.kind,
            stream=head.stream,
            fingerprint=head.fingerprint,
            state_hash=_sha(_canon("release", head.fingerprint, head.id)),
            code=head.code,
            params=dict(head.params),
            suppressed=False,
            created_at=now,
        )
        if alert is None:
            return 0  # another caller released it
        channels = repos.alert_rules.channels_for(head.kind)
        repos.alert_deliveries.add_pending(alert.id, channels, now)
        logger.info(
            "suppressed alert %d released as alert %d",
            head.id,
            alert.id,
            extra={"event": "alerts.released", "tenant_id": repos.ctx.tenant_id},
        )
        return 1

    # --- delivery ------------------------------------------------------------------------------

    def backoff(self, attempt: int) -> timedelta:
        """Delay after failed attempt number `attempt` (1-based)."""
        step: timedelta = self._backoff_base * (2 ** min(max(attempt - 1, 0), 20))
        return min(step, self._backoff_cap)

    async def deliver_due(
        self, ctx: TenantContext, send: Sender, *, limit: int = DEFAULT_BATCH
    ) -> DeliveryReport:
        """Send the tenant's due deliveries (at most `limit`), one claim, send and record each.
        Database work runs in worker threads, so the event loop is never blocked."""
        if not isinstance(ctx, TenantContext):
            raise TypeError("deliver_due requires a TenantContext")
        now = self._clock.now()
        due = await asyncio.to_thread(self._load_due, ctx, now, limit)
        counts = {"sent": 0, "failed": 0, "abandoned": 0, "skipped": 0}
        for delivery, alert in due:
            counts[await self._deliver_one(ctx, send, delivery, alert)] += 1
        return DeliveryReport(**counts)

    def _load_due(
        self, ctx: TenantContext, now: datetime, limit: int
    ) -> list[tuple[DeliveryRecord, AlertRecord]]:
        out: list[tuple[DeliveryRecord, AlertRecord]] = []
        with self._factory.begin() as db:
            repos = repo_for(ctx, db)
            for delivery in repos.alert_deliveries.due(now, limit=limit):
                alert = repos.alerts.get(delivery.alert_id)
                if alert is not None:
                    out.append((delivery, alert))
        return out

    def _write(self, ctx: TenantContext, action: Callable[[TenantRepositories], bool]) -> bool:
        with self._factory.begin() as db:
            return action(repo_for(ctx, db))

    async def _deliver_one(
        self, ctx: TenantContext, send: Sender, delivery: DeliveryRecord, alert: AlertRecord
    ) -> str:
        now = self._clock.now()
        claimed = await asyncio.to_thread(
            self._write,
            ctx,
            lambda r: r.alert_deliveries.claim(
                delivery.id, delivery.attempts, now, now + self._lease
            ),
        )
        if not claimed:
            return "skipped"  # another worker has it, or it is no longer due
        attempt = delivery.attempts + 1
        try:
            await asyncio.wait_for(
                send(ctx, delivery.channel_id, AlertMessage.of(alert)),
                self._send_timeout.total_seconds(),
            )
        except TimeoutError:
            code = SEND_TIMEOUT  # cancelled before the lease ends: retryable
        except DeliveryError as exc:
            code = error_code(exc.code)
            if exc.permanent:
                return await self._abandon_now(ctx, delivery, attempt, code)
        except Exception as exc:  # noqa: BLE001 - a channel bug is a failed attempt
            code = INTERNAL_ERROR
            logger.error(
                "alert channel raised %s",
                type(exc).__name__,
                extra={"event": "alerts.channel_crashed", "tenant_id": ctx.tenant_id},
            )
        else:
            # Marked before anything else: a retry decision never sees a sent delivery as due.
            sent_at = self._clock.now()
            marked = await asyncio.to_thread(
                self._write,
                ctx,
                lambda r: r.alert_deliveries.mark_sent(delivery.id, attempt, sent_at),
            )
            if not marked:
                logger.warning(
                    "alert delivery %d sent but not marked (state changed meanwhile)",
                    delivery.id,
                    extra={"event": "alerts.mark_sent_lost", "tenant_id": ctx.tenant_id},
                )
                return "skipped"
            return "sent"
        abandon = attempt >= self._max_attempts
        retry_at = None if abandon else self._clock.now() + self.backoff(attempt)
        await asyncio.to_thread(
            self._write,
            ctx,
            lambda r: r.alert_deliveries.mark_failed(delivery.id, attempt, code, retry_at),
        )
        logger.warning(
            "alert delivery %d to channel %d failed (attempt %d, %s)%s",
            delivery.id,
            delivery.channel_id,
            attempt,
            code,
            ", abandoned" if abandon else "",
            extra={"event": "alerts.delivery_failed", "tenant_id": ctx.tenant_id},
        )
        return "abandoned" if abandon else "failed"

    async def _abandon_now(
        self, ctx: TenantContext, delivery: DeliveryRecord, attempt: int, code: str
    ) -> str:
        """A permanent failure: `abandoned` at once, no further attempt. Conditional on the
        claimed attempt like `mark_sent`, so a stale worker cannot abandon a delivery."""
        marked = await asyncio.to_thread(
            self._write,
            ctx,
            lambda r: r.alert_deliveries.mark_abandoned(delivery.id, attempt, code),
        )
        if not marked:
            logger.warning(
                "alert delivery %d failed permanently but not marked (state changed meanwhile)",
                delivery.id,
                extra={"event": "alerts.mark_abandoned_lost", "tenant_id": ctx.tenant_id},
            )
            return "skipped"
        logger.warning(
            "alert delivery %d to channel %d failed permanently (attempt %d, %s), abandoned",
            delivery.id,
            delivery.channel_id,
            attempt,
            code,
            extra={"event": "alerts.delivery_failed", "tenant_id": ctx.tenant_id},
        )
        return "abandoned"


__all__ = [
    "CODES",
    "DEFAULT_MIN_REALERT",
    "FAMILIES",
    "I18N_PREFIX",
    "AlertMessage",
    "AlertService",
    "DeliveryError",
    "DeliveryReport",
    "EmitIncomplete",
    "EmitResult",
    "Sender",
    "is_valid_event",
    "payload",
    "state_hash",
    "stream_key",
]
