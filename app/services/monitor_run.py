"""The scheduled run executor (M7-10): the `RunFn` the scheduler (M7-09) calls for a claimed target.

One run of a `ScheduledRun`:
1. Context: `TenantContext(target.tenant_id, principal=None)` (system work for the tenant). Every
   read and write below goes through `repo_for(ctx, session)`; nothing else of the tenant is
   touched, and a target, domain or run of another tenant reads as missing.
2. Load (one read transaction, ended before any DNS): the target (skipped if it was deleted,
   disabled or moved to another domain since the claim), the domain, the enabled DKIM selectors
   for the snapshot, the check registry (`prepare_registry`: DKIM on the tenant's probe selectors,
   DNSBL on the instance's enabled lists, through `domain_registry.prepare_domain_registry`
   shared with the API domain routes), and the history change detection compares against: per
   check the latest stored run and the latest non-`error` one (`latest_non_error`: however many
   `error` runs followed it, M7-10b), and the DNS snapshot baseline (`snapshot_baseline`: the
   newest snapshot with each entry it could not evaluate replaced by that entry's last non-error
   state, paging back through history only as far as needed).
3. Run: the target's check ids through `app.services.checks.run_checks` (the one runner: an
   exception or timeout in one check is that check's `error`, the others still run) and the DNS
   snapshot (`dns_snapshot.collect_snapshot`), concurrently. Check ids no longer registered
   (`ScheduledRun.unknown_check_ids`, or missing from the prepared registry) become `error`
   results with `CHECK_INTERNAL_ERROR` (`reason: unknown_check`), never skipped. If the runner
   itself fails (e.g. the stored domain name is no longer a valid target) every check is `error`.
4. Store (one write transaction): a `check_runs` row per check (`source=scheduled`, findings as
   code + params only, `error` stays `error`), the snapshot when due (`store_if_due`, heartbeat),
   and the target's `last_run_at` (the run's start) and `last_status` (`summary_status`).
   `next_run_at` is NOT touched: the scheduler's claim already moved it to the next slot, and
   moving it here would race the next claim.
   Before the store, for the DNSBL check only (M7-10b), one more read builds the per-list
   baseline: for each list the new run evaluated, its outcome in the newest stored run where
   that list was evaluated (`change_detect.list_baseline` over the history paged newest first,
   stopping as soon as every such list is resolved). A list that errored for any number of runs
   is still judged against its last real outcome, and a list failing for good blocks nothing.
5. Events: `change_detect.detect_events` (pure) after the commit, handed to the injected
   `EventSink` in a worker thread. The app wires `AlertSink` (M7-14c): the M7-14 alert service
   records them (dedup, flapping, deliveries). `log_events` (kind, domain id and fingerprint only)
   is the default when nothing is injected. When the sink raises `EmitIncomplete` (some events not
   recorded, e.g. a transient database error), the same events are offered again, at most
   `emit_attempts` times in all with exponential backoff from `emit_backoff`, and only while this
   is still the latest run of the target started by this executor: an older run is never replayed
   after a newer one (M7-14: replaying an older run alerts again). Any other sink exception, or
   the last failed attempt, is logged by type and never fails the run. After every completed run
   the optional `on_run` hook gets the tenant id (in memory, no I/O): `AlertSink.note_run`, so
   suppressed alerts of that tenant are released by `AlertSink.run_release` once due.

Not produced: certificate/key expiry events (no check reads them before M9; see change_detect).
Blocking database work runs in worker threads, so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import threading
from collections.abc import Awaitable, Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy.orm import Session, sessionmaker

from app.checks.dnsbl import DnsblCheck
from app.checks.models import CheckContext, CheckResult, finding
from app.checks.registry import CheckRegistry
from app.core.tenancy import TenantContext
from app.dns.types import Resolver
from app.models.check_run import MAX_DURATION_MS
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.check_runs import CheckRunInvalid, CheckRunRecord
from app.repositories.dns_snapshots import (
    DnsSnapshotInvalid,
    DnsSnapshotRecord,
    SnapshotCursor,
)
from app.services.alerts import AlertService, EmitIncomplete
from app.services.change_detect import (
    ChangeEvent,
    CheckInput,
    CheckState,
    ListView,
    detect_events,
    list_baseline,
    list_view_of_data,
    list_view_of_findings,
)
from app.services.checks import DEFAULT_DEADLINE_S, default_registry, run_checks
from app.services.clock import Clock
from app.services.dns_diff import Entry, Snapshot, SnapshotFormatError, build_snapshot
from app.services.dns_snapshot import collect_snapshot, load_snapshot, store_if_due
from app.services.domain_registry import prepare_domain_registry
from app.services.scheduler import ScheduledRun

logger = logging.getLogger("app.monitor_run")

# Page size when paging back through stored runs and snapshots (not a cap on how far back).
HISTORY_LIMIT: Final = 50
SOURCE: Final = "scheduled"
UNKNOWN_CHECK: Final = "unknown_check"
RUNNER_FAILED: Final = "runner_failed"
# Emit retries after `EmitIncomplete` (M7-14c), project choices: 3 attempts in all, waiting 2 s then
# 4 s, so a run holds its scheduler slot at most a few seconds longer.
DEFAULT_EMIT_ATTEMPTS: Final = 3
DEFAULT_EMIT_BACKOFF: Final = timedelta(seconds=2)
MAX_EMIT_ATTEMPTS: Final = 10
# Suppressed alerts are released this often by `AlertSink.run_release` (as the M7-15 dispatcher).
DEFAULT_RELEASE_INTERVAL: Final = timedelta(seconds=30)
# `last_status` summary: a failure is never hidden by an error, an error never by a lesser status.
_SUMMARY_ORDER: Final[tuple[str, ...]] = ("fail", "error", "warn", "info", "ok")

RegistryFn = Callable[[TenantContext, Session, Sequence[str]], CheckRegistry]
EventSink = Callable[[TenantContext, Sequence[ChangeEvent]], None]
RunHook = Callable[[int], None]


def prepare_registry(ctx: TenantContext, db: Session, ids: Sequence[str]) -> CheckRegistry:
    """The registry of a domain run, prepared as the API domain routes do
    (`prepare_domain_registry`), in its non-strict mode: an unreadable DNSBL enablement makes
    the DNSBL check `error` instead of failing the run."""
    return prepare_domain_registry(ctx, db, ids, strict=False) or default_registry()


def log_events(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
    """Default sink until M7-14: one log line per event (kind, domain id, fingerprint only)."""
    for event in events:
        logger.info(
            "change event %s on domain %d (%s)",
            event.kind,
            event.domain_id,
            event.fingerprint,
            extra={"event": "monitor_run.change_event", "tenant_id": ctx.tenant_id},
        )


def summary_status(statuses: Sequence[str]) -> str | None:
    """The target's `last_status`: the first of fail, error, warn, info, ok present; None if no
    check ran."""
    present = set(statuses)
    return next((s for s in _SUMMARY_ORDER if s in present), None)


def error_result(check_id: str, target: str, reason: str, at: datetime) -> CheckResult:
    return CheckResult.build(
        check_id=check_id,
        target=target,
        findings=[finding("CHECK_INTERNAL_ERROR", "medium", {"reason": reason}, remediation=False)],
        evaluated=False,
        started_at=at,
        duration_ms=0,
    )


def list_view_of_record(record: CheckRunRecord) -> ListView | None:
    """The per-list DNSBL view of a stored run (None for any other check)."""
    if record.check_id != DnsblCheck.id:
        return None
    return list_view_of_findings(record.status, ((f.code, f.params) for f in record.findings))


def state_of_record(record: CheckRunRecord) -> CheckState:
    return CheckState(record.check_id, record.status, list_view_of_record(record))


def state_of_result(result: CheckResult) -> CheckState:
    lists = list_view_of_data(result.data) if result.check_id == DnsblCheck.id else None
    return CheckState(result.check_id, result.status, lists)


def snapshot_baseline(records: Iterable[DnsSnapshotRecord]) -> Snapshot | None:
    """The DNS baseline from stored snapshots given newest first, consumed lazily and no further
    than needed: the newest usable snapshot, with each entry it could not evaluate (`error`)
    replaced by that entry's newest non-error state, looking back only while the entry stays
    monitored (present) in every snapshot in between. This is what folding the whole history
    oldest to newest with `dns_diff.carry_forward` gives, so a lookup failing for any number of
    snapshots keeps its last real state (M7-10b). A malformed stored snapshot is skipped. None
    when there is no usable snapshot."""
    base: Snapshot | None = None
    entries: dict[tuple[str, str], Entry] = {}
    pending: set[tuple[str, str]] = set()
    carried = truncated = False
    for record in records:
        try:
            snap = load_snapshot(record)
        except SnapshotFormatError:
            logger.warning(
                "stored snapshot skipped (malformed)",
                extra={"event": "monitor_run.snapshot_malformed"},
            )
            continue
        older = {(e.name, e.rdtype): e for e in snap.entries}
        if base is None:
            base, entries = snap, older
            pending = {k for k, e in older.items() if e.state == "error"}
        else:
            for key in sorted(pending):
                entry = older.get(key)
                if entry is None or entry.state != "error":
                    pending.discard(key)  # absent: not monitored then, the chain ends here
                if entry is not None and entry.state != "error":
                    entries[key] = entry
                    carried, truncated = True, truncated or snap.truncated
        if not pending:
            break
    if base is None or not carried:
        return base
    return build_snapshot(entries.values(), truncated=base.truncated or truncated)


def _snapshots_newest_first(
    repos: TenantRepositories, domain_id: int, page: int
) -> Iterator[DnsSnapshotRecord]:
    before: SnapshotCursor | None = None
    while True:
        items = repos.dns_snapshots.list_for_domain(domain_id, limit=page, before=before)
        yield from items
        if len(items) < page:
            return
        before = SnapshotCursor.after(items[-1])


def _runs_newest_first(
    repos: TenantRepositories, domain_id: int, check_id: str, page: int
) -> Iterator[CheckRunRecord]:
    cursor = None
    while True:
        result = repos.check_runs.list_for_domain(
            domain_id, check_id=check_id, limit=page, cursor=cursor
        )
        yield from result.items
        if result.next_cursor is None:
            return
        cursor = result.next_cursor


@dataclass(frozen=True, slots=True)
class _History:
    previous: CheckState | None
    baseline: CheckState | None


@dataclass(frozen=True, slots=True)
class _Loaded:
    domain_id: int
    domain_name: str
    selectors: tuple[str, ...]
    registry: CheckRegistry
    history: dict[str, _History]
    snapshot_baseline: Snapshot | None


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """What one run did (for logs and tests)."""

    target_id: int
    status: str | None
    results: tuple[CheckResult, ...]
    recorded: int
    snapshot: str | None  # store reason (first/changed/heartbeat/unchanged) or None (not stored)
    events: tuple[ChangeEvent, ...]


class MonitorRunExecutor:
    """The scheduler's `RunFn`. Dependencies are injected so tests use fake checks and DNS."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        resolver: Resolver,
        clock: Clock,
        *,
        heartbeat: timedelta,
        sink: EventSink = log_events,
        prepare: RegistryFn = prepare_registry,
        deadline_s: float = DEFAULT_DEADLINE_S,
        history: int = HISTORY_LIMIT,
        on_run: RunHook | None = None,
        emit_attempts: int = DEFAULT_EMIT_ATTEMPTS,
        emit_backoff: timedelta = DEFAULT_EMIT_BACKOFF,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not isinstance(heartbeat, timedelta) or heartbeat <= timedelta(0):
            raise ValueError("heartbeat must be a positive timedelta")
        if type(history) is not int or not 1 <= history <= MAX_LIMIT:
            raise ValueError(f"history must be an int between 1 and {MAX_LIMIT}")
        if type(emit_attempts) is not int or not 1 <= emit_attempts <= MAX_EMIT_ATTEMPTS:
            raise ValueError(f"emit_attempts must be an int between 1 and {MAX_EMIT_ATTEMPTS}")
        if not isinstance(emit_backoff, timedelta) or emit_backoff < timedelta(0):
            raise ValueError("emit_backoff must be a non-negative timedelta")
        self._factory = factory
        self._resolver = resolver
        self._clock = clock
        self._heartbeat = heartbeat
        self._sink = sink
        self._prepare = prepare
        self._deadline_s = deadline_s
        self._history = history
        self._on_run = on_run
        self._emit_attempts = emit_attempts
        self._emit_backoff = emit_backoff
        self._sleep = sleep
        # Latest run started per target id (this executor): an older run never replays its events.
        self._runs = itertools.count(1)
        self._latest: dict[int, int] = {}

    async def __call__(self, run: ScheduledRun) -> None:
        await self.execute(run)

    async def execute(self, run: ScheduledRun) -> RunOutcome | None:
        """Run, store and detect for one claimed target. None if the target or domain is gone."""
        number = next(self._runs)
        self._latest[run.target.id] = number
        try:
            return await self._execute(run, number)
        finally:
            if self._latest.get(run.target.id) == number:
                del self._latest[run.target.id]

    async def _execute(self, run: ScheduledRun, number: int) -> RunOutcome | None:
        ctx = TenantContext(run.target.tenant_id, None)
        now = self._clock.now()
        ids = list(run.target.check_ids)
        unknown = set(run.unknown_check_ids)
        loaded = await asyncio.to_thread(self._load, ctx, run, ids, unknown)
        if loaded is None:
            logger.info(
                "scheduled run of target %d skipped (target or domain gone)",
                run.target.id,
                extra={"event": "monitor_run.skipped"},
            )
            return None

        runnable = [c for c in ids if c not in unknown and c in loaded.registry.all_ids()]
        checks_out, snap_out = await asyncio.gather(
            self._run_checks(runnable, loaded, ctx),
            collect_snapshot(self._resolver, loaded.domain_name, loaded.selectors),
            return_exceptions=True,
        )
        by_id: dict[str, CheckResult] = {}
        if isinstance(checks_out, BaseException):
            if not isinstance(checks_out, Exception):
                raise checks_out
            self._log_failed("checks", checks_out)
            checks_out = [error_result(c, loaded.domain_name, RUNNER_FAILED, now) for c in runnable]
        for result in checks_out:
            by_id[result.check_id] = result
        results = tuple(
            by_id.get(c) or error_result(c, loaded.domain_name, UNKNOWN_CHECK, now) for c in ids
        )
        snapshot: Snapshot | None
        if isinstance(snap_out, BaseException):
            if not isinstance(snap_out, Exception):
                raise snap_out
            self._log_failed("snapshot", snap_out)
            snapshot = None
        else:
            snapshot = snap_out

        status = summary_status([r.status for r in results])
        inputs = [
            CheckInput(
                state_of_result(r),
                loaded.history[r.check_id].previous,
                loaded.history[r.check_id].baseline,
            )
            for r in results
        ]
        inputs = await asyncio.to_thread(self._with_lists_baseline, ctx, loaded.domain_id, inputs)
        recorded, stored = await asyncio.to_thread(
            self._store, ctx, run.target.id, loaded.domain_id, results, snapshot, status, now
        )
        events = detect_events(loaded.domain_id, inputs, loaded.snapshot_baseline, snapshot)
        if events:
            await self._emit(ctx, run.target.id, number, events)
        if self._on_run is not None:
            try:
                self._on_run(ctx.tenant_id)
            except Exception as exc:  # noqa: BLE001 - a hook failure never fails the run
                self._log_failed("on_run", exc)
        logger.info(
            "scheduled run of target %d done (%s, %d checks, %d events)",
            run.target.id,
            status,
            len(results),
            len(events),
            extra={"event": "monitor_run.done"},
        )
        return RunOutcome(run.target.id, status, results, recorded, stored, tuple(events))

    async def _emit(
        self, ctx: TenantContext, target_id: int, number: int, events: Sequence[ChangeEvent]
    ) -> None:
        """Hand the events to the sink (worker thread); retry `EmitIncomplete` for the latest
        run of the target only, bounded (module docstring). Raises only on cancellation."""
        for attempt in range(1, self._emit_attempts + 1):
            if self._latest.get(target_id) != number:
                logger.warning(
                    "change events of target %d not emitted (a newer run started)",
                    target_id,
                    extra={"event": "monitor_run.emit_superseded", "tenant_id": ctx.tenant_id},
                )
                return
            try:
                await asyncio.to_thread(self._sink, ctx, events)
                return
            except EmitIncomplete as exc:
                last = attempt >= self._emit_attempts
                logger.log(
                    logging.ERROR if last else logging.WARNING,
                    "change events of target %d partly not recorded (%d failed, attempt %d of %d)",
                    target_id,
                    exc.result.failed,
                    attempt,
                    self._emit_attempts,
                    extra={
                        "event": "monitor_run.emit_gave_up" if last else "monitor_run.emit_retry",
                        "tenant_id": ctx.tenant_id,
                    },
                )
                if last:
                    return
            except Exception as exc:  # noqa: BLE001 - a sink failure never fails the run
                self._log_failed("sink", exc)
                return
            await self._sleep((self._emit_backoff * 2 ** (attempt - 1)).total_seconds())

    async def _run_checks(
        self, ids: list[str], loaded: _Loaded, ctx: TenantContext
    ) -> list[CheckResult]:
        if not ids:
            return []
        check_ctx = CheckContext(
            resolver=self._resolver,
            clock=self._clock.now,
            tenant_id=str(ctx.tenant_id),
            domain_id=str(loaded.domain_id),
        )
        return await run_checks(
            ids,
            loaded.domain_name,
            check_ctx,
            registry=loaded.registry,
            deadline_s=self._deadline_s,
        )

    @staticmethod
    def _log_failed(part: str, exc: BaseException) -> None:
        logger.error(
            "scheduled run %s failed (%s)",
            part,
            type(exc).__name__,
            extra={"event": f"monitor_run.{part}_failed"},
        )

    # --- database (worker threads) -----------------------------------------------------------

    def _load(
        self, ctx: TenantContext, run: ScheduledRun, ids: list[str], unknown: set[str]
    ) -> _Loaded | None:
        with self._factory() as db:
            try:
                repos = repo_for(ctx, db)
                target = repos.monitor_targets.get(run.target.id)
                if target is None or not target.enabled or target.domain_id != run.target.domain_id:
                    return None
                domain = repos.domains.get(target.domain_id)
                if domain is None:
                    return None
                selectors = tuple(
                    s.selector
                    for s in repos.dkim_selectors.list(enabled_only=True, limit=MAX_LIMIT)
                )
                registry = self._prepare(ctx, db, [c for c in ids if c not in unknown])
                history = {c: self._check_history(repos, target.domain_id, c) for c in ids}
                baseline = snapshot_baseline(
                    _snapshots_newest_first(repos, target.domain_id, self._history)
                )
                return _Loaded(
                    target.domain_id, domain.name, selectors, registry, history, baseline
                )
            finally:
                db.rollback()

    def _check_history(self, repos: TenantRepositories, domain_id: int, check_id: str) -> _History:
        try:
            page = repos.check_runs.list_for_domain(domain_id, check_id=check_id, limit=1)
            if not page.items:
                return _History(None, None)
            latest = page.items[0]
            stored = latest if latest.status != "error" else None
            if stored is None:
                stored = repos.check_runs.latest_non_error(domain_id, check_id)
        except CheckRunInvalid:
            return _History(None, None)  # an id the history cannot hold: no previous run
        baseline = None if stored is None else state_of_record(stored)
        return _History(state_of_record(latest), baseline)

    def _with_lists_baseline(
        self, ctx: TenantContext, domain_id: int, inputs: list[CheckInput]
    ) -> list[CheckInput]:
        """`inputs` with the per-list baseline of the DNSBL check (M7-10b): only the lists the
        new run evaluated, each resolved at the newest stored run that evaluated it."""
        out: list[CheckInput] = []
        for item in inputs:
            lists = item.current.lists
            if (
                item.current.check_id != DnsblCheck.id
                or item.previous is None
                or lists is None
                or not lists.evaluated
            ):
                out.append(item)
                continue
            try:
                with self._factory() as db:
                    try:
                        repos = repo_for(ctx, db)
                        runs = _runs_newest_first(repos, domain_id, DnsblCheck.id, self._history)
                        found = list_baseline(lists.evaluated, map(list_view_of_record, runs))
                    finally:
                        db.rollback()
            except Exception as exc:  # noqa: BLE001 - results are still stored, no listing event
                self._log_failed("lists_baseline", exc)
                out.append(item)
                continue
            out.append(item._replace(lists_baseline=found))
        return out

    def _store(
        self,
        ctx: TenantContext,
        target_id: int,
        domain_id: int,
        results: Sequence[CheckResult],
        snapshot: Snapshot | None,
        status: str | None,
        now: datetime,
    ) -> tuple[int, str | None]:
        recorded = 0
        stored: str | None = None
        with self._factory.begin() as db:
            repos = repo_for(ctx, db)
            for result in results:
                try:
                    row = repos.check_runs.record(
                        domain_id,
                        check_id=result.check_id,
                        status=result.status,
                        started_at=result.started_at,
                        duration_ms=min(max(result.duration_ms, 0), MAX_DURATION_MS),
                        source=SOURCE,
                        findings=list(result.findings),
                    )
                except CheckRunInvalid as exc:
                    logger.error(
                        "check run not recorded (%s: %s)",
                        exc.field,
                        exc.reason,
                        extra={"event": "monitor_run.record_rejected"},
                    )
                    continue
                recorded += row is not None
            if snapshot is not None:
                try:
                    outcome = store_if_due(
                        repos.dns_snapshots, domain_id, snapshot, now, self._heartbeat
                    )
                except (SnapshotFormatError, DnsSnapshotInvalid) as exc:
                    self._log_failed("snapshot_store", exc)
                else:
                    stored = None if outcome is None else outcome.reason
            if status is not None:
                repos.monitor_targets.update(target_id, last_run_at=now, last_status=status)
        return recorded, stored


class AlertSink:
    """The scheduler process's `EventSink` (M7-14c): `AlertService` records the events (raising
    `EmitIncomplete` when some were not recorded, so the executor retries), and the tenant is
    remembered for `release_suppressed`.

    Releasing: `AlertService.release_suppressed` is per tenant and there is no cross-tenant query
    for streams with a suppressed head, so this keeps, per process and in memory, the tenants to
    release with a deadline: a tenant whose events were offered stays until `min_realert` after
    that (by then every alert suppressed so far has left its window), a tenant that only ran
    (`note_run`, the executor's `on_run` hook) for one pass. `release_pending` (sync, worker
    thread) releases each pending tenant and drops it once its deadline has passed;
    `run_release` calls it every `interval`. After a restart, the next run of a tenant's target
    puts the tenant back, so a suppressed state is released at the latest one run interval after
    its window ended. Thread-safe."""

    def __init__(
        self,
        alerts: AlertService,
        clock: Clock,
        *,
        interval: timedelta = DEFAULT_RELEASE_INTERVAL,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not isinstance(interval, timedelta) or interval <= timedelta(0):
            raise ValueError("interval must be a positive timedelta")
        self._alerts = alerts
        self._clock = clock
        self._interval = interval
        self._sleep = sleep
        self._pending: dict[int, datetime] = {}
        self._lock = threading.Lock()

    def __call__(self, ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        try:
            self._alerts(ctx, events)
        finally:
            self._note(ctx.tenant_id, self._alerts.min_realert)

    def note_run(self, tenant_id: int) -> None:
        """`on_run` hook of the executor: release this tenant at the next pass."""
        self._note(tenant_id, timedelta(0))

    def _note(self, tenant_id: int, window: timedelta) -> None:
        until = self._clock.now() + window
        with self._lock:
            known = self._pending.get(tenant_id)
            self._pending[tenant_id] = until if known is None else max(known, until)

    def pending(self) -> dict[int, datetime]:
        """Tenant id -> release deadline (a copy)."""
        with self._lock:
            return dict(self._pending)

    def release_pending(self) -> int:
        """Release the pending tenants' suppressed alerts that are due; returns the number
        released. A failure for one tenant is logged by type and the tenant stays pending."""
        now = self._clock.now()
        released = 0
        for tenant_id, until in sorted(self.pending().items()):
            try:
                released += self._alerts.release_suppressed(TenantContext(tenant_id, None), now)
            except Exception as exc:  # noqa: BLE001 - one tenant never blocks the others
                logger.error(
                    "suppressed alerts not released (%s)",
                    type(exc).__name__,
                    extra={"event": "monitor_run.release_failed", "tenant_id": tenant_id},
                )
                continue
            if now >= until:
                with self._lock:
                    if self._pending.get(tenant_id) == until:
                        del self._pending[tenant_id]
        return released

    async def run_release(self) -> None:
        """Call `release_pending` in a worker thread every `interval` until cancelled."""
        while True:
            try:
                await asyncio.to_thread(self.release_pending)
            except Exception as exc:  # noqa: BLE001 - the loop survives a failed pass
                logger.error(
                    "suppressed alert release pass failed (%s)",
                    type(exc).__name__,
                    extra={"event": "monitor_run.release_pass_failed"},
                )
            await self._sleep(self._interval.total_seconds())


__all__ = [
    "HISTORY_LIMIT",
    "AlertSink",
    "EventSink",
    "MonitorRunExecutor",
    "RegistryFn",
    "RunHook",
    "RunOutcome",
    "error_result",
    "list_view_of_record",
    "log_events",
    "prepare_registry",
    "snapshot_baseline",
    "state_of_record",
    "state_of_result",
    "summary_status",
]
