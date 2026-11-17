"""The scheduled run executor (M7-10): the `RunFn` the scheduler (M7-09) calls for a claimed target.

One run of a `ScheduledRun`:
1. Context: `TenantContext(target.tenant_id, principal=None)` (system work for the tenant). Every
   read and write below goes through `repo_for(ctx, session)`; nothing else of the tenant is
   touched, and a target, domain or run of another tenant reads as missing.
2. Load (one read transaction, ended before any DNS): the target (skipped if it was deleted,
   disabled or moved to another domain since the claim), the domain, the enabled DKIM selectors
   for the snapshot, the check registry (`prepare_registry`: DKIM on the tenant's probe selectors,
   DNSBL on the instance's enabled lists, as the API domain routes do), and the history change
   detection compares against: per check the latest stored run and the latest non-`error` one
   (within the newest `history` runs of that check), and the newest `history` snapshots folded
   with `dns_diff.carry_forward` into the last non-error state of each entry.
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
5. Events: `change_detect.detect_events` (pure) after the commit, handed to the injected
   `EventSink`. Until M7-14 (delivery and dedup) the app wires `log_events`, which only logs kind,
   domain id and fingerprint. Nothing is stored for events here.

Not produced: certificate/key expiry events (no check reads them before M9; see change_detect).
Blocking database work runs in worker threads, so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from sqlalchemy.orm import Session, sessionmaker

from app.checks.dkim import DkimCheck
from app.checks.dnsbl import DnsblCheck
from app.checks.models import CheckContext, CheckResult, finding
from app.checks.registry import CheckRegistry
from app.core.tenancy import TenantContext
from app.dns.types import Resolver
from app.models.check_run import MAX_DURATION_MS
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.check_runs import CheckRunInvalid, CheckRunRecord
from app.repositories.dns_snapshots import DnsSnapshotInvalid, DnsSnapshotRecord
from app.services.change_detect import (
    ChangeEvent,
    CheckState,
    detect_events,
    evaluated_ids,
    listed_ids,
)
from app.services.checks import (
    DEFAULT_DEADLINE_S,
    default_registry,
    run_checks,
    with_dnsbl_enabled,
)
from app.services.clock import Clock
from app.services.dkim_probe_selectors import registry_for, resolve_probe_selectors
from app.services.dns_diff import Snapshot, SnapshotFormatError, carry_forward
from app.services.dns_snapshot import collect_snapshot, load_snapshot, store_if_due
from app.services.dnsbl_admin import enabled_list_ids
from app.services.scheduler import ScheduledRun

logger = logging.getLogger("app.monitor_run")

HISTORY_LIMIT: Final = 50
SOURCE: Final = "scheduled"
UNKNOWN_CHECK: Final = "unknown_check"
RUNNER_FAILED: Final = "runner_failed"
# `last_status` summary: a failure is never hidden by an error, an error never by a lesser status.
_SUMMARY_ORDER: Final[tuple[str, ...]] = ("fail", "error", "warn", "info", "ok")

RegistryFn = Callable[[TenantContext, Session, Sequence[str]], CheckRegistry]
EventSink = Callable[[TenantContext, Sequence[ChangeEvent]], None]


def prepare_registry(ctx: TenantContext, db: Session, ids: Sequence[str]) -> CheckRegistry:
    """The registry of a domain run, as the API domain routes build it: DKIM probing the tenant's
    selectors, DNSBL running the instance's enabled lists (unreadable: the check is `error`)."""
    registry = default_registry()
    if DkimCheck.id in ids:
        registry = registry_for(resolve_probe_selectors(ctx, db))
    if DnsblCheck.id in ids:
        try:
            enabled: frozenset[str] | None = enabled_list_ids(db)
        except Exception as exc:  # noqa: BLE001 - the DNSBL check then reports `error`
            logger.warning(
                "dnsbl enablement unreadable (%s)",
                type(exc).__name__,
                extra={"event": "monitor_run.dnsbl_enablement_failed"},
            )
            enabled = None
        registry = with_dnsbl_enabled(registry, enabled)
    return registry


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


def state_of_record(record: CheckRunRecord) -> CheckState:
    return CheckState(
        check_id=record.check_id,
        status=record.status,
        listed=listed_ids((f.code, f.params) for f in record.findings),
        complete=not record.findings_truncated,
    )


def state_of_result(result: CheckResult) -> CheckState:
    return CheckState(
        check_id=result.check_id,
        status=result.status,
        listed=listed_ids((f.code, f.params) for f in result.findings),
        evaluated=evaluated_ids(result.data),
    )


def snapshot_baseline(records: Sequence[DnsSnapshotRecord]) -> Snapshot | None:
    """Fold stored snapshots (newest first, as `list_for_domain` returns them) oldest to newest
    with `carry_forward`: the last non-error state of each entry. A malformed stored snapshot is
    skipped. None when there is no usable snapshot."""
    baseline: Snapshot | None = None
    for record in reversed(records):
        try:
            snap = load_snapshot(record)
        except SnapshotFormatError:
            logger.warning(
                "stored snapshot skipped (malformed)",
                extra={"event": "monitor_run.snapshot_malformed"},
            )
            continue
        baseline = snap if baseline is None else carry_forward(baseline, snap)
    return baseline


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
    ) -> None:
        if not isinstance(heartbeat, timedelta) or heartbeat <= timedelta(0):
            raise ValueError("heartbeat must be a positive timedelta")
        if type(history) is not int or not 1 <= history <= MAX_LIMIT:
            raise ValueError(f"history must be an int between 1 and {MAX_LIMIT}")
        self._factory = factory
        self._resolver = resolver
        self._clock = clock
        self._heartbeat = heartbeat
        self._sink = sink
        self._prepare = prepare
        self._deadline_s = deadline_s
        self._history = history

    async def __call__(self, run: ScheduledRun) -> None:
        await self.execute(run)

    async def execute(self, run: ScheduledRun) -> RunOutcome | None:
        """Run, store and detect for one claimed target. None if the target or domain is gone."""
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
        recorded, stored = await asyncio.to_thread(
            self._store, ctx, run.target.id, loaded.domain_id, results, snapshot, status, now
        )
        events = detect_events(
            loaded.domain_id,
            [
                (
                    state_of_result(r),
                    loaded.history[r.check_id].previous,
                    loaded.history[r.check_id].baseline,
                )
                for r in results
            ],
            loaded.snapshot_baseline,
            snapshot,
        )
        if events:
            try:
                self._sink(ctx, events)
            except Exception as exc:  # noqa: BLE001 - a sink failure never fails the run
                self._log_failed("sink", exc)
        logger.info(
            "scheduled run of target %d done (%s, %d checks, %d events)",
            run.target.id,
            status,
            len(results),
            len(events),
            extra={"event": "monitor_run.done"},
        )
        return RunOutcome(run.target.id, status, results, recorded, stored, tuple(events))

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
                    repos.dns_snapshots.list_for_domain(target.domain_id, limit=self._history)
                )
                return _Loaded(
                    target.domain_id, domain.name, selectors, registry, history, baseline
                )
            finally:
                db.rollback()

    def _check_history(self, repos: TenantRepositories, domain_id: int, check_id: str) -> _History:
        try:
            page = repos.check_runs.list_for_domain(
                domain_id, check_id=check_id, limit=self._history
            )
        except CheckRunInvalid:
            return _History(None, None)  # an id the history cannot hold: no previous run
        previous = state_of_record(page.items[0]) if page.items else None
        baseline = next((state_of_record(r) for r in page.items if r.status != "error"), None)
        return _History(previous, baseline)

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


__all__ = [
    "HISTORY_LIMIT",
    "EventSink",
    "MonitorRunExecutor",
    "RegistryFn",
    "RunOutcome",
    "error_result",
    "log_events",
    "prepare_registry",
    "snapshot_baseline",
    "state_of_record",
    "state_of_result",
    "summary_status",
]
