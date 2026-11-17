"""Scheduled monitoring runs and maintenance jobs (M7-09, ARCHITECTURE section 6).

Started only for `ROLE=worker|all` (app.main lifespan). APScheduler 3.x (`AsyncIOScheduler`) is
only the timer: it calls `MonitorScheduler.tick_safely` every `SCHEDULER_TICK_SECONDS` and
`run_maintenance` every `MAINTENANCE_INTERVAL_MINUTES`. Everything else is plain code with an
injected clock and random source, so tests need neither APScheduler nor real time.

One tick:
1. `select`: `MonitorSchedulerRepository.due_targets(now, SCHEDULER_BATCH_SIZE)` and the enabled
   DNSBL list ids (rate-limit keys), in one short read transaction.
2. `claim`: for each due target, while a concurrency slot is free
   (`SCHEDULER_MAX_CONCURRENCY` minus the runs in flight):
   - rate-limit keys (`rate_keys`): the tenant, each enabled DNSBL list if the target runs the
     `dnsbl` check, and (once a check fetches over HTTP) each remote host. If any key is full the
     target is rescheduled to when they all have room (claimed with that time): not dropped, not
     run, not a failed run.
   - otherwise the target is claimed with `next_run_at = now + interval + jitter` (jitter uniform
     in [0, min(SCHEDULER_JITTER_SECONDS, interval)] from the injected random source). The claim
     is a conditional UPDATE committed at once, so of several schedulers (replicas) exactly one
     wins; the losers skip the target. Only the winner takes the rate-limit slots.
   Targets beyond the free slots are left untouched and stay due for the next tick.
3. Each claimed target becomes an asyncio task running `run(ScheduledRun)` under the global
   semaphore. An exception is logged by type and never reaches the loop; a slow run only holds
   its own slot. `shutdown` cancels the runs in flight and waits for them.

What a run does (checks, history, `last_run_at`/`last_status`) is M7-10, behind `RunFn`. Check ids
of the target that are no longer in the registry are passed through in
`ScheduledRun.unknown_check_ids` (and logged): the run must record them as `error`, never skip
them. Until M7-10 the app wires `log_only_run`.

Limiter state is per process (app.services.rate_limit): several workers each apply the limits.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.repositories.dnsbl_enablement import DnsblEnablementRepository
from app.repositories.monitor_targets import DueTarget, MonitorSchedulerRepository
from app.services.auth import SessionPolicy, purge_sessions
from app.services.clock import Clock
from app.services.rate_limit import (
    RateKey,
    RateKind,
    RateLimit,
    SlidingWindowLimiter,
    dnsbl_key,
    tenant_key,
)
from app.services.retention import (
    RetentionPolicy,
    policy_from_settings,
    prune_check_runs,
    prune_dns_snapshots,
)

logger = logging.getLogger("app.scheduler")
maintenance_logger = logging.getLogger("app.maintenance")

DNSBL_CHECK_ID = "dnsbl"
_MINUTE = timedelta(minutes=1)


@dataclass(frozen=True, slots=True)
class ScheduledRun:
    """A claimed target handed to the run function. `unknown_check_ids` must end as `error`."""

    target: DueTarget
    unknown_check_ids: tuple[str, ...]
    claimed_at: datetime


RunFn = Callable[[ScheduledRun], Awaitable[None]]
KeysFn = Callable[[DueTarget, Collection[str]], Sequence[RateKey]]


@dataclass(frozen=True, slots=True)
class SchedulerConfig:
    tick_seconds: int
    batch_size: int
    max_concurrency: int
    max_jitter_seconds: int
    limits: Mapping[RateKind, RateLimit]
    maintenance_minutes: int

    def __post_init__(self) -> None:
        for name in ("tick_seconds", "batch_size", "max_concurrency", "maintenance_minutes"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive int")
        if type(self.max_jitter_seconds) is not int or self.max_jitter_seconds < 0:
            raise ValueError("max_jitter_seconds must be a non-negative int")

    @classmethod
    def from_settings(cls, settings: Settings) -> SchedulerConfig:
        return cls(
            tick_seconds=settings.scheduler_tick_seconds,
            batch_size=settings.scheduler_batch_size,
            max_concurrency=settings.scheduler_max_concurrency,
            max_jitter_seconds=settings.scheduler_jitter_seconds,
            limits={
                RateKind.DNSBL_LIST: RateLimit(settings.scheduler_dnsbl_runs_per_minute, _MINUTE),
                RateKind.HTTP_HOST: RateLimit(
                    settings.scheduler_http_host_runs_per_minute, _MINUTE
                ),
                RateKind.TENANT: RateLimit(settings.scheduler_tenant_runs_per_minute, _MINUTE),
            },
            maintenance_minutes=settings.maintenance_interval_minutes,
        )


# --- policy: plain functions ---------------------------------------------------------------------


def next_run_time(
    now: datetime, interval_seconds: int, max_jitter_seconds: int, rng: random.Random
) -> datetime:
    """`now + interval + jitter`, jitter uniform in [0, min(max_jitter, interval)] seconds.
    Based on `now`, not on the missed slot, so a long downtime does not cause a catch-up burst."""
    if type(interval_seconds) is not int or interval_seconds < 1:
        raise ValueError("interval_seconds must be a positive int")
    if type(max_jitter_seconds) is not int or max_jitter_seconds < 0:
        raise ValueError("max_jitter_seconds must be a non-negative int")
    jitter = rng.uniform(0, min(max_jitter_seconds, interval_seconds))
    return now + timedelta(seconds=interval_seconds + jitter)


def rate_keys(target: DueTarget, enabled_dnsbl_ids: Collection[str]) -> list[RateKey]:
    """The keys one run of `target` touches: its tenant and, if it runs the DNSBL check, each
    enabled list. No built-in check fetches over HTTP yet; when one does, its remote hosts are
    added here with `http_host_key`."""
    keys = [tenant_key(target.tenant_id)]
    if DNSBL_CHECK_ID in target.check_ids:
        keys.extend(dnsbl_key(list_id) for list_id in sorted(enabled_dnsbl_ids))
    return keys


def unknown_check_ids(target: DueTarget, known: Collection[str]) -> tuple[str, ...]:
    return tuple(c for c in target.check_ids if c not in known)


@dataclass
class TickPlan:
    runs: list[ScheduledRun] = field(default_factory=list)
    rate_limited: list[int] = field(default_factory=list)  # target ids rescheduled
    lost: list[int] = field(default_factory=list)  # claimed by another scheduler


def select_due(
    factory: sessionmaker[Session], now: datetime, limit: int
) -> tuple[list[DueTarget], frozenset[str]]:
    """Due targets of every tenant and the enabled DNSBL list ids, in one read transaction."""
    with factory() as session:
        due = MonitorSchedulerRepository(session).due_targets(now, limit)
        enabled = DnsblEnablementRepository(session).enabled_ids() if due else frozenset()
        session.rollback()
    return due, enabled


def _claim(factory: sessionmaker[Session], target: DueTarget, new_next_run: datetime) -> bool:
    with factory.begin() as session:
        return MonitorSchedulerRepository(session).claim(
            target.id, target.next_run_at, new_next_run
        )


def claim_due(
    factory: sessionmaker[Session],
    due: Sequence[DueTarget],
    enabled_dnsbl_ids: Collection[str],
    *,
    now: datetime,
    slots: int,
    limiter: SlidingWindowLimiter,
    rng: random.Random,
    max_jitter_seconds: int,
    known_check_ids: Collection[str],
    keys_for: KeysFn = rate_keys,
) -> TickPlan:
    """Step 2 of a tick (see the module docstring). Each claim commits on its own."""
    plan = TickPlan()
    for target in due:
        if len(plan.runs) >= slots:
            break
        keys = keys_for(target, enabled_dnsbl_ids)
        wait = limiter.retry_after(keys)
        if wait > timedelta(0):
            if _claim(factory, target, now + wait):
                plan.rate_limited.append(target.id)
                logger.debug(
                    "target %d rescheduled by rate limit",
                    target.id,
                    extra={"event": "scheduler.rate_limited"},
                )
            else:
                plan.lost.append(target.id)
            continue
        new_next = next_run_time(now, target.interval_seconds, max_jitter_seconds, rng)
        if not _claim(factory, target, new_next):
            plan.lost.append(target.id)
            continue
        limiter.try_acquire(keys)  # cannot fail: checked above, single owner
        unknown = unknown_check_ids(target, known_check_ids)
        if unknown:
            logger.warning(
                "target %d has %d check id(s) no longer registered; the run reports them as error",
                target.id,
                len(unknown),
                extra={"event": "scheduler.unknown_check"},
            )
        plan.runs.append(ScheduledRun(target, unknown, now))
    return plan


# --- maintenance ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MaintenanceResult:
    """Rows removed per job; None if that job failed (logged)."""

    sessions: int | None
    check_runs: int | None
    dns_snapshots: int | None


def run_maintenance(
    factory: sessionmaker[Session],
    now: datetime,
    session_policy: SessionPolicy,
    retention: RetentionPolicy,
) -> MaintenanceResult:
    """Session purge (R1-14), check run pruning (M7-07), DNS snapshot pruning (M7-08). Each job
    commits in its own transaction; a failure is logged by exception type (its text can carry
    query details) and the other jobs still run."""
    jobs: dict[str, Callable[[Session], int]] = {
        "sessions": lambda db: purge_sessions(db, policy=session_policy, now=now),
        "check_runs": lambda db: prune_check_runs(db, now, retention),
        "dns_snapshots": lambda db: prune_dns_snapshots(db, now, retention),
    }
    counts: dict[str, int | None] = {}
    for name, job in jobs.items():
        try:
            with factory.begin() as db:
                counts[name] = job(db)
        except Exception as exc:
            counts[name] = None
            maintenance_logger.error(
                "maintenance %s failed (%s)",
                name,
                type(exc).__name__,
                extra={"event": f"maintenance.{name}.failed"},
            )
        else:
            maintenance_logger.info(
                "maintenance %s done (%d removed)",
                name,
                counts[name],
                extra={"event": f"maintenance.{name}.done"},
            )
    return MaintenanceResult(counts["sessions"], counts["check_runs"], counts["dns_snapshots"])


# --- runtime -------------------------------------------------------------------------------------


async def log_only_run(run: ScheduledRun) -> None:
    """Placeholder run function until M7-10 records runs: logs the hand-over only."""
    logger.info(
        "scheduled run of target %d claimed (run recording is M7-10)",
        run.target.id,
        extra={"event": "scheduler.run.pending"},
    )


class MonitorScheduler:
    """Owns the limiter, the semaphore and the runs in flight of one process."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        run: RunFn,
        config: SchedulerConfig,
        clock: Clock,
        rng: random.Random,
        *,
        known_check_ids: Collection[str],
        keys_for: KeysFn = rate_keys,
    ) -> None:
        self._factory = factory
        self._run = run
        self._config = config
        self._clock = clock
        self._rng = rng
        self._known = frozenset(known_check_ids)
        self._keys_for = keys_for
        self._limiter = SlidingWindowLimiter(config.limits, clock)
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._in_flight: set[asyncio.Task[None]] = set()
        self._tick_lock = asyncio.Lock()
        self._timer: Any = None  # AsyncIOScheduler; apscheduler ships no type hints
        self._closed = False

    @property
    def in_flight(self) -> int:
        return len(self._in_flight)

    def free_slots(self) -> int:
        return max(0, self._config.max_concurrency - len(self._in_flight))

    def select(self, now: datetime) -> tuple[list[DueTarget], frozenset[str]]:
        return select_due(self._factory, now, self._config.batch_size)

    def claim(
        self, due: Sequence[DueTarget], enabled: Collection[str], now: datetime, slots: int
    ) -> TickPlan:
        return claim_due(
            self._factory,
            due,
            enabled,
            now=now,
            slots=slots,
            limiter=self._limiter,
            rng=self._rng,
            max_jitter_seconds=self._config.max_jitter_seconds,
            known_check_ids=self._known,
            keys_for=self._keys_for,
        )

    def plan(self, now: datetime, slots: int) -> TickPlan:
        if slots <= 0:
            return TickPlan()
        due, enabled = self.select(now)
        return self.claim(due, enabled, now, slots)

    async def tick(self) -> TickPlan:
        """One tick: plan in a worker thread (blocking DB calls), then start the runs."""
        async with self._tick_lock:
            if self._closed:
                return TickPlan()
            now = self._clock.now()
            plan = await asyncio.to_thread(self.plan, now, self.free_slots())
            if self._closed:  # shut down while planning: the claims wait for their next slot
                return plan
            for scheduled in plan.runs:
                task = asyncio.create_task(self._execute(scheduled))
                self._in_flight.add(task)
                task.add_done_callback(self._in_flight.discard)
            return plan

    async def tick_safely(self) -> None:
        """The timer's job: a failing tick is logged and the next one runs as usual."""
        try:
            await self.tick()
        except Exception as exc:
            logger.error(
                "scheduler tick failed (%s)",
                type(exc).__name__,
                extra={"event": "scheduler.tick.failed"},
            )

    async def _execute(self, scheduled: ScheduledRun) -> None:
        async with self._semaphore:
            try:
                await self._run(scheduled)
            except Exception as exc:
                logger.error(
                    "scheduled run of target %d failed (%s)",
                    scheduled.target.id,
                    type(exc).__name__,
                    extra={"event": "scheduler.run.failed"},
                )

    def start(self, maintenance: Callable[[], Awaitable[None]] | None = None) -> None:
        """Start the APScheduler timer (needs a running event loop). Ticks never overlap
        (max_instances=1, coalesced); the first tick runs one interval after start."""
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        timer = AsyncIOScheduler(timezone="UTC")
        timer.add_job(
            self.tick_safely,
            "interval",
            seconds=self._config.tick_seconds,
            id="monitor.tick",
            max_instances=1,
            coalesce=True,
        )
        if maintenance is not None:
            timer.add_job(
                maintenance,
                "interval",
                minutes=self._config.maintenance_minutes,
                id="maintenance",
                max_instances=1,
                coalesce=True,
            )
        timer.start()
        self._timer = timer

    async def shutdown(self) -> None:
        """Stop the timer, cancel the runs in flight and wait for them to finish cancelling."""
        self._closed = True
        if self._timer is not None:
            self._timer.shutdown(wait=False)
            self._timer = None
        tasks = list(self._in_flight)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def maintenance_job(
    factory: sessionmaker[Session], settings: Settings, clock: Clock
) -> Callable[[], Awaitable[None]]:
    """The timer job for `run_maintenance`, run in a worker thread with policies from settings."""
    session_policy = SessionPolicy.from_settings(settings)
    retention = policy_from_settings(settings)

    async def job() -> None:
        await asyncio.to_thread(run_maintenance, factory, clock.now(), session_policy, retention)

    return job
