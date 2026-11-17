"""M7-09 scheduler core: selection, jitter, concurrency, rate limits, claims, maintenance.

Fake clock, seeded random source and fake run functions: no APScheduler timer firing, no real
time, no sleeping, no network. Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL.
"""

import asyncio
import logging
import random
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import (
    DEFAULT_SCHEDULER_MAX_CONCURRENCY,
    SCHEDULER_MAX_CONCURRENCY_MAX,
    ConfigError,
    Settings,
)
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.main import start_scheduler
from app.models import Tenant
from app.repositories import repo_for
from app.repositories.dnsbl_enablement import DnsblEnablementRepository
from app.repositories.monitor_targets import DueTarget, MonitorSchedulerRepository
from app.services import scheduler as scheduler_module
from app.services.auth import SessionPolicy
from app.services.rate_limit import RateKind, RateLimit, dnsbl_key, tenant_key
from app.services.retention import RetentionPolicy
from app.services.scheduler import (
    MaintenanceResult,
    MonitorScheduler,
    ScheduledRun,
    SchedulerConfig,
    next_run_time,
    rate_keys,
    run_maintenance,
)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)
SECRET = "s3cr3t-value-DO-NOT-LEAK-0123456789abcdef"
ENC = "enc-value-DO-NOT-LEAK-0123456789abcdef-xyz"
KNOWN = frozenset({"dkim", "dmarc", "dnsbl", "spf"})


class FakeClock:
    def __init__(self, at: datetime = NOW) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at

    def advance(self, **kw: float) -> None:
        self.at += timedelta(**kw)


def _config(
    *, concurrency: int = 8, jitter: int = 0, dnsbl: int = 100, tenant: int = 100
) -> SchedulerConfig:
    return SchedulerConfig(
        tick_seconds=30,
        batch_size=100,
        max_concurrency=concurrency,
        max_jitter_seconds=jitter,
        limits={
            RateKind.DNSBL_LIST: RateLimit(dnsbl, MIN),
            RateKind.HTTP_HOST: RateLimit(100, MIN),
            RateKind.TENANT: RateLimit(tenant, MIN),
        },
        maintenance_minutes=60,
    )


@dataclass
class Recorder:
    """A fake run function: records runs, can block until released or raise for some targets."""

    runs: list[ScheduledRun] = field(default_factory=list)
    gate: asyncio.Event | None = None
    fail_ids: set[int] = field(default_factory=set)
    cancelled: list[int] = field(default_factory=list)

    async def __call__(self, run: ScheduledRun) -> None:
        self.runs.append(run)
        if run.target.id in self.fail_ids:
            raise RuntimeError("boom")
        if self.gate is not None:
            try:
                await self.gate.wait()
            except asyncio.CancelledError:
                self.cancelled.append(run.target.id)
                raise

    @property
    def ids(self) -> list[int]:
        return [r.target.id for r in self.runs]


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    factory: sessionmaker[Session]
    tenants: dict[str, int]
    domains: dict[str, list[int]]

    def target(
        self,
        tenant: str = "a",
        n: int = 0,
        *,
        checks: list[str] | None = None,
        at: datetime = NOW,
        interval: int = 3600,
        enabled: bool = True,
    ) -> int:
        with self.factory.begin() as s:
            rec = repo_for(TenantContext(self.tenants[tenant], None), s).monitor_targets.create(
                self.domains[tenant][n],
                check_ids=checks or ["spf"],
                interval_seconds=interval,
                next_run_at=at,
                enabled=enabled,
            )
            assert rec is not None
            return rec.id

    def next_run(self, target_id: int) -> datetime:
        with self.factory() as s:
            for tid in self.tenants.values():
                rec = repo_for(TenantContext(tid, None), s).monitor_targets.get(target_id)
                if rec is not None:
                    return rec.next_run_at
        raise AssertionError("target not found")

    def due(self, at: datetime = NOW) -> list[int]:
        with self.factory() as s:
            return [d.id for d in MonitorSchedulerRepository(s).due_targets(at, 1000)]

    def enable_dnsbl(self, *list_ids: str) -> None:
        with self.factory.begin() as s:
            repo = DnsblEnablementRepository(s)
            for lid in list_ids:
                repo.enable(
                    lid, actor=None, policy_acknowledged=True, unverified_confirmed=True, now=NOW
                )

    def scheduler(
        self,
        run: Any,
        config: SchedulerConfig | None = None,
        clock: FakeClock | None = None,
        known: frozenset[str] = KNOWN,
    ) -> MonitorScheduler:
        return MonitorScheduler(
            self.factory,
            run,
            config or _config(),
            clock or FakeClock(),
            random.Random(7),
            known_check_ids=known,
        )


@pytest.fixture
def world(engine: Engine) -> World:
    factory = create_session_factory(engine)
    with factory.begin() as s:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        s.add_all([ta, tb])
        s.flush()
        domains: dict[str, list[int]] = {}
        for key, tenant in (("a", ta), ("b", tb)):
            repo = repo_for(TenantContext(tenant.id, None), s).domains
            domains[key] = [repo.create(f"d{i}.{key}.example").id for i in range(12)]
        tenants = {"a": ta.id, "b": tb.id}
    return World(factory, tenants, domains)


async def _drain(sched: MonitorScheduler) -> None:
    for _ in range(50):
        if sched.in_flight == 0:
            return
        await asyncio.sleep(0)  # yields to the loop; no real time passes
    raise AssertionError("runs did not finish")


# --- plain policy functions ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("interval", "jitter", "low", "high"),
    [
        (3600, 0, 3600, 3600),
        (3600, 300, 3600, 3900),
        (3600, 7200, 3600, 7200),  # jitter never exceeds the interval
        (86400, 3600, 86400, 90000),
    ],
)
def test_jitter_bounds(interval: int, jitter: int, low: int, high: int) -> None:
    rng = random.Random(1)
    offsets = [
        (next_run_time(NOW, interval, jitter, rng) - NOW).total_seconds() for _ in range(500)
    ]
    assert all(low <= o <= high for o in offsets)
    if jitter:
        assert max(offsets) - min(offsets) > (high - low) / 2  # actually spread


def test_jitter_is_deterministic_for_a_seed() -> None:
    a = [next_run_time(NOW, 3600, 300, random.Random(42)) for _ in range(3)]
    b = [next_run_time(NOW, 3600, 300, random.Random(42)) for _ in range(3)]
    assert a == b


@pytest.mark.parametrize(
    ("interval", "jitter"), [(0, 10), (-1, 10), (True, 10), (3600.0, 10), (3600, -1), (3600, None)]
)
def test_next_run_time_rejects_malformed(interval: Any, jitter: Any) -> None:
    with pytest.raises(ValueError):
        next_run_time(NOW, interval, jitter, random.Random(1))


def _due(checks: tuple[str, ...], tenant_id: int = 5) -> DueTarget:
    return DueTarget(1, tenant_id, 9, checks, 3600, NOW)


def test_rate_keys() -> None:
    assert rate_keys(_due(("spf",)), {"zen", "abc"}) == [tenant_key(5)]
    assert rate_keys(_due(("dnsbl", "spf")), {"zen", "abc"}) == [
        tenant_key(5),
        dnsbl_key("abc"),
        dnsbl_key("zen"),
    ]
    assert rate_keys(_due(("dnsbl",)), set()) == [tenant_key(5)]


@pytest.mark.parametrize(
    "bad",
    [
        {"tick_seconds": 0},
        {"batch_size": -1},
        {"max_concurrency": 0},
        {"max_concurrency": True},
        {"maintenance_minutes": 1.5},
        {"max_jitter_seconds": -1},
    ],
)
def test_config_rejects_malformed(bad: dict[str, Any]) -> None:
    values: dict[str, Any] = {
        "tick_seconds": 30,
        "batch_size": 10,
        "max_concurrency": 2,
        "max_jitter_seconds": 0,
        "limits": _config().limits,
        "maintenance_minutes": 60,
    }
    with pytest.raises(ValueError):
        SchedulerConfig(**{**values, **bad})


# --- settings ------------------------------------------------------------------------------------

_SCHEDULER_VARS = [
    "SCHEDULER_TICK_SECONDS",
    "SCHEDULER_BATCH_SIZE",
    "SCHEDULER_MAX_CONCURRENCY",
    "SCHEDULER_JITTER_SECONDS",
    "SCHEDULER_DNSBL_RUNS_PER_MINUTE",
    "SCHEDULER_HTTP_HOST_RUNS_PER_MINUTE",
    "SCHEDULER_TENANT_RUNS_PER_MINUTE",
    "MAINTENANCE_INTERVAL_MINUTES",
    "ROLE",
]


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for name in _SCHEDULER_VARS:
        monkeypatch.delenv(name, raising=False)
    for name, value in {"SECRET_KEY": SECRET, "ENCRYPTION_KEY": ENC, **env}.items():
        monkeypatch.setenv(name, value)
    return Settings()  # type: ignore[call-arg]


def test_settings_defaults_build_a_config(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = SchedulerConfig.from_settings(_settings(monkeypatch))
    assert cfg.max_concurrency == DEFAULT_SCHEDULER_MAX_CONCURRENCY
    assert set(cfg.limits) == set(RateKind)
    assert all(limit.window == MIN for limit in cfg.limits.values())


@pytest.mark.parametrize(
    ("name", "raw"),
    [
        ("SCHEDULER_TICK_SECONDS", "4"),
        ("SCHEDULER_TICK_SECONDS", "601"),
        ("SCHEDULER_BATCH_SIZE", "0"),
        ("SCHEDULER_BATCH_SIZE", "1001"),
        ("SCHEDULER_MAX_CONCURRENCY", "0"),
        ("SCHEDULER_MAX_CONCURRENCY", str(SCHEDULER_MAX_CONCURRENCY_MAX + 1)),
        ("SCHEDULER_JITTER_SECONDS", "-1"),
        ("SCHEDULER_JITTER_SECONDS", "3601"),
        ("SCHEDULER_DNSBL_RUNS_PER_MINUTE", "0"),
        ("SCHEDULER_HTTP_HOST_RUNS_PER_MINUTE", "601"),
        ("SCHEDULER_TENANT_RUNS_PER_MINUTE", "abc"),
        ("MAINTENANCE_INTERVAL_MINUTES", "4"),
        ("MAINTENANCE_INTERVAL_MINUTES", "1.5"),
        ("MAINTENANCE_INTERVAL_MINUTES", ""),
        ("ROLE", "scheduler"),
    ],
)
def test_settings_reject_out_of_range_and_malformed(
    monkeypatch: pytest.MonkeyPatch, name: str, raw: str
) -> None:
    with pytest.raises(ConfigError) as exc:
        _settings(monkeypatch, **{name: raw})
    assert exc.value.params == {"name": name}


@pytest.mark.parametrize(("role", "starts"), [("web", False), ("worker", True), ("all", True)])
async def test_role_decides_whether_the_scheduler_starts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, role: str, starts: bool
) -> None:
    app = FastAPI()
    app.state.settings = _settings(
        monkeypatch, ROLE=role, DATABASE_URL=f"sqlite:///{tmp_path}/unused.db"
    )
    sched = start_scheduler(app)
    try:
        assert (sched is not None) is starts
        if sched is not None:
            assert {j.id for j in sched._timer.get_jobs()} == {"monitor.tick", "maintenance"}
    finally:
        if sched is not None:
            await sched.shutdown()
            assert sched._timer is None
        engine = getattr(app.state, "db_engine", None)
        if engine is not None:
            engine.dispose()


# --- ticks against a database --------------------------------------------------------------------


async def test_tick_claims_runs_and_reschedules_with_jitter(world: World) -> None:
    a, b = world.target("a"), world.target("b", checks=["dmarc", "spf"])
    world.target("a", 1, at=NOW + timedelta(seconds=1))  # not yet due
    world.target("b", 1, enabled=False)
    rec = Recorder()
    sched = world.scheduler(rec, _config(jitter=300))
    plan = await sched.tick()
    await _drain(sched)
    assert sorted(rec.ids) == sorted([a, b])
    assert plan.rate_limited == [] and plan.lost == []
    run_b = next(r for r in rec.runs if r.target.id == b)
    assert run_b.target.tenant_id == world.tenants["b"] and run_b.unknown_check_ids == ()
    for tid in (a, b):
        offset = world.next_run(tid) - NOW
        assert timedelta(hours=1) <= offset <= timedelta(hours=1, seconds=300)
    assert world.due() == []
    assert (await sched.tick()).runs == []  # nothing due any more


async def test_semaphore_caps_concurrency(world: World) -> None:
    ids = [world.target("a", n) for n in range(5)]
    rec = Recorder(gate=asyncio.Event())
    sched = world.scheduler(rec, _config(concurrency=2))
    await sched.tick()
    await asyncio.sleep(0)
    assert sched.in_flight == 2 and rec.ids == ids[:2]
    assert (await sched.tick()).runs == []  # no free slot: nothing is claimed
    assert world.due() == ids[2:]  # the rest stays due, untouched
    assert rec.gate is not None
    rec.gate.set()
    await _drain(sched)
    await sched.tick()
    await _drain(sched)
    assert rec.ids == ids[:4]


async def test_semaphore_cap_holds_with_many_due_targets(world: World) -> None:
    for n in range(12):
        world.target("a", n)
        world.target("b", n)
    peak = 0
    active = 0
    gate = asyncio.Event()

    async def run(_: ScheduledRun) -> None:
        nonlocal peak, active
        active += 1
        peak = max(peak, active)
        await gate.wait()
        active -= 1

    sched = world.scheduler(run, _config(concurrency=3))
    for _ in range(5):
        await sched.tick()
        await asyncio.sleep(0)
    assert peak == 3
    gate.set()
    await _drain(sched)


async def test_per_list_rate_limit_across_many_targets(world: World) -> None:
    world.enable_dnsbl("zen", "other")
    ids = [world.target("a", n, checks=["dnsbl", "spf"]) for n in range(6)]
    ids += [world.target("b", n, checks=["dnsbl"]) for n in range(6)]
    plain = world.target("b", 6, checks=["spf"])  # no DNSBL key: not limited by the lists
    clock = FakeClock()
    rec = Recorder()
    sched = world.scheduler(rec, _config(dnsbl=3), clock)
    plan = await sched.tick()
    await _drain(sched)
    assert sorted(rec.ids) == sorted([*ids[:3], plain])
    assert sorted(plan.rate_limited) == sorted(ids[3:])
    # Rescheduled for when the lists have room: not dropped, not run, not counted as a run.
    for tid in ids[3:]:
        assert world.next_run(tid) == NOW + MIN
    assert world.due() == []
    clock.advance(seconds=59)
    assert (await sched.tick()).runs == []
    clock.advance(seconds=1)
    plan = await sched.tick()
    await _drain(sched)
    assert [r.target.id for r in plan.runs] == ids[3:6]
    assert len(rec.runs) == 7


async def test_tenant_rate_limit(world: World) -> None:
    a_ids = [world.target("a", n) for n in range(4)]
    b_id = world.target("b")
    rec = Recorder()
    sched = world.scheduler(rec, _config(tenant=2))
    plan = await sched.tick()
    await _drain(sched)
    assert sorted(rec.ids) == sorted([*a_ids[:2], b_id])
    assert plan.rate_limited == a_ids[2:]


async def test_rate_limited_target_is_not_dropped_or_failed(world: World) -> None:
    world.enable_dnsbl("zen")
    first = world.target("a", 0, checks=["dnsbl"])
    second = world.target("a", 1, checks=["dnsbl"])
    clock = FakeClock()
    rec = Recorder()
    sched = world.scheduler(rec, _config(dnsbl=1), clock)
    await sched.tick()
    await _drain(sched)
    assert rec.ids == [first]
    with world.factory() as s:
        target = repo_for(TenantContext(world.tenants["a"], None), s).monitor_targets.get(second)
    assert target is not None
    assert target.enabled and target.last_run_at is None and target.last_status is None
    clock.advance(minutes=1)
    await sched.tick()
    await _drain(sched)
    assert rec.ids == [first, second]


async def test_two_schedulers_over_one_database_claim_each_target_once(world: World) -> None:
    ids = [world.target("a", n) for n in range(3)] + [world.target("b", n) for n in range(3)]
    rec1, rec2 = Recorder(), Recorder()
    s1, s2 = world.scheduler(rec1), world.scheduler(rec2)
    # Both read the same due targets before either claims (the interleaving of two replicas).
    due1, en1 = s1.select(NOW)
    due2, en2 = s2.select(NOW)
    assert [d.id for d in due1] == [d.id for d in due2] == ids
    plan1 = s1.claim(due1, en1, NOW, 8)
    plan2 = s2.claim(due2, en2, NOW, 8)
    assert [r.target.id for r in plan1.runs] == ids
    assert plan2.runs == [] and plan2.lost == ids


async def test_interleaved_claims_split_the_targets(world: World) -> None:
    ids = [world.target("a", n) for n in range(4)]
    s1, s2 = world.scheduler(Recorder()), world.scheduler(Recorder())
    due1, en1 = s1.select(NOW)
    due2, en2 = s2.select(NOW)
    p1a = s1.claim(due1[:2], en1, NOW, 8)
    p2 = s2.claim(due2[1:], en2, NOW, 8)
    p1b = s1.claim(due1[2:], en1, NOW, 8)
    winners = [r.target.id for p in (p1a, p2, p1b) for r in p.runs]
    assert sorted(winners) == ids  # every target exactly once
    assert p2.lost == [ids[1]] and p1b.lost == [ids[2], ids[3]]


async def test_unknown_check_ids_are_passed_through_not_skipped(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    tid = world.target("a", checks=["dmarc", "spf"])
    rec = Recorder()
    sched = world.scheduler(rec, known=frozenset({"spf"}))  # "dmarc" left the registry
    with caplog.at_level(logging.WARNING, logger="app.scheduler"):
        await sched.tick()
        await _drain(sched)
    assert rec.ids == [tid]
    assert rec.runs[0].unknown_check_ids == ("dmarc",)
    assert any(r.event == "scheduler.unknown_check" for r in caplog.records)  # type: ignore[attr-defined]


async def test_failing_run_is_logged_and_others_continue(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    bad, good = world.target("a", 0), world.target("a", 1)
    later = world.target("a", 2, at=NOW + timedelta(minutes=5))
    clock = FakeClock()
    rec = Recorder(fail_ids={bad})
    sched = world.scheduler(rec, clock=clock)
    with caplog.at_level(logging.ERROR, logger="app.scheduler"):
        await sched.tick()
        await _drain(sched)
    assert rec.ids == [bad, good]
    failed = [r for r in caplog.records if getattr(r, "event", "") == "scheduler.run.failed"]
    assert len(failed) == 1 and "RuntimeError" in failed[0].getMessage()
    assert "boom" not in caplog.text
    clock.advance(minutes=5)
    await sched.tick()  # the loop goes on
    await _drain(sched)
    assert rec.ids == [bad, good, later]


async def test_slow_run_does_not_block_others(world: World) -> None:
    slow, fast = world.target("a", 0), world.target("a", 1)
    gate = asyncio.Event()
    done: list[int] = []

    async def run(r: ScheduledRun) -> None:
        if r.target.id == slow:
            await gate.wait()
        done.append(r.target.id)

    sched = world.scheduler(run, _config(concurrency=2))
    await sched.tick()
    for _ in range(5):
        await asyncio.sleep(0)
    assert done == [fast] and sched.in_flight == 1
    gate.set()
    await _drain(sched)
    assert done == [fast, slow]


async def test_failing_tick_is_logged_and_the_next_tick_works(
    world: World, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = world.target("a")
    rec = Recorder()
    sched = world.scheduler(rec)

    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("db down: secret detail")

    with monkeypatch.context() as m:
        m.setattr(scheduler_module, "select_due", broken)
        with caplog.at_level(logging.ERROR, logger="app.scheduler"):
            await sched.tick_safely()
    assert any(getattr(r, "event", "") == "scheduler.tick.failed" for r in caplog.records)
    assert "secret detail" not in caplog.text
    await sched.tick_safely()
    await _drain(sched)
    assert rec.ids == [tid]


async def test_shutdown_cancels_in_flight_runs(world: World) -> None:
    ids = [world.target("a", n) for n in range(3)]
    rec = Recorder(gate=asyncio.Event())
    sched = world.scheduler(rec)
    await sched.tick()
    for _ in range(3):
        await asyncio.sleep(0)
    assert sched.in_flight == 3
    await sched.shutdown()
    assert sched.in_flight == 0
    assert sorted(rec.cancelled) == ids
    world.target("a", 5)
    assert (await sched.tick()).runs == []  # a closed scheduler claims nothing


async def test_shutdown_restores_next_run_of_cancelled_runs(world: World) -> None:
    early = NOW - timedelta(minutes=10)
    ids = [world.target("a", n, at=early) for n in range(3)]
    rec = Recorder(gate=asyncio.Event())
    sched = world.scheduler(rec, _config(concurrency=2))
    plan = await sched.tick()
    assert [r.target.id for r in plan.runs] == ids[:2]
    assert all(r.new_next_run_at == NOW + timedelta(hours=1) for r in plan.runs)
    await asyncio.sleep(0)  # both runs start and block on the gate
    assert all(world.next_run(t) == NOW + timedelta(hours=1) for t in ids[:2])
    await sched.shutdown()
    # Both claims undone to the claim time: due at the next start, no interval lost.
    assert [world.next_run(t) for t in ids] == [NOW, NOW, early]
    assert sorted(world.due()) == ids


async def test_shutdown_before_any_run_started_restores_all(world: World) -> None:
    ids = [world.target("a", n) for n in range(3)]
    rec = Recorder()
    sched = world.scheduler(rec)
    await sched.tick()
    await sched.shutdown()  # no yield: no task got to run
    assert rec.runs == []
    assert [world.next_run(t) for t in ids] == [NOW] * 3


async def test_finished_and_failed_runs_keep_their_claim(world: World) -> None:
    ok, bad = world.target("a", 0), world.target("a", 1)
    rec = Recorder(fail_ids={bad})
    sched = world.scheduler(rec)
    await sched.tick()
    await _drain(sched)
    await sched.shutdown()
    assert world.next_run(ok) == world.next_run(bad) == NOW + timedelta(hours=1)


async def test_restore_is_conditional(world: World) -> None:
    tid = world.target("a")
    rec = Recorder(gate=asyncio.Event())
    sched = world.scheduler(rec)
    plan = await sched.tick()
    moved = NOW + timedelta(hours=5)
    with world.factory.begin() as s:  # the user rescheduled it meanwhile
        repo_for(TenantContext(world.tenants["a"], None), s).monitor_targets.update(
            tid, next_run_at=moved
        )
    assert scheduler_module.restore_claims(world.factory, plan.runs) == 0
    await sched.shutdown()
    assert world.next_run(tid) == moved


async def test_restore_failure_is_logged(
    world: World, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.target("a")
    sched = world.scheduler(Recorder(gate=asyncio.Event()))
    plan = await sched.tick()

    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("db down: secret detail")

    monkeypatch.setattr(MonitorSchedulerRepository, "claim", broken)
    with caplog.at_level(logging.ERROR, logger="app.scheduler"):
        assert scheduler_module.restore_claims(world.factory, plan.runs) == 0
        await sched.shutdown()
    assert any(getattr(r, "event", "") == "scheduler.restore.failed" for r in caplog.records)
    assert "secret detail" not in caplog.text


async def test_shutdown_waits_for_a_tick_in_progress_and_undoes_its_claims(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = world.target("a")
    rec = Recorder()
    sched = world.scheduler(rec)
    entered, release = threading.Event(), threading.Event()
    original = sched.plan

    def slow_plan(now: datetime, slots: int) -> Any:
        plan = original(now, slots)  # the claim is committed here
        entered.set()
        release.wait(timeout=10)
        return plan

    monkeypatch.setattr(sched, "plan", slow_plan)
    tick = asyncio.create_task(sched.tick())
    await asyncio.to_thread(entered.wait, 10)
    assert world.next_run(tid) == NOW + timedelta(hours=1)
    stop = asyncio.create_task(sched.shutdown())
    for _ in range(5):
        await asyncio.sleep(0)
    assert not stop.done()  # held by the tick lock while the planning thread runs
    release.set()
    await stop
    assert tick.done()
    plan = tick.result()
    assert [r.target.id for r in plan.runs] == [tid] and rec.runs == []
    assert world.next_run(tid) == NOW  # claimed while closing, then undone


# --- maintenance ---------------------------------------------------------------------------------

_SESSION_POLICY = SessionPolicy(idle=timedelta(minutes=30), absolute=timedelta(hours=12))


def test_maintenance_runs_every_job(world: World) -> None:
    result = run_maintenance(world.factory, NOW, _SESSION_POLICY, RetentionPolicy(90))
    assert result == MaintenanceResult(sessions=0, check_runs=0, dns_snapshots=0)


def test_maintenance_failure_is_logged_and_the_other_jobs_run(
    world: World, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any, **__: Any) -> int:
        raise RuntimeError("secret query detail")

    monkeypatch.setattr(scheduler_module, "purge_sessions", broken)
    with caplog.at_level(logging.INFO, logger="app.maintenance"):
        result = run_maintenance(world.factory, NOW, _SESSION_POLICY, RetentionPolicy(90))
    assert result == MaintenanceResult(sessions=None, check_runs=0, dns_snapshots=0)
    events = [getattr(r, "event", "") for r in caplog.records]
    assert events == [
        "maintenance.sessions.failed",
        "maintenance.check_runs.done",
        "maintenance.dns_snapshots.done",
    ]
    assert "secret query detail" not in caplog.text


def test_maintenance_passes_the_policies_and_clock(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def purge(db: Session, *, policy: SessionPolicy, now: datetime) -> int:
        seen["sessions"] = (policy, now)
        return 2

    def prune(name: str) -> Any:
        def inner(db: Session, now: datetime, policy: RetentionPolicy) -> int:
            seen[name] = (policy, now)
            return 1

        return inner

    monkeypatch.setattr(scheduler_module, "purge_sessions", purge)
    monkeypatch.setattr(scheduler_module, "prune_check_runs", prune("runs"))
    monkeypatch.setattr(scheduler_module, "prune_dns_snapshots", prune("snaps"))
    retention = RetentionPolicy(30, 400)
    result = run_maintenance(world.factory, NOW, _SESSION_POLICY, retention)
    assert result == MaintenanceResult(2, 1, 1)
    assert seen == {
        "sessions": (_SESSION_POLICY, NOW),
        "runs": (retention, NOW),
        "snaps": (retention, NOW),
    }
