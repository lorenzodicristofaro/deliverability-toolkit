"""M7-14c alert wiring: scheduled runs emit through the alert service, emit retries for the latest
run only, suppressed alerts are released once their window ends, the delivery loop starts only for
ROLE worker/all and stops cleanly, and the ALERT_* settings are validated at startup.

Fake checks, a scripted resolver, a fake clock and a fake channel: no network, no real sleeping.
DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core import i18n
from app.core.config import (
    CONFIG_ALERT_BACKOFF_CAP_TOO_SHORT_KEY,
    CONFIG_ALERT_SEND_TIMEOUT_TOO_LONG_KEY,
    CONFIG_INVALID_VALUE_KEY,
    ConfigError,
    Settings,
)
from app.core.secrets_crypto import SecretCipher
from app.core.tenancy import TenantContext
from app.main import create_app, start_alert_tasks, start_scheduler, stop_alert_tasks
from app.models import Alert
from app.models.alert import KINDS
from app.repositories import repo_for
from app.repositories.monitor_targets import DueTarget
from app.services import alerts as alerts_module
from app.services.alert_dispatch import AlertDispatcher, ChannelRegistry, seal_secrets
from app.services.alerts import AlertService, EmitIncomplete, EmitResult
from app.services.change_detect import ChangeEvent
from app.services.monitor_run import AlertReleaser, MonitorRunExecutor, RunOutcome
from app.services.scheduler import ScheduledRun
from tests.services import test_monitor_run as mr
from tests.services.test_alert_dispatch import FakeChannel

# Fixtures of the run executor tests (migrated database, two tenants, fake checks and resolver).
engine = mr.engine
world = mr.world

SECRET = "s3cr3t-value-DO-NOT-LEAK-0123456789abcdef"
FERNET = Fernet.generate_key().decode()
HOUR = timedelta(hours=1)
ALERT_VARS = (
    "ALERT_MIN_REALERT_MINUTES",
    "ALERT_MAX_ATTEMPTS",
    "ALERT_BACKOFF_BASE_SECONDS",
    "ALERT_BACKOFF_CAP_SECONDS",
    "ALERT_LEASE_SECONDS",
    "ALERT_SEND_TIMEOUT_SECONDS",
    "ROLE",
)


# --- settings ------------------------------------------------------------------------------------


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for name in ALERT_VARS:
        monkeypatch.delenv(name, raising=False)
    for name, value in {"SECRET_KEY": SECRET, "ENCRYPTION_KEY": FERNET, **env}.items():
        monkeypatch.setenv(name, value)
    return Settings()  # type: ignore[call-arg]


def test_default_settings_are_the_service_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    service = AlertService.from_settings(None, mr.FakeClock(), _settings(monkeypatch))  # type: ignore[arg-type]
    assert service.min_realert == alerts_module.DEFAULT_MIN_REALERT
    assert service._max_attempts == alerts_module.DEFAULT_MAX_ATTEMPTS
    assert service._backoff_base == alerts_module.DEFAULT_BACKOFF_BASE
    assert service._backoff_cap == alerts_module.DEFAULT_BACKOFF_CAP
    assert service._lease == alerts_module.DEFAULT_LEASE
    assert service._send_timeout == alerts_module.DEFAULT_SEND_TIMEOUT


def test_settings_reach_the_service(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _settings(
        monkeypatch,
        ALERT_MIN_REALERT_MINUTES="0",
        ALERT_MAX_ATTEMPTS="7",
        ALERT_BACKOFF_BASE_SECONDS="5",
        ALERT_BACKOFF_CAP_SECONDS="5",
        ALERT_LEASE_SECONDS="120",
        ALERT_SEND_TIMEOUT_SECONDS="119",
    )
    service = AlertService.from_settings(None, mr.FakeClock(), cfg)  # type: ignore[arg-type]
    assert service.min_realert == timedelta(0) and service._max_attempts == 7
    assert service.backoff(3) == timedelta(seconds=5)
    assert (service._lease, service._send_timeout) == (
        timedelta(seconds=120),
        timedelta(seconds=119),
    )


def _bad(name: str, raw: str) -> tuple[dict[str, str], str, dict[str, str]]:
    return {name: raw}, CONFIG_INVALID_VALUE_KEY, {"name": name}


INVALID: list[tuple[dict[str, str], str, dict[str, str]]] = [
    _bad("ALERT_MIN_REALERT_MINUTES", "-1"),
    _bad("ALERT_MIN_REALERT_MINUTES", "10081"),
    _bad("ALERT_MIN_REALERT_MINUTES", "1.5"),
    _bad("ALERT_MAX_ATTEMPTS", "0"),
    _bad("ALERT_MAX_ATTEMPTS", "101"),
    _bad("ALERT_MAX_ATTEMPTS", "abc"),
    _bad("ALERT_BACKOFF_BASE_SECONDS", "0"),
    _bad("ALERT_BACKOFF_BASE_SECONDS", ""),
    _bad("ALERT_BACKOFF_CAP_SECONDS", "86401"),
    _bad("ALERT_LEASE_SECONDS", "9"),
    _bad("ALERT_LEASE_SECONDS", "3601"),
    _bad("ALERT_SEND_TIMEOUT_SECONDS", "0"),
    _bad("ALERT_SEND_TIMEOUT_SECONDS", "-5"),
    (
        {"ALERT_BACKOFF_BASE_SECONDS": "60", "ALERT_BACKOFF_CAP_SECONDS": "59"},
        CONFIG_ALERT_BACKOFF_CAP_TOO_SHORT_KEY,
        {"cap": "59", "base": "60"},
    ),
    (
        {"ALERT_LEASE_SECONDS": "300", "ALERT_SEND_TIMEOUT_SECONDS": "300"},
        CONFIG_ALERT_SEND_TIMEOUT_TOO_LONG_KEY,
        {"timeout": "300", "lease": "300"},
    ),
    (
        {"ALERT_LEASE_SECONDS": "30"},  # the default send timeout (60 s) is not shorter
        CONFIG_ALERT_SEND_TIMEOUT_TOO_LONG_KEY,
        {"timeout": "60", "lease": "30"},
    ),
]  # fmt: skip


@pytest.mark.parametrize(("env", "key", "params"), INVALID, ids=[repr(c[0]) for c in INVALID])
def test_invalid_settings_raise_a_config_error(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], key: str, params: dict[str, str]
) -> None:
    with pytest.raises(ConfigError) as exc:
        _settings(monkeypatch, **env)
    assert (exc.value.key, exc.value.params) == (key, params)


@pytest.mark.parametrize("lang", ["en", "it"])
@pytest.mark.parametrize(
    ("key", "params"),
    [
        (CONFIG_ALERT_BACKOFF_CAP_TOO_SHORT_KEY, {"cap": "59", "base": "60"}),
        (CONFIG_ALERT_SEND_TIMEOUT_TOO_LONG_KEY, {"timeout": "300", "lease": "300"}),
    ],
)
def test_config_errors_are_translated(lang: str, key: str, params: dict[str, str]) -> None:
    i18n.set_strict(True)
    try:
        text = i18n.t(key, lang, **params)
    finally:
        i18n.set_strict(False)
    assert text != key and all(value in text for value in params.values())


def test_invalid_setting_stops_the_app_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    _settings(monkeypatch)  # valid secrets in the environment
    monkeypatch.setenv("ALERT_SEND_TIMEOUT_SECONDS", "600")
    with pytest.raises(ConfigError) as exc, TestClient(create_app()):
        pass
    assert exc.value.key == CONFIG_ALERT_SEND_TIMEOUT_TOO_LONG_KEY


# --- helpers for runs ----------------------------------------------------------------------------


class Flaky:
    """A session factory whose `begin()` fails `failures` times (a transient database error)."""

    def __init__(self, factory: sessionmaker[Session], failures: int) -> None:
        self.factory = factory
        self.failures = failures

    def begin(self) -> Any:
        if self.failures > 0:
            self.failures -= 1
            raise OperationalError("SELECT 1", {}, RuntimeError("db down: secret detail"))
        return self.factory.begin()

    def __call__(self) -> Session:
        return self.factory()


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def wiring(
    w: mr.World, *, min_realert: timedelta = HOUR, failures: int = 0, **kw: Any
) -> tuple[AlertService, MonitorRunExecutor]:
    factory: Any = Flaky(w.factory, failures) if failures else w.factory
    service = AlertService(factory, w.clock, min_realert=min_realert)
    return service, w.executor(sink=service, **kw)


async def run(w: mr.World, executor: MonitorRunExecutor, due: DueTarget) -> RunOutcome | None:
    """One run at the current fake time (the clock is moved by the test)."""
    now = w.clock.now()
    return await executor.execute(ScheduledRun(due, (), now, now + HOUR))


def alerts(w: mr.World, tenant: str = "a") -> list[tuple[str, bool]]:
    with w.factory() as db:
        rows = db.execute(
            select(Alert.kind, Alert.suppressed)
            .where(Alert.tenant_id == w.tenants[tenant])
            .order_by(Alert.id)
        ).all()
    return [(r.kind, r.suppressed) for r in rows]


def route_all(w: mr.World, cipher: SecretCipher, tenant: str = "a") -> int:
    """A webhook channel of `tenant` that every alert kind is routed to."""
    sealed, names = seal_secrets(cipher, {"url": "https://hooks.example.com/x"})
    with w.factory.begin() as db:
        repos = repo_for(w.ctx(tenant), db)
        channel = repos.alert_channels.create(
            kind="webhook", name="ops", enabled=True, config={}, secret_token=sealed,
            secret_fields=names, now=w.clock.now(),
        ).id  # fmt: skip
        for kind in KINDS:
            repos.alert_rules.add(kind, channel)
    return channel


def zen(w: mr.World, outcome: str) -> None:
    found = [mr.listed("zen")] if outcome == "listed" else []
    w.checks["dnsbl"].set(*found, data={"lists": mr.lists(zen=outcome, sbl="not_listed")})


# --- emit from runs ------------------------------------------------------------------------------


async def test_a_change_makes_one_alert_and_an_identical_run_none(world: mr.World) -> None:
    _, executor = wiring(world)
    due = world.target()
    await run(world, executor, due)
    assert alerts(world) == []  # first run: the baseline
    world.zone(spf=mr.SPF_Y)
    changed = await run(world, executor, due)
    assert mr.kinds(changed) == [("record_changed", "@ TXT")]
    assert alerts(world) == [("record_changed", False)]
    world.clock.at += timedelta(minutes=5)
    assert mr.kinds(await run(world, executor, due)) == []
    assert alerts(world) == [("record_changed", False)]
    assert alerts(world, "b") == []


async def test_an_error_run_never_alerts_a_removal_or_clearing(world: mr.World) -> None:
    _, executor = wiring(world)
    due = world.target()
    await run(world, executor, due)
    zen(world, "listed")
    await run(world, executor, due)
    assert alerts(world) == [("new_listing", False)]
    # Everything unreadable: the listing and the record are unknown, not gone.
    world.checks["dnsbl"].set(
        mr.list_error("zen"), evaluated=False, data={"lists": mr.lists(zen="error", sbl="error")}
    )
    world.checks["spf"].set(evaluated=False)
    world.zone(spf=mr.ResultState.servfail)
    await run(world, executor, due)
    assert alerts(world) == [
        ("new_listing", False),
        ("check_error_started", False),
        ("check_error_started", False),
    ]


async def test_emit_runs_in_a_worker_thread(world: mr.World) -> None:
    threads: list[int] = []

    def sink(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        threads.append(threading.get_ident())

    due = world.target()
    executor = world.executor(sink=sink)
    await run(world, executor, due)
    world.zone(spf=mr.SPF_Y)
    await run(world, executor, due)
    assert threads and threading.get_ident() not in threads


async def test_a_transient_db_error_on_emit_is_retried_and_the_alert_kept(
    world: mr.World, caplog: pytest.LogCaptureFixture
) -> None:
    sleeps = Sleeps()
    _, executor = wiring(world, sleep=sleeps)
    due = world.target()
    await run(world, executor, due)
    _, flaky = wiring(world, failures=1, sleep=sleeps)
    world.zone(spf=mr.SPF_Y)
    with caplog.at_level(logging.WARNING):
        out = await run(world, flaky, due)
    assert out is not None and out.status == "ok"
    assert alerts(world) == [("record_changed", False)]
    assert sleeps.calls == [2.0]
    events = [getattr(r, "event", "") for r in caplog.records]
    assert "alerts.emit_failed" in events and "monitor_run.emit_retry" in events
    assert "secret detail" not in caplog.text and mr.SPF_Y not in caplog.text


async def test_emit_retries_are_bounded_and_never_fail_the_run(
    world: mr.World, caplog: pytest.LogCaptureFixture
) -> None:
    sleeps = Sleeps()
    _, executor = wiring(world, sleep=sleeps)
    due = world.target()
    await run(world, executor, due)
    _, flaky = wiring(world, failures=99, sleep=sleeps)
    world.zone(spf=mr.SPF_Y)
    with caplog.at_level(logging.WARNING):
        out = await run(world, flaky, due)
    assert out is not None and mr.kinds(out) == [("record_changed", "@ TXT")]
    assert sleeps.calls == [2.0, 4.0] and alerts(world) == []
    gave_up = [r for r in caplog.records if getattr(r, "event", "") == "monitor_run.emit_gave_up"]
    assert len(gave_up) == 1 and gave_up[0].levelno == logging.ERROR
    # The next run still works (the scheduler goes on).
    world.clock.at += timedelta(minutes=5)
    assert await run(world, executor, due) is not None


async def test_an_older_run_is_never_replayed_after_a_newer_one(
    world: mr.World, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[list[str]] = []

    def sink(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        calls.append([e.after for e in events])
        if len(calls) == 1:
            raise EmitIncomplete(EmitResult(failed=1))

    due = world.target()
    newer_done: list[RunOutcome | None] = []

    async def sleep(seconds: float) -> None:
        # A newer run of the same target starts (and finishes) during the older run's backoff.
        world.zone(spf=mr.SPF_X)
        newer_done.append(await run(world, executor, due))

    executor = world.executor(sink=sink, sleep=sleep)
    await run(world, executor, due)
    world.zone(spf=mr.SPF_Y)
    with caplog.at_level(logging.WARNING):
        older = await run(world, executor, due)
    assert older is not None and len(newer_done) == 1
    newer = newer_done[0]
    assert newer is not None
    # older events once (failed), the newer run's once; the older run is not offered again
    assert calls == [[e.after for e in older.events], [e.after for e in newer.events]]
    assert any(getattr(r, "event", "") == "monitor_run.emit_superseded" for r in caplog.records)


async def test_a_newer_run_stored_by_another_replica_stops_the_retry(
    world: mr.World, caplog: pytest.LogCaptureFixture
) -> None:
    """Two executors (two worker replicas) on one database: the older run's retry checks the
    stored `last_run_at` and is skipped once the other replica stored a newer run."""
    calls: list[str] = []

    def sink(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        calls.append("older" if not calls else "newer")
        if len(calls) == 1:
            raise EmitIncomplete(EmitResult(failed=1))

    due = world.target()
    other_replica = world.executor(sink=sink)
    newer: list[RunOutcome | None] = []

    async def sleep(seconds: float) -> None:
        world.clock.at += timedelta(minutes=1)
        world.zone(spf=mr.SPF_X)
        newer.append(await run(world, other_replica, due))

    replica = world.executor(sink=sink, sleep=sleep)
    await run(world, replica, due)
    world.zone(spf=mr.SPF_Y)
    with caplog.at_level(logging.WARNING):
        older = await run(world, replica, due)
    assert older is not None and newer and newer[0] is not None and newer[0].events
    assert calls == ["older", "newer"]  # the older run was not offered again
    assert any(getattr(r, "event", "") == "monitor_run.emit_superseded" for r in caplog.records)


async def test_a_failing_latest_run_check_is_a_failed_attempt_not_a_lost_alert(
    world: mr.World, caplog: pytest.LogCaptureFixture
) -> None:
    """The stored-run check before a retry fails once (database error): that attempt counts as
    failed, the next one retries, the alert is recorded and nothing escapes the run."""
    sleeps = Sleeps()
    _, executor = wiring(world, sleep=sleeps)
    due = world.target()
    await run(world, executor, due)
    _, flaky = wiring(world, failures=1, sleep=sleeps)
    real = flaky._still_latest
    checks: list[str] = []

    def still_latest(*args: Any) -> bool:
        checks.append("check")
        if len(checks) == 1:
            raise OperationalError("SELECT 1", {}, RuntimeError("db down: secret detail"))
        return real(*args)

    flaky._still_latest = still_latest  # type: ignore[method-assign]
    world.zone(spf=mr.SPF_Y)
    with caplog.at_level(logging.WARNING):
        out = await run(world, flaky, due)
    assert out is not None and out.status == "ok"
    assert alerts(world) == [("record_changed", False)]
    assert checks == ["check", "check"] and sleeps.calls == [2.0, 4.0]
    retries = [r for r in caplog.records if getattr(r, "event", "") == "monitor_run.emit_retry"]
    assert len(retries) == 2 and "OperationalError" in retries[1].getMessage()
    assert "secret detail" not in caplog.text


async def test_a_retry_goes_ahead_while_no_newer_run_is_stored(world: mr.World) -> None:
    calls: list[int] = []

    def sink(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        calls.append(len(events))
        if len(calls) == 1:
            raise EmitIncomplete(EmitResult(failed=1))

    sleeps = Sleeps()
    due = world.target()
    executor = world.executor(sink=sink, sleep=sleeps)
    await run(world, executor, due)
    world.zone(spf=mr.SPF_Y)
    await run(world, executor, due)
    assert calls == [1, 1] and sleeps.calls == [2.0]


async def test_any_other_sink_error_is_not_retried(world: mr.World) -> None:
    calls: list[int] = []

    def sink(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        calls.append(len(events))
        raise RuntimeError("bug")

    sleeps = Sleeps()
    due = world.target()
    executor = world.executor(sink=sink, sleep=sleeps)
    await run(world, executor, due)
    world.zone(spf=mr.SPF_Y)
    assert await run(world, executor, due) is not None
    assert calls == [1] and sleeps.calls == []


@pytest.mark.parametrize(
    "kw",
    [
        {"emit_attempts": 0},
        {"emit_attempts": 11},
        {"emit_attempts": True},
        {"emit_attempts": "3"},
        {"emit_backoff": timedelta(seconds=-1)},
        {"emit_backoff": 2},
    ],
    ids=repr,
)
def test_executor_rejects_bad_emit_settings(world: mr.World, kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        world.executor(**kw)


def test_releaser_rejects_bad_settings(world: mr.World) -> None:
    service = AlertService(world.factory, world.clock)
    for kw in ({"interval": timedelta(0)}, {"interval": 30}, {"tenants": 0}, {"tenants": 1001}):
        with pytest.raises(ValueError):
            AlertReleaser(world.factory, service, world.clock, **kw)  # type: ignore[arg-type]


def flap(w: mr.World, service: AlertService, tenant: str) -> None:
    """listed -> cleared -> listed, 10 minutes apart: the last one is a suppressed head."""
    domain, ctx = w.domains[tenant], w.ctx(tenant)
    listed = ChangeEvent("new_listing", domain, "zen", None, "listed", "dnsbl")
    cleared = ChangeEvent("listing_cleared", domain, "zen", "listed", "not_listed", "dnsbl")
    for change in (listed, cleared, listed):
        service.emit(ctx, [change])
        w.clock.at += timedelta(minutes=10)
    assert alerts(w, tenant)[-1] == ("new_listing", True)


# --- release of suppressed alerts and delivery ---------------------------------------------------


async def test_flapping_listing_is_delivered_once_after_the_window(world: mr.World) -> None:
    """listed -> cleared -> listed inside min_realert: the second "listed" is suppressed, then
    released and delivered exactly once after the window."""
    cipher = SecretCipher(Fernet.generate_key().decode())
    service, executor = wiring(world)
    releaser = AlertReleaser(world.factory, service, world.clock)
    channel = FakeChannel()
    dispatcher = AlertDispatcher(
        world.factory, service, ChannelRegistry({"webhook": channel}), cipher, world.clock
    )
    route_all(world, cipher)
    due = world.target(checks=("dnsbl",))
    t0 = world.clock.now()

    async def step(minutes: int, outcome: str) -> None:
        world.clock.at = t0 + timedelta(minutes=minutes)
        zen(world, outcome)
        await run(world, executor, due)
        await asyncio.to_thread(releaser.release_pending)
        await dispatcher.run_once()

    def sent() -> list[str]:
        return [call[0].code for call in channel.calls]

    await step(0, "not_listed")
    await step(10, "listed")
    await step(20, "not_listed")
    await step(30, "listed")
    assert alerts(world) == [
        ("new_listing", False),
        ("listing_cleared", False),
        ("new_listing", True),
    ]
    assert sent() == ["ALERT_NEW_LISTING", "ALERT_LISTING_CLEARED"]
    # Still inside the window (opened by the first delivered "listed" at minute 10).
    world.clock.at = t0 + timedelta(minutes=69)
    assert releaser.due_tenants(world.clock.now()) == []
    assert releaser.release_pending() == 0
    world.clock.at = t0 + timedelta(minutes=70)
    assert releaser.release_pending() == 1
    await dispatcher.run_once()
    assert sent() == ["ALERT_NEW_LISTING", "ALERT_LISTING_CLEARED", "ALERT_NEW_LISTING"]
    # Later passes: nothing more.
    world.clock.at = t0 + timedelta(minutes=95)
    assert releaser.due_tenants(world.clock.now()) == []
    assert releaser.release_pending() == 0
    await dispatcher.run_once()
    assert len(channel.calls) == 3


@pytest.mark.parametrize("tenant", ["a", "b"])
def test_a_new_releaser_finds_heads_from_before_a_restart(world: mr.World, tenant: str) -> None:
    """No in-memory state: a fresh releaser (a restarted process) releases a suppressed head
    exactly once, also for a tenant without any monitor target, and only its tenant's."""
    flap(world, AlertService(world.factory, world.clock, min_realert=HOUR), tenant)
    with world.factory() as db:
        assert repo_for(world.ctx(tenant), db).monitor_targets.list() == []
    other = "b" if tenant == "a" else "a"
    before_other = alerts(world, other)
    restarted = AlertReleaser(
        world.factory, AlertService(world.factory, world.clock, min_realert=HOUR), world.clock
    )
    assert restarted.release_pending() == 0  # still inside the window
    world.clock.at += HOUR
    assert restarted.due_tenants(world.clock.now()) == [world.tenants[tenant]]
    assert restarted.release_pending() == 1
    assert alerts(world, tenant)[-1] == ("new_listing", False)
    again = AlertReleaser(world.factory, AlertService(world.factory, world.clock), world.clock)
    assert again.release_pending() == 0 and restarted.release_pending() == 0
    assert alerts(world, other) == before_other


def test_a_release_failure_is_retried_at_the_next_pass(
    world: mr.World, caplog: pytest.LogCaptureFixture
) -> None:
    flap(world, AlertService(world.factory, world.clock, min_realert=HOUR), "a")
    world.clock.at += HOUR
    flaky = AlertService(Flaky(world.factory, 1), world.clock, min_realert=HOUR)  # type: ignore[arg-type]
    releaser = AlertReleaser(world.factory, flaky, world.clock)
    with caplog.at_level(logging.ERROR):
        assert releaser.release_pending() == 0
    assert any(getattr(r, "event", "") == "monitor_run.release_failed" for r in caplog.records)
    assert "secret detail" not in caplog.text
    assert releaser.release_pending() == 1 and releaser.release_pending() == 0


async def test_release_loop_runs_off_the_loop_until_cancelled(world: mr.World) -> None:
    passes: list[int] = []
    sleeps = Sleeps()

    class Counting(AlertReleaser):
        def release_pending(self) -> int:
            passes.append(threading.get_ident())
            if len(passes) == 1:
                raise RuntimeError("one bad pass")
            return 0

    async def sleep(seconds: float) -> None:
        await sleeps(seconds)
        await asyncio.sleep(0)

    service = AlertService(world.factory, world.clock)
    releaser = Counting(world.factory, service, world.clock, sleep=sleep)
    task = asyncio.create_task(releaser.run())
    while len(passes) < 3:
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert threading.get_ident() not in passes and set(sleeps.calls) == {30.0}


# --- startup by ROLE -----------------------------------------------------------------------------


def _app(monkeypatch: pytest.MonkeyPatch, url: str, **env: str) -> FastAPI:
    app = FastAPI()
    app.state.settings = _settings(monkeypatch, DATABASE_URL=url, **env)
    return app


@pytest.mark.parametrize(("role", "starts"), [("web", False), ("worker", True), ("all", True)])
async def test_role_decides_whether_the_alert_loops_start(
    monkeypatch: pytest.MonkeyPatch, migrated_db_url: str, role: str, starts: bool
) -> None:
    app = _app(monkeypatch, migrated_db_url, ROLE=role)
    sched = start_scheduler(app)
    checkouts: list[int] = []
    engine = getattr(app.state, "db_engine", None)
    if engine is not None:
        event.listen(engine, "checkout", lambda *_a: checkouts.append(1))
    tasks = start_alert_tasks(app)
    try:
        names = sorted(t.get_name() for t in tasks)
        assert names == (["alerts.dispatch", "alerts.release"] if starts else [])
        await asyncio.sleep(0.2)
        assert all(not t.done() for t in tasks)
        assert checkouts == []  # first passes wait one interval: no DB use at startup
    finally:
        await stop_alert_tasks(tasks)
        if sched is not None:
            await sched.shutdown()
        engine = getattr(app.state, "db_engine", None)
        if engine is not None:
            engine.dispose()
    assert all(t.cancelled() for t in tasks)


async def test_without_a_usable_encryption_key_delivery_does_not_start(
    monkeypatch: pytest.MonkeyPatch, migrated_db_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    bad_key = "not-a-fernet-key-but-long-enough-0123456789"
    app = _app(monkeypatch, migrated_db_url, ROLE="worker", ENCRYPTION_KEY=bad_key)
    sched = start_scheduler(app)
    with caplog.at_level(logging.ERROR):
        tasks = start_alert_tasks(app)
    try:
        assert [t.get_name() for t in tasks] == ["alerts.release"]
        assert any(
            getattr(r, "event", "") == "alerts.dispatcher_not_started" for r in caplog.records
        )
        assert bad_key not in caplog.text
    finally:
        await stop_alert_tasks(tasks)
        if sched is not None:
            await sched.shutdown()
        engine = getattr(app.state, "db_engine", None)
        if engine is not None:
            engine.dispose()


@pytest.mark.parametrize(("role", "count"), [("web", 0), ("worker", 2)])
def test_lifespan_starts_and_cancels_the_alert_loops(
    monkeypatch: pytest.MonkeyPatch, migrated_db_url: str, role: str, count: int
) -> None:
    cfg = _settings(monkeypatch, DATABASE_URL=migrated_db_url, ROLE=role)
    app = create_app(cfg)
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        tasks = list(app.state.alert_tasks)
        assert len(tasks) == count
        assert [t.get_name() for t in tasks].count("alerts.dispatch") == (1 if count else 0)
    assert all(t.done() for t in tasks)
    engine = getattr(app.state, "db_engine", None)
    if engine is not None:
        engine.dispose()
