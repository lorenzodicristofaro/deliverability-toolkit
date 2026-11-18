"""M7-14 alert service: idempotent creation (replay, concurrency, restart), true-change rules,
flapping suppression, rules routing, delivery with retry/backoff/abandon on a fake clock.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). The race
that forces both emitters past the stream read before either inserts needs PostgreSQL (SQLite
serializes writers). No network: the sender is a fake.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import typing
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Alert, AlertDelivery, Tenant
from app.models.alert import KINDS
from app.repositories import repo_for
from app.repositories.alerts import INVALID_ERROR, AlertRecord, AlertRepository
from app.services import alerts as alerts_module
from app.services.alerts import (
    CODES,
    FAMILIES,
    I18N_PREFIX,
    AlertMessage,
    AlertService,
    DeliveryError,
    EmitIncomplete,
    is_valid_event,
    payload,
    state_hash,
    stream_key,
)
from app.services.change_detect import ChangeEvent, EventKind
from app.services.monitor_run import EventSink

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
LOCALES = Path(__file__).resolve().parents[2] / "locales"


class FakeClock:
    def __init__(self, now: datetime = T0) -> None:
        self.at = now

    def now(self) -> datetime:
        return self.at

    def advance(self, delta: timedelta) -> None:
        self.at += delta


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    engine: Engine
    factory: sessionmaker[Session]
    ctx: TenantContext
    ctx_b: TenantContext
    domain: int
    domain_b: int
    clock: FakeClock = field(default_factory=FakeClock)

    def service(self, **kw: Any) -> AlertService:
        kw.setdefault("min_realert", timedelta(0))
        return AlertService(self.factory, self.clock, **kw)

    def alerts(self, ctx: TenantContext | None = None) -> list[AlertRecord]:
        with self.factory() as db:
            repo = repo_for(ctx or self.ctx, db).alerts
            domain = self.domain if (ctx or self.ctx) == self.ctx else self.domain_b
            return list(reversed(repo.list_for_domain(domain)))

    def deliveries(self) -> list[Any]:
        with self.factory() as db:
            repos = repo_for(self.ctx, db)
            out = []
            for alert in self.alerts():
                out.extend(repos.alert_deliveries.for_alert(alert.id))
            return out

    def count(self, model: Any) -> int:
        with self.factory() as db:
            return int(db.scalar(select(func.count()).select_from(model)) or 0)

    def route(self, kind: str, *channels: int) -> None:
        with self.factory.begin() as db:
            for channel in channels:
                repo_for(self.ctx, db).alert_rules.add(kind, channel)

    def run(self, check_id: str, status: str, at: datetime) -> None:
        with self.factory.begin() as db:
            rec = repo_for(self.ctx, db).check_runs.record(
                self.domain,
                check_id=check_id,
                status=status,
                started_at=at,
                duration_ms=1,
                source="scheduled",
                findings=[],
            )
            assert rec is not None


@pytest.fixture
def world(engine: Engine) -> World:
    factory = create_session_factory(engine)
    with factory.begin() as db:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        db.add_all([ta, tb])
        db.flush()
        ctx, ctx_b = TenantContext(ta.id, None), TenantContext(tb.id, None)
        domain = repo_for(ctx, db).domains.create("a.example").id
        domain_b = repo_for(ctx_b, db).domains.create("b.example").id
    return World(engine, factory, ctx, ctx_b, domain, domain_b)


def ev(
    world: World,
    kind: EventKind = "new_listing",
    subject: str = "zen.example",
    before: str | None = "not_listed",
    after: str = "listed",
    check_id: str | None = "dnsbl",
    domain: int | None = None,
) -> ChangeEvent:
    return ChangeEvent(kind, domain or world.domain, subject, before, after, check_id)


def listing(world: World, listed: bool = True) -> ChangeEvent:
    if listed:
        return ev(world)
    return ev(world, "listing_cleared", before="listed", after="not_listed")


def regression(world: World, before: str = "ok", after: str = "warn") -> ChangeEvent:
    return ev(world, "policy_regression", "spf", before, after, "spf")


# --- pure parts --------------------------------------------------------------------------------


def test_kinds_match_change_detect() -> None:
    assert set(KINDS) == set(typing.get_args(EventKind))
    assert set(FAMILIES) == set(KINDS) == set(CODES)


@pytest.mark.parametrize("lang", ["en", "it"])
def test_every_alert_code_has_title_and_detail(lang: str) -> None:
    catalogue = json.loads((LOCALES / f"{lang}.json").read_text(encoding="utf-8"))
    for code in CODES.values():
        for part in ("title", "detail"):
            assert f"{I18N_PREFIX}.{code}.{part}" in catalogue


def test_stream_and_state_hash() -> None:
    new = ChangeEvent("new_listing", 1, "zen", "not_listed", "listed", "dnsbl")
    cleared = ChangeEvent("listing_cleared", 1, "zen", "listed", "not_listed", "dnsbl")
    other_list = ChangeEvent("new_listing", 1, "sbl", "not_listed", "listed", "dnsbl")
    other_domain = ChangeEvent("new_listing", 2, "zen", "not_listed", "listed", "dnsbl")
    assert stream_key(new) == stream_key(cleared)  # one list, one stream
    assert len({stream_key(new), stream_key(other_list), stream_key(other_domain)}) == 3
    regression = ChangeEvent("policy_regression", 1, "spf", "ok", "warn", "spf")
    error = ChangeEvent("check_error_started", 1, "spf", "ok", "error", "spf")
    assert stream_key(regression) != stream_key(error)
    assert state_hash(new, None) == state_hash(new, 0) != state_hash(new, 1)
    assert state_hash(new, 1) != state_hash(cleared, 1)


def test_payload_is_bounded_codes_and_short_values() -> None:
    long = ChangeEvent("record_changed", 1, "x" * 2000, "a" * 500, "b" * 500)
    code, params = payload(long)
    assert code == "ALERT_RECORD_CHANGED"
    assert len(params["subject"]) == 512
    assert len(params["before"]) == len(params["after"]) == 128
    assert "check_id" not in params
    _, removed = payload(ChangeEvent("record_changed", 1, "@ TXT", None, "absent"))
    assert removed["before"] == ""


MALFORMED_EVENTS = [
    ("not an event", "new_listing"),
    ("dict", {"kind": "new_listing"}),
    ("none", None),
    ("unknown kind", ChangeEvent("bogus", 1, "s", None, "x")),  # type: ignore[arg-type]
    ("domain zero", ChangeEvent("new_listing", 0, "s", None, "x")),
    ("domain negative", ChangeEvent("new_listing", -3, "s", None, "x")),
    ("domain str", ChangeEvent("new_listing", "1", "s", None, "x")),  # type: ignore[arg-type]
    ("domain bool", ChangeEvent("new_listing", True, "s", None, "x")),
    ("empty subject", ChangeEvent("new_listing", 1, "", None, "x")),
    ("subject int", ChangeEvent("new_listing", 1, 5, None, "x")),  # type: ignore[arg-type]
    ("after none", ChangeEvent("new_listing", 1, "s", None, None)),  # type: ignore[arg-type]
    ("before int", ChangeEvent("new_listing", 1, "s", 1, "x")),  # type: ignore[arg-type]
    ("check id int", ChangeEvent("new_listing", 1, "s", None, "x", 3)),  # type: ignore[arg-type]
]


@pytest.mark.parametrize(("case", "event"), MALFORMED_EVENTS, ids=[c for c, _ in MALFORMED_EVENTS])
def test_malformed_events_are_rejected_not_stored(world: World, case: str, event: Any) -> None:
    assert not is_valid_event(event)
    result = world.service().emit(world.ctx, [event, listing(world)])
    assert (result.rejected, result.created) == (1, 1)
    assert world.count(Alert) == 1


def test_service_is_an_event_sink(world: World) -> None:
    sink: EventSink = world.service()
    sink(world.ctx, [listing(world)])
    assert world.count(Alert) == 1


def test_emit_requires_a_tenant_context(world: World) -> None:
    with pytest.raises(TypeError):
        world.service().emit(world.ctx.tenant_id, [])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kw",
    [
        {"min_realert": timedelta(-1)},
        {"min_realert": 5},
        {"max_attempts": 0},
        {"max_attempts": 1.5},
        {"backoff_base": timedelta(0)},
        {"backoff_cap": None},
        {"lease": timedelta(-1)},
    ],
    ids=repr,
)
def test_bad_settings_are_refused(world: World, kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        AlertService(world.factory, world.clock, **kw)


def test_backoff_doubles_up_to_the_cap(world: World) -> None:
    svc = world.service(backoff_base=timedelta(minutes=1), backoff_cap=timedelta(minutes=10))
    assert [svc.backoff(n) for n in (1, 2, 3, 4, 5, 50)] == [
        timedelta(minutes=m) for m in (1, 2, 4, 8, 10, 10)
    ]


# --- idempotent creation -----------------------------------------------------------------------


def test_same_events_twice_make_one_alert(world: World) -> None:
    world.route("new_listing", 1)
    svc = world.service()
    events = [listing(world), ev(world, subject="sbl.example")]
    first = svc.emit(world.ctx, events)
    second = svc.emit(world.ctx, events)
    assert (first.created, first.deliveries) == (2, 2)
    assert (second.created, second.duplicates, second.deliveries) == (0, 2, 0)
    assert world.count(Alert) == 2 and world.count(AlertDelivery) == 2


def test_duplicate_events_in_one_batch_make_one_alert(world: World) -> None:
    result = world.service().emit(world.ctx, [listing(world), listing(world)])
    assert (result.created, result.duplicates) == (1, 1)


def test_reenabled_list_duplicate_new_listing_is_deduped(world: World) -> None:
    """M7-10b: a list disabled and re-enabled while still listed yields `new_listing` again with
    the same fingerprint, even much later: no new alert."""
    svc = world.service()
    svc.emit(world.ctx, [listing(world)])
    world.clock.advance(timedelta(days=30))
    assert svc.emit(world.ctx, [listing(world)]).duplicates == 1
    assert world.count(Alert) == 1


def test_a_b_a_b_alerts_every_transition(world: World) -> None:
    svc = world.service()
    for listed in (True, False, True, False):
        world.clock.advance(timedelta(hours=1))
        assert svc.emit(world.ctx, [listing(world, listed)]).created == 1
    kinds = [a.kind for a in world.alerts()]
    assert kinds == ["new_listing", "listing_cleared", "new_listing", "listing_cleared"]
    # Each is chained on the previous alert of the stream.
    assert len({a.state_hash for a in world.alerts()}) == 4


def test_record_changes_follow_the_entry_state(world: World) -> None:
    svc = world.service()
    a_to_b = ev(world, "record_changed", "@ TXT", "hash-a", "hash-b", None)
    b_to_a = ev(world, "record_changed", "@ TXT", "hash-b", "hash-a", None)
    assert svc.emit(world.ctx, [a_to_b]).created == 1
    assert svc.emit(world.ctx, [a_to_b]).duplicates == 1  # replay
    assert svc.emit(world.ctx, [b_to_a]).created == 1
    assert svc.emit(world.ctx, [a_to_b]).created == 1  # truly back to B
    other_entry = ev(world, "record_changed", "_dmarc TXT", "hash-a", "hash-b", None)
    assert svc.emit(world.ctx, [other_entry]).created == 1


def test_check_error_started_and_cleared_alternate(world: World) -> None:
    svc = world.service()
    started = ev(world, "check_error_started", "spf", "ok", "error", "spf")
    cleared = ev(world, "check_error_cleared", "spf", "error", "ok", "spf")
    assert [svc.emit(world.ctx, [e]).created for e in (started, started, cleared, started)] == [
        1,
        0,
        1,
        1,
    ]


def test_policy_regression_realerts_only_after_a_real_improvement(world: World) -> None:
    """ok -> warn alerts; the same run replayed does not; warn runs do not count; after an `ok`
    run (no event: improvements are silent) the next ok -> warn alerts again."""
    svc = world.service()
    world.run("spf", "warn", T0)
    assert svc.emit(world.ctx, [regression(world)]).created == 1
    assert svc.emit(world.ctx, [regression(world)]).duplicates == 1
    world.clock.advance(timedelta(hours=1))
    world.run("spf", "warn", world.clock.now())
    world.run("spf", "error", world.clock.now() + timedelta(minutes=1))
    world.run("dkim", "ok", world.clock.now() + timedelta(minutes=2))  # another check
    assert svc.emit(world.ctx, [regression(world)]).duplicates == 1
    world.clock.advance(timedelta(hours=1))
    world.run("spf", "ok", world.clock.now())
    world.clock.advance(timedelta(hours=1))
    world.run("spf", "warn", world.clock.now())
    assert svc.emit(world.ctx, [regression(world)]).created == 1
    assert svc.emit(world.ctx, [regression(world)]).duplicates == 1  # replay of that run
    # warn -> fail is a different state: alerts at once.
    assert svc.emit(world.ctx, [regression(world, "warn", "fail")]).created == 1
    assert world.count(Alert) == 3


def test_policy_regression_to_fail_counts_a_warn_run_as_improvement(world: World) -> None:
    svc = world.service()
    assert svc.emit(world.ctx, [regression(world, "ok", "fail")]).created == 1
    world.clock.advance(timedelta(hours=1))
    world.run("spf", "warn", world.clock.now())
    assert svc.emit(world.ctx, [regression(world, "warn", "fail")]).created == 1


def test_tenants_have_separate_alerts(world: World) -> None:
    svc = world.service()
    svc.emit(world.ctx, [listing(world)])
    other = ev(world, domain=world.domain_b)
    # Tenant A cannot record an alert on tenant B's domain: it is not stored (no foreign row).
    assert svc.emit(world.ctx, [other]).duplicates == 1
    assert svc.emit(world.ctx_b, [other]).created == 1
    assert len(world.alerts()) == 1 and len(world.alerts(world.ctx_b)) == 1


# --- flapping ----------------------------------------------------------------------------------


def test_flapping_inside_the_interval_is_recorded_as_suppressed(world: World) -> None:
    world.route("new_listing", 1)
    world.route("listing_cleared", 1)
    svc = world.service(min_realert=timedelta(hours=1))
    results = []
    for listed in (True, False, True, False, True):
        world.clock.advance(timedelta(minutes=5))
        results.append(svc.emit(world.ctx, [listing(world, listed)]))
    assert [(r.created, r.suppressed) for r in results] == [
        (1, 0),
        (1, 0),
        (0, 1),
        (0, 1),
        (0, 1),
    ]
    alerts = world.alerts()
    assert [a.suppressed for a in alerts] == [False, False, True, True, True]
    assert world.count(AlertDelivery) == 2  # suppressed alerts are never delivered
    # The stream state stays exact: a replay of the last (suppressed) event is a duplicate.
    assert svc.emit(world.ctx, [listing(world, True)]).duplicates == 1
    # After the interval, the next true change is delivered again.
    world.clock.advance(timedelta(hours=1))
    assert svc.emit(world.ctx, [listing(world, False)]).created == 1


# --- rules -------------------------------------------------------------------------------------


def test_without_rules_alerts_are_recorded_but_not_delivered(world: World) -> None:
    result = world.service().emit(world.ctx, [listing(world)])
    assert (result.created, result.deliveries) == (1, 0)
    assert world.count(AlertDelivery) == 0


def test_rules_route_kinds_to_channels(world: World) -> None:
    world.route("new_listing", 3, 1)
    world.route("record_changed", 2)
    world.service().emit(
        world.ctx,
        [listing(world), ev(world, "record_changed", "@ MX", "a", "b", None)],
    )
    by_alert = {a.kind: a.id for a in world.alerts()}
    pairs = sorted((d.alert_id, d.channel_id) for d in world.deliveries())
    assert pairs == sorted(
        [
            (by_alert["new_listing"], 1),
            (by_alert["new_listing"], 3),
            (by_alert["record_changed"], 2),
        ]
    )
    assert all(d.status == "pending" and d.next_attempt_at == T0 for d in world.deliveries())


# --- concurrency and restart -------------------------------------------------------------------


def test_two_concurrent_emitters_make_one_alert(world: World, engine: Engine) -> None:
    world.route("new_listing", 1)
    services = [world.service(), world.service()]
    barrier = threading.Barrier(2)

    def emit(i: int) -> Any:
        barrier.wait(timeout=10)
        return services[i].emit(world.ctx, [listing(world)])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(emit, [0, 1]))
    assert sum(r.created for r in results) == 1
    if engine.dialect.name == "postgresql":
        assert sorted(r.duplicates for r in results) == [0, 1]
    assert world.count(Alert) == 1 and world.count(AlertDelivery) == 1


def test_emitters_racing_past_the_stream_read_make_one_alert(
    world: World, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both emitters read the stream (no alert yet) before either inserts, so both compute the
    same state_hash: the UNIQUE constraint lets exactly one insert land; the other waits for its
    commit and gets the conflict. PostgreSQL only: SQLite's single writer lock cannot interleave
    two write transactions like this."""
    if engine.dialect.name != "postgresql":
        pytest.skip("needs concurrent writers (PostgreSQL)")
    world.route("new_listing", 1)
    barrier = threading.Barrier(2)
    original = AlertRepository.latest_in_stream

    def latest_then_wait(self: AlertRepository, *a: Any) -> AlertRecord | None:
        found = original(self, *a)
        barrier.wait(timeout=10)
        return found

    monkeypatch.setattr(AlertRepository, "latest_in_stream", latest_then_wait)
    services = [world.service(), world.service()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda i: services[i].emit(world.ctx, [listing(world)]), [0, 1]))
    assert sorted((r.created, r.duplicates, r.failed) for r in results) == [(0, 1, 0), (1, 0, 0)]
    assert world.count(Alert) == 1 and world.count(AlertDelivery) == 1


class FakeSender:
    def __init__(self, failures: Sequence[BaseException | None] = ()) -> None:
        self.calls: list[tuple[int, int, AlertMessage]] = []
        self.failures = list(failures)

    async def __call__(self, ctx: TenantContext, channel_id: int, message: AlertMessage) -> None:
        self.calls.append((ctx.tenant_id, channel_id, message))
        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure


async def test_restart_replay_creates_nothing_and_resumes_pending(world: World) -> None:
    world.route("new_listing", 1, 2)
    events = [listing(world)]
    world.service().emit(world.ctx, events)
    # Channel 1 is delivered, then the process "dies" before channel 2 is attempted.
    sender = FakeSender()
    with world.factory.begin() as db:
        d1 = repo_for(world.ctx, db).alert_deliveries.for_alert(world.alerts()[0].id)[0]
        assert repo_for(world.ctx, db).alert_deliveries.claim(
            d1.id, 0, T0, T0 + timedelta(minutes=5)
        )
        assert repo_for(world.ctx, db).alert_deliveries.mark_sent(d1.id, 1, T0)
    # Restart: a new service replays the same run's events.
    restarted = world.service()
    result = restarted.emit(world.ctx, events)
    assert (result.created, result.duplicates, result.deliveries) == (0, 1, 0)
    assert world.count(Alert) == 1 and world.count(AlertDelivery) == 2
    report = await restarted.deliver_due(world.ctx, sender)
    assert (report.sent, report.skipped) == (1, 0)
    assert [c[1] for c in sender.calls] == [2]  # the pending one resumed, the sent one not resent
    assert {d.status for d in world.deliveries()} == {"sent"}
    assert (await restarted.deliver_due(world.ctx, sender)).sent == 0
    assert len(sender.calls) == 1


async def test_crash_during_send_resumes_after_the_lease(world: World) -> None:
    world.route("new_listing", 1)
    svc = world.service(lease=timedelta(minutes=5))
    svc.emit(world.ctx, [listing(world)])
    with world.factory.begin() as db:
        d = repo_for(world.ctx, db).alert_deliveries.due(T0)[0]
        assert repo_for(world.ctx, db).alert_deliveries.claim(
            d.id, 0, T0, T0 + timedelta(minutes=5)
        )
    # The claimer crashed before recording any outcome: nothing is due during the lease.
    sender = FakeSender()
    assert (await svc.deliver_due(world.ctx, sender)).sent == 0
    world.clock.advance(timedelta(minutes=5))
    assert (await world.service().deliver_due(world.ctx, sender)).sent == 1
    (delivery,) = world.deliveries()
    assert (delivery.status, delivery.attempts) == ("sent", 2)


# --- delivery ----------------------------------------------------------------------------------


async def test_delivery_message_carries_codes_and_params(world: World) -> None:
    world.route("new_listing", 4)
    svc = world.service()
    svc.emit(world.ctx, [listing(world)])
    sender = FakeSender()
    assert (await svc.deliver_due(world.ctx, sender)).sent == 1
    ((tenant, channel, message),) = sender.calls
    assert (tenant, channel) == (world.ctx.tenant_id, 4)
    assert message.code == "ALERT_NEW_LISTING" and message.kind == "new_listing"
    assert message.params["subject"] == "zen.example"
    (delivery,) = world.deliveries()
    assert (delivery.status, delivery.sent_at, delivery.attempts) == ("sent", T0, 1)


async def test_retry_with_backoff_then_abandon(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.route("new_listing", 1)
    svc = world.service(
        max_attempts=3, backoff_base=timedelta(minutes=1), backoff_cap=timedelta(hours=1)
    )
    svc.emit(world.ctx, [listing(world)])
    sender = FakeSender([DeliveryError("timeout")] * 3)
    caplog.set_level(logging.WARNING, logger="app.alerts")
    assert (await svc.deliver_due(world.ctx, sender)).failed == 1
    (d,) = world.deliveries()
    assert (d.status, d.attempts, d.last_error) == ("failed", 1, "timeout")
    assert d.next_attempt_at == T0 + timedelta(minutes=1)
    assert (await svc.deliver_due(world.ctx, sender)).failed == 0  # not due yet
    world.clock.advance(timedelta(minutes=1))
    assert (await svc.deliver_due(world.ctx, sender)).failed == 1
    (d,) = world.deliveries()
    assert d.next_attempt_at == world.clock.now() + timedelta(minutes=2)
    world.clock.advance(timedelta(minutes=2))
    assert (await svc.deliver_due(world.ctx, sender)).abandoned == 1
    (d,) = world.deliveries()
    assert (d.status, d.attempts, d.next_attempt_at) == ("abandoned", 3, None)
    world.clock.advance(timedelta(days=1))
    assert (await svc.deliver_due(world.ctx, sender)) == alerts_module.DeliveryReport()
    assert len(sender.calls) == 3


async def test_failures_store_and_log_no_secret_or_body(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.route("new_listing", 1, 2)
    svc = world.service()
    svc.emit(world.ctx, [listing(world)])
    secret = "Bearer sk-SECRET-123 <html>body</html>"
    sender = FakeSender([DeliveryError(secret), RuntimeError(secret)])
    caplog.set_level(logging.DEBUG)
    report = await svc.deliver_due(world.ctx, sender)
    assert report.failed == 2
    assert sorted(d.last_error for d in world.deliveries()) == sorted(
        [INVALID_ERROR, alerts_module.INTERNAL_ERROR]
    )
    assert "SECRET" not in caplog.text and "body" not in caplog.text
    assert "RuntimeError" in caplog.text


async def test_a_sent_delivery_is_never_resent_by_a_stale_worker(world: World) -> None:
    world.route("new_listing", 1)
    svc = world.service()
    svc.emit(world.ctx, [listing(world)])
    sender = FakeSender()
    assert (await svc.deliver_due(world.ctx, sender)).sent == 1
    world.clock.advance(timedelta(days=1))
    assert (await world.service().deliver_due(world.ctx, sender)).sent == 0
    assert len(sender.calls) == 1


async def test_deliver_due_is_per_tenant(world: World) -> None:
    world.route("new_listing", 1)
    world.service().emit(world.ctx, [listing(world)])
    sender = FakeSender()
    assert (await world.service().deliver_due(world.ctx_b, sender)).sent == 0
    assert sender.calls == []
    with pytest.raises(TypeError):
        await world.service().deliver_due(world.ctx.tenant_id, sender)  # type: ignore[arg-type]


# --- release of suppressed state (flapping ends notified) --------------------------------------


def _flap(world: World, svc: AlertService, states: Sequence[bool]) -> None:
    for listed in states:
        world.clock.advance(timedelta(minutes=10))
        svc.emit(world.ctx, [listing(world, listed)])


def test_flapping_ends_with_the_final_state_delivered_once(world: World) -> None:
    """listed (delivered at T0+10m), cleared (delivered), then listed -> cleared -> listed inside
    the window: after the window "listed" is delivered once, and never again."""
    world.route("new_listing", 1)
    world.route("listing_cleared", 1)
    svc = world.service(min_realert=timedelta(hours=1))
    _flap(world, svc, [True, False, True, False, True])
    assert [a.suppressed for a in world.alerts()] == [False, False, True, True, True]
    assert world.count(AlertDelivery) == 2
    assert svc.release_suppressed(world.ctx) == 0  # T0+50m: the window of "listed" is open
    world.clock.at = T0 + timedelta(minutes=70)
    assert svc.release_suppressed(world.ctx) == 1
    assert svc.release_suppressed(world.ctx) == 0
    assert world.service(min_realert=timedelta(hours=1)).release_suppressed(world.ctx) == 0
    latest = world.alerts()[-1]
    assert (latest.kind, latest.suppressed) == ("new_listing", False)
    deliveries = world.deliveries()
    assert len(deliveries) == 3 and deliveries[-1].alert_id == latest.id
    # The released alert is the stream's state: the same event replayed is a duplicate.
    assert svc.emit(world.ctx, [listing(world, True)]).duplicates == 1
    assert svc.release_suppressed(world.ctx) == 0


def test_nothing_is_released_when_the_final_state_was_delivered(world: World) -> None:
    world.route("new_listing", 1)
    world.route("listing_cleared", 1)
    svc = world.service(min_realert=timedelta(hours=1))
    _flap(world, svc, [True, False, True, False])  # ends "cleared", delivered at T0+20m
    world.clock.advance(timedelta(hours=3))
    assert svc.release_suppressed(world.ctx) == 0
    assert world.count(Alert) == 4 and world.count(AlertDelivery) == 2


def test_release_is_per_tenant(world: World) -> None:
    svc = world.service(min_realert=timedelta(hours=1))
    _flap(world, svc, [True, False, True])
    world.clock.advance(timedelta(hours=3))
    assert svc.release_suppressed(world.ctx_b) == 0
    assert svc.release_suppressed(world.ctx) == 1
    with pytest.raises(TypeError):
        svc.release_suppressed(world.ctx.tenant_id)  # type: ignore[arg-type]


def test_concurrent_releases_release_once(world: World, engine: Engine) -> None:
    world.route("new_listing", 1)
    svc = world.service(min_realert=timedelta(hours=1))
    _flap(world, svc, [True, False, True])
    world.clock.advance(timedelta(hours=3))
    services = [world.service(min_realert=timedelta(hours=1)) for _ in range(2)]
    barrier = threading.Barrier(2)

    def release(i: int) -> int:
        barrier.wait(timeout=10)
        return services[i].release_suppressed(world.ctx)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(release, [0, 1])) == 1
    assert world.count(Alert) == 4 and world.count(AlertDelivery) == 2


def test_releases_racing_past_the_stream_read_release_once(
    world: World, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("needs concurrent writers (PostgreSQL)")
    world.route("new_listing", 1)
    svc = world.service(min_realert=timedelta(hours=1))
    _flap(world, svc, [True, False, True])
    world.clock.advance(timedelta(hours=3))
    barrier = threading.Barrier(2)
    original = AlertRepository.latest_in_stream

    def latest_then_wait(self: AlertRepository, *a: Any) -> AlertRecord | None:
        found = original(self, *a)
        barrier.wait(timeout=10)
        return found

    monkeypatch.setattr(AlertRepository, "latest_in_stream", latest_then_wait)
    services = [world.service(min_realert=timedelta(hours=1)) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda i: services[i].release_suppressed(world.ctx), [0, 1]))
    assert sorted(results) == [0, 1]
    assert world.count(Alert) == 4 and world.count(AlertDelivery) == 2


# --- sink retry, send timeout, lost mark ------------------------------------------------------


def test_sink_raises_when_an_event_was_not_recorded_and_retry_completes(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    svc = world.service()
    original = AlertRepository.insert_if_absent
    calls = {"n": 0}

    def flaky(self: AlertRepository, *a: Any, **kw: Any) -> AlertRecord | None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("database went away")
        return original(self, *a, **kw)

    monkeypatch.setattr(AlertRepository, "insert_if_absent", flaky)
    events = [listing(world), ev(world, subject="sbl.example")]
    with pytest.raises(EmitIncomplete) as info:
        svc(world.ctx, events)
    assert (info.value.result.created, info.value.result.failed) == (1, 1)
    svc(world.ctx, events)  # the retry: the first is a duplicate, the second is recorded
    assert world.count(Alert) == 2


def test_send_timeout_must_be_shorter_than_the_lease(world: World) -> None:
    with pytest.raises(ValueError):
        world.service(lease=timedelta(minutes=1), send_timeout=timedelta(minutes=1))
    with pytest.raises(ValueError):
        world.service(send_timeout=timedelta(0))
    world.service(lease=timedelta(minutes=1), send_timeout=timedelta(seconds=59))


async def test_a_slow_channel_times_out_and_is_retried(world: World) -> None:
    world.route("new_listing", 1)
    svc = world.service(send_timeout=timedelta(milliseconds=50), backoff_base=timedelta(minutes=1))
    svc.emit(world.ctx, [listing(world)])
    cancelled = asyncio.Event()

    async def slow(ctx: TenantContext, channel_id: int, message: AlertMessage) -> None:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    assert (await svc.deliver_due(world.ctx, slow)).failed == 1
    assert cancelled.is_set()  # the send did not outlive its timeout (nor its lease)
    (d,) = world.deliveries()
    assert (d.status, d.last_error, d.attempts) == ("failed", "timeout", 1)
    assert d.next_attempt_at == T0 + timedelta(minutes=1)
    world.clock.advance(timedelta(minutes=1))
    assert (await svc.deliver_due(world.ctx, FakeSender())).sent == 1


async def test_a_lost_mark_sent_is_not_counted_as_sent(world: World) -> None:
    world.route("new_listing", 1)
    svc = world.service()
    svc.emit(world.ctx, [listing(world)])

    async def send_then_lose_row(ctx: TenantContext, channel_id: int, message: Any) -> None:
        with world.factory.begin() as db:
            db.execute(AlertDelivery.__table__.delete())

    report = await svc.deliver_due(world.ctx, send_then_lose_row)
    assert (report.sent, report.skipped) == (0, 1)
