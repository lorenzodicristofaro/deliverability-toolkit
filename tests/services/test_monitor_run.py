"""M7-10 scheduled run executor: checks, history, snapshots, target status, change events.

Fake checks (scripted per run), a scripted resolver and a fake clock: no network, no sleeping.
Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture).
"""

import asyncio
import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.checks.registry import CheckRegistry
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.models import CheckRun, DnsSnapshot, Tenant
from app.repositories import repo_for
from app.repositories.monitor_targets import DueTarget
from app.services import monitor_run
from app.services.change_detect import ChangeEvent
from app.services.dns_diff import build_entry, normalise_txt
from app.services.monitor_run import MonitorRunExecutor, RunOutcome, log_events, summary_status
from app.services.scheduler import ScheduledRun

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
HB = timedelta(hours=24)
SPF_X = "v=spf1 include:_spf.example.net -all"
SPF_Y = "v=spf1 include:_spf.other.example -all"


class Scripted:
    """Resolver by (name, type): a list of TXT/MX/NS texts or a ResultState; else nxdomain."""

    identity = "scripted"

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], Any] = {}

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        answer = self.answers.get((question.name, question.rdtype), ResultState.nxdomain)
        if isinstance(answer, ResultState):
            return DnsResult(question, answer)
        records = tuple(DnsRecord(question.name, question.rdtype, 300, t) for t in answer)
        return DnsResult(question, ResultState.ok, records)


@dataclass
class FakeCheck:
    """A check whose next outcome is set by the test: findings + evaluated, or an exception."""

    id: str
    findings: list[Finding] = field(default_factory=list)
    evaluated: bool = True
    raises: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    targets: list[str] = field(default_factory=list)

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        self.targets.append(target.domain)
        if self.raises:
            raise RuntimeError("check exploded: secret detail")
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=self.findings,
            evaluated=self.evaluated,
            started_at=ctx.clock(),
            duration_ms=0,
            data=self.data,
        )

    def set(
        self, *findings: Finding, evaluated: bool = True, data: dict[str, Any] | None = None
    ) -> None:
        self.findings, self.evaluated, self.raises = list(findings), evaluated, False
        self.data = data or {}


def listed(list_id: str) -> Finding:
    return finding("DNSBL_LISTED", "high", {"list_id": list_id, "list": list_id.upper()})


def txt_hash(value: str) -> str:
    return build_entry("@", "TXT", "ok", [normalise_txt(value)]).entry_hash


def lists(**outcomes: str) -> list[dict[str, Any]]:
    return [{"id": k, "outcome": v} for k, v in sorted(outcomes.items())]


class FakeClock:
    def __init__(self) -> None:
        self.at = NOW

    def now(self) -> datetime:
        return self.at


@dataclass
class World:
    factory: sessionmaker[Session]
    tenants: dict[str, int]
    domains: dict[str, int]
    names: dict[str, str]
    checks: dict[str, FakeCheck]
    resolver: Scripted
    clock: FakeClock
    sunk: list[tuple[TenantContext, list[ChangeEvent]]] = field(default_factory=list)
    prepared: list[tuple[TenantContext, list[str]]] = field(default_factory=list)

    def prepare(self, ctx: TenantContext, db: Session, ids: Sequence[str]) -> CheckRegistry:
        self.prepared.append((ctx, list(ids)))
        reg = CheckRegistry()
        for check in self.checks.values():
            reg.register(check)
        return reg

    def sink(self, ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        self.sunk.append((ctx, list(events)))

    def executor(self, **kw: Any) -> MonitorRunExecutor:
        kw.setdefault("sink", self.sink)
        return MonitorRunExecutor(
            self.factory,
            self.resolver,
            self.clock,
            heartbeat=HB,
            prepare=self.prepare,
            **kw,
        )

    def ctx(self, tenant: str) -> TenantContext:
        return TenantContext(self.tenants[tenant], None)

    def target(self, tenant: str = "a", checks: Sequence[str] = ("dnsbl", "spf")) -> DueTarget:
        with self.factory.begin() as s:
            rec = repo_for(self.ctx(tenant), s).monitor_targets.create(
                self.domains[tenant],
                check_ids=list(checks),
                interval_seconds=3600,
                next_run_at=NOW + timedelta(hours=1),  # as left by the claim
            )
            assert rec is not None
        return DueTarget(
            rec.id,
            self.tenants[tenant],
            rec.domain_id,
            rec.check_ids,
            rec.interval_seconds,
            NOW,
        )

    def zone(self, tenant: str = "a", spf: Any = SPF_X) -> None:
        name = self.names[tenant]
        self.resolver.answers[(name, "TXT")] = spf if isinstance(spf, ResultState) else [spf]
        self.resolver.answers[(name, "NS")] = ["ns1.example.net."]

    async def run(
        self, due: DueTarget, unknown: tuple[str, ...] = (), **kw: Any
    ) -> RunOutcome | None:
        scheduled = ScheduledRun(due, unknown, self.clock.now(), NOW + timedelta(hours=1))
        outcome = await self.executor(**kw).execute(scheduled)
        self.clock.at += timedelta(hours=1)
        return outcome

    def rows(self, tenant: str = "a") -> list[Any]:
        with self.factory() as s:
            page = repo_for(self.ctx(tenant), s).check_runs.list_for_domain(
                self.domains[tenant], limit=1000
            )
            return list(reversed(page.items))

    def snapshots(self, tenant: str = "a") -> int:
        with self.factory() as s:
            return len(
                repo_for(self.ctx(tenant), s).dns_snapshots.list_for_domain(
                    self.domains[tenant], limit=1000
                )
            )

    def stored_target(self, due: DueTarget, tenant: str = "a") -> Any:
        with self.factory() as s:
            return repo_for(self.ctx(tenant), s).monitor_targets.get(due.id)


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def world(engine: Engine) -> World:
    factory = create_session_factory(engine)
    with factory.begin() as s:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        s.add_all([ta, tb])
        s.flush()
        domains, names = {}, {}
        for key, tenant in (("a", ta), ("b", tb)):
            name = f"{key}.example.com"
            domains[key] = repo_for(TenantContext(tenant.id, None), s).domains.create(name).id
            names[key] = name
        tenants = {"a": ta.id, "b": tb.id}
    checks = {c: FakeCheck(c) for c in ("dmarc", "dnsbl", "spf")}
    checks["dnsbl"].set(data={"lists": lists(zen="not_listed", sbl="not_listed")})
    w = World(factory, tenants, domains, names, checks, Scripted(), FakeClock())
    w.zone("a")
    w.zone("b")
    return w


def kinds(outcome: RunOutcome | None) -> list[tuple[str, str]]:
    assert outcome is not None
    return [(e.kind, e.subject) for e in outcome.events]


# --- baseline, unchanged, change, revert ------------------------------------------------------


async def test_first_run_records_everything_and_is_the_baseline(world: World) -> None:
    due = world.target()
    out = await world.run(due)
    assert out is not None and out.events == () and world.sunk == []
    rows = world.rows()
    assert [(r.check_id, r.status, r.source) for r in rows] == [
        ("dnsbl", "ok", "scheduled"),
        ("spf", "ok", "scheduled"),
    ]
    assert out.recorded == 2 and out.snapshot == "first" and world.snapshots() == 1
    stored = world.stored_target(due)
    assert stored.last_run_at == NOW and stored.last_status == "ok"
    assert stored.next_run_at == NOW + timedelta(hours=1)  # the claim's value, untouched
    assert world.checks["spf"].targets == ["a.example.com"]


async def test_unchanged_run_has_no_events(world: World) -> None:
    due = world.target()
    await world.run(due)
    out = await world.run(due)
    assert kinds(out) == [] and out is not None and out.snapshot == "unchanged"
    assert world.snapshots() == 1 and len(world.rows()) == 4


async def test_change_and_revert(world: World) -> None:
    due = world.target()
    await world.run(due)
    world.zone(spf=SPF_Y)
    world.checks["spf"].set(finding("SPF_TOO_MANY_LOOKUPS", "high", {"count": 11}))
    changed = await world.run(due)
    assert kinds(changed) == [("policy_regression", "spf"), ("record_changed", "@ TXT")]
    world.zone(spf=SPF_X)
    world.checks["spf"].set()
    reverted = await world.run(due)
    assert kinds(reverted) == [("record_changed", "@ TXT")]  # an improvement is no event
    assert changed is not None and reverted is not None
    # the revert's new state is the original record: same `after` as the first state
    assert reverted.events[0].after == changed.events[1].before
    assert [len(evs) for _, evs in world.sunk] == [2, 1]
    stored = world.rows()[-1]
    assert stored.check_id == "spf" and stored.status == "ok"


async def test_findings_are_stored_as_code_and_params_only(world: World) -> None:
    due = world.target()
    world.checks["spf"].set(finding("SPF_TOO_MANY_LOOKUPS", "high", {"count": 11}))
    await world.run(due)
    with world.factory() as s:
        stored = s.scalars(select(CheckRun.findings).where(CheckRun.check_id == "spf")).one()
    assert stored == [{"code": "SPF_TOO_MANY_LOOKUPS", "params": {"count": 11}}]


# --- DNSBL listings ------------------------------------------------------------------------------


async def test_listing_appears_and_disappears(world: World) -> None:
    due = world.target()
    bl = world.checks["dnsbl"]
    await world.run(due)
    bl.set(listed("zen"), data={"lists": lists(zen="listed", sbl="not_listed")})
    appeared = await world.run(due)
    assert kinds(appeared) == [("new_listing", "zen")]
    still = await world.run(due)
    assert kinds(still) == []
    bl.set(data={"lists": lists(zen="not_listed", sbl="not_listed")})
    cleared = await world.run(due)
    assert kinds(cleared) == [("listing_cleared", "zen")]


async def test_error_in_the_middle_gives_only_error_events(world: World) -> None:
    due = world.target()
    bl = world.checks["dnsbl"]
    bl.set(listed("zen"), data={"lists": lists(zen="listed", sbl="not_listed")})
    await world.run(due)
    # One list errors: the whole run is error; its other findings must not become events.
    bl.set(
        finding("DNSBL_LIST_ERROR", "medium", {"list_id": "sbl"}),
        listed("spamhaus"),
        evaluated=False,
        data={"lists": lists(zen="not_listed", sbl="error")},
    )
    world.zone(spf=ResultState.servfail)
    errored = await world.run(due)
    assert kinds(errored) == [("check_error_started", "dnsbl")]
    assert [r.status for r in world.rows()][-2:] == ["error", "ok"]  # dnsbl error, spf ok
    still = await world.run(due)
    assert kinds(still) == []
    # Back: compared with the last non-error run (zen listed): nothing new, nothing cleared.
    bl.set(listed("zen"), data={"lists": lists(zen="listed", sbl="not_listed")})
    world.zone(spf=SPF_Y)  # changed while it could not be read: still seen as a change
    back = await world.run(due)
    assert kinds(back) == [("check_error_cleared", "dnsbl"), ("record_changed", "@ TXT")]
    assert back is not None
    assert (back.events[1].before, back.events[1].after) == (txt_hash(SPF_X), txt_hash(SPF_Y))


async def test_error_is_stored_as_error_and_never_ok(world: World) -> None:
    due = world.target()
    world.checks["spf"].set(evaluated=False)
    out = await world.run(due)
    assert out is not None and out.status == "error"
    assert {r.check_id: r.status for r in world.rows()} == {"dnsbl": "ok", "spf": "error"}
    assert world.stored_target(due).last_status == "error"


# --- isolation of failures ---------------------------------------------------------------------


async def test_exception_in_a_check_is_isolated(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    due = world.target(checks=("dmarc", "dnsbl", "spf"))
    await world.run(due)
    world.checks["dmarc"].raises = True
    out = await world.run(due)
    latest = {r.check_id: r for r in world.rows()[-3:]}
    assert {k: r.status for k, r in latest.items()} == {
        "dmarc": "error",
        "dnsbl": "ok",
        "spf": "ok",
    }
    assert [f.code for f in latest["dmarc"].findings] == ["CHECK_INTERNAL_ERROR"]
    assert kinds(out) == [("check_error_started", "dmarc")]
    assert "secret detail" not in caplog.text


async def test_unknown_check_ids_are_recorded_as_error(world: World) -> None:
    due = world.target(checks=("dmarc", "spf"))
    del world.checks["dmarc"]  # also missing from the prepared registry
    out = await world.run(due, unknown=("dmarc",))
    rows = {r.check_id: r for r in world.rows()}
    assert rows["dmarc"].status == "error" and rows["spf"].status == "ok"
    assert [(f.code, dict(f.params)) for f in rows["dmarc"].findings] == [
        ("CHECK_INTERNAL_ERROR", {"reason": "unknown_check"})
    ]
    assert out is not None and out.status == "error"
    assert world.prepared[-1][1] == ["spf"]  # the unknown id is not asked of the registry


async def test_id_missing_from_the_registry_is_error_too(world: World) -> None:
    due = world.target(checks=("dmarc", "spf"))
    del world.checks["dmarc"]
    await world.run(due)  # not in unknown_check_ids, but the registry lacks it
    assert {r.check_id: r.status for r in world.rows()} == {"dmarc": "error", "spf": "ok"}


async def test_snapshot_failure_is_isolated(
    world: World, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("dns secret detail")

    monkeypatch.setattr(monitor_run, "collect_snapshot", broken)
    due = world.target()
    with caplog.at_level(logging.ERROR, logger="app.monitor_run"):
        out = await world.run(due)
    assert out is not None and out.snapshot is None and len(world.rows()) == 2
    assert any(getattr(r, "event", "") == "monitor_run.snapshot_failed" for r in caplog.records)
    assert "dns secret detail" not in caplog.text


async def test_sink_failure_is_logged_and_the_run_stands(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    due = world.target()
    await world.run(due)
    world.checks["spf"].set(evaluated=False)

    def broken(ctx: TenantContext, events: Sequence[ChangeEvent]) -> None:
        raise RuntimeError("sink down")

    with caplog.at_level(logging.ERROR, logger="app.monitor_run"):
        out = await world.run(due, sink=broken)
    assert kinds(out) == [("check_error_started", "spf")] and len(world.rows()) == 4
    assert any(getattr(r, "event", "") == "monitor_run.sink_failed" for r in caplog.records)


async def test_default_sink_logs_kind_and_fingerprint_only(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    due = world.target()
    await world.run(due, sink=log_events)
    world.zone(spf=SPF_Y)
    with caplog.at_level(logging.INFO, logger="app.monitor_run"):
        out = await world.run(due, sink=log_events)
    assert out is not None
    logged = [r for r in caplog.records if getattr(r, "event", "") == "monitor_run.change_event"]
    assert len(logged) == 1 and out.events[0].fingerprint in logged[0].getMessage()
    assert SPF_Y not in caplog.text and "_spf.other" not in caplog.text


# --- tenancy --------------------------------------------------------------------------------------


async def test_run_uses_the_target_tenant_context_only(world: World) -> None:
    due_a = world.target("a")
    due_b = world.target("b")
    await world.run(due_b)
    before_b = (world.rows("b"), world.snapshots("b"), world.stored_target(due_b, "b"))
    world.checks["spf"].set(evaluated=False)
    await world.run(due_a)
    world.zone("a", spf=SPF_Y)
    world.checks["spf"].set()
    out = await world.run(due_a)
    assert all(ctx == TenantContext(world.tenants["a"], None) for ctx, _ in world.prepared[1:])
    assert [ctx for ctx, _ in world.sunk] == [TenantContext(world.tenants["a"], None)]
    assert out is not None and {e.domain_id for e in out.events} == {world.domains["a"]}
    # history of B did not leak into A's detection: A's first run was the baseline
    assert kinds(out) == [("check_error_cleared", "spf"), ("record_changed", "@ TXT")]
    assert (world.rows("b"), world.snapshots("b"), world.stored_target(due_b, "b")) == before_b


async def test_forged_target_of_another_tenant_is_skipped(world: World) -> None:
    due_b = world.target("b")
    forged = DueTarget(
        due_b.id,
        world.tenants["a"],  # tenant A's context, tenant B's target and domain
        due_b.domain_id,
        due_b.check_ids,
        due_b.interval_seconds,
        NOW,
    )
    assert await world.run(forged) is None
    assert world.prepared == [] and world.checks["spf"].targets == []
    with world.factory() as s:
        assert s.scalar(select(func.count()).select_from(CheckRun)) == 0
        assert s.scalar(select(func.count()).select_from(DnsSnapshot)) == 0
    assert world.stored_target(due_b, "b").last_run_at is None


@pytest.mark.parametrize("change", ["delete", "disable"])
async def test_target_gone_or_disabled_since_the_claim_is_skipped(
    world: World, change: str
) -> None:
    due = world.target()
    with world.factory.begin() as s:
        repo = repo_for(world.ctx("a"), s).monitor_targets
        if change == "delete":
            repo.delete(due.id)
        else:
            repo.update(due.id, enabled=False)
    assert await world.run(due) is None
    assert world.rows() == [] and world.snapshots() == 0


# --- plain functions ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], None),
        (["ok"], "ok"),
        (["ok", "info"], "info"),
        (["info", "warn"], "warn"),
        (["warn", "error"], "error"),
        (["ok", "error"], "error"),
        (["error", "fail"], "fail"),
        (["fail", "ok", "warn"], "fail"),
    ],
)
def test_summary_status(statuses: list[str], expected: str | None) -> None:
    assert summary_status(statuses) == expected


def test_executor_rejects_malformed_settings(world: World) -> None:
    for kw in ({"heartbeat": timedelta(0)}, {"heartbeat": 5}):
        with pytest.raises(ValueError):
            MonitorRunExecutor(world.factory, world.resolver, world.clock, **kw)  # type: ignore[arg-type]
    for history in (0, 1001, True, "5"):
        with pytest.raises(ValueError):
            MonitorRunExecutor(
                world.factory,
                world.resolver,
                world.clock,
                heartbeat=HB,
                history=history,  # type: ignore[arg-type]
            )


async def test_runs_of_two_targets_concurrently(world: World) -> None:
    due_a, due_b = world.target("a"), world.target("b")
    ex = world.executor()
    outs = await asyncio.gather(
        ex.execute(ScheduledRun(due_a, (), NOW, NOW)), ex.execute(ScheduledRun(due_b, (), NOW, NOW))
    )
    assert all(o is not None for o in outs)
    assert len(world.rows("a")) == 2 and len(world.rows("b")) == 2
