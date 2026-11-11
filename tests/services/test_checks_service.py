"""Check runner tests: fake clock, fake resolver, no network."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.checks.models import CheckContext, CheckResult, Target, finding
from app.checks.registry import CheckRegistry
from app.dns.types import DnsQuestion, ResultState
from app.services.checks import InvalidTarget, UnknownCheck, run_check, run_checks
from tests.support.dns_zones import parse_zones

T0 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

ZONES = {
    "zones": {
        "default": [
            {"name": "ok.example.com", "type": "TXT", "ttl": 60, "rdata": ["v=spf1 -all"]},
            {"name": "sf.example.com", "type": "TXT", "state": "servfail"},
            {"name": "to.example.com", "type": "TXT", "state": "timeout"},
        ]
    }
}


class FakeClock:
    """Advances 10 ms on every read."""

    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        value = self.now
        self.now += timedelta(milliseconds=10)
        return value


def _ctx() -> CheckContext:
    return CheckContext(resolver=parse_zones(ZONES).resolver(), clock=FakeClock())


class _Check:
    def __init__(self, id: str, fn: Any) -> None:
        self.id = id
        self._fn = fn

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        return await self._fn(ctx, target)  # type: ignore[no-any-return]


def _ok(id: str) -> _Check:
    async def fn(ctx: CheckContext, target: Target) -> CheckResult:
        return CheckResult.build(
            check_id="wrong-id",
            target="wrong",
            findings=[],
            evaluated=True,
            started_at=T0,
            duration_ms=999,
        )

    return _Check(id, fn)


def _raising(id: str, exc: BaseException) -> _Check:
    async def fn(ctx: CheckContext, target: Target) -> CheckResult:
        raise exc

    return _Check(id, fn)


def _dns_check(id: str, name: str, strict: bool) -> _Check:
    """Looks a TXT record up; `strict` checks follow the contract (evaluated=False on failure),
    the others raise."""

    async def fn(ctx: CheckContext, target: Target) -> CheckResult:
        res = await ctx.resolver.resolve(DnsQuestion(name, "TXT"))
        if res.state is ResultState.ok:
            return CheckResult.build(
                check_id=id,
                target=target.domain,
                findings=[],
                evaluated=True,
                started_at=T0,
                duration_ms=0,
            )
        if strict:
            return CheckResult.build(
                check_id=id,
                target=target.domain,
                findings=[],
                evaluated=False,
                started_at=T0,
                duration_ms=0,
            )
        raise RuntimeError(res.state.value)

    return _Check(id, fn)


def _registry(*checks: _Check) -> CheckRegistry:
    reg = CheckRegistry()
    for c in checks:
        reg.register(c)
    return reg


async def test_ok_result_is_restamped_by_runner() -> None:
    reg = _registry(_ok("a"))
    r = await run_check("a", "Example.COM.", _ctx(), registry=reg)
    assert r.status == "ok"
    assert (r.check_id, r.target) == ("a", "example.com")
    assert r.started_at == T0
    assert r.duration_ms == 10  # fake clock: one tick between start and end


async def test_exception_yields_error_and_does_not_leak(caplog: pytest.LogCaptureFixture) -> None:
    secret = "SECRET-RAW-INPUT"
    reg = _registry(_raising("boom", ValueError(secret)))
    with caplog.at_level(logging.DEBUG):
        r = await run_check("boom", "example.com", _ctx(), registry=reg)
    assert r.status == "error"
    assert [f.code for f in r.findings] == ["CHECK_INTERNAL_ERROR"]
    assert secret not in caplog.text
    assert secret not in r.model_dump_json()


async def test_timeout_yields_error() -> None:
    async def slow(ctx: CheckContext, target: Target) -> CheckResult:
        await asyncio.sleep(5)
        raise AssertionError("unreachable")

    reg = _registry(_Check("slow", slow))
    r = await run_check("slow", "example.com", _ctx(), registry=reg, deadline_s=0.01)
    assert r.status == "error"
    assert [f.code for f in r.findings] == ["CHECK_TIMEOUT"]


async def test_timeout_raised_inside_check_is_timeout() -> None:
    reg = _registry(_raising("t", TimeoutError()))
    r = await run_check("t", "example.com", _ctx(), registry=reg)
    assert r.status == "error"
    assert [f.code for f in r.findings] == ["CHECK_TIMEOUT"]


@pytest.mark.parametrize("strict", [True, False])
@pytest.mark.parametrize("name", ["sf.example.com", "to.example.com"])
async def test_dns_failure_yields_error(name: str, strict: bool) -> None:
    reg = _registry(_dns_check("dns", name, strict))
    r = await run_check("dns", "example.com", _ctx(), registry=reg)
    assert r.status == "error"


async def test_dns_success_with_fake_resolver() -> None:
    reg = _registry(_dns_check("dns", "ok.example.com", False))
    assert (await run_check("dns", "example.com", _ctx(), registry=reg)).status == "ok"


async def test_non_result_return_is_error() -> None:
    async def bad(ctx: CheckContext, target: Target) -> Any:
        return {"status": "ok"}

    reg = _registry(_Check("bad", bad))
    r = await run_check("bad", "example.com", _ctx(), registry=reg)
    assert r.status == "error"
    assert [f.code for f in r.findings] == ["CHECK_INTERNAL_ERROR"]


async def test_cancellation_propagates() -> None:
    reg = _registry(_raising("c", asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        await run_check("c", "example.com", _ctx(), registry=reg)


async def test_unknown_check_id() -> None:
    reg = _registry(_ok("a"))
    with pytest.raises(UnknownCheck):
        await run_check("nope", "example.com", _ctx(), registry=reg)
    with pytest.raises(UnknownCheck):
        await run_checks(["a", "nope"], "example.com", _ctx(), registry=reg)


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("localhost", "single_label"),
        ("1.2.3.4", "ip_address"),
        ("exa mple.com", "forbidden_character"),
        ("_dmarc.example.com", "label"),
        ("a\x00b.com", "forbidden_character"),
        ("x" * 2000, "too_long"),
        (None, "not_a_string"),
    ],
)
async def test_bad_names(name: Any, reason: str) -> None:
    reg = _registry(_ok("a"))
    with pytest.raises(InvalidTarget) as ei:
        await run_check("a", name, _ctx(), registry=reg)
    assert ei.value.reason == reason
    with pytest.raises(InvalidTarget):
        await run_checks(["a"], name, _ctx(), registry=reg)


async def test_run_checks_order_follows_requested_ids() -> None:
    async def delayed(ctx: CheckContext, target: Target) -> CheckResult:
        await asyncio.sleep(0.05)
        return CheckResult.build(
            check_id="x",
            target="x",
            findings=[finding("SOME_CODE", "low")],
            evaluated=True,
            started_at=T0,
            duration_ms=0,
        )

    reg = _registry(
        _Check("first", delayed),
        _ok("second"),
        _raising("third", RuntimeError("x")),
    )
    results = await run_checks(
        ["third", "first", "second", "first"], "example.com", _ctx(), registry=reg
    )
    assert [r.check_id for r in results] == ["third", "first", "second", "first"]
    assert [r.status for r in results] == ["error", "warn", "ok", "warn"]


async def test_run_checks_empty_ids() -> None:
    assert await run_checks([], "example.com", _ctx(), registry=_registry()) == []


async def test_run_checks_concurrency_is_bounded() -> None:
    running = 0
    peak = 0

    async def probe(ctx: CheckContext, target: Target) -> CheckResult:
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return CheckResult.build(
            check_id="x",
            target="x",
            findings=[],
            evaluated=True,
            started_at=T0,
            duration_ms=0,
        )

    reg = _registry(*(_Check(f"c{i}", probe) for i in range(6)))
    results = await run_checks(reg.all_ids(), "example.com", _ctx(), registry=reg, concurrency=2)
    assert len(results) == 6
    assert peak == 2
