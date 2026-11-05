"""CachingResolver tests: fake clock, fake inner resolver, no network, no sleeping."""

from __future__ import annotations

import asyncio

import pytest

from app.dns.cache import CachingResolver
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState

Q = DnsQuestion("example.com", "TXT")
FAILURES = [s for s in ResultState if s.is_failure]


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def ok(q: DnsQuestion = Q, *ttls: int) -> DnsResult:
    ttls = ttls or (300,)
    recs = tuple(DnsRecord(q.name, q.rdtype, t, f"v{i}") for i, t in enumerate(ttls))
    return DnsResult(q, ResultState.ok, recs, ttl_min=min(ttls))


def bare(state: ResultState, q: DnsQuestion = Q) -> DnsResult:
    return DnsResult(q, state)


class Inner:
    def __init__(self, results: list[DnsResult], identity: str = "r1") -> None:
        self.identity = identity
        self.results = results
        self.calls = 0
        self.gate: asyncio.Event | None = None

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.calls += 1
        idx = min(self.calls, len(self.results)) - 1
        if self.gate is not None:
            await self.gate.wait()
        return self.results[idx]


def make(inner: Inner, clock: Clock, **kw: int) -> CachingResolver:
    return CachingResolver(inner, clock=clock, **kw)


async def test_hit_and_ttl_decrement() -> None:
    c = Clock()
    inner = Inner([ok(Q, 300, 100)])
    r = make(inner, c)
    first = await r.resolve(Q)
    assert first.ttl_min == 100
    c.t += 30
    hit = await r.resolve(Q)
    assert inner.calls == 1
    assert [x.ttl for x in hit.records] == [270, 70]
    assert hit.ttl_min == 70


@pytest.mark.parametrize(
    ("delta", "calls"),
    [(99.9, 1), (100, 2), (101, 2)],
)
async def test_expiry_boundary(delta: float, calls: int) -> None:
    c = Clock()
    inner = Inner([ok(Q, 100)])
    r = make(inner, c)
    await r.resolve(Q)
    c.t += delta
    await r.resolve(Q)
    assert inner.calls == calls


@pytest.mark.parametrize(
    ("raw", "min_ttl", "max_ttl", "cached_for"),
    [
        (5, 30, 600, 30),
        (30, 30, 600, 30),
        (600, 30, 600, 600),
        (9999, 30, 600, 600),
        (0, 30, 600, 0),
    ],
)
async def test_clamp_edges(raw: int, min_ttl: int, max_ttl: int, cached_for: int) -> None:
    c = Clock()
    inner = Inner([ok(Q, raw)])
    r = make(inner, c, min_ttl=min_ttl, max_ttl=max_ttl)
    await r.resolve(Q)
    if cached_for == 0:
        await r.resolve(Q)
        assert inner.calls == 2
        return
    c.t += cached_for - 0.5
    await r.resolve(Q)
    assert inner.calls == 1
    c.t += 1
    await r.resolve(Q)
    assert inner.calls == 2


async def test_clamped_up_ttl_never_negative() -> None:
    c = Clock()
    r = make(Inner([ok(Q, 5)]), c, min_ttl=60)
    await r.resolve(Q)
    c.t += 20
    hit = await r.resolve(Q)
    assert hit.records[0].ttl == 0


@pytest.mark.parametrize("state", [ResultState.nxdomain, ResultState.nodata])
async def test_negative_cached_with_negative_ttl(state: ResultState) -> None:
    c = Clock()
    inner = Inner([bare(state)])
    r = make(inner, c, negative_ttl=60)
    assert (await r.resolve(Q)).state is state
    c.t += 59
    assert (await r.resolve(Q)).state is state
    assert inner.calls == 1
    c.t += 1
    await r.resolve(Q)
    assert inner.calls == 2


@pytest.mark.parametrize("state", FAILURES)
async def test_failure_never_cached(state: ResultState) -> None:
    c = Clock()
    inner = Inner([bare(state), ok(Q, 300)])
    r = make(inner, c)
    assert (await r.resolve(Q)).state is state
    assert len(r) == 0
    second = await r.resolve(Q)  # must re-query, not replay the failure or report absence
    assert inner.calls == 2
    assert second.state is ResultState.ok


def test_failure_set_is_every_non_answer_state() -> None:
    assert set(FAILURES) == {
        ResultState.servfail,
        ResultState.refused,
        ResultState.timeout,
        ResultState.truncated,
        ResultState.malformed,
        ResultState.network_error,
        ResultState.blocked,
        ResultState.error,
    }


@pytest.mark.parametrize("state", FAILURES)
async def test_failure_after_expiry_is_not_masked(state: ResultState) -> None:
    c = Clock()
    inner = Inner([ok(Q, 10), bare(state)])
    r = make(inner, c)
    await r.resolve(Q)
    c.t += 10
    assert (await r.resolve(Q)).state is state


async def test_mixed_identities_not_shared() -> None:
    c = Clock()
    a, b = Inner([ok(Q, 100)], "a"), Inner([bare(ResultState.nxdomain)], "b")
    ra, rb = make(a, c), make(b, c)
    assert (await ra.resolve(Q)).state is ResultState.ok
    assert (await rb.resolve(Q)).state is ResultState.nxdomain
    assert (a.calls, b.calls) == (1, 1)


async def test_different_questions_separate() -> None:
    q2 = DnsQuestion("example.com", "A")
    inner = Inner([ok(Q, 100), ok(q2, 100)])
    r = make(inner, Clock())
    await r.resolve(Q)
    await r.resolve(q2)
    await r.resolve(Q)
    assert inner.calls == 2


async def test_lru_eviction() -> None:
    qs = [DnsQuestion(f"d{i}.example.com", "A") for i in range(3)]
    inner = Inner([ok(q, 100) for q in qs] + [ok(qs[1], 100)])
    r = make(inner, Clock(), max_entries=2)
    await r.resolve(qs[0])
    await r.resolve(qs[1])
    await r.resolve(qs[0])  # touch 0 so 1 is the LRU
    await r.resolve(qs[2])  # evicts 1
    assert len(r) == 2
    calls = inner.calls
    await r.resolve(qs[0])
    assert inner.calls == calls
    await r.resolve(qs[1])
    assert inner.calls == calls + 1


async def test_single_flight_coalesces() -> None:
    inner = Inner([ok(Q, 100)])
    inner.gate = asyncio.Event()
    r = make(inner, Clock())
    tasks = [asyncio.create_task(r.resolve(Q)) for _ in range(5)]
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    inner.gate.set()
    results = await asyncio.gather(*tasks)
    assert inner.calls == 1
    assert all(x.state is ResultState.ok for x in results)


async def test_cancelled_waiter_does_not_poison_others() -> None:
    inner = Inner([ok(Q, 100)])
    inner.gate = asyncio.Event()
    r = make(inner, Clock())
    t1 = asyncio.create_task(r.resolve(Q))
    t2 = asyncio.create_task(r.resolve(Q))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    t1.cancel()
    with pytest.raises(asyncio.CancelledError):
        await t1
    inner.gate.set()
    assert (await t2).state is ResultState.ok
    assert inner.calls == 1
    assert len(r) == 1


async def test_coalesced_failure_shared_but_not_cached() -> None:
    inner = Inner([bare(ResultState.timeout), ok(Q, 100)])
    inner.gate = asyncio.Event()
    r = make(inner, Clock())
    ts = [asyncio.create_task(r.resolve(Q)) for _ in range(2)]
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    inner.gate.set()
    assert [x.state for x in await asyncio.gather(*ts)] == [ResultState.timeout] * 2
    assert (await r.resolve(Q)).state is ResultState.ok


async def test_inner_exception_propagates_and_not_cached() -> None:
    class Boom(Inner):
        async def resolve(self, question: DnsQuestion) -> DnsResult:
            raise RuntimeError("x")

    r = make(Boom([]), Clock())
    for _ in range(2):
        with pytest.raises(RuntimeError):
            await r.resolve(Q)
    assert len(r) == 0


async def test_bypass_cache_gets_live_answer_and_leaves_cache() -> None:
    c = Clock()
    inner = Inner([ok(Q, 100), bare(ResultState.nxdomain)])
    r = make(inner, c)
    await r.resolve(Q)
    live = await r.resolve(Q, bypass_cache=True)
    assert live.state is ResultState.nxdomain
    assert inner.calls == 2
    assert (await r.resolve(Q)).state is ResultState.ok  # cache untouched
    assert inner.calls == 2


@pytest.mark.parametrize(
    "kw",
    [{"min_ttl": -1}, {"min_ttl": 10, "max_ttl": 5}, {"negative_ttl": -1}, {"max_entries": 0}],
)
def test_invalid_bounds(kw: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        CachingResolver(Inner([]), **kw)


@pytest.mark.parametrize(
    ("ttl_min", "cached_for"),
    [(None, 60), (30, 30), (500, 60), (0, 0)],
)
async def test_negative_ttl_min_bounds_and_counts_down(
    ttl_min: int | None, cached_for: int
) -> None:
    c = Clock()
    res = DnsResult(Q, ResultState.nxdomain, ttl_min=ttl_min)
    inner = Inner([res])
    r = make(inner, c, negative_ttl=60)
    await r.resolve(Q)
    if cached_for == 0:
        await r.resolve(Q)
        assert inner.calls == 2
        return
    c.t += cached_for - 1
    hit = await r.resolve(Q)
    assert inner.calls == 1
    assert hit.ttl_min == (None if ttl_min is None else max(0, ttl_min - (cached_for - 1)))
    c.t += 1
    await r.resolve(Q)
    assert inner.calls == 2


def test_identity_is_inner_identity() -> None:
    assert CachingResolver(Inner([], "zz")).identity == "zz"
