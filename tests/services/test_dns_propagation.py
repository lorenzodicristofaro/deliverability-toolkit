import asyncio
from pathlib import Path
from typing import Any

import pytest

from app.dns.cache import CachingResolver
from app.dns.knowledge import PublicResolver
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.services.dns_propagation import MAX_RESOLVERS, Verdict, check_propagation
from app.services.dns_tools import InvalidLookupInput
from tests.support.dns_zones import FakeResolver, FakeServerSet, load_zones, parse_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"


def entry(rid: str, addrs: list[str], status: str = "verified") -> PublicResolver:
    return PublicResolver(rid, rid, rid, tuple(addrs), 53, None, (), status)


def servers(spec: dict[str, list[dict[str, Any]]]) -> FakeServerSet:
    return parse_zones({"zones": spec})


def a(
    rdata: list[str], ttl: int = 300, typ: str = "A", name: str = "example.com"
) -> dict[str, Any]:
    return {"name": name, "type": typ, "ttl": ttl, "rdata": rdata}


def st(state: str) -> dict[str, Any]:
    return {"name": "example.com", "type": "A", "state": state}


async def run(fs: FakeServerSet, entries: list[PublicResolver], ids: Any = None, **kw: Any) -> Any:
    return await check_propagation(
        "example.com",
        "A",
        ids,
        default_resolver=fs.resolver("default"),
        address_factory=lambda e, addr: fs.resolver(addr),
        catalog=entries,
        **kw,
    )


E = [entry("p", ["10.0.0.1", "10.0.0.2"]), entry("q", ["10.0.1.1"])]


def mk(default: Any, p1: Any, p2: Any, q1: Any) -> FakeServerSet:
    return servers({"default": default, "10.0.0.1": p1, "10.0.0.2": p2, "10.0.1.1": q1})


AGREE = [a(["192.0.2.1", "192.0.2.2"])]
TXT = [a(["x"], typ="TXT")]  # name exists, no A: nodata
CASES: list[tuple[str, FakeServerSet, Verdict, int, int, int]] = [
    ("all_agree", mk(AGREE, AGREE, AGREE, AGREE), Verdict.consistent, 1, 4, 0),
    (
        "order_and_ttl_ignored",
        mk(AGREE, [a(["192.0.2.2", "192.0.2.1"], ttl=5)], AGREE, AGREE),
        Verdict.consistent,
        1,
        4,
        0,
    ),
    ("split_answers", mk(AGREE, AGREE, [a(["192.0.2.9"])], AGREE), Verdict.inconsistent, 2, 4, 0),
    (
        "servfail_among_agreeing",
        mk(AGREE, AGREE, [st("servfail")], AGREE),
        Verdict.consistent,
        1,
        3,
        1,
    ),
    (
        "all_timeout",
        mk([st("timeout")], [st("timeout")], [st("timeout")], [st("timeout")]),
        Verdict.inconclusive,
        0,
        0,
        4,
    ),
    (
        "nxdomain_vs_ok",
        mk(AGREE, AGREE, [a(["192.0.2.1"], name="other.example")], AGREE),
        Verdict.inconsistent,
        2,
        4,
        0,
    ),
    (
        "cname_vs_a",
        mk(AGREE, AGREE, [a(["x.example.net"], typ="CNAME")], AGREE),
        Verdict.inconsistent,
        2,
        4,
        0,
    ),
    (
        "nodata_vs_ok",
        mk(AGREE, AGREE, TXT, AGREE),
        Verdict.inconsistent,
        2,
        4,
        0,
    ),
    (
        "failures_never_absence",
        mk(TXT, [st("refused")], [st("timeout")], [st("network_error")]),
        Verdict.inconclusive,
        1,
        1,
        3,
    ),
    ("same_absence_consistent", mk(TXT, TXT, TXT, TXT), Verdict.consistent, 1, 4, 0),
    (
        "failure_among_absences_is_not_agreement_or_split",
        mk(TXT, TXT, [st("servfail")], TXT),
        Verdict.consistent,
        1,
        3,
        1,
    ),
]


@pytest.mark.parametrize(("label", "fs", "verdict", "groups", "evaluated", "failed"), CASES)
async def test_aggregation(
    label: str, fs: FakeServerSet, verdict: Verdict, groups: int, evaluated: int, failed: int
) -> None:
    rep = await run(fs, E)
    assert rep.verdict is verdict, label
    assert len(rep.groups) == groups
    assert rep.evaluated_count == evaluated
    assert rep.not_evaluated_count == failed
    for r in rep.rows:
        assert (r.group is None) == (not r.evaluated)


async def test_nxdomain_state_kept_per_row() -> None:
    fs = mk(AGREE, AGREE, [a(["192.0.2.1"], name="other.example")], AGREE)
    rep = await run(fs, E)
    assert {r.address: r.state for r in rep.rows}["10.0.0.2"] is ResultState.nxdomain


async def test_ttl_shown_but_ignored() -> None:
    fs = mk(AGREE, [a(["192.0.2.1", "192.0.2.2"], ttl=5)], AGREE, AGREE)
    rep = await run(fs, E)
    assert rep.rows[1].records[0][3] == 5
    assert rep.rows[0].records[0][3] == 300


async def test_every_address_queried_and_reported() -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    rep = await run(fs, E)
    assert [(r.resolver_id, r.address) for r in rep.rows] == [
        ("default", None),
        ("p", "10.0.0.1"),
        ("p", "10.0.0.2"),
        ("q", "10.0.1.1"),
    ]
    assert all(len(fs.resolver(x).questions) == 1 for x in ("10.0.0.1", "10.0.0.2", "10.0.1.1"))


async def test_disagree_fixture() -> None:
    fs = load_zones(ZONES / "disagree.yaml")
    fs.servers["default"] = FakeResolver(fs.resolver("192.0.2.53").zones, "default")
    rep = await run(fs, [entry("x", ["192.0.2.53", "198.51.100.53", "203.0.113.53"])])
    assert rep.verdict is Verdict.inconsistent
    assert len(rep.groups) == 2
    assert rep.not_evaluated_count == 1
    by = {r.address: r for r in rep.rows}
    assert by["203.0.113.53"].state is ResultState.servfail
    assert by["203.0.113.53"].group is None
    assert by["192.0.2.53"].group != by["198.51.100.53"].group


async def test_min_evaluated_configurable() -> None:
    fs = mk(AGREE, [st("servfail")], [st("servfail")], [st("servfail")])
    assert (await run(fs, E)).verdict is Verdict.inconclusive
    assert (await run(fs, E, min_evaluated=1)).verdict is Verdict.consistent


async def test_unverified_only_when_selected_and_flagged() -> None:
    cat = [entry("v", ["10.0.0.1"]), entry("u", ["10.0.0.2"], status="unverified")]
    fs = servers({"default": AGREE, "10.0.0.1": AGREE, "10.0.0.2": AGREE})
    rep = await run(fs, cat)
    assert {r.resolver_id for r in rep.rows} == {"default", "v"}
    assert not rep.includes_unverified
    rep = await run(fs, cat, ["u"])
    assert rep.includes_unverified
    assert [r.unverified for r in rep.rows] == [False, True]


@pytest.mark.parametrize(
    ("ids", "reason"),
    [
        (["nope"], "unknown_public_id"),
        (["default"], "unknown_public_id"),
        (["8.8.8.8"], "unknown_public_id"),
        ("p", "not_a_list"),
        ([1], "not_a_string"),
        ([], "empty_selection"),
        (["p", None], "not_a_string"),
    ],
)
async def test_bad_selection(ids: Any, reason: str) -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    with pytest.raises(InvalidLookupInput) as ei:
        await run(fs, E, ids)
    assert ei.value.field == "resolver"
    assert ei.value.reason == reason
    assert fs.all_questions == []


async def test_max_resolvers_cap() -> None:
    cat = [entry(f"r{i}", [f"10.1.0.{i + 1}"]) for i in range(MAX_RESOLVERS + 1)]
    fs = servers({"default": AGREE, **{f"10.1.0.{i + 1}": AGREE for i in range(len(cat))}})
    with pytest.raises(InvalidLookupInput) as ei:
        await run(fs, cat, [e.id for e in cat])
    assert ei.value.reason == "too_many"
    ok = await run(fs, cat, [e.id for e in cat[:MAX_RESOLVERS]])
    assert len(ok.rows) == MAX_RESOLVERS + 1


@pytest.mark.parametrize(
    ("name", "rdtype", "field"),
    [
        ("", "A", "name"),
        ("bad name", "A", "name"),
        (None, "A", "name"),
        ("example.com", "ANY", "rdtype"),
        ("example.com", "ALL", "rdtype"),
        ("example.com", 5, "rdtype"),
    ],
)
async def test_bad_input(name: Any, rdtype: Any, field: str) -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    with pytest.raises(InvalidLookupInput) as ei:
        await check_propagation(name, rdtype, default_resolver=fs.resolver("default"), catalog=E)
    assert ei.value.field == field
    assert fs.all_questions == []


class Hang:
    identity = "hang"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        await asyncio.sleep(10)
        raise AssertionError


class Boom:
    identity = "boom"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        raise RuntimeError("x")


async def test_timeout_and_exception_are_failures() -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    special = {"10.0.0.1": Hang(), "10.0.0.2": Boom()}
    rep = await check_propagation(
        "example.com",
        "A",
        ["p", "q"],
        default_resolver=fs.resolver("default"),
        address_factory=lambda e, ad: special.get(ad) or fs.resolver(ad),
        catalog=E,
        timeout_s=0.05,
    )
    by = {r.address: r for r in rep.rows}
    assert by["10.0.0.1"].state is ResultState.timeout
    assert by["10.0.0.2"].state is ResultState.error
    assert rep.not_evaluated_count == 2
    assert rep.verdict is Verdict.consistent


async def test_concurrency_cap() -> None:
    live = peak = 0

    class Slow:
        identity = "slow"

        async def resolve(self, question: DnsQuestion) -> DnsResult:
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.01)
            live -= 1
            return DnsResult(
                question, ResultState.ok, (DnsRecord("example.com", "A", 1, "192.0.2.1"),)
            )

    cat = [entry(f"r{i}", [f"10.1.0.{i + 1}"]) for i in range(6)]
    rep = await check_propagation(
        "example.com",
        "A",
        default_resolver=Slow(),
        address_factory=lambda e, ad: Slow(),
        catalog=cat,
        max_concurrency=2,
    )
    assert peak == 2
    assert rep.verdict is Verdict.consistent


async def test_cache_bypassed_and_not_shared() -> None:
    fs = servers({"default": AGREE, "10.0.0.1": [a(["192.0.2.9"])]})
    default_cached = CachingResolver(fs.resolver("default"))
    other_cached = CachingResolver(fs.resolver("10.0.0.1"))
    q = DnsQuestion("example.com", "A")
    await default_cached.resolve(q)  # prime: a cached answer must not be served
    assert len(fs.resolver("default").questions) == 1
    rep = await check_propagation(
        "example.com",
        "A",
        ["p"],
        default_resolver=default_cached,
        address_factory=lambda e, ad: other_cached,
        catalog=[entry("p", ["10.0.0.1"])],
    )
    assert len(fs.resolver("default").questions) == 2  # live query despite warm cache
    assert len(other_cached) == 0  # propagation did not populate any cache
    assert rep.verdict is Verdict.inconsistent  # distinct resolvers gave distinct answers


class Fixed:
    def __init__(self, state: ResultState) -> None:
        self.identity = f"fixed:{state}"
        self.state = state

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        return DnsResult(question, self.state, detail_code="stub")


async def test_blocked_among_agreeing_stays_consistent() -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    rep = await check_propagation(
        "example.com",
        "A",
        ["p", "q"],
        default_resolver=fs.resolver("default"),
        address_factory=lambda e, ad: (
            Fixed(ResultState.blocked) if ad == "10.0.0.2" else fs.resolver(ad)
        ),
        catalog=E,
    )
    blocked = next(r for r in rep.rows if r.address == "10.0.0.2")
    assert blocked.state is ResultState.blocked
    assert blocked.group is None
    assert rep.verdict is Verdict.consistent
    assert (rep.evaluated_count, rep.not_evaluated_count) == (3, 1)


async def test_real_factory_private_address_blocked_nothing_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    def boom(*a: Any, **k: Any) -> Any:
        raise AssertionError("network touched")

    for fn in ("connect", "sendto", "send", "connect_ex"):
        monkeypatch.setattr(socket.socket, fn, boom)
    fs = servers({"default": AGREE})
    rep = await check_propagation(
        "example.com",
        "A",
        ["priv"],
        default_resolver=fs.resolver("default"),
        catalog=[entry("priv", ["10.0.0.1"])],
        min_evaluated=1,
    )
    row = rep.rows[1]
    assert row.state is ResultState.blocked
    assert row.detail_code is not None
    assert row.group is None
    assert rep.not_evaluated_count == 1


async def test_name_rdata_case_insensitive_row_keeps_original() -> None:
    def c(v: str) -> list[dict[str, Any]]:
        return [a([v], typ="CNAME")]

    fs = mk(c("x.example.net"), c("X.Example.NET"), c("x.example.net"), c("x.example.net"))
    rep = await check_propagation(
        "example.com",
        "CNAME",
        ["p", "q"],
        default_resolver=fs.resolver("default"),
        address_factory=lambda e, ad: fs.resolver(ad),
        catalog=E,
    )
    assert rep.verdict is Verdict.consistent
    assert rep.rows[1].records[0][2] == "X.Example.NET"


async def test_txt_compared_exactly() -> None:
    def t(v: str) -> list[dict[str, Any]]:
        return [a([v], typ="TXT")]

    fs = mk(t("v=spf1 -all"), t("V=SPF1 -ALL"), t("v=spf1 -all"), t("v=spf1 -all"))
    rep = await check_propagation(
        "example.com",
        "TXT",
        ["p", "q"],
        default_resolver=fs.resolver("default"),
        address_factory=lambda e, ad: fs.resolver(ad),
        catalog=E,
    )
    assert rep.verdict is Verdict.inconsistent


async def test_max_targets_rejected_not_truncated() -> None:
    cat = [entry(f"r{i}", [f"10.2.{i}.1", f"10.2.{i}.2", f"10.2.{i}.3"]) for i in range(6)]
    fs = servers({"default": AGREE})
    with pytest.raises(InvalidLookupInput) as ei:
        await run(fs, cat, [e.id for e in cat])  # 18 > 16
    assert (ei.value.field, ei.value.reason) == ("resolver", "too_many_targets")
    assert fs.all_questions == []
    sixteen = [entry(f"s{i}", [f"10.3.{i}.1", f"10.3.{i}.2"]) for i in range(8)]
    fs2 = servers({"default": AGREE, **{x: AGREE for e in sixteen for x in e.addresses}})
    rep = await run(fs2, sixteen, [e.id for e in sixteen])
    assert len(rep.rows) == 17


async def test_overall_deadline() -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    rep = await check_propagation(
        "example.com",
        "A",
        ["p", "q"],
        default_resolver=fs.resolver("default"),
        address_factory=lambda e, ad: Hang() if ad == "10.0.0.1" else fs.resolver(ad),
        catalog=E,
        timeout_s=30,
        deadline_s=0.05,
    )
    hung = next(r for r in rep.rows if r.address == "10.0.0.1")
    assert hung.state is ResultState.timeout
    assert hung.detail_code == "overall_deadline"
    assert rep.verdict is Verdict.consistent


async def test_no_verified_entries_only_default_inconclusive() -> None:
    fs = servers({"default": AGREE, "10.0.0.2": AGREE})
    rep = await run(fs, [entry("u", ["10.0.0.2"], status="unverified")])
    assert [r.resolver_id for r in rep.rows] == ["default"]
    assert rep.verdict is Verdict.inconclusive


class Tracking:
    """A resolver that never answers and records whether its task was cancelled."""

    def __init__(self) -> None:
        self.identity = "tracking"
        self.started = asyncio.Event()
        self.cancelled = False

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("unreachable")


async def test_caller_cancellation_cancels_per_address_tasks() -> None:
    fs = mk(AGREE, AGREE, AGREE, AGREE)
    hung = Tracking()
    caller = asyncio.ensure_future(
        check_propagation(
            "example.com",
            "A",
            ["p"],
            default_resolver=hung,
            address_factory=lambda e, ad: fs.resolver(ad),
            catalog=E,
            timeout_s=30,
            deadline_s=30,
        )
    )
    await asyncio.wait_for(hung.started.wait(), 2)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert hung.cancelled
