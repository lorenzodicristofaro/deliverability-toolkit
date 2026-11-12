"""M2-09 DNS trace: fake server set only, no sockets, no network."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncGenerator, Callable
from typing import Any

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from app.core.config import ResolverAddr
from app.dns import backends
from app.dns.egress import DEFAULT_POLICY, BlockReason, TargetPolicy
from app.dns.knowledge import RootServer, root_hints
from app.dns.trace import (
    DEFAULT_LIMITS,
    MAX_GLUELESS_LOOKUPS_PER_ZONE,
    MAX_HOP_RECORDS,
    MAX_REFERRAL_DEPTH,
    MAX_REFERRAL_GLUE,
    MAX_REFERRAL_NS,
    MAX_SERVERS_PER_ZONE,
    MAX_TOTAL_QUERIES,
    TOTAL_DEADLINE_S,
    HopKind,
    TraceLimits,
    TraceOutcome,
    TraceReport,
    query_server_for,
    trace,
)
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from tests.support.dns_zones import (
    FakeResolver,
    FakeServerSet,
    NsAddr,
    Referral,
    ZoneFixtureError,
    parse_zones,
)

ROOTS = (RootServer("a.root-servers.net", "192.0.2.1", "2001:db8::1"),)


class FixturePolicy:
    """The production policy, except that documentation ranges (the fixture addresses) pass.
    Records every check so tests can assert addresses are always treated as UNTRUSTED."""

    def __init__(self) -> None:
        self.checks: list[tuple[ResolverAddr, bool]] = []

    def check(self, addr: ResolverAddr, trusted: bool) -> BlockReason | None:
        self.checks.append((addr, trusted))
        reason = DEFAULT_POLICY.check(addr, trusted)
        return None if reason is BlockReason.documentation else reason


def q(name: str, rdtype: str = "A") -> DnsQuestion:
    return DnsQuestion(name, rdtype)


def sent(servers: FakeServerSet) -> list[str]:
    return [addr for addr, _ in servers.server_queries]


async def run(
    servers: FakeServerSet,
    question: DnsQuestion,
    *,
    limits: TraceLimits = DEFAULT_LIMITS,
    resolver: Any = None,
    roots: Any = ROOTS,
    policy: Any = None,
    query_server: Any = None,
    clock: Callable[[], float] | None = None,
) -> TraceReport:
    kw: dict[str, Any] = {} if clock is None else {"clock": clock}
    return await trace(
        question,
        query_server=query_server or servers.query_server,
        root_hints=roots,
        policy=policy or FixturePolicy(),
        limits=limits,
        resolver=resolver,
        **kw,
    )


def ref(zone: str, *ns: tuple[str, str]) -> dict[str, Any]:
    return {"referral": {"zone": zone, "ns": [{"name": n, "addr": a} for n, a in ns]}}


def chain(com_ns: list[tuple[str, str]], extra: dict[str, list[Any]]) -> FakeServerSet:
    """root (192.0.2.1) -> com (192.0.2.2) -> example.com delegated to com_ns."""
    zones: dict[str, list[Any]] = {
        "192.0.2.1": [ref("com", ("a.gtld.example.net", "192.0.2.2"))],
        "192.0.2.2": [ref("example.com", *com_ns)],
    }
    zones.update(extra)
    return parse_zones({"zones": zones})


GOOD = {"192.0.2.3": [{"name": "example.com", "type": "A", "ttl": 300, "rdata": ["192.0.2.10"]}]}


def assert_never_missing(report: TraceReport) -> None:
    """A failure outcome is never absence, and a referral hop is never nodata/nxdomain.
    (ns_lookup hops ask about the NS name, not the traced name, so their absence is genuine.)"""
    for hop in report.hops:
        if hop.kind is HopKind.referral:
            assert hop.state is ResultState.ok
        if hop.kind not in (HopKind.answer, HopKind.ns_lookup):
            assert hop.question == report.question
            assert not hop.state.is_definitive_absence
    if report.outcome not in (TraceOutcome.nxdomain, TraceOutcome.nodata):
        assert not report.state.is_definitive_absence


# --- normal chain and final outcomes ---------------------------------------------------------


@pytest.mark.parametrize(
    ("question", "outcome", "answer"),
    [
        (q("example.com"), TraceOutcome.ok, ("192.0.2.10",)),
        (q("example.com", "MX"), TraceOutcome.nodata, ()),
        (q("nope.example.com"), TraceOutcome.nxdomain, ()),
    ],
)
async def test_normal_chain(
    fake_dns: Any, question: DnsQuestion, outcome: TraceOutcome, answer: tuple[str, ...]
) -> None:
    servers = fake_dns("delegation")
    report = await run(servers, question)
    assert report.outcome is outcome
    assert report.state.value == outcome.value
    assert report.detail_code is None
    assert tuple(r.rdata_text for r in report.answer) == answer
    assert [h.kind for h in report.hops] == [HopKind.referral, HopKind.referral, HopKind.answer]
    assert [h.zone for h in report.hops] == [".", "com", "example.com"]
    assert [h.referral_zone for h in report.hops] == ["com", "example.com", None]
    assert report.hops[0].referral_ns == ("a.gtld.example.net",)
    assert report.hops[1].referral_ns == ("ns1.example.net",)
    assert report.hops[1].server_name == "a.gtld.example.net"
    assert all(h.question == question for h in report.hops)
    assert sent(servers) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert report.final_zone == "example.com" and report.final_server == "192.0.2.3"
    assert report.queries_sent == 3
    assert report.answer == report.hops[-1].records
    assert_never_missing(report)


async def test_underscore_name(fake_dns: Any) -> None:
    servers = fake_dns("delegation")
    zone = servers.resolver("192.0.2.3").zones
    rec = DnsRecord("_dmarc.example.com", "TXT", 300, "v=DMARC1; p=none")
    zone.entries[("_dmarc.example.com", "TXT")] = type(zone.entries[("example.com", "A")])(
        records=(rec,)
    )
    report = await run(servers, q("_dmarc.example.com", "TXT"))
    assert report.outcome is TraceOutcome.ok
    assert report.answer == (rec,)


async def test_ad_flag_is_carried_not_validated() -> None:
    servers = chain(
        [("ns1.example.net", "192.0.2.3")],
        {
            "192.0.2.3": [
                {"name": "example.com", "type": "A", "ttl": 1, "rdata": ["192.0.2.9"], "ad": True}
            ]
        },
    )
    report = await run(servers, q("example.com"))
    assert report.hops[-1].authenticated_data is True
    assert report.hops[0].authenticated_data is False


async def test_ipv6_root_and_ipv6_glue() -> None:
    # The IPv4 root address has no fixture (unreachable); the IPv6 one answers.
    servers = parse_zones(
        {
            "zones": {
                "2001:db8::1": [ref("com", ("a.gtld.example.net", "2001:db8::2"))],
                "2001:db8::2": [ref("example.com", ("ns1.example.com", "2001:db8::53"))],
                "2001:db8::53": GOOD["192.0.2.3"],
            }
        }
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.ok
    assert sent(servers) == ["192.0.2.1", "2001:db8::1", "2001:db8::2", "2001:db8::53"]
    assert report.hops[0].kind is HopKind.failure
    assert report.hops[0].state is ResultState.network_error
    assert report.final_server == "2001:db8::53"


async def test_real_root_hints_are_accepted_and_bounded() -> None:
    servers = FakeServerSet({})  # every server unreachable
    report = await run(servers, q("example.com"), roots=root_hints(), policy=DEFAULT_POLICY)
    hints = root_hints().servers
    assert sent(servers) == [hints[0].ipv4, hints[0].ipv6, hints[1].ipv4, hints[1].ipv6]
    assert report.outcome is TraceOutcome.all_failed
    assert report.state is ResultState.error


# --- egress: untrusted referral / glue / NS addresses ----------------------------------------


async def test_private_referral_in_delegation_fixture_is_never_contacted(fake_dns: Any) -> None:
    servers = fake_dns("delegation")
    # The root fixture only delegates com; add net so the trace reaches the private referral.
    servers.resolver("192.0.2.1").zones.referrals.append(
        Referral("net", (NsAddr("a.gtld.example.net", "192.0.2.2"),))
    )
    report = await run(servers, q("example.net"))
    assert "10.0.0.53" not in sent(servers)
    assert sent(servers) == ["192.0.2.1", "192.0.2.2"]
    blocked = [h for h in report.hops if h.kind is HopKind.blocked]
    assert len(blocked) == 1
    assert blocked[0].server_addr == "10.0.0.53"
    assert blocked[0].state is ResultState.blocked
    assert blocked[0].detail_code == BlockReason.private
    assert report.outcome is TraceOutcome.no_allowed_server
    assert report.state is ResultState.error
    assert report.detail_code == "all_servers_blocked"
    assert_never_missing(report)


SSRF_ADDRS = [
    ("10.1.2.3", BlockReason.private),
    ("127.0.0.1", BlockReason.loopback),
    ("169.254.169.254", BlockReason.link_local),
    ("::1", BlockReason.loopback),
    ("::ffff:10.0.0.1", BlockReason.ipv4_mapped),
    ("::ffff:127.0.0.1", BlockReason.ipv4_mapped),
    ("0.0.0.0", BlockReason.unspecified),
    ("fe80::1", BlockReason.link_local),
    ("fd00::53", BlockReason.private),
    ("100.64.0.1", BlockReason.shared_address_space),
]


async def test_blocked_referral_addresses_are_never_queried() -> None:
    ns = [(f"ns{i}.example.com", a) for i, (a, _) in enumerate(SSRF_ADDRS)]
    # Give each blocked address a fixture too, so a leak would be visible as an answer.
    extra = {a: GOOD["192.0.2.3"] for a, _ in SSRF_ADDRS}
    servers = chain(ns, extra)
    policy = FixturePolicy()
    report = await run(servers, q("example.com"), policy=policy)
    assert sent(servers) == ["192.0.2.1", "192.0.2.2"]
    blocked = [h for h in report.hops if h.kind is HopKind.blocked]
    assert [(h.server_addr, h.detail_code) for h in blocked] == SSRF_ADDRS
    assert all(h.state is ResultState.blocked for h in blocked)
    assert report.outcome is TraceOutcome.no_allowed_server
    assert report.state is ResultState.error
    assert all(trusted is False for _, trusted in policy.checks)
    assert all(addr.port == 53 for addr, _ in policy.checks)
    assert_never_missing(report)


async def test_blocked_server_skipped_then_allowed_one_used() -> None:
    servers = chain(
        [("ns0.example.com", "169.254.169.254"), ("ns1.example.com", "192.0.2.3")],
        {"169.254.169.254": GOOD["192.0.2.3"], **GOOD},
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.ok
    assert "169.254.169.254" not in sent(servers)
    assert [h.kind for h in report.hops].count(HopKind.blocked) == 1


async def test_production_policy_blocks_documentation_roots_too(fake_dns: Any) -> None:
    servers = fake_dns("delegation")
    report = await run(servers, q("example.com"), policy=DEFAULT_POLICY)
    assert servers.server_queries == []
    assert report.outcome is TraceOutcome.no_allowed_server
    assert {h.detail_code for h in report.hops} == {BlockReason.documentation}


# --- glueless delegation ---------------------------------------------------------------------


def glueless_servers(ns_names: tuple[str, ...]) -> FakeServerSet:
    servers = parse_zones(
        {
            "zones": {
                "192.0.2.1": [ref("org", ("a.gtld.example.net", "192.0.2.2"))],
                "192.0.2.2": [],
                "192.0.2.30": [
                    {"name": "example.org", "type": "A", "ttl": 60, "rdata": ["192.0.2.80"]}
                ],
                "2001:db8::30": [
                    {"name": "example.org", "type": "A", "ttl": 60, "rdata": ["192.0.2.80"]}
                ],
            }
        }
    )
    servers.resolver("192.0.2.2").zones.referrals.append(
        backends.Referral(zone="example.org", ns=(), ns_names=ns_names)  # type: ignore[arg-type]
    )
    return servers


def ns_resolver(entries: list[dict[str, Any]]) -> FakeResolver:
    return parse_zones({"zones": {"default": entries}}).resolver()


async def test_glueless_ns_resolved_through_resolver() -> None:
    servers = glueless_servers(("ns1.example.com",))
    resolver = ns_resolver(
        [
            {"name": "ns1.example.com", "type": "A", "ttl": 60, "rdata": ["192.0.2.30"]},
            {"name": "ns1.example.com", "type": "AAAA", "ttl": 60, "rdata": ["2001:db8::30"]},
        ]
    )
    report = await run(servers, q("example.org"), resolver=resolver)
    assert report.outcome is TraceOutcome.ok
    assert resolver.questions == [q("ns1.example.com"), q("ns1.example.com", "AAAA")]
    lookups = [h for h in report.hops if h.kind is HopKind.ns_lookup]
    assert [h.state for h in lookups] == [ResultState.ok, ResultState.ok]
    assert sent(servers) == ["192.0.2.1", "192.0.2.2", "192.0.2.30"]
    assert report.queries_sent == 5  # 3 server queries + 2 resolver lookups


async def test_glueless_ns_resolving_to_private_address_is_blocked() -> None:
    servers = glueless_servers(("ns1.example.com",))
    resolver = ns_resolver(
        [
            {"name": "ns1.example.com", "type": "A", "ttl": 60, "rdata": ["10.0.0.53"]},
            {"name": "ns1.example.com", "type": "AAAA", "ttl": 60, "rdata": ["::1"]},
        ]
    )
    report = await run(servers, q("example.org"), resolver=resolver)
    assert "10.0.0.53" not in sent(servers) and "::1" not in sent(servers)
    assert [h.server_addr for h in report.hops if h.kind is HopKind.blocked] == ["10.0.0.53", "::1"]
    assert report.outcome is TraceOutcome.no_allowed_server
    assert_never_missing(report)


class AliasResolver:
    """The configured resolver followed a CNAME: the A record is owned by another name."""

    identity = "stub"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        rec = DnsRecord("target.example.com", question.rdtype, 60, "192.0.2.30")
        return DnsResult(question, ResultState.ok, records=(rec,))


async def test_cname_at_ns_name_is_rejected() -> None:
    servers = glueless_servers(("ns1.example.com",))
    report = await run(servers, q("example.org"), resolver=AliasResolver())
    lookups = [h for h in report.hops if h.kind is HopKind.ns_lookup]
    assert {h.detail_code for h in lookups} == {"ns_is_cname"}
    assert "192.0.2.30" not in sent(servers)
    assert report.outcome is TraceOutcome.no_server_address
    assert report.state is ResultState.error


@pytest.mark.parametrize(
    ("ns_names", "resolver_entries", "use_resolver", "details"),
    [
        # CNAME at the NS name in the fake: no A/AAAA, so nodata for both
        (
            ("ns1.example.com",),
            [{"name": "ns1.example.com", "type": "CNAME", "ttl": 60, "rdata": ["x.example.com"]}],
            True,
            [None, None],
        ),
        (("ns1.example.com",), [], True, [None, None]),  # nxdomain for both
        (("ns1.example.com",), [], False, ["no_resolver"]),
        (("bad name.example.com",), [], True, ["bad_ns_name"]),
        (
            ("ns1.example.com",),
            [{"name": "ns1.example.com", "type": "A", "state": "servfail"}],
            True,
            [None, None],
        ),
    ],
)
async def test_glueless_failures_end_explicitly(
    ns_names: tuple[str, ...],
    resolver_entries: list[dict[str, Any]],
    use_resolver: bool,
    details: list[str | None],
) -> None:
    servers = glueless_servers(ns_names)
    resolver = ns_resolver(
        resolver_entries or [{"name": "x.test", "type": "A", "state": "timeout"}]
    )
    report = await run(servers, q("example.org"), resolver=resolver if use_resolver else None)
    lookups = [h for h in report.hops if h.kind is HopKind.ns_lookup]
    assert [h.detail_code for h in lookups] == details
    assert report.outcome is TraceOutcome.no_server_address
    assert report.state is ResultState.error
    assert sent(servers) == ["192.0.2.1", "192.0.2.2"]
    assert_never_missing(report)


async def test_glueless_lookups_per_zone_are_capped() -> None:
    names = tuple(f"ns{i}.example.com" for i in range(MAX_GLUELESS_LOOKUPS_PER_ZONE + 2))
    servers = glueless_servers(names)
    resolver = ns_resolver([{"name": "x.test", "type": "A", "state": "timeout"}])
    report = await run(servers, q("example.org"), resolver=resolver)
    assert len(resolver.questions) == 2 * MAX_GLUELESS_LOOKUPS_PER_ZONE
    details = [h.detail_code for h in report.hops if h.kind is HopKind.ns_lookup]
    assert details.count("glueless_limit") == 2
    assert report.outcome is TraceOutcome.no_server_address


# --- failing, lame and looping servers -------------------------------------------------------


REFUSED = {"192.0.2.3": [{"name": "example.com", "type": "A", "state": "refused"}]}


async def test_lame_server_then_good_server() -> None:
    servers = chain(
        [("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.4")],
        {**REFUSED, "192.0.2.4": GOOD["192.0.2.3"]},
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.ok
    assert sent(servers)[-2:] == ["192.0.2.3", "192.0.2.4"]
    lame = report.hops[2]
    assert (lame.kind, lame.state, lame.detail_code) == (
        HopKind.failure,
        ResultState.refused,
        "lame_refused",
    )


async def test_all_servers_lame() -> None:
    servers = chain(
        [("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.4")],
        {**REFUSED, "192.0.2.4": REFUSED["192.0.2.3"]},
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.lame_delegation
    assert report.state is ResultState.error
    assert report.detail_code == "lame_delegation"


@pytest.mark.parametrize(
    "state", ["servfail", "timeout", "network_error", "malformed", "truncated"]
)
async def test_all_servers_fail_is_failure_not_absence(state: str) -> None:
    entry = [{"name": "example.com", "type": "A", "state": state}]
    servers = chain(
        [("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.4")],
        {"192.0.2.3": entry, "192.0.2.4": entry},
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.all_failed
    assert report.state is ResultState.error
    assert [h.state.value for h in report.hops[2:]] == [state, state]
    assert report.answer == ()
    assert_never_missing(report)


async def test_servfail_then_nxdomain_from_next_server() -> None:
    servers = chain(
        [("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.4")],
        {
            "192.0.2.3": [{"name": "nope.example.com", "type": "A", "state": "servfail"}],
            "192.0.2.4": GOOD["192.0.2.3"],
        },
    )
    report = await run(servers, q("nope.example.com"))
    assert report.outcome is TraceOutcome.nxdomain
    assert report.hops[2].state is ResultState.servfail
    assert report.final_server == "192.0.2.4"


async def test_servers_per_zone_cap() -> None:
    ns = [(f"ns{i}.example.com", f"192.0.2.{50 + i}") for i in range(6)]  # all unreachable
    servers = chain(ns, {})
    limits = TraceLimits(max_servers_per_zone=3)
    report = await run(servers, q("example.com"), limits=limits)
    assert sent(servers)[2:] == ["192.0.2.50", "192.0.2.51", "192.0.2.52"]
    assert report.outcome is TraceOutcome.all_failed


@pytest.mark.parametrize(
    ("loop_zone", "detail"),
    [("com", "referral_loop"), (".", "referral_upward")],
)
async def test_referral_that_does_not_move_closer_is_a_loop(loop_zone: str, detail: str) -> None:
    servers = parse_zones(
        {
            "zones": {
                "192.0.2.1": [ref("com", ("a.gtld.example.net", "192.0.2.2"))],
                "192.0.2.2": [ref(loop_zone, ("a.gtld.example.net", "192.0.2.2"))],
            }
        }
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.loop
    assert report.state is ResultState.error
    assert report.hops[-1].detail_code == detail
    assert sent(servers) == ["192.0.2.1", "192.0.2.2"]
    assert_never_missing(report)


async def test_same_zone_server_pair_is_queried_once() -> None:
    servers = chain(
        [("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.3")],
        {"192.0.2.3": [{"name": "example.com", "type": "A", "state": "servfail"}]},
    )
    report = await run(servers, q("example.com"))
    assert sent(servers).count("192.0.2.3") == 1
    assert report.hops[-1].kind is HopKind.skipped
    assert report.hops[-1].detail_code == "repeated_server"
    assert report.outcome is TraceOutcome.all_failed


async def test_query_server_exception_tries_next_server() -> None:
    servers = chain([("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.4")], {})
    servers.servers["192.0.2.4"] = parse_zones({"zones": GOOD}).resolver("192.0.2.3")

    async def flaky(addr: str, question: DnsQuestion) -> Any:
        if addr == "192.0.2.3":
            raise RuntimeError("boom")
        return await servers.query_server(addr, question)

    report = await run(servers, q("example.com"), query_server=flaky)
    assert report.outcome is TraceOutcome.ok
    assert report.hops[2].detail_code == "query_exception"


# --- malformed referrals ---------------------------------------------------------------------


def rewriting(servers: FakeServerSet, at: str, referral: Any) -> Callable[..., Any]:
    """Wrap the fake so that server ``at`` returns ``referral`` (shapes the fixture can't hold)."""

    async def query(addr: str, question: DnsQuestion) -> Any:
        reply = await servers.query_server(addr, question)
        return type(reply)(reply.result, referral) if addr == at else reply

    return query


@pytest.mark.parametrize(
    ("zone", "detail"),
    [
        ("example.net", "referral_out_of_bailiwick"),
        ("other.example.com", "referral_out_of_bailiwick"),  # sibling below, not an ancestor
        ("Example.COM", "bad_referral"),
        ("bad zone", "bad_referral"),
        ("", "bad_referral"),
    ],
)
async def test_malformed_or_out_of_bailiwick_referral(zone: str, detail: str) -> None:
    servers = chain([("ns1.example.com", "192.0.2.3")], GOOD)
    bad = Referral(zone, (NsAddr("ns.evil.example", "192.0.2.66"),))
    report = await run(servers, q("example.com"), query_server=rewriting(servers, "192.0.2.2", bad))
    assert "192.0.2.66" not in sent(servers)
    assert report.hops[-1].kind is HopKind.failure
    assert report.hops[-1].detail_code == detail
    assert report.outcome is TraceOutcome.all_failed
    assert_never_missing(report)


@pytest.mark.parametrize(
    ("addr", "reason"),
    [
        ("not-an-ip", BlockReason.malformed),
        ("ns1.example.net", BlockReason.malformed),
        ("192.0.2.3:5353", BlockReason.malformed),
        ("", BlockReason.malformed),
        (" 192.0.2.3", BlockReason.malformed),
        ("[2001:db8::53]", BlockReason.malformed),
    ],
)
async def test_glue_with_non_address_data_is_blocked(addr: str, reason: BlockReason) -> None:
    servers = chain([("ns1.example.com", "192.0.2.3")], GOOD)
    bad = Referral("example.com", (NsAddr("ns1.example.com", addr),))
    report = await run(servers, q("example.com"), query_server=rewriting(servers, "192.0.2.2", bad))
    assert sent(servers) == ["192.0.2.1", "192.0.2.2"]
    assert report.hops[-1].kind is HopKind.blocked
    assert report.hops[-1].detail_code == reason
    assert report.outcome is TraceOutcome.no_allowed_server


async def test_oversized_referral_is_rejected() -> None:
    ns = tuple(NsAddr(f"ns{i}.example.com", "192.0.2.3") for i in range(MAX_REFERRAL_NS + 1))
    servers = chain([("ns1.example.com", "192.0.2.3")], GOOD)
    big = Referral("example.com", ns)
    report = await run(servers, q("example.com"), query_server=rewriting(servers, "192.0.2.2", big))
    assert report.hops[-1].detail_code == "referral_too_large"
    assert report.outcome is TraceOutcome.all_failed


async def test_oversized_answer_is_rejected() -> None:
    servers = chain(
        [("ns1.example.com", "192.0.2.3")],
        {
            "192.0.2.3": [
                {"name": "example.com", "type": "A", "ttl": 1, "rdata": ["1.1.1.1", "8.8.8.8"]}
            ]
        },
    )
    report = await run(servers, q("example.com"), limits=TraceLimits(max_hop_records=1))
    assert report.hops[-1].detail_code == "oversized_answer"
    assert report.outcome is TraceOutcome.all_failed


# --- authority (AA flag) ---------------------------------------------------------------------


TWO_NS = [("ns1.example.com", "192.0.2.3"), ("ns2.example.com", "192.0.2.4")]


def entry(state_or_rdata: str, aa: bool, name: str = "example.com") -> dict[str, Any]:
    if state_or_rdata in ("nxdomain", "nodata"):
        return {"name": name, "type": "A", "state": state_or_rdata, "aa": aa}
    return {"name": name, "type": "A", "ttl": 60, "rdata": [state_or_rdata], "aa": aa}


@pytest.mark.parametrize("absence", ["nxdomain", "nodata"])
async def test_non_authoritative_absence_is_lame_then_next_server(absence: str) -> None:
    servers = chain(
        TWO_NS, {"192.0.2.3": [entry(absence, False)], "192.0.2.4": [entry(absence, True)]}
    )
    report = await run(servers, q("example.com"))
    lame = report.hops[2]
    assert (lame.kind, lame.state, lame.detail_code) == (
        HopKind.failure,
        ResultState.error,
        "lame_or_non_authoritative",
    )
    assert report.outcome.value == absence
    assert report.final_server == "192.0.2.4"


@pytest.mark.parametrize("absence", ["nxdomain", "nodata"])
async def test_only_non_authoritative_absence_ends_error(absence: str) -> None:
    servers = chain(
        TWO_NS, {"192.0.2.3": [entry(absence, False)], "192.0.2.4": [entry(absence, False)]}
    )
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.lame_delegation
    assert report.state is ResultState.error
    assert report.detail_code == "lame_or_non_authoritative"
    assert_never_missing(report)


async def test_non_authoritative_positive_answer_is_ok_but_flagged() -> None:
    servers = chain(TWO_NS[:1], {"192.0.2.3": [entry("192.0.2.10", False)]})
    report = await run(servers, q("example.com"))
    assert report.outcome is TraceOutcome.ok
    assert report.hops[-1].detail_code == "non_authoritative"
    authoritative = await run(chain(TWO_NS[:1], GOOD), q("example.com"))
    assert authoritative.hops[-1].detail_code is None


async def test_fake_server_set_reports_authority(fake_dns: Any) -> None:
    servers = fake_dns("delegation")
    assert (await servers.query_server("192.0.2.1", q("example.com"))).authoritative is False
    assert (await servers.query_server("192.0.2.3", q("example.com"))).authoritative is True
    assert (await servers.query_server("192.0.2.3", q("nope.example.com"))).authoritative is True
    assert (await servers.query_server("192.0.2.99", q("example.com"))).authoritative is False
    with pytest.raises(ZoneFixtureError, match="`aa` must be a boolean"):
        parse_zones({"zones": {"default": [{**entry("192.0.2.1", True), "aa": "no"}]}})


# --- timeouts raised by collaborators vs the trace deadline ----------------------------------


async def test_timeout_from_query_server_is_a_server_failure() -> None:
    servers = chain(TWO_NS, {"192.0.2.4": GOOD["192.0.2.3"]})

    async def raising(addr: str, question: DnsQuestion) -> Any:
        if addr == "192.0.2.3":
            raise TimeoutError
        return await servers.query_server(addr, question)

    report = await run(servers, q("example.com"), query_server=raising)
    assert report.outcome is TraceOutcome.ok
    assert (report.hops[2].state, report.hops[2].detail_code) == (
        ResultState.timeout,
        "query_timeout",
    )


class TimeoutResolver:
    identity = "stub"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        raise TimeoutError


async def test_timeout_from_resolver_is_a_lookup_failure() -> None:
    servers = glueless_servers(("ns1.example.com",))
    report = await run(servers, q("example.org"), resolver=TimeoutResolver())
    lookups = [h for h in report.hops if h.kind is HopKind.ns_lookup]
    assert [(h.state, h.detail_code) for h in lookups] == [
        (ResultState.timeout, "resolver_timeout"),
        (ResultState.timeout, "resolver_timeout"),
    ]
    assert report.outcome is TraceOutcome.no_server_address


async def test_glueless_addresses_are_capped() -> None:
    servers = glueless_servers(("ns1.example.com",))
    many = [f"192.0.2.{i}" for i in range(100, 110)]
    resolver = ns_resolver(
        [
            {"name": "ns1.example.com", "type": "A", "ttl": 60, "rdata": many},
            {"name": "ns1.example.com", "type": "AAAA", "ttl": 60, "rdata": ["2001:db8::30"]},
        ]
    )
    limits = TraceLimits(max_referral_glue=3, max_servers_per_zone=10)
    report = await run(servers, q("example.org"), resolver=resolver, limits=limits)
    lookups = [h for h in report.hops if h.kind is HopKind.ns_lookup]
    assert [h.detail_code for h in lookups] == ["addresses_capped", "addresses_capped"]
    assert sent(servers)[2:] == many[:3]  # all unreachable; nothing beyond the cap is tried
    assert report.outcome is TraceOutcome.all_failed


# --- the GM note: a referral never reaches the user as "missing" -----------------------------


async def test_referral_reply_with_nodata_placeholder_is_not_missing(fake_dns: Any) -> None:
    servers = fake_dns("delegation")
    raw = await servers.query_server("192.0.2.1", q("example.com"))
    assert raw.referral is not None and raw.result.state is ResultState.nodata  # placeholder
    servers.server_queries.clear()
    report = await run(servers, q("example.com"))
    referrals = [h for h in report.hops if h.kind is HopKind.referral]
    assert len(referrals) == 2
    assert all(h.state is ResultState.ok and h.referral_zone for h in referrals)
    assert all(h.state is not ResultState.nodata for h in report.hops[:-1])


async def test_referral_as_last_reply_is_never_missing() -> None:
    # Every server only refers further, until the depth limit: the outcome is not "nodata".
    servers = chain([("ns1.example.com", "192.0.2.3")], {"192.0.2.3": []})
    servers.resolver("192.0.2.3").zones.referrals.append(
        Referral("a.example.com", (NsAddr("ns.a.example.com", "192.0.2.4"),))
    )
    report = await run(servers, q("a.example.com"), limits=TraceLimits(max_depth=2))
    assert report.outcome is TraceOutcome.depth_exceeded
    assert report.state is ResultState.error
    assert "192.0.2.4" not in sent(servers)
    assert_never_missing(report)


# --- limits ----------------------------------------------------------------------------------


def deep_servers(depth: int) -> tuple[FakeServerSet, DnsQuestion]:
    """root -> com -> example.com -> l1.example.com -> ... (one server per level)."""
    labels = [f"l{i}" for i in range(depth, 0, -1)]
    name = ".".join([*labels, "example", "com"])
    parts = name.split(".")
    zones: dict[str, list[Any]] = {}
    for level in range(len(parts) + 1):
        server = f"192.0.2.{level + 1}"
        if level == len(parts):
            zones[server] = [{"name": name, "type": "A", "ttl": 1, "rdata": ["192.0.2.200"]}]
        else:
            child = ".".join(parts[len(parts) - level - 1 :])
            zones[server] = [ref(child, (f"ns.{child}", f"192.0.2.{level + 2}"))]
    return parse_zones({"zones": zones}), q(name)


async def test_deep_chain_within_limits() -> None:
    servers, question = deep_servers(6)
    report = await run(servers, question)
    assert report.outcome is TraceOutcome.ok
    assert len(report.hops) == 9  # root, com, example.com, l6..l1 = 8 referrals + answer
    assert report.queries_sent == 9


async def test_depth_exceeded() -> None:
    servers, question = deep_servers(6)
    report = await run(servers, question, limits=TraceLimits(max_depth=3))
    assert report.outcome is TraceOutcome.depth_exceeded
    assert report.state is ResultState.error
    assert report.detail_code == "depth_exceeded"
    assert len(servers.server_queries) == 4


async def test_total_query_limit() -> None:
    servers, question = deep_servers(2)
    report = await run(servers, question, limits=TraceLimits(max_total_queries=2))
    assert report.outcome is TraceOutcome.query_limit
    assert report.queries_sent == 2
    assert len(servers.server_queries) == 2


async def test_total_deadline_with_virtual_clock() -> None:
    servers, question = deep_servers(2)
    now = [0.0]

    async def slow(addr: str, question: DnsQuestion) -> Any:
        now[0] += 10.0
        return await servers.query_server(addr, question)

    report = await run(
        servers,
        question,
        limits=TraceLimits(deadline_s=15.0),
        query_server=slow,
        clock=lambda: now[0],
    )
    assert report.outcome is TraceOutcome.deadline
    assert report.state is ResultState.error
    assert len(servers.server_queries) == 2
    assert report.elapsed_ms == 20000.0
    assert report.hops[0].elapsed_ms == 10000.0


async def test_deadline_cancels_a_hanging_query() -> None:
    async def hang(addr: str, question: DnsQuestion) -> Any:
        await asyncio.Event().wait()

    report = await run(
        FakeServerSet({}), q("example.com"), limits=TraceLimits(deadline_s=0.05), query_server=hang
    )
    assert report.outcome is TraceOutcome.deadline
    assert report.hops[-1].state is ResultState.timeout
    assert report.hops[-1].detail_code == "trace_deadline"


def test_default_limits_are_the_named_constants() -> None:
    assert (
        TraceLimits(
            max_depth=MAX_REFERRAL_DEPTH,
            max_total_queries=MAX_TOTAL_QUERIES,
            max_servers_per_zone=MAX_SERVERS_PER_ZONE,
            deadline_s=TOTAL_DEADLINE_S,
            max_referral_ns=MAX_REFERRAL_NS,
            max_referral_glue=MAX_REFERRAL_GLUE,
            max_hop_records=MAX_HOP_RECORDS,
            max_glueless_lookups_per_zone=MAX_GLUELESS_LOOKUPS_PER_ZONE,
        )
        == DEFAULT_LIMITS
    )
    assert (MAX_REFERRAL_DEPTH, MAX_TOTAL_QUERIES, MAX_SERVERS_PER_ZONE) == (16, 64, 4)
    assert TOTAL_DEADLINE_S == 15.0
    assert MAX_HOP_RECORDS == backends.MAX_RECORDS_PER_SECTION


@pytest.mark.parametrize(
    ("outcome", "state"),
    [(o, o.state) for o in TraceOutcome],
)
def test_only_answers_are_evaluations(outcome: TraceOutcome, state: ResultState) -> None:
    if outcome in (TraceOutcome.ok, TraceOutcome.nxdomain, TraceOutcome.nodata):
        assert state.value == outcome.value
    elif outcome is TraceOutcome.cname:
        assert state is ResultState.ok  # an alias was read: evaluated, never absence
    else:
        assert state is ResultState.error


# --- production adapter and no network -------------------------------------------------------


async def test_query_server_adapter_passes_untrusted_port_53_addr() -> None:
    calls: list[tuple[Any, DnsQuestion, dict[str, Any]]] = []

    class Stub:
        async def query_server(self, addr: Any, question: DnsQuestion, **kw: Any) -> Any:
            calls.append((addr, question, kw))
            return backends.ServerReply(DnsResult(question, ResultState.timeout))

    reply = await query_server_for(Stub())("2001:db8::53", q("example.com"))
    assert reply.result.state is ResultState.timeout
    assert calls == [(ResolverAddr("2001:db8::53", 53), q("example.com"), {})]


async def test_no_socket_is_created(fake_dns: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("socket created")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    report = await run(fake_dns("delegation"), q("example.com"))
    assert report.outcome is TraceOutcome.ok


# --- R1-07: CNAME at the query name into another zone (reported, not followed) ---------------

_RR = tuple[str, int, str, list[str]]


class _DocsPolicy(TargetPolicy):
    """The production policy, except that documentation ranges (the fixture addresses) pass."""

    def check(self, addr: ResolverAddr, trusted: bool) -> BlockReason | None:
        reason = DEFAULT_POLICY.check(addr, trusted)
        return None if reason is BlockReason.documentation else reason


def _section(items: list[_RR]) -> list[dns.rrset.RRset]:
    return [dns.rrset.from_text_list(n, ttl, "IN", ty, rd) for n, ttl, ty, rd in items]


def _wire_trace(final: dict[str, Any]) -> tuple[Any, list[str]]:
    """Real ``DnsPythonResolver.query_server`` over hand-built dnspython messages, no sockets:
    the root (192.0.2.1) refers to example.com (ns1.example.com, 192.0.2.3), which answers with
    ``final`` (rcode/answer/authority/flags)."""
    sent_to: list[str] = []

    async def transport(
        wire: bytes, target: ResolverAddr, *, tcp: bool
    ) -> AsyncGenerator[backends.WireReply, None]:
        sent_to.append(target.host)
        resp = dns.message.make_response(dns.message.from_wire(wire))
        if target.host == "192.0.2.1":
            resp.authority = _section([("example.com.", 86400, "NS", ["ns1.example.com."])])
            resp.additional = _section([("ns1.example.com.", 86400, "A", ["192.0.2.3"])])
        else:
            resp.set_rcode(final.get("rcode", dns.rcode.NOERROR))
            resp.flags |= final.get("flags", dns.flags.AA)
            resp.answer = _section(final.get("answer", []))
            resp.authority = _section(final.get("authority", []))
        yield backends.WireReply(resp.to_wire(), target)

    resolver = backends.DnsPythonResolver(
        [], trusted=False, identity="wire", policy=_DocsPolicy(), transport=transport
    )
    return query_server_for(resolver), sent_to


SOA = [("example.com.", 300, "SOA", ["ns1.example.com. h.example.com. 1 2 3 4 5"])]
CNAME_WWW: _RR = ("www.example.com.", 300, "CNAME", ["host.example.net."])

# (id, final server reply, outcome, answer rdata, chain (owner, target), target, hop detail)
TRACE_CNAME_CASES: list[
    tuple[
        str,
        dict[str, Any],
        str,
        tuple[str, ...],
        list[tuple[str, str]],
        str | None,
        str | None,
    ]
] = [
    (
        "cname_into_other_zone",
        {"answer": [CNAME_WWW]},
        "cname",
        (),
        [("www.example.com", "host.example.net")],
        "host.example.net",
        "cname",
    ),
    (
        "in_zone_then_other_zone",
        {
            "answer": [
                ("www.example.com.", 300, "CNAME", ["a.example.com."]),
                ("a.example.com.", 300, "CNAME", ["host.example.net."]),
            ],
            "authority": SOA,
        },
        "cname",
        (),
        [("www.example.com", "a.example.com"), ("a.example.com", "host.example.net")],
        "host.example.net",
        "cname",
    ),
    (
        "non_authoritative_cname_flagged",
        {"answer": [CNAME_WWW], "flags": 0},
        "cname",
        (),
        [("www.example.com", "host.example.net")],
        "host.example.net",
        "non_authoritative",
    ),
    (
        "in_zone_chain_with_record_is_ok",
        {
            "answer": [
                ("www.example.com.", 300, "CNAME", ["a.example.com."]),
                ("a.example.com.", 300, "A", ["192.0.2.7"]),
            ]
        },
        "ok",
        ("192.0.2.7",),
        [],
        None,
        None,
    ),
    ("empty_aa_noerror_is_nodata", {"authority": SOA}, "nodata", (), [], None, None),
    (
        "nxdomain_with_cname_is_nxdomain",
        {"rcode": dns.rcode.NXDOMAIN, "answer": [CNAME_WWW], "authority": SOA},
        "nxdomain",
        (),
        [],
        None,
        None,
    ),
]


@pytest.mark.parametrize(
    ("final", "outcome", "answer", "chain", "target", "detail"),
    [c[1:] for c in TRACE_CNAME_CASES],
    ids=[c[0] for c in TRACE_CNAME_CASES],
)
async def test_cname_at_query_name(
    final: dict[str, Any],
    outcome: str,
    answer: tuple[str, ...],
    chain: list[tuple[str, str]],
    target: str | None,
    detail: str | None,
) -> None:
    query_server, sent_to = _wire_trace(final)
    report = await trace(
        q("www.example.com"), query_server=query_server, root_hints=ROOTS, policy=FixturePolicy()
    )
    assert report.outcome.value == outcome
    assert tuple(r.rdata_text for r in report.answer) == answer
    assert sent_to == ["192.0.2.1", "192.0.2.3"]  # the target is reported, never followed
    last = report.hops[-1]
    assert last.kind is HopKind.answer
    assert last.detail_code == detail
    assert [(r.name, r.rdata_text) for r in report.cname_chain] == chain
    assert report.cname_target == target
    if outcome == "cname":
        assert report.state is ResultState.ok  # evaluated; neither an error nor "no record"
        assert last.state is ResultState.ok
        assert [(r.name, r.rdtype, r.rdata_text) for r in last.records] == [
            (n, "CNAME", t) for n, t in chain
        ]
        assert (report.final_zone, report.final_server) == ("example.com", "192.0.2.3")
    assert_never_missing(report)
