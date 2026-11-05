"""M2-05 dnspython backends. No network, no sockets: the transport is injected and fed canned
wire messages built with dnspython."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from app.core.config import ResolverAddr, Settings
from app.dns.backends import (
    EDNS_PAYLOAD,
    MAX_RECORDS_PER_SECTION,
    MAX_RESPONSE_BYTES,
    BlockedResolver,
    DnsPythonResolver,
    ResponseTooLarge,
    ServerReply,
    WireReply,
    classify_exception,
)
from app.dns.egress import BlockReason, TargetPolicy
from app.dns.factory import build_resolver, build_resolver_for_target, system_nameservers
from app.dns.types import DnsQuestion, ResultState

S = ResultState
NS1 = ResolverAddr("172.28.53.2", 5353)  # trusted (operator-configured)
NS2 = ResolverAddr("10.0.0.2", 53)
PUBLIC = ResolverAddr("1.1.1.1", 53)  # globally routable; never actually contacted
Q_A = DnsQuestion("example.com", "A")
SECRET = "s" * 40

Handler = Callable[[dns.message.Message, ResolverAddr, bool], bytes | WireReply | BaseException]


@pytest.fixture(autouse=True)
async def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Async so the event loop (which owns a self-pipe socketpair) exists before patching."""

    def boom(*_a: Any, **_k: Any) -> None:
        raise AssertionError("socket created in a unit test")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)


class FakeTransport:
    """Records every packet; the handler builds the reply from the parsed query."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.calls: list[tuple[ResolverAddr, bool]] = []
        self.queries: list[dns.message.Message] = []

    async def __call__(self, wire: bytes, target: ResolverAddr, *, tcp: bool) -> WireReply:
        self.calls.append((target, tcp))
        query = dns.message.from_wire(wire)
        self.queries.append(query)
        out = self.handler(query, target, tcp)
        if isinstance(out, BaseException):
            raise out
        return out if isinstance(out, WireReply) else WireReply(out)


def response(
    query: dns.message.Message,
    *,
    rcode: int = dns.rcode.NOERROR,
    answer: list[tuple[str, int, str, list[str]]] = (),  # type: ignore[assignment]
    authority: list[tuple[str, int, str, list[str]]] = (),  # type: ignore[assignment]
    additional: list[tuple[str, int, str, list[str]]] = (),  # type: ignore[assignment]
    flags: int = 0,
) -> dns.message.Message:
    resp = dns.message.make_response(query)
    resp.set_rcode(rcode)
    resp.flags |= flags
    for section, items in ((resp.answer, answer), (resp.authority, authority)):
        for name, ttl, rdtype, rdatas in items:
            section.append(dns.rrset.from_text_list(name, ttl, "IN", rdtype, rdatas))
    for name, ttl, rdtype, rdatas in additional:
        resp.additional.append(dns.rrset.from_text_list(name, ttl, "IN", rdtype, rdatas))
    return resp


def wire(resp: dns.message.Message) -> bytes:
    return resp.to_wire(max_size=65535)


def answer_with(**kw: Any) -> Handler:
    return lambda q, _t, _tcp: wire(response(q, **kw))


def custom(transport: FakeTransport, **kw: Any) -> DnsPythonResolver:
    nameservers = kw.pop("nameservers", [NS1])
    return DnsPythonResolver(
        nameservers, trusted=True, identity="custom", transport=transport, **kw
    )


# --- rcode mapping -----------------------------------------------------------------------------

A_ANSWER = [("example.com.", 300, "A", ["192.0.2.10", "192.0.2.11"])]

RCODE_CASES = [
    ("noerror_answer", dns.rcode.NOERROR, A_ANSWER, S.ok, 0),
    ("noerror_empty", dns.rcode.NOERROR, [], S.nodata, 0),
    ("nxdomain", dns.rcode.NXDOMAIN, [], S.nxdomain, 3),
    ("servfail", dns.rcode.SERVFAIL, [], S.servfail, 2),
    ("refused", dns.rcode.REFUSED, [], S.refused, 5),
    ("formerr", dns.rcode.FORMERR, [], S.error, 1),
    ("notimp", dns.rcode.NOTIMP, [], S.error, 4),
    ("yxdomain", dns.rcode.YXDOMAIN, [], S.error, 6),
    ("notauth", dns.rcode.NOTAUTH, [], S.error, 9),
    ("badvers_extended", dns.rcode.BADVERS, [], S.error, 16),
    # Answer records next to SERVFAIL must not turn it into ok.
    ("servfail_with_records", dns.rcode.SERVFAIL, A_ANSWER, S.servfail, 2),
]


@pytest.mark.parametrize(
    ("rcode", "answer", "state", "expected_rcode"),
    [c[1:] for c in RCODE_CASES],
    ids=[c[0] for c in RCODE_CASES],
)
async def test_rcode_mapping(
    rcode: int, answer: list[Any], state: ResultState, expected_rcode: int
) -> None:
    t = FakeTransport(answer_with(rcode=rcode, answer=answer))
    result = await custom(t).resolve(Q_A)
    assert result.state is state
    assert result.rcode == expected_rcode
    assert result.server == "172.28.53.2:5353"
    assert len(t.calls) == 1  # no retry on any rcode
    if state is S.ok:
        assert [r.rdata_text for r in result.records] == ["192.0.2.10", "192.0.2.11"]
        assert result.ttl_min == 300


EXCEPTION_CASES = [
    ("dns_timeout", dns.exception.Timeout(), S.timeout),
    ("timeout_error", TimeoutError(), S.timeout),
    ("conn_refused", ConnectionRefusedError(), S.network_error),
    ("conn_reset", ConnectionResetError(), S.network_error),
    ("os_error", OSError(101, "Network is unreachable"), S.network_error),
    ("eof", EOFError(), S.network_error),
    ("incomplete_read", asyncio.IncompleteReadError(b"\x00", 2), S.network_error),
    ("too_large", ResponseTooLarge(70000), S.malformed),
    ("form_error", dns.exception.FormError(), S.malformed),
    ("runtime_error", RuntimeError("boom"), S.error),
    ("value_error", ValueError("boom"), S.error),
    ("key_error", KeyError("boom"), S.error),
    ("generic_dns_exception", dns.exception.DNSException(), S.error),
]


@pytest.mark.parametrize(
    ("exc", "state"), [c[1:] for c in EXCEPTION_CASES], ids=[c[0] for c in EXCEPTION_CASES]
)
async def test_exception_mapping(exc: BaseException, state: ResultState) -> None:
    assert classify_exception(exc)[0] is state
    t = FakeTransport(lambda _q, _t, _tcp: exc)
    result = await custom(t).resolve(Q_A)
    assert result.state is state
    assert result.records == ()


# --- malformed responses -----------------------------------------------------------------------


def _id_mismatch(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    resp = response(q, answer=A_ANSWER)
    resp.id = (q.id + 1) % 65536
    return wire(resp)


def _wrong_question(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    other = dns.message.make_query("other.example.com", "A", id=q.id)
    other.flags = q.flags
    return wire(response(other, answer=[("other.example.com.", 300, "A", ["192.0.2.1"])]))


def _not_a_response(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    return q.to_wire()  # QR bit not set


def _cut_mid_record(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    return wire(response(q, answer=A_ANSWER))[:-3]  # TC not set: just broken


def _trailing_junk(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    return wire(response(q, answer=A_ANSWER)) + b"\xde\xad"


def _too_many(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    ips = [f"192.0.2.{i % 250}" if i < 250 else "192.0.2.1" for i in range(1, 200)]
    ips = list(dict.fromkeys(ips))[: MAX_RECORDS_PER_SECTION + 1]
    return wire(response(q, answer=[("example.com.", 300, "A", ips)]))


def _oversized(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    return wire(response(q, answer=A_ANSWER)) + b"\x00" * MAX_RESPONSE_BYTES


def _unexpected_source(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> WireReply:
    return WireReply(wire(response(q, answer=A_ANSWER)), ResolverAddr("192.0.2.66", 5353))


def _cname_loop(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> bytes:
    return wire(
        response(
            q,
            answer=[
                ("example.com.", 300, "CNAME", ["a.example.com."]),
                ("a.example.com.", 300, "CNAME", ["example.com."]),
            ],
        )
    )


MALFORMED_CASES: list[tuple[str, Handler, str]] = [
    ("garbage", lambda _q, _t, _tcp: b"\xff\xfe garbage bytes \x00\x01", "unparseable"),
    ("empty", lambda _q, _t, _tcp: b"", "unparseable"),
    ("short_header", lambda _q, _t, _tcp: b"\x12\x34\x81", "unparseable"),
    ("cut_mid_record", _cut_mid_record, "unparseable"),
    ("trailing_junk", _trailing_junk, "unparseable"),
    ("id_mismatch", _id_mismatch, "mismatched_response"),
    ("wrong_question", _wrong_question, "mismatched_response"),
    ("not_a_response", _not_a_response, "mismatched_response"),
    ("too_many_records", _too_many, "too_many_records"),
    ("oversized", _oversized, "oversized"),
    ("unexpected_source", _unexpected_source, "unexpected_source"),
    ("cname_loop", _cname_loop, "bad_cname_chain"),
]


@pytest.mark.parametrize(
    ("handler", "detail"), [c[1:] for c in MALFORMED_CASES], ids=[c[0] for c in MALFORMED_CASES]
)
async def test_malformed_responses(handler: Handler, detail: str) -> None:
    t = FakeTransport(handler)
    result = await custom(t).resolve(Q_A)
    assert result.state is S.malformed
    assert result.detail_code == detail
    assert len(t.calls) == 1  # malformed is not retried


async def test_expected_source_is_accepted() -> None:
    t = FakeTransport(
        lambda q, _t, _tcp: WireReply(
            wire(response(q, answer=A_ANSWER)), ResolverAddr("172.28.53.2", 5353)
        )
    )
    assert (await custom(t).resolve(Q_A)).state is S.ok


# --- the M2 acceptance line: failures are never absence ---------------------------------------

NEVER_ABSENCE: list[tuple[str, Handler]] = [
    ("servfail", answer_with(rcode=dns.rcode.SERVFAIL)),
    ("refused", answer_with(rcode=dns.rcode.REFUSED)),
    ("timeout", lambda _q, _t, _tcp: dns.exception.Timeout()),
    ("network", lambda _q, _t, _tcp: ConnectionRefusedError()),
    ("garbage", lambda _q, _t, _tcp: b"\x00"),
    ("truncated", lambda q, _t, _tcp: wire(response(q, flags=dns.flags.TC))),
    ("unknown_exception", lambda _q, _t, _tcp: RuntimeError()),
]


@pytest.mark.parametrize(
    "handler", [c[1] for c in NEVER_ABSENCE], ids=[c[0] for c in NEVER_ABSENCE]
)
async def test_failures_never_map_to_absence(handler: Handler) -> None:
    result = await custom(FakeTransport(handler)).resolve(Q_A)
    assert result.state not in (S.nxdomain, S.nodata)
    assert result.state.is_failure
    reply = await custom(FakeTransport(handler)).query_server(NS1, Q_A)
    assert reply.result.state not in (S.nxdomain, S.nodata)
    assert reply.referral is None


# --- truncation / TCP fallback -----------------------------------------------------------------


async def test_tc_falls_back_to_tcp() -> None:
    def handler(q: dns.message.Message, _t: ResolverAddr, tcp: bool) -> bytes:
        if tcp:
            return wire(response(q, answer=A_ANSWER))
        return wire(response(q, flags=dns.flags.TC))

    t = FakeTransport(handler)
    result = await custom(t).resolve(Q_A)
    assert result.state is S.ok
    assert [tcp for _, tcp in t.calls] == [False, True]


async def test_tc_with_cut_payload_falls_back_to_tcp() -> None:
    def handler(q: dns.message.Message, _t: ResolverAddr, tcp: bool) -> bytes:
        data = wire(response(q, answer=A_ANSWER, flags=dns.flags.TC if not tcp else 0))
        return data if tcp else data[:-3]

    t = FakeTransport(handler)
    assert (await custom(t).resolve(Q_A)).state is S.ok
    assert [tcp for _, tcp in t.calls] == [False, True]


async def test_tc_over_tcp_is_truncated() -> None:
    t = FakeTransport(lambda q, _t, _tcp: wire(response(q, flags=dns.flags.TC)))
    result = await custom(t).resolve(Q_A)
    assert result.state is S.truncated
    assert [tcp for _, tcp in t.calls] == [False, True]


# --- retries, deadline, semaphore --------------------------------------------------------------


RETRY_CASES: list[tuple[str, list[Any], ResultState, int]] = [
    ("timeout_then_ok", [dns.exception.Timeout(), A_ANSWER], S.ok, 2),
    ("network_then_ok", [ConnectionResetError(), A_ANSWER], S.ok, 2),
    ("always_timeout", [dns.exception.Timeout()] * 5, S.timeout, 3),
    ("nxdomain_no_retry", [dns.rcode.NXDOMAIN], S.nxdomain, 1),
    ("nodata_no_retry", [[]], S.nodata, 1),
    ("refused_no_retry", [dns.rcode.REFUSED], S.refused, 1),
    ("servfail_no_retry", [dns.rcode.SERVFAIL], S.servfail, 1),
    ("malformed_no_retry", [b"\x00"], S.malformed, 1),
]


@pytest.mark.parametrize(
    ("script", "state", "calls"), [c[1:] for c in RETRY_CASES], ids=[c[0] for c in RETRY_CASES]
)
async def test_retry_policy(script: list[Any], state: ResultState, calls: int) -> None:
    steps = iter(script)

    def handler(q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> Any:
        step = next(steps)
        if isinstance(step, BaseException | bytes):
            return step
        if isinstance(step, int):
            return wire(response(q, rcode=step))
        return wire(response(q, answer=step))

    t = FakeTransport(handler)
    assert (await custom(t).resolve(Q_A)).state is state
    assert len(t.calls) == calls


async def test_retries_rotate_over_nameservers() -> None:
    t = FakeTransport(lambda _q, _t, _tcp: dns.exception.Timeout())
    await custom(t, nameservers=[NS1, NS2]).resolve(Q_A)
    assert [a for a, _ in t.calls] == [NS1, NS2, NS1]


async def test_total_deadline_stops_retries() -> None:
    now = [0.0]

    def handler(_q: dns.message.Message, _t: ResolverAddr, _tcp: bool) -> BaseException:
        now[0] += 3.0  # each attempt "takes" 3 s on the virtual clock
        return dns.exception.Timeout()

    t = FakeTransport(handler)
    r = custom(t, clock=lambda: now[0], deadline_s=5.0, max_attempts=10)
    result = await r.resolve(Q_A)
    assert result.state is S.timeout
    assert len(t.calls) == 2  # t=0 and t=3; at t=6 the deadline has passed
    assert result.elapsed_ms == pytest.approx(6000.0)


async def test_per_query_timeout_is_enforced() -> None:
    async def slow(_w: bytes, _t: ResolverAddr, *, tcp: bool) -> WireReply:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")

    r = DnsPythonResolver(
        [NS1], trusted=True, identity="x", transport=slow, query_timeout_s=0.01, max_attempts=1
    )
    assert (await r.resolve(Q_A)).state is S.timeout


async def test_one_query_in_flight_per_nameserver() -> None:
    in_flight: dict[str, int] = {}
    peak: dict[str, int] = {}

    async def transport(w: bytes, target: ResolverAddr, *, tcp: bool) -> WireReply:
        key = target.host
        in_flight[key] = in_flight.get(key, 0) + 1
        peak[key] = max(peak.get(key, 0), in_flight[key])
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        in_flight[key] -= 1
        return WireReply(wire(response(dns.message.from_wire(w), answer=A_ANSWER)))

    one = DnsPythonResolver([NS1], trusted=True, identity="x", transport=transport)
    other = DnsPythonResolver([NS2], trusted=True, identity="y", transport=transport)
    results = await asyncio.gather(*(one.resolve(Q_A) for _ in range(5)), other.resolve(Q_A))
    assert all(r.state is S.ok for r in results)
    assert peak == {"172.28.53.2": 1, "10.0.0.2": 1}
    assert one._slots._slots == {}  # semaphores are released and dropped


# --- query construction, CNAME, rdata, AD ------------------------------------------------------


async def test_query_construction_custom() -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    await custom(t).resolve(Q_A)
    q = t.queries[0]
    assert q.question[0].name == dns.name.from_text("example.com")
    assert q.question[0].rdtype == dns.rdatatype.A
    assert q.flags & dns.flags.RD
    assert q.edns == 0 and q.payload == EDNS_PAYLOAD
    assert not q.ednsflags & dns.flags.DO


AD_CASES = [
    ("unbound_ad", True, dns.flags.AD, True),
    ("unbound_no_ad", True, 0, False),
    ("custom_ignores_ad", False, dns.flags.AD, False),
]


@pytest.mark.parametrize(
    ("dnssec_ok", "flags", "expected"), [c[1:] for c in AD_CASES], ids=[c[0] for c in AD_CASES]
)
async def test_ad_flag(dnssec_ok: bool, flags: int, expected: bool) -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER, flags=flags))
    result = await custom(t, dnssec_ok=dnssec_ok).resolve(Q_A)
    assert result.authenticated_data is expected
    assert bool(t.queries[0].ednsflags & dns.flags.DO) is dnssec_ok


CNAME_CASES: list[tuple[str, int, list[Any], ResultState, list[tuple[str, str]], int | None]] = [
    (
        "chain_to_a",
        dns.rcode.NOERROR,
        [
            ("example.com.", 600, "CNAME", ["a.example.net."]),
            ("a.example.net.", 60, "CNAME", ["b.example.net."]),
            ("b.example.net.", 300, "A", ["192.0.2.7"]),
        ],
        S.ok,
        [("b.example.net", "192.0.2.7")],
        60,
    ),
    (
        "cname_to_nothing",
        dns.rcode.NOERROR,
        [("example.com.", 600, "CNAME", ["gone.example.net."])],
        S.nodata,
        [],
        None,
    ),
    (
        "cname_to_nxdomain",
        dns.rcode.NXDOMAIN,
        [("example.com.", 600, "CNAME", ["gone.example.net."])],
        S.nxdomain,
        [],
        None,
    ),
    (
        "unrelated_records_ignored",
        dns.rcode.NOERROR,
        [("other.example.com.", 300, "A", ["192.0.2.9"])],
        S.nodata,
        [],
        None,
    ),
]


@pytest.mark.parametrize(
    ("rcode", "answer", "state", "records", "ttl_min"),
    [c[1:] for c in CNAME_CASES],
    ids=[c[0] for c in CNAME_CASES],
)
async def test_cname_chain_server_side(
    rcode: int,
    answer: list[Any],
    state: ResultState,
    records: list[tuple[str, str]],
    ttl_min: int | None,
) -> None:
    t = FakeTransport(answer_with(rcode=rcode, answer=answer))
    result = await custom(t).resolve(Q_A)
    assert result.state is state
    assert [(r.name, r.rdata_text) for r in result.records] == records
    assert result.ttl_min == ttl_min
    assert len(t.calls) == 1  # never follows the chain client-side


RDATA_CASES = [
    (
        "mx",
        "MX",
        ["10 mx1.example.com.", "20 mx2.example.com."],
        ["10 mx1.example.com", "20 mx2.example.com"],
    ),
    ("null_mx", "MX", ["0 ."], ["0 ."]),
    ("txt_joined", "TXT", ['"v=DKIM1; k=rsa; " "p=AAAA"'], ["v=DKIM1; k=rsa; p=AAAA"]),
    ("txt_binary", "TXT", ['"\\255\\000x"'], ["\xff\x00x"]),
    ("cname_type", "CNAME", ["target.example.net."], ["target.example.net"]),
    ("aaaa", "AAAA", ["2001:db8::1"], ["2001:db8::1"]),
    ("caa", "CAA", ['0 iodef "mailto:a@example.com"'], ['0 iodef "mailto:a@example.com"']),
]


@pytest.mark.parametrize(
    ("rdtype", "rdatas", "expected"), [c[1:] for c in RDATA_CASES], ids=[c[0] for c in RDATA_CASES]
)
async def test_rdata_text(rdtype: str, rdatas: list[str], expected: list[str]) -> None:
    t = FakeTransport(answer_with(answer=[("Example.COM.", 300, rdtype, rdatas)]))
    result = await custom(t).resolve(DnsQuestion("example.com", rdtype))
    assert result.state is S.ok
    assert sorted(r.rdata_text for r in result.records) == sorted(expected)
    assert {r.name for r in result.records} == {"example.com"}


async def test_root_question() -> None:
    t = FakeTransport(
        answer_with(answer=[(".", 86400, "NS", ["a.root-servers.net."])], flags=dns.flags.AA)
    )
    result = await custom(t).resolve(DnsQuestion(".", "NS"))
    assert result.state is S.ok
    assert result.records[0].name == "."
    assert result.records[0].rdata_text == "a.root-servers.net"


# --- referrals (query_server) ------------------------------------------------------------------

REFERRAL = {
    "authority": [("example.com.", 86400, "NS", ["ns1.example.com.", "ns2.example.net."])],
    "additional": [
        ("ns1.example.com.", 86400, "A", ["192.0.2.53"]),
        ("ns2.example.net.", 86400, "A", ["198.51.100.53"]),  # out of bailiwick: ignored
        ("unrelated.example.com.", 86400, "A", ["192.0.2.99"]),  # not an NS name: ignored
    ],
}


async def test_query_server_returns_referral() -> None:
    t = FakeTransport(answer_with(**REFERRAL))
    reply = await custom(t).query_server(PUBLIC, DnsQuestion("www.example.com", "A"))
    assert isinstance(reply, ServerReply)
    assert reply.referral is not None
    assert reply.referral.zone == "example.com"
    assert [(n.name, n.addr) for n in reply.referral.ns] == [("ns1.example.com", "192.0.2.53")]
    assert reply.referral.ns_names == ("ns1.example.com", "ns2.example.net")
    assert reply.result.state is S.nodata  # placeholder: callers check referral first
    assert not t.queries[0].flags & dns.flags.RD


REFERRAL_EDGE_CASES: list[tuple[str, dict[str, Any], ResultState, bool]] = [
    (
        "aa_nodata_with_soa",
        {
            "authority": [
                ("example.com.", 300, "SOA", ["ns1.example.com. h.example.com. 1 2 3 4 5"])
            ],
            "flags": dns.flags.AA,
        },
        S.nodata,
        False,
    ),
    ("aa_with_ns_is_not_referral", {**REFERRAL, "flags": dns.flags.AA}, S.nodata, False),
    (
        "out_of_bailiwick_ns",
        {
            "authority": [("example.org.", 86400, "NS", ["ns1.example.org."])],
        },
        S.malformed,
        False,
    ),
    (
        "root_referral",
        {
            "authority": [(".", 86400, "NS", ["a.root-servers.net."])],
        },
        S.nodata,
        True,
    ),
]


@pytest.mark.parametrize(
    ("kw", "state", "has_referral"),
    [c[1:] for c in REFERRAL_EDGE_CASES],
    ids=[c[0] for c in REFERRAL_EDGE_CASES],
)
async def test_referral_edge_cases(
    kw: dict[str, Any], state: ResultState, has_referral: bool
) -> None:
    reply = await custom(FakeTransport(answer_with(**kw))).query_server(
        PUBLIC, DnsQuestion("www.example.com", "A")
    )
    assert reply.result.state is state
    assert (reply.referral is not None) is has_referral


async def test_resolve_never_returns_referral() -> None:
    result = await custom(FakeTransport(answer_with(**REFERRAL))).resolve(
        DnsQuestion("www.example.com", "A")
    )
    assert result.state is S.error
    assert result.detail_code == "unexpected_referral"


# --- egress policy -----------------------------------------------------------------------------

UNTRUSTED_TARGETS = [
    ("private", "10.0.0.1", BlockReason.private),
    ("bundled_unbound_untrusted", "172.28.53.2", BlockReason.private),
    ("loopback", "127.0.0.1", BlockReason.loopback),
    ("metadata", "169.254.169.254", BlockReason.link_local),
    ("port", "1.1.1.1:5353", BlockReason.port_not_allowed),
    ("hostname", "dns.example.com", BlockReason.malformed),
    ("garbage", "1.1.1.1:53:53", BlockReason.malformed),
    ("documentation", "192.0.2.1", BlockReason.documentation),
]


@pytest.mark.parametrize(
    ("target", "reason"), [c[1:] for c in UNTRUSTED_TARGETS], ids=[c[0] for c in UNTRUSTED_TARGETS]
)
async def test_untrusted_target_blocked_before_any_packet(target: str, reason: BlockReason) -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    r = build_resolver_for_target(target, transport=t)
    assert isinstance(r, BlockedResolver)
    result = await r.resolve(Q_A)
    assert result.state is S.blocked
    assert result.detail_code == reason
    assert (await r.query_server(target, Q_A)).result.state is S.blocked
    assert t.calls == []


async def test_untrusted_public_target_allowed() -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    r = build_resolver_for_target("1.1.1.1", transport=t)
    assert isinstance(r, DnsPythonResolver)
    assert not r.trusted and r.identity == "target:1.1.1.1:53"
    assert (await r.resolve(Q_A)).state is S.ok
    assert t.calls == [(PUBLIC, False)]


QUERY_SERVER_TARGETS = [
    ("configured_trusted", NS1, S.ok),  # configured nameserver: trusted, private + 5353 ok
    ("other_private_untrusted", ResolverAddr("172.28.53.3", 5353), S.blocked),
    ("configured_host_other_port", ResolverAddr("172.28.53.2", 53), S.blocked),
    ("public", PUBLIC, S.ok),
    ("string_public", "1.1.1.1", S.ok),
    ("string_hostname", "ns1.example.com", S.blocked),
    ("string_private", "10.0.0.53", S.blocked),
    ("string_empty", "", S.blocked),
]


@pytest.mark.parametrize(
    ("addr", "state"),
    [c[1:] for c in QUERY_SERVER_TARGETS],
    ids=[c[0] for c in QUERY_SERVER_TARGETS],
)
async def test_query_server_policy(addr: str | ResolverAddr, state: ResultState) -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    reply = await custom(t).query_server(addr, Q_A)
    assert reply.result.state is state
    assert (t.calls == []) is (state is S.blocked)


class _CountingPolicy(TargetPolicy):
    """Allows the first `allow` checks, then blocks: proves the check runs per packet."""

    def __init__(self, allow: int) -> None:
        object.__setattr__(self, "untrusted_port", 53)
        object.__setattr__(self, "_left", [allow])

    def check(self, addr: ResolverAddr, trusted: bool) -> BlockReason | None:
        left: list[int] = object.__getattribute__(self, "_left")
        left[0] -= 1
        return None if left[0] >= 0 else BlockReason.private


async def test_policy_checked_before_every_packet() -> None:
    # 1 check in resolve() pre-filter, 1 before the UDP packet; the TCP fallback is blocked.
    def handler(q: dns.message.Message, _t: ResolverAddr, tcp: bool) -> bytes:
        return wire(response(q, flags=0 if tcp else dns.flags.TC))

    t = FakeTransport(handler)
    r = DnsPythonResolver(
        [NS1], trusted=True, identity="x", transport=t, policy=_CountingPolicy(allow=2)
    )
    result = await r.resolve(Q_A)
    assert result.state is S.blocked
    assert t.calls == [(NS1, False)]


async def test_trusted_resolver_with_malformed_nameserver_is_blocked() -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    r = DnsPythonResolver(
        [ResolverAddr("fe80::1%eth0", 53)], trusted=True, identity="system", transport=t
    )
    result = await r.resolve(Q_A)
    assert result.state is S.blocked and result.detail_code == BlockReason.malformed
    assert t.calls == []


# --- factory -----------------------------------------------------------------------------------


def settings(**kw: str) -> Settings:
    return Settings(secret_key=SECRET, encryption_key=SECRET, **kw)


RESOLV_CASES = [
    ("v4_v6", "nameserver 192.0.2.1\nnameserver 2001:db8::1\n", ["192.0.2.1", "2001:db8::1"]),
    (
        "comments",
        "# c\nsearch example.com\nnameserver 192.0.2.1 \noptions ndots:2\n",
        ["192.0.2.1"],
    ),
    ("no_nameserver", "search example.com\n", []),
    ("garbage", "\x00\xff nameserver\n:::\n", []),
]


@pytest.mark.parametrize(
    ("content", "expected"), [c[1:] for c in RESOLV_CASES], ids=[c[0] for c in RESOLV_CASES]
)
def test_system_nameservers(tmp_path: Path, content: str, expected: list[str]) -> None:
    path = tmp_path / "resolv.conf"
    path.write_text(content, encoding="latin-1")
    addrs = system_nameservers(str(path))
    assert [a.host for a in addrs] == expected
    assert all(a.port == 53 for a in addrs)


async def test_build_system_resolver(tmp_path: Path) -> None:
    path = tmp_path / "resolv.conf"
    path.write_text("nameserver 192.0.2.1\n")
    r = build_resolver(settings(resolver_mode="system"), resolv_conf=str(path))
    assert r.identity == "system" and r.trusted and not r.dnssec_ok
    assert r.nameservers == (ResolverAddr("192.0.2.1", 53),)


async def test_build_system_resolver_without_resolv_conf(tmp_path: Path) -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    r = build_resolver(
        settings(resolver_mode="system"), transport=t, resolv_conf=str(tmp_path / "missing")
    )
    result = await r.resolve(Q_A)
    assert result.state is S.error and result.detail_code == "no_nameservers"
    assert t.calls == []


async def test_build_custom_resolver() -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER))
    r = build_resolver(
        settings(resolver_mode="custom", resolver_addrs="10.0.0.2,[2001:db8::2]:5300"), transport=t
    )
    assert r.trusted and not r.dnssec_ok
    assert r.identity == "custom:10.0.0.2:53,[2001:db8::2]:5300"
    assert (await r.resolve(Q_A)).state is S.ok
    assert t.calls == [(NS2, False)]


async def test_build_unbound_resolver() -> None:
    t = FakeTransport(answer_with(answer=A_ANSWER, flags=dns.flags.AD))
    r = build_resolver(
        settings(resolver_mode="unbound", resolver_addrs="172.28.53.2:5353"), transport=t
    )
    assert r.trusted and r.dnssec_ok and r.identity == "unbound:172.28.53.2:5353"
    result = await r.resolve(Q_A)
    assert result.state is S.ok and result.authenticated_data
    assert t.queries[0].ednsflags & dns.flags.DO
