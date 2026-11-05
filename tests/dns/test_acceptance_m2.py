"""M2 acceptance (TODO.md): "tests pass against recorded zones; SERVFAIL/timeout never reported
as 'record missing'", asserted through the whole stack: backend mapping, cache, lookup service,
propagation, trace, REST API and rendered HTML. No network (tests/dns/conftest.py enforces it).

Zones are the recorded fixtures of tests/support (FakeServerSet). The API and the UI are driven
through the real app with the same backend, so the same query must give the same state on both.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import html as htmllib
import re
from pathlib import Path
from typing import Any

import dns.exception
import dns.flags
import dns.rcode
import pytest

from app.api.v1.dns_tools import DnsBackend, dns_backend
from app.core.csrf import CSRF_HEADER
from app.core.i18n import load_catalogue
from app.dns.backends import BlockedResolver
from app.dns.cache import CachingResolver
from app.dns.egress import BlockReason
from app.dns.knowledge import PublicResolver
from app.dns.trace import DEFAULT_LIMITS, HopKind, TraceOutcome, TraceReport, trace
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.services.dns_propagation import Verdict, check_propagation
from app.services.dns_tools import FcrdnsState, LookupResolvers, lookup, reverse
from tests.dns.test_backends import (
    NS1,
    Q_A,
    FakeTransport,
    Handler,
    answer_with,
    custom,
    response,
    wire,
)
from tests.support.dns_backend import ZONES, fake_backend
from tests.support.dns_zones import FakeResolver, FakeServerSet, is_reserved_name

from tests.web.test_dns_tools_ui import _strict_mode, world  # noqa: F401  # isort: skip
from tests.web.test_domains_ui import World, _login, post

S = ResultState
ROOT = Path(__file__).resolve().parents[2]

ZONE_FAILURES = ("servfail", "refused", "timeout", "truncated", "malformed", "network_error")
HOST = {s: f"{s.replace('_', '-')}.example.com" for s in ZONE_FAILURES}
MIXED = {s: f"mixed-{s.replace('_', '-')}.example.com" for s in ZONE_FAILURES}
# A REFUSED authoritative server is a lame delegation (M2-09); every other failure: all_failed.
TRACE_OUTCOME = {s: "all_failed" for s in ZONE_FAILURES} | {"refused": "lame_delegation"}
ABSENCE_STATES = (S.nxdomain, S.nodata)
STATE_BOX = re.compile(r'class="dns-state dns-state-(\w+)" data-state="(\w+)" data-kind="(\w+)"')
HOP = re.compile(r'class="dns-hop" data-kind="(\w+)" data-state="(\w+)"')
PTR_STATE = re.compile(r'data-testid="reverse-result".*?data-state="(\w+)"', re.S)


# --- the recorded world -------------------------------------------------------------------------


def _fail(name: str, state: str, rtype: str = "A") -> dict[str, Any]:
    return {"name": name, "type": rtype, "state": state}


def _a(name: str, address: str) -> dict[str, Any]:
    return {"name": name, "type": "A", "ttl": 300, "rdata": [address]}


def acc_zones() -> dict[str, list[dict[str, Any]]]:
    """The M2-12 chain (root 192.0.2.1 -> com 192.0.2.2 -> example.com 192.0.2.3) plus failures."""
    z = copy.deepcopy(ZONES)
    known = {(e.get("name"), e.get("type")) for e in z["default"]}
    z["default"] += [_fail(h, s) for s, h in HOST.items() if (h, "A") not in known]
    z["default"] += [_fail(h, s) for s, h in MIXED.items()]
    z["default"] += [
        _a("nodata.example.com", "192.0.2.30"),
        {
            "name": "77.2.0.192.in-addr.arpa",
            "type": "PTR",
            "ttl": 300,
            "rdata": ["other.example.com"],
        },
        _a("other.example.com", "192.0.2.78"),
        _fail("11.2.0.192.in-addr.arpa", "servfail", "PTR"),
        {
            "name": "12.2.0.192.in-addr.arpa",
            "type": "PTR",
            "ttl": 300,
            "rdata": ["fwd.example.com"],
        },
        _fail("fwd.example.com", "servfail"),
        _fail("fwd.example.com", "servfail", "AAAA"),
    ]
    z["192.0.2.3"] += [_fail(h, s) for s, h in HOST.items()]  # authoritative for example.com
    z["192.0.2.3"] += [
        _a("nodata.example.com", "192.0.2.30"),
        {"name": "lame.example.com", "type": "A", "state": "nxdomain", "rcode": 3, "aa": False},
    ]
    z["192.0.2.1"] += [
        _fail("sf.example.org", "servfail"),  # a failing ROOT server for this name
        {"referral": {"zone": "net", "ns": [{"name": "a.gtld.example.net", "addr": "192.0.2.2"}]}},
    ]
    z["192.0.2.2"] += [
        {
            "referral": {
                "zone": "example.net",
                "ns": [{"name": "ns.private.example.net", "addr": "10.0.0.53"}],
            }
        }
    ]
    # public-resolver stand-ins (RFC 5737 addresses, mapped onto real resolver addresses below)
    z["192.0.2.53"] = [
        _a("example.com", "192.0.2.99"),
        *[_a(h, "192.0.2.10") for h in MIXED.values()],
    ]
    z["198.51.100.53"] = [_a("example.com", "192.0.2.10")]
    return z


def make_backend(public: dict[str, str] | None = None) -> tuple[DnsBackend, FakeServerSet]:
    """Recorded-zone backend; `public` maps real public-resolver addresses to fixture servers
    (any other address answers like the default resolver)."""
    backend, servers = fake_backend(acc_zones())
    mapping = public or {}
    default = servers.resolver("default")

    def factory(_entry: PublicResolver, address: str) -> FakeResolver:
        return servers.servers[mapping[address]] if address in mapping else default

    return dataclasses.replace(backend, address_factory=factory), servers


class StateResolver:
    """Answers one fixed state for every question (states a zone cannot record)."""

    def __init__(self, state: ResultState) -> None:
        self.state = state
        self.identity = f"stub:{state.value}"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        if self.state is S.ok:
            rec = DnsRecord(question.name, question.rdtype, 60, "192.0.2.10")
            return DnsResult(question, S.ok, records=(rec,), ttl_min=60, rcode=0)
        rcode = {S.nxdomain: 3, S.nodata: 0}.get(self.state)
        detail = None if self.state.is_definitive_absence else "stub"
        return DnsResult(question, self.state, rcode=rcode, detail_code=detail)


def stub_backend(state: ResultState) -> DnsBackend:
    backend, _ = make_backend()
    stub = StateResolver(state)
    return dataclasses.replace(backend, lookup=LookupResolvers(stub, lambda _e: stub))


def install(w: World, backend: DnsBackend) -> None:
    w.client.app.dependency_overrides[dns_backend] = lambda: backend  # type: ignore[attr-defined]


@pytest.fixture
def acc(world: World) -> tuple[World, DnsBackend, FakeServerSet]:  # noqa: F811
    backend, servers = make_backend()
    install(world, backend)
    return world, backend, servers


def api(w: World, path: str, body: dict[str, Any]) -> dict[str, Any]:
    token = _login(w, "analyst")
    assert token
    r = w.client.post(f"/api/v1/dns/{path}", json=body, headers={CSRF_HEADER: token})
    assert r.status_code == 200, r.text[:300]
    out: dict[str, Any] = r.json()
    return out


def ui(w: World, path: str, form: dict[str, str], lang: str = "en") -> str:
    r = post(w, "analyst", f"/tools/dns/{path}", form, **{"Accept-Language": lang})
    assert r.status_code == 200, r.text[:300]
    return htmllib.unescape(r.text)


def lookup_ui_states(page: str) -> list[tuple[str, str]]:
    return re.findall(
        r'<section class="dns-type" data-rdtype="(\w+)">.*?data-state="(\w+)"', page, re.S
    )


def absence_phrases() -> list[str]:
    keys = ("tools.dns.state.nxdomain", "tools.dns.state.nodata")
    return [load_catalogue(lang)[k] for lang in ("en", "it") for k in keys]


def assert_failure_page(page: str, state: str) -> None:
    """The page says "could not be evaluated" for `state` and nowhere "absent"."""
    assert f'data-state="{state}"' in page
    assert 'data-kind="failure"' in page and 'data-kind="absent"' not in page
    for phrase in absence_phrases():
        assert phrase not in page


async def run_trace(backend: DnsBackend, name: str, rtype: str = "A") -> TraceReport:
    return await trace(
        DnsQuestion(name, rtype),
        query_server=backend.query_server,
        root_hints=backend.root_hints,
        policy=backend.policy,
        limits=DEFAULT_LIMITS,
        resolver=backend.default,
    )


# === 1. recorded zones: healthy, nxdomain, nodata, disagreement, delegation chain ================


async def test_m2_recorded_zone_healthy_lookup(acc: Any) -> None:
    w, backend, _ = acc
    report = await lookup("example.com", "A", "default", resolvers=backend.lookup)
    assert report.results[0].state is S.ok and report.summary.found == ("A",)
    body = api(w, "lookup", {"name": "example.com", "type": "A"})
    assert body["results"][0]["state"] == "ok" and body["results"][0]["evaluated"] is True
    page = ui(w, "lookup", {"name": "example.com", "type": "A"})
    assert lookup_ui_states(page) == [("A", "ok")] and "192.0.2.10" in page


@pytest.mark.parametrize(
    ("name", "rtype", "state"),
    [("missing.example.com", "A", "nxdomain"), ("nodata.example.com", "AAAA", "nodata")],
)
async def test_m2_recorded_zone_nxdomain_and_nodata_are_definitive_absence(
    acc: Any, name: str, rtype: str, state: str
) -> None:
    w, backend, _ = acc
    report = await lookup(name, rtype, "default", resolvers=backend.lookup)
    assert report.results[0].state.value == state and report.summary.absent == (rtype,)
    body = api(w, "lookup", {"name": name, "type": rtype})
    assert body["results"][0]["state"] == state and body["results"][0]["evaluated"] is True
    assert body["summary"]["failed"] == [] and body["summary"]["evaluated"] is True
    page = ui(w, "lookup", {"name": name, "type": rtype})
    assert lookup_ui_states(page) == [(rtype, state)] and 'data-kind="absent"' in page


async def test_m2_recorded_zone_delegation_chain_trace(acc: Any) -> None:
    w, _, servers = acc
    body = api(w, "trace", {"name": "example.com", "type": "A"})
    assert body["outcome"] == "ok" and body["final_zone"] == "example.com"
    assert [h["kind"] for h in body["hops"]] == ["referral", "referral", "answer"]
    assert [a["rdata"] for a in body["answer"]] == ["192.0.2.10"]
    page = ui(w, "trace", {"name": "example.com", "type": "A"})
    assert 'data-outcome="ok"' in page
    assert [k for k, _ in HOP.findall(page)] == ["referral", "referral", "answer"]
    assert [a for a, _ in servers.server_queries][:3] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]


async def test_m2_recorded_zone_disagreement_is_reported_not_hidden(world: World) -> None:  # noqa: F811
    backend, _ = make_backend({"8.8.8.8": "192.0.2.53", "8.8.4.4": "198.51.100.53"})
    install(world, backend)
    req = {"name": "example.com", "type": "A"}
    body = api(world, "propagation", {**req, "resolver_ids": ["google"]})
    assert body["verdict"] == "inconsistent" and len(body["groups"]) == 2
    page = ui(world, "propagation", {**req, "resolver_ids": "google"})
    assert 'data-verdict="inconsistent"' in page
    assert "192.0.2.99" in page and "192.0.2.10" in page


async def test_m2_recorded_zone_agreement_is_consistent(acc: Any) -> None:
    w, _, _ = acc
    req = {"name": "example.com", "type": "A"}
    body = api(w, "propagation", {**req, "resolver_ids": ["google"]})
    assert body["verdict"] == "consistent" and body["evaluated"] is True
    assert 'data-verdict="consistent"' in ui(w, "propagation", {**req, "resolver_ids": "google"})


# === 2. SERVFAIL/timeout never "record missing", layer by layer ===================================

WIRE_FAILURES: list[tuple[str, Handler, ResultState | None]] = [
    ("servfail", answer_with(rcode=dns.rcode.SERVFAIL), S.servfail),
    ("refused", answer_with(rcode=dns.rcode.REFUSED), S.refused),
    ("timeout", lambda _q, _t, _tcp: dns.exception.Timeout(), S.timeout),
    ("network_error", lambda _q, _t, _tcp: ConnectionRefusedError(), S.network_error),
    ("garbage_datagram", lambda _q, _t, _tcp: b"\x00", S.timeout),  # UDP junk is ignored
    ("truncated", lambda q, _t, _tcp: wire(response(q, flags=dns.flags.TC)), S.truncated),
    ("unknown_error", lambda _q, _t, _tcp: RuntimeError(), None),
]


@pytest.mark.parametrize(
    ("handler", "expected"), [c[1:] for c in WIRE_FAILURES], ids=[c[0] for c in WIRE_FAILURES]
)
async def test_m2_layer_backend_mapping_never_absence(
    handler: Handler, expected: ResultState | None
) -> None:
    result = await custom(FakeTransport(handler)).resolve(Q_A)
    assert result.state.is_failure and result.state not in ABSENCE_STATES
    if expected is not None:
        assert result.state is expected
    reply = await custom(FakeTransport(handler)).query_server(NS1, Q_A)
    assert reply.result.state.is_failure and reply.referral is None


async def test_m2_layer_backend_non_authoritative_nxdomain_is_flagged() -> None:
    reply = await custom(FakeTransport(answer_with(rcode=dns.rcode.NXDOMAIN))).query_server(
        NS1, Q_A
    )
    assert reply.result.state is S.nxdomain and reply.authoritative is False
    aa = answer_with(rcode=dns.rcode.NXDOMAIN, flags=dns.flags.AA)
    assert (await custom(FakeTransport(aa)).query_server(NS1, Q_A)).authoritative is True


@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_cache_does_not_cache_failures_as_absence(state: str, acc: Any) -> None:
    _, _, servers = acc
    inner = servers.resolver("default")
    cache = CachingResolver(inner)
    q = DnsQuestion(HOST[state], "A")
    first = await cache.resolve(q)
    second = await cache.resolve(q)
    assert first.state.value == second.state.value == state
    assert len(cache) == 0 and inner.questions == [q, q]  # asked twice, nothing stored
    nx = DnsQuestion("missing.example.com", "A")  # contrast: a definitive absence IS cached
    await cache.resolve(nx)
    assert (await cache.resolve(nx)).state is S.nxdomain and len(cache) == 1
    assert inner.questions.count(nx) == 1


@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_lookup_service_never_absence(state: str, acc: Any) -> None:
    _, backend, _ = acc
    report = await lookup(HOST[state], "A", "default", resolvers=backend.lookup)
    (res,) = report.results
    assert res.state.value == state and res.evaluated is False and res.records == ()
    assert report.summary.failed == ("A",) and report.summary.absent == ()
    assert report.summary.found == () and report.summary.evaluated is False


async def test_m2_layer_lookup_all_types_failure_is_not_absence() -> None:
    backend = stub_backend(S.servfail)
    report = await lookup("example.com", "ALL", "default", resolvers=backend.lookup)
    assert report.results and all(r.state is S.servfail for r in report.results)
    assert report.summary.absent == () and report.summary.evaluated is False


@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_reverse_fcrdns_never_mismatch_or_absent(state: str, acc: Any) -> None:
    _, backend, _ = acc
    # .11: the PTR query itself SERVFAILs; .12: PTR is fine but the forward leg SERVFAILs
    for ip, ptr_state in (("192.0.2.11", S.servfail), ("192.0.2.12", S.ok)):
        report = await reverse(ip, "default", resolvers=backend.lookup, forward_confirm=True)
        assert report.ptr.state is ptr_state
        assert report.fcrdns is FcrdnsState.could_not_verify and report.evaluated is False
    stub = stub_backend(S(state))
    report = await reverse("192.0.2.10", "default", resolvers=stub.lookup, forward_confirm=True)
    assert report.ptr.state.value == state and report.evaluated is False
    assert report.fcrdns is FcrdnsState.could_not_verify


async def test_m2_layer_reverse_recorded_outcomes(acc: Any) -> None:
    _, backend, _ = acc
    got = {}
    for ip in ("192.0.2.10", "192.0.2.77", "192.0.2.13"):
        r = await reverse(ip, "default", resolvers=backend.lookup, forward_confirm=True)
        got[ip] = r.fcrdns
    assert got == {
        "192.0.2.10": FcrdnsState.confirmed,
        "192.0.2.77": FcrdnsState.mismatch,  # every step evaluated: a real mismatch
        "192.0.2.13": FcrdnsState.no_ptr,  # PTR nxdomain: definitive absence
    }


@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_trace_never_absence(state: str, acc: Any) -> None:
    _, backend, _ = acc
    report = await run_trace(backend, HOST[state])
    assert report.outcome.value == TRACE_OUTCOME[state]
    assert report.state is S.error and report.state.is_failure and report.answer == ()
    assert not any(h.state in ABSENCE_STATES for h in report.hops if h.kind is HopKind.failure)


async def test_m2_layer_trace_root_failure_lame_and_blocked_referral(acc: Any) -> None:
    _, backend, servers = acc
    root = await run_trace(backend, "sf.example.org")
    assert root.outcome is TraceOutcome.all_failed and root.state is S.error
    lame = await run_trace(backend, "lame.example.com")  # non-authoritative "nxdomain"
    assert lame.outcome is TraceOutcome.lame_delegation and lame.state is S.error
    private = await run_trace(backend, "example.net")
    assert private.outcome is TraceOutcome.no_allowed_server and private.state is S.error
    assert "10.0.0.53" not in [a for a, _ in servers.server_queries]
    for report in (root, lame, private):
        assert report.outcome not in (TraceOutcome.nxdomain, TraceOutcome.nodata)


async def test_m2_layer_trace_authoritative_absence_is_still_absence(acc: Any) -> None:
    _, backend, _ = acc
    assert (await run_trace(backend, "missing.example.com")).outcome is TraceOutcome.nxdomain
    assert (await run_trace(backend, "nodata.example.com", "AAAA")).outcome is TraceOutcome.nodata


@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_propagation_failed_rows_are_not_evaluated_not_missing(
    state: str,
    world: World,  # noqa: F811
) -> None:
    backend, _ = make_backend({"8.8.8.8": "192.0.2.53", "8.8.4.4": "192.0.2.53"})
    install(world, backend)
    name = MIXED[state]
    report = await check_propagation(
        name,
        "A",
        ["google"],
        default_resolver=backend.default,
        address_factory=backend.address_factory,
    )
    failed = [r for r in report.rows if not r.evaluated]
    assert len(failed) == report.not_evaluated_count == 3  # default + the two IPv6 addresses
    assert all(r.state.value == state for r in failed)
    assert all(r.group is None for r in failed)  # failures never join an answer group
    assert report.verdict is Verdict.consistent  # the two evaluated agree; the rest not counted
    req = {"name": name, "type": "A"}
    body = api(world, "propagation", {**req, "resolver_ids": ["google"]})
    assert body["evaluated"] is False
    assert [r["state"] for r in body["rows"] if not r["evaluated"]] == [state] * 3
    page = ui(world, "propagation", {**req, "resolver_ids": "google"})
    na = re.findall(r'<li data-resolver="([^"]+)" data-state="(\w+)"', page)
    assert [s for _, s in na] == [state] * 3
    rows = re.findall(r'<tr data-resolver="([^"]+)" data-state="(\w+)"', page)
    assert [s for _, s in rows] == ["ok", "ok"]
    assert_failure_page(page, state)


async def test_m2_layer_propagation_all_failing_is_inconclusive(acc: Any) -> None:
    w, _, _ = acc
    for state in ZONE_FAILURES:
        req = {"name": HOST[state], "type": "A"}
        body = api(w, "propagation", {**req, "resolver_ids": ["google"]})
        assert body["verdict"] == "inconclusive" and body["evaluated_count"] == 0
        assert {r["state"] for r in body["rows"]} == {state}
        page = ui(w, "propagation", {**req, "resolver_ids": "google"})
        assert 'data-verdict="inconclusive"' in page
        assert_failure_page(page, state)


@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_rest_response(state: str, acc: Any) -> None:
    w, _, _ = acc
    lk = api(w, "lookup", {"name": HOST[state], "type": "A"})
    assert lk["results"][0]["state"] == state and lk["results"][0]["evaluated"] is False
    assert lk["results"][0]["records"] == [] and lk["summary"]["absent"] == []
    tr = api(w, "trace", {"name": HOST[state], "type": "A"})
    assert (
        tr["outcome"] == TRACE_OUTCOME[state]
        and tr["state"] == "error"
        and tr["evaluated"] is False
    )
    assert tr["answer"] == []


@pytest.mark.parametrize("lang", ["en", "it"])
@pytest.mark.parametrize("state", ZONE_FAILURES)
async def test_m2_layer_rendered_html(state: str, lang: str, acc: Any) -> None:
    w, _, _ = acc
    cat = load_catalogue(lang)
    page = ui(w, "lookup", {"name": HOST[state], "type": "A"}, lang)
    assert_failure_page(page, state)
    assert cat[f"tools.dns.state.{state}"] in page
    page = ui(w, "trace", {"name": HOST[state], "type": "A"}, lang)
    assert f'data-outcome="{TRACE_OUTCOME[state]}"' in page and 'data-kind="failure"' in page
    for phrase in (
        *absence_phrases(),
        cat["tools.dns.trace.outcome.nxdomain"],
        cat["tools.dns.trace.outcome.nodata"],
    ):
        assert phrase not in page
    page = ui(w, "reverse", {"ip": "192.0.2.11"}, lang)  # PTR SERVFAIL
    assert 'data-state="servfail"' in page and 'data-fcrdns="could_not_verify"' in page
    assert 'data-fcrdns="mismatch"' not in page and 'data-kind="absent"' not in page


@pytest.mark.parametrize("state", ["blocked", "error"])
async def test_m2_layer_blocked_and_error_states(state: str, world: World) -> None:  # noqa: F811
    if state == "blocked":  # a real BlockedResolver, as the factory builds for a rejected target
        blocked = BlockedResolver("10.0.0.53", BlockReason.private)
        base, _ = make_backend()
        backend = dataclasses.replace(base, lookup=LookupResolvers(blocked, lambda _e: blocked))
    else:
        backend = stub_backend(S.error)
    install(world, backend)
    req = {"name": "example.com", "type": "A"}
    body = api(world, "lookup", req)
    assert body["results"][0]["state"] == state and body["summary"]["absent"] == []
    assert_failure_page(ui(world, "lookup", req), state)


# === 3. the same query gives the same state on API and UI ========================================

CASES = [
    ("example.com", "A"),
    ("missing.example.com", "A"),
    ("nodata.example.com", "AAAA"),
    *[(h, "A") for h in HOST.values()],
    ("example.com", "ALL"),
]


@pytest.mark.parametrize(("name", "rtype"), CASES)
async def test_m2_same_lookup_same_state_on_api_and_ui(name: str, rtype: str, acc: Any) -> None:
    w, _, _ = acc
    body = api(w, "lookup", {"name": name, "type": rtype})
    page = ui(w, "lookup", {"name": name, "type": rtype})
    assert lookup_ui_states(page) == [(r["rdtype"], r["state"]) for r in body["results"]]


@pytest.mark.parametrize(
    "ip", ["192.0.2.10", "192.0.2.77", "192.0.2.13", "192.0.2.11", "192.0.2.12"]
)
async def test_m2_same_reverse_same_state_on_api_and_ui(ip: str, acc: Any) -> None:
    w, _, _ = acc
    body = api(w, "reverse", {"ip": ip})
    page = ui(w, "reverse", {"ip": ip})
    match = PTR_STATE.search(page)
    assert match and match.group(1) == body["ptr"]["state"]
    if body["fcrdns"] in ("confirmed", "mismatch", "could_not_verify"):
        assert f'data-fcrdns="{body["fcrdns"]}"' in page
    else:  # no_ptr: the PTR state box already says nxdomain; no FCrDNS verdict is drawn
        assert "data-fcrdns" not in page


@pytest.mark.parametrize(
    "name",
    ["example.com", "missing.example.com", "lame.example.com", "sf.example.org", "example.net"]
    + list(HOST.values()),
)
async def test_m2_same_trace_same_state_on_api_and_ui(name: str, acc: Any) -> None:
    w, _, _ = acc
    body = api(w, "trace", {"name": name, "type": "A"})
    page = ui(w, "trace", {"name": name, "type": "A"})
    assert f'data-outcome="{body["outcome"]}"' in page
    assert HOP.findall(page) == [(h["kind"], h["state"]) for h in body["hops"]]
    final = STATE_BOX.findall(page)[-1]
    assert final[1] == body["state"]
    assert (final[2] == "failure") is (not body["evaluated"])


@pytest.mark.parametrize(
    "public",
    [{}, {"8.8.8.8": "192.0.2.53", "8.8.4.4": "198.51.100.53"}],
    ids=["agree", "disagree"],
)
async def test_m2_same_propagation_same_verdict_on_api_and_ui(
    public: dict[str, str],
    world: World,  # noqa: F811
) -> None:
    backend, _ = make_backend(public)
    install(world, backend)
    for name in ("example.com", MIXED["servfail"], HOST["timeout"]):
        req = {"name": name, "type": "A"}
        body = api(world, "propagation", {**req, "resolver_ids": ["google"]})
        page = ui(world, "propagation", {**req, "resolver_ids": "google"})
        assert f'data-verdict="{body["verdict"]}"' in page
        shown = re.findall(r'<(?:tr|li) data-resolver="([^"]+)" data-state="(\w+)"', page)
        rows = [r for r in body["rows"] if r["evaluated"]] + [
            r for r in body["rows"] if not r["evaluated"]
        ]
        assert shown == [(r["resolver"], r["state"]) for r in rows]


# === 4. guards ====================================================================================


def test_m2_guard_every_result_state_is_classified_translated_and_rendered(
    world: World,  # noqa: F811
) -> None:
    catalogue = {lang: load_catalogue(lang) for lang in ("en", "it")}
    for state in ResultState:
        assert (state.is_ok, state.is_definitive_absence, state.is_failure).count(True) == 1, state
        key = f"tools.dns.state.{state.value}"
        assert all(catalogue[lang].get(key) for lang in catalogue), key
        kind = "ok" if state.is_ok else "absent" if state.is_definitive_absence else "failure"
        install(world, stub_backend(state))
        body = api(world, "lookup", {"name": "example.com", "type": "A"})
        assert body["results"][0]["state"] == state.value
        assert body["results"][0]["evaluated"] is (not state.is_failure)
        for lang in catalogue:
            page = ui(world, "lookup", {"name": "example.com", "type": "A"}, lang)
            assert (state.value, kind) in {(s, k) for _, s, k in STATE_BOX.findall(page)}, state
            assert catalogue[lang][key] in page


def test_m2_guard_every_trace_outcome_is_translated_and_never_a_failure_of_absence() -> None:
    template = (ROOT / "app/web/templates/dns/trace.html").read_text()
    keys = re.findall(r't\("(tools\.dns\.trace\.outcome\.\w+)"\)', template)
    assert len(keys) == len(TraceOutcome)
    for lang in ("en", "it"):
        assert all(load_catalogue(lang).get(k) for k in keys)
    for outcome in TraceOutcome:
        assert f'"{outcome.value}":' in template, outcome
        if outcome not in (TraceOutcome.ok, TraceOutcome.nxdomain, TraceOutcome.nodata):
            assert outcome.state is S.error  # every non-answer outcome is a failure to evaluate


_NETWORK_MODULES = {"socket", "ssl", "httpx", "requests", "aiohttp", "urllib3", "ftplib", "smtplib"}
_NETWORK_FROM = {
    ("dns", "query"),
    ("dns", "asyncquery"),
    ("dns", "asyncresolver"),
    ("http", "client"),
    ("urllib", "request"),
}
_NETWORK_CALLS = {
    "open_connection",
    "create_connection",
    "create_datagram_endpoint",
    "sock_connect",
    "getaddrinfo",
    "gethostbyname",
    "start_server",
}


def network_use(source: str) -> list[str]:
    """Imports and calls that reach the network, in `source`."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in _NETWORK_MODULES or tuple(a.name.split(".")[:2]) in (
                    _NETWORK_FROM
                ):
                    found.append(a.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = tuple(node.module.split("."))
            if module[0] in _NETWORK_MODULES or module[:2] in _NETWORK_FROM:
                found.append(node.module)
            found += [
                f"{node.module}.{a.name}"
                for a in node.names
                if (node.module, a.name) in _NETWORK_FROM
            ]
        elif isinstance(node, ast.Attribute) and node.attr in _NETWORK_CALLS:
            found.append(node.attr)
        elif isinstance(node, ast.Name) and node.id in _NETWORK_CALLS:
            found.append(node.id)
    return found


def test_m2_guard_only_the_backend_module_touches_the_network() -> None:
    files = sorted([*(ROOT / "app/dns").glob("*.py"), *(ROOT / "app/services").glob("dns_*.py")])
    assert {f.name for f in files} >= {
        "backends.py",
        "trace.py",
        "dns_tools.py",
        "dns_propagation.py",
    }
    offenders = {
        str(f.relative_to(ROOT)): hits
        for f in files
        if f.name != "backends.py" and (hits := network_use(f.read_text()))
    }
    assert offenders == {}


@pytest.mark.parametrize(
    "source",
    [
        "import socket",
        "from socket import socket",
        "import dns.query",
        "from dns import asyncquery",
        "import httpx",
        "import asyncio\nasyncio.open_connection('x', 1)",
        "x.create_datagram_endpoint()",
    ],
)
def test_m2_guard_detector_catches_network_use(source: str) -> None:
    assert network_use(source)
    assert not network_use("import ipaddress\nimport dns.rdatatype\nfrom dns import name")


def test_m2_guard_unit_tests_cannot_open_connections() -> None:
    import socket

    s = socket.socket()
    try:
        with pytest.raises(AssertionError, match="network access"):
            s.connect(("192.0.2.1", 53))
        with pytest.raises(AssertionError, match="network access"):
            socket.getaddrinfo("example.com", 53)
    finally:
        s.close()


def test_m2_guard_acceptance_zones_stay_in_reserved_namespaces() -> None:
    names = {e["name"] for entries in acc_zones().values() for e in entries if "name" in e}
    assert names
    assert all(is_reserved_name(n) or n.endswith(".in-addr.arpa") for n in names)
