"""DNSBL engine (M7-03): query names, interpretation of every answer shape, run orchestration.

Invented lists (tests/checks/fixtures/dnsbl_test_lists.yaml), reserved IPs and names, and the
in-memory fake resolver from tests/support: no network.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.checks.dnsbl_engine import (
    MAX_EVIDENCE_CODES,
    DnsblEngine,
    DnsblQueryError,
    DnsblTarget,
    Outcome,
    Reason,
    build_query_name,
    interpret,
    parse_target,
)
from app.checks.dnsbl_schema import DNSBL_FILE, DnsblList, parse_dnsbl_lists, read_dnsbl_lists
from app.dns.egress import BlockReason, IPAddress, address_reason
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from tests.support.dns_zones import FakeResolver, parse_zones

FIXTURE = Path(__file__).parent / "fixtures" / "dnsbl_test_lists.yaml"
LISTS = {x.id: x for x in read_dnsbl_lists(FIXTURE, date(2026, 11, 13))}
BOTH, V4, DOM, UNVERIFIED = (
    LISTS["ip-both"],
    LISTS["ip-v4only"],
    LISTS["dom"],
    LISTS["ip-unverified"],
)
Q4 = "1.2.0.192.bl.example.com"
V6_NIBBLES = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"


# --- targets and query names ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lst", "raw", "expected"),
    [
        (BOTH, "192.0.2.1", Q4),
        (V4, "198.51.100.200", "200.100.51.198.v4.example.net"),
        (BOTH, "2001:db8::1", f"{V6_NIBBLES}.bl.example.com"),
        (BOTH, "2001:DB8:0:0:0:0:0:1", f"{V6_NIBBLES}.bl.example.com"),
        (BOTH, "::ffff:192.0.2.1", Q4),  # IPv4-mapped is queried as IPv4
        (DOM, "Example.COM", "example.com.dbl.example.net"),
        (DOM, "example.com.", "example.com.dbl.example.net"),
        (DOM, "bücher.example", "xn--bcher-kva.example.dbl.example.net"),
    ],
)
def test_query_name(lst: DnsblList, raw: str, expected: str) -> None:
    assert build_query_name(lst, parse_target(raw)) == expected


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (None, "not_a_string"),
        (3232235777, "not_a_string"),
        ("", "forbidden_character"),
        (" 192.0.2.1", "forbidden_character"),
        ("192.0.2.1\n", "forbidden_character"),
        ("192.0.2.1\x00", "forbidden_character"),
        ("x" * 2000, "too_long"),
        ("192.0.2", "invalid_ip"),
        ("192.0.2.256", "invalid_ip"),
        ("192.000.2.1", "invalid_ip"),
        ("3232235777", "invalid_ip"),
        ("fe80::1%eth0", "invalid_ip"),
        ("2001:db8::g", "invalid_ip"),
        ("[2001:db8::1]", "invalid_ip"),
        ("a..example.com", "invalid_domain_idna"),
        ("ex ample.com", "invalid_domain_forbidden_character"),
        ("_dmarc.example.com", "invalid_domain_idna"),
        ("*.example.com", "invalid_domain_idna"),
        ("localhost", "invalid_domain_single_label"),
        ("a" * 64 + ".example.com", "invalid_domain_idna"),
        ("example.com/../x", "invalid_domain_idna"),
        ("\u202eexample.com", "forbidden_character"),
    ],
)
def test_invalid_target(raw: object, reason: str) -> None:
    with pytest.raises(DnsblQueryError) as info:
        parse_target(raw)
    assert info.value.reason == reason
    if isinstance(raw, str) and len(raw) > 3:
        assert raw not in str(info.value)  # the input is never echoed


@pytest.mark.parametrize(
    ("lst", "raw", "reason"),
    [
        (DOM, "192.0.2.1", "kind_mismatch"),
        (BOTH, "example.com", "kind_mismatch"),
        (V4, "2001:db8::1", "ipv6_unsupported"),
        (DOM, ".".join(["a" * 63] * 3) + "." + "b" * 40 + ".example", "name_too_long"),
    ],
)
def test_query_name_rejected(lst: DnsblList, raw: str, reason: str) -> None:
    with pytest.raises(DnsblQueryError) as info:
        build_query_name(lst, parse_target(raw))
    assert info.value.reason == reason


def test_ipv6_only_list_rejects_ipv4() -> None:
    v6only = dataclasses.replace(BOTH, ipv4=False)
    with pytest.raises(DnsblQueryError, match="ipv4_unsupported"):
        build_query_name(v6only, parse_target("192.0.2.1"))


# --- interpretation (pure) -----------------------------------------------------------------------


def _res(state: ResultState, *answers: str, rdtype: str = "A") -> DnsResult:
    q = DnsQuestion(Q4, "A")
    records = tuple(DnsRecord(Q4, rdtype, 60, a) for a in answers)
    return DnsResult(question=q, state=state, records=records)


OK = ResultState.ok


@pytest.mark.parametrize(
    ("lst", "result", "outcome", "reason", "categories"),
    [
        (BOTH, _res(ResultState.nxdomain), Outcome.not_listed, None, ()),
        (BOTH, _res(ResultState.nodata), Outcome.error, Reason.nodata, ()),
        (V4, _res(ResultState.nodata), Outcome.not_listed, None, ()),  # declared clean
        (BOTH, _res(ResultState.servfail), Outcome.error, Reason.servfail, ()),
        (BOTH, _res(ResultState.refused), Outcome.error, Reason.rcode_refused, ()),
        (BOTH, _res(ResultState.timeout), Outcome.error, Reason.timeout, ()),
        (BOTH, _res(ResultState.truncated), Outcome.error, Reason.truncated, ()),
        (BOTH, _res(ResultState.malformed), Outcome.error, Reason.malformed_response, ()),
        (BOTH, _res(ResultState.network_error), Outcome.error, Reason.network_error, ()),
        (BOTH, _res(ResultState.blocked), Outcome.error, Reason.egress_blocked, ()),
        (BOTH, _res(ResultState.error), Outcome.error, Reason.resolver_error, ()),
        (BOTH, _res(OK, "127.0.0.2"), Outcome.listed, None, ("spam_source",)),
        (
            BOTH,
            _res(OK, "127.0.0.2", "127.0.0.3"),
            Outcome.listed,
            None,
            ("spam_source", "exploited_host"),
        ),
        (
            BOTH,
            _res(OK, "127.0.0.2", "127.0.0.10"),
            Outcome.listed,
            None,
            ("spam_source", "dynamic_range"),
        ),
        (BOTH, _res(OK, "127.0.0.10"), Outcome.info, None, ("dynamic_range",)),
        (BOTH, _res(OK, "127.0.0.254"), Outcome.error, Reason.refused, ()),  # mapped refused
        (BOTH, _res(OK, "127.255.255.252"), Outcome.error, Reason.refused, ()),  # convention
        (BOTH, _res(OK, "127.255.255.254", "127.255.255.255"), Outcome.error, Reason.refused, ()),
        (V4, _res(OK, "127.255.255.254"), Outcome.error, Reason.unmapped_code, ()),  # no conv.
        (BOTH, _res(OK, "127.0.0.2", "127.255.255.254"), Outcome.error, Reason.conflicting_codes,
         ()),
        (BOTH, _res(OK, "127.0.0.10", "127.0.0.254"), Outcome.error, Reason.conflicting_codes, ()),
        (BOTH, _res(OK, "127.0.0.99"), Outcome.error, Reason.unmapped_code, ()),
        (BOTH, _res(OK, "127.0.0.2", "127.0.0.99"), Outcome.error, Reason.unmapped_code, ()),
        (BOTH, _res(OK, "192.0.2.53"), Outcome.error, Reason.answer_out_of_range, ()),
        (BOTH, _res(OK, "127.0.0.2", "203.0.113.9"), Outcome.error, Reason.answer_out_of_range, ()),
        (BOTH, _res(OK, "0.0.0.0"), Outcome.error, Reason.answer_out_of_range, ()),
        (BOTH, _res(OK, "not-an-ip"), Outcome.error, Reason.malformed_answer, ()),
        (BOTH, _res(OK, "::1"), Outcome.error, Reason.malformed_answer, ()),
        (BOTH, _res(OK, "x.example.com", rdtype="CNAME"), Outcome.error, Reason.malformed_answer,
         ()),
        (DOM, _res(OK, "127.0.1.2"), Outcome.listed, None, ("spam_domain",)),
        (DOM, _res(OK, "127.0.0.2"), Outcome.error, Reason.unmapped_code, ()),
    ],
)  # fmt: skip
def test_interpret(
    lst: DnsblList,
    result: DnsResult,
    outcome: Outcome,
    reason: Reason | None,
    categories: tuple[str, ...],
) -> None:
    got = interpret(lst, result)
    assert (got.outcome, got.reason, got.categories) == (outcome, reason, categories)
    if outcome is not Outcome.listed and outcome is not Outcome.info:
        assert not got.categories
    if result.state is OK and got.reason is not Reason.malformed_answer:
        assert got.codes  # the answer is kept as evidence


def test_every_failure_state_is_error() -> None:
    for state in ResultState:
        if state in (ResultState.ok, ResultState.nxdomain):
            continue
        got = interpret(BOTH, _res(state) if state is not OK else _res(OK, "127.0.0.2"))
        assert got.outcome is Outcome.error, state


def test_evidence_is_bounded() -> None:
    answers = [f"127.0.0.{i}" for i in range(100, 140)]
    got = interpret(BOTH, _res(OK, *answers))
    assert got.reason is Reason.unmapped_code
    assert len(got.codes) == MAX_EVIDENCE_CODES and got.codes_truncated


# --- bitmask return codes (M7-03b) ---------------------------------------------------------------

# Invented bitmask list: bits 2, 4, 16, 64 listed, 32 info, 1 refused; 8 and 128 unmapped.
MASK = parse_dnsbl_lists(
    {
        "lists": [
            {
                "id": "mask",
                "name": "Example bitmask list",
                "zone": "multi.example.org",
                "kind": "domain",
                "return_code_mode": "bitmask",
                "return_codes": [
                    {"code": "127.0.0.1", "meaning": "refused"},
                    {"code": "127.0.0.2", "meaning": "listed", "category": "spam_domain"},
                    {"code": "127.0.0.4", "meaning": "listed", "category": "phishing"},
                    {"code": "127.0.0.16", "meaning": "listed", "category": "malware"},
                    {"code": "127.0.0.32", "meaning": "info", "category": "tracker"},
                    {"code": "127.0.0.64", "meaning": "listed", "category": "abuse"},
                    {"code": "127.255.255.254", "meaning": "refused"},
                ],
                "refused_networks": ["127.255.255.0/24"],
                "verified_on": date(2026, 1, 1),
                "sources": ["https://docs.example.org/multi"],
                "status": "verified",
            }
        ]
    },
    date(2026, 11, 13),
)[0]
# The same table read as exact codes: sums are not decomposed (regression of M7-03 behaviour).
MASK_EXACT = dataclasses.replace(MASK, return_code_mode="exact")


@pytest.mark.parametrize(
    ("lst", "answers", "outcome", "reason", "categories"),
    [
        # single bit
        (MASK, ("127.0.0.2",), Outcome.listed, None, ("spam_domain",)),
        (MASK, ("127.0.0.64",), Outcome.listed, None, ("abuse",)),
        (MASK, ("127.0.0.32",), Outcome.info, None, ("tracker",)),
        # summed bits: every category, listed wins over info
        (MASK, ("127.0.0.80",), Outcome.listed, None, ("malware", "abuse")),
        (MASK, ("127.0.0.6",), Outcome.listed, None, ("spam_domain", "phishing")),
        (MASK, ("127.0.0.48",), Outcome.listed, None, ("malware", "tracker")),
        (MASK, ("127.0.0.118",), Outcome.listed, None,
         ("spam_domain", "phishing", "malware", "tracker", "abuse")),
        (MASK, ("127.0.0.2", "127.0.0.80"), Outcome.listed, None,
         ("spam_domain", "malware", "abuse")),
        # unmapped bit, alone or in a sum, never listed
        (MASK, ("127.0.0.8",), Outcome.error, Reason.unmapped_code, ()),
        (MASK, ("127.0.0.128",), Outcome.error, Reason.unmapped_code, ()),
        (MASK, ("127.0.0.10",), Outcome.error, Reason.unmapped_code, ()),
        (MASK, ("127.0.0.144",), Outcome.error, Reason.unmapped_code, ()),
        (MASK, ("127.0.0.2", "127.0.0.8"), Outcome.error, Reason.unmapped_code, ()),
        (MASK, ("127.0.0.8", "127.0.0.1"), Outcome.error, Reason.unmapped_code, ()),
        # refusal: alone, summed with bits, or next to listed answers
        (MASK, ("127.0.0.1",), Outcome.error, Reason.refused, ()),
        (MASK, ("127.255.255.254",), Outcome.error, Reason.refused, ()),
        (MASK, ("127.255.255.200",), Outcome.error, Reason.refused, ()),  # refused network
        (MASK, ("127.0.0.3",), Outcome.error, Reason.conflicting_codes, ()),
        (MASK, ("127.0.0.65",), Outcome.error, Reason.conflicting_codes, ()),
        (MASK, ("127.0.0.255",), Outcome.error, Reason.conflicting_codes, ()),  # +unmapped
        (MASK, ("127.0.0.119",), Outcome.error, Reason.conflicting_codes, ()),
        (MASK, ("127.0.0.80", "127.0.0.1"), Outcome.error, Reason.conflicting_codes, ()),
        (MASK, ("127.0.0.4", "127.255.255.254"), Outcome.error, Reason.conflicting_codes, ()),
        # zero and out-of-range octets
        (MASK, ("127.0.0.0",), Outcome.error, Reason.unmapped_code, ()),
        (MASK, ("127.0.1.2",), Outcome.error, Reason.answer_out_of_range, ()),
        (MASK, ("127.1.0.80",), Outcome.error, Reason.answer_out_of_range, ()),
        (MASK, ("127.0.0.2", "127.0.2.0"), Outcome.error, Reason.answer_out_of_range, ()),
        # non-127 and malformed answers
        (MASK, ("10.0.0.80",), Outcome.error, Reason.answer_out_of_range, ()),
        (MASK, ("0.0.0.2",), Outcome.error, Reason.answer_out_of_range, ()),
        (MASK, ("127.0.0.80", "192.0.2.4"), Outcome.error, Reason.answer_out_of_range, ()),
        (MASK, ("127.0.0.256",), Outcome.error, Reason.malformed_answer, ()),
        (MASK, ("127.0.0.0x50",), Outcome.error, Reason.malformed_answer, ()),
        (MASK, ("",), Outcome.error, Reason.malformed_answer, ()),
        # exact mode on the same table: sums stay unmapped, refusal handling unchanged
        (MASK_EXACT, ("127.0.0.80",), Outcome.error, Reason.unmapped_code, ()),
        (MASK_EXACT, ("127.0.0.6",), Outcome.error, Reason.unmapped_code, ()),
        (MASK_EXACT, ("127.0.0.3",), Outcome.error, Reason.unmapped_code, ()),
        (MASK_EXACT, ("127.0.0.16",), Outcome.listed, None, ("malware",)),
        (MASK_EXACT, ("127.0.0.1",), Outcome.error, Reason.refused, ()),
        (MASK_EXACT, ("127.0.0.16", "127.0.0.1"), Outcome.error, Reason.conflicting_codes, ()),
        (MASK_EXACT, ("127.0.1.2",), Outcome.error, Reason.unmapped_code, ()),
    ],
)  # fmt: skip
def test_interpret_bitmask(
    lst: DnsblList,
    answers: tuple[str, ...],
    outcome: Outcome,
    reason: Reason | None,
    categories: tuple[str, ...],
) -> None:
    got = interpret(lst, _res(OK, *answers))
    assert (got.outcome, got.reason, got.categories) == (outcome, reason, categories)
    if reason is not Reason.malformed_answer:
        assert got.codes == tuple(dict.fromkeys(answers))  # the raw answer is the evidence


def test_bitmask_non_a_records_are_malformed() -> None:
    got = interpret(MASK, _res(OK, "x.example.org", rdtype="CNAME"))
    assert (got.outcome, got.reason) == (Outcome.error, Reason.malformed_answer)


def test_bitmask_dns_states_unchanged() -> None:
    assert interpret(MASK, _res(ResultState.nxdomain)).outcome is Outcome.not_listed
    for state in ResultState:
        if state not in (ResultState.ok, ResultState.nxdomain):
            assert interpret(MASK, _res(state)).outcome is Outcome.error, state


def test_every_bitmask_octet_is_never_clean() -> None:
    """Exhaustive: every 127.0.0.x answer is listed/info only when all its bits are mapped."""
    mapped = {2, 4, 16, 32, 64}
    for octet in range(256):
        got = interpret(MASK, _res(OK, f"127.0.0.{octet}"))
        assert got.outcome is not Outcome.not_listed
        bits = {1 << i for i in range(8) if octet & (1 << i)}
        if bits and bits <= mapped:
            assert got.outcome in (Outcome.listed, Outcome.info), octet
        else:
            assert got.outcome is Outcome.error, octet


def test_shipped_bitmask_lists() -> None:
    shipped = {x.id: x for x in read_dnsbl_lists(DNSBL_FILE)}
    assert shipped["surbl-multi"].return_code_mode == "bitmask"
    assert shipped["uribl-multi"].return_code_mode == "bitmask"
    assert shipped["spamcop-bl"].return_code_mode == "exact"
    assert not any(x.default_enabled for x in shipped.values())
    got = interpret(shipped["surbl-multi"], _res(OK, "127.0.0.80"))
    assert (got.outcome, got.categories) == (Outcome.listed, ("malware", "abuse"))
    got = interpret(shipped["uribl-multi"], _res(OK, "127.0.0.3"))
    assert (got.outcome, got.reason) == (Outcome.error, Reason.conflicting_codes)


# --- engine runs ---------------------------------------------------------------------------------


def _docs_allowed(ip: IPAddress) -> BlockReason | None:
    """Test policy: production classification, except documentation ranges (our test IPs)."""
    reason = address_reason(ip)
    return None if reason is BlockReason.documentation else reason


def _engine(resolver: Any, lists: list[DnsblList], **kw: Any) -> DnsblEngine:
    kw.setdefault("address_policy", _docs_allowed)
    return DnsblEngine(resolver, lists, **kw)


def _fake(entries: list[dict[str, Any]]) -> FakeResolver:
    return parse_zones({"zones": {"default": entries}}).resolver()


def _a(name: str, *answers: str) -> dict[str, Any]:
    return {"name": name, "type": "A", "ttl": 60, "rdata": list(answers)}


def _targets(*raw: str) -> list[DnsblTarget]:
    return [parse_target(r) for r in raw]


async def test_run_mixed_targets_and_lists() -> None:
    fake = _fake(
        [
            _a(Q4, "127.0.0.2"),
            _a("example.com.dbl.example.net", "127.0.1.2"),
            {"name": f"{V6_NIBBLES}.bl.example.com", "type": "A", "state": "servfail"},
        ]
    )
    engine = _engine(fake, [BOTH, V4, DOM, UNVERIFIED])
    report = await engine.run(_targets("192.0.2.1", "2001:db8::1", "example.com"))
    got = {(r.target, r.list_id): (r.outcome, r.reason) for r in report.results}
    assert got == {
        ("192.0.2.1", "ip-both"): (Outcome.listed, None),
        ("192.0.2.1", "ip-v4only"): (Outcome.not_listed, None),  # fake NXDOMAIN
        ("192.0.2.1", "dom"): (Outcome.not_applicable, Reason.kind_mismatch),
        ("192.0.2.1", "ip-unverified"): (Outcome.error, Reason.list_unverified),
        ("2001:db8::1", "ip-both"): (Outcome.error, Reason.servfail),
        ("2001:db8::1", "ip-v4only"): (Outcome.not_applicable, Reason.ipv6_unsupported),
        ("2001:db8::1", "dom"): (Outcome.not_applicable, Reason.kind_mismatch),
        ("2001:db8::1", "ip-unverified"): (Outcome.not_applicable, Reason.ipv6_unsupported),
        ("example.com", "ip-both"): (Outcome.not_applicable, Reason.kind_mismatch),
        ("example.com", "ip-v4only"): (Outcome.not_applicable, Reason.kind_mismatch),
        ("example.com", "dom"): (Outcome.listed, None),
        ("example.com", "ip-unverified"): (Outcome.not_applicable, Reason.kind_mismatch),
    }
    listed = report.results[0]
    assert listed.query_name == Q4 and listed.codes == ("127.0.0.2",)
    assert listed.dns_state is ResultState.ok and listed.categories == ("spam_source",)
    # no query for not-applicable or unverified lists
    asked = {q.name for q in fake.questions}
    assert not any(n.endswith("unverified.example.com") for n in asked)
    assert len(fake.questions) == 4
    assert report.blocked_lists == frozenset()


@pytest.mark.parametrize(
    ("answer", "outcome"), [("127.0.0.2", Outcome.listed), (None, Outcome.not_listed)]
)
async def test_unverified_list_with_flag(answer: str | None, outcome: Outcome) -> None:
    name = "1.2.0.192.unverified.example.com"
    fake = _fake([_a(name, answer)] if answer else [])
    engine = _engine(fake, [UNVERIFIED], include_unverified=True)
    (res,) = (await engine.run(_targets("192.0.2.1"))).results
    assert res.outcome is outcome and res.unverified and res.query_name == name


@pytest.mark.parametrize(
    ("answers", "blocked", "queried"),
    [
        (["127.255.255.254"] * 6, True, 3),  # convention code on every probe
        (["127.0.0.254"] * 6, True, 3),  # mapped refused code
        (["rcode_refused"] * 6, True, 3),  # REFUSED rcode
        (["127.255.255.254", "127.255.255.254", None, None, None, None], False, 6),
        (["servfail"] * 6, False, 6),  # failures that are not refusals do not block
    ],
)
async def test_blocked_resolver_short_circuit(
    answers: list[str | None], blocked: bool, queried: int
) -> None:
    ips = [f"192.0.2.{i}" for i in range(1, 7)]
    entries: list[dict[str, Any]] = []
    for ip, ans in zip(ips, answers, strict=True):
        name = ".".join(reversed(ip.split("."))) + ".bl.example.com"
        if ans == "rcode_refused":
            entries.append({"name": name, "type": "A", "state": "refused"})
        elif ans == "servfail":
            entries.append({"name": name, "type": "A", "state": "servfail"})
        elif ans is not None:
            entries.append(_a(name, ans))
    fake = _fake(entries)
    engine = _engine(fake, [BOTH], concurrency=1, block_threshold=3)
    report = await engine.run(_targets(*ips))
    assert len(fake.questions) == queried
    assert (report.blocked_lists == {"ip-both"}) is blocked
    for res in report.results:
        assert res.outcome is not Outcome.listed
        if blocked:
            assert res.outcome is Outcome.error
    if blocked:
        assert [r.reason for r in report.results[3:]] == [Reason.blocked_resolver] * 3
        assert all(r.dns_state is None for r in report.results[3:])


class _ScriptedResolver:
    """Wraps a FakeResolver: names in `states` return that state; `hang` never answers."""

    identity = "fake:scripted"

    def __init__(
        self,
        inner: FakeResolver,
        states: dict[str, ResultState] | None = None,
        hang: frozenset[str] = frozenset(),
        raise_on: frozenset[str] = frozenset(),
    ) -> None:
        self.inner, self.states, self.hang, self.raise_on = inner, states or {}, hang, raise_on
        self.in_flight = 0
        self.max_in_flight = 0

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0)
            if question.name in self.raise_on:
                raise RuntimeError("backend bug")
            if question.name in self.hang:
                await asyncio.Event().wait()
            if (state := self.states.get(question.name)) is not None:
                return DnsResult(question=question, state=state)
            return await self.inner.resolve(question)
        finally:
            self.in_flight -= 1


async def test_egress_blocked_probes_block_list() -> None:
    names = {f"{i}.2.0.192.bl.example.com": ResultState.blocked for i in range(1, 5)}
    resolver = _ScriptedResolver(_fake([]), names)
    engine = _engine(resolver, [BOTH], block_threshold=2, concurrency=4)
    report = await engine.run(_targets(*(f"192.0.2.{i}" for i in range(1, 5))))
    assert report.blocked_lists == {"ip-both"}
    assert [r.reason for r in report.results] == [Reason.egress_blocked] * 2 + [
        Reason.blocked_resolver
    ] * 2


async def test_timeout_and_exception_are_errors() -> None:
    resolver = _ScriptedResolver(
        _fake([]), hang=frozenset({Q4}), raise_on=frozenset({"2.2.0.192.bl.example.com"})
    )
    engine = _engine(resolver, [BOTH], query_timeout_s=0.01)
    report = await engine.run(_targets("192.0.2.1", "192.0.2.2", "192.0.2.3"))
    assert [(r.outcome, r.reason) for r in report.results] == [
        (Outcome.error, Reason.timeout),
        (Outcome.error, Reason.resolver_exception),
        (Outcome.not_listed, None),
    ]


async def test_concurrency_cap_and_acquire_hook() -> None:
    resolver = _ScriptedResolver(_fake([]))
    acquired: list[str] = []

    async def acquire(list_id: str) -> None:
        acquired.append(list_id)

    engine = _engine(resolver, [BOTH, V4], concurrency=2, acquire=acquire)
    report = await engine.run(_targets(*(f"192.0.2.{i}" for i in range(1, 11))))
    assert all(r.outcome is Outcome.not_listed for r in report.results)
    assert resolver.max_in_flight <= 2
    assert sorted(acquired) == ["ip-both"] * 10 + ["ip-v4only"] * 10


async def test_acquire_not_called_without_query() -> None:
    calls: list[str] = []

    async def acquire(list_id: str) -> None:
        calls.append(list_id)

    engine = _engine(_fake([]), [DOM, UNVERIFIED], acquire=acquire)
    await engine.run(_targets("192.0.2.1"))
    assert calls == []


def test_engine_rejects_bad_settings() -> None:
    for kw in ({"concurrency": 0}, {"block_threshold": 0}, {"query_timeout_s": 0}):
        with pytest.raises(ValueError):
            _engine(_fake([]), [BOTH], **kw)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="duplicate"):
        _engine(_fake([]), [BOTH, BOTH])


async def test_too_many_targets() -> None:
    engine = _engine(_fake([]), [BOTH])
    with pytest.raises(ValueError, match="at most"):
        await engine.run(_targets("192.0.2.1") * 257)


@pytest.mark.parametrize(
    "raw",
    [
        "10.1.2.3",  # private
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.2",  # loopback, incl. a typical list test point
        "169.254.169.254",  # link-local / metadata
        "100.64.0.1",  # shared address space
        "0.0.0.0",
        "224.0.0.1",  # multicast
        "255.255.255.255",
        "240.0.0.1",
        "192.0.2.1",  # documentation, under the default policy
        "::1",
        "::",
        "fe80::1",
        "fd00::1",  # unique local
        "ff02::1",
        "2001:db8::1",  # documentation, under the default policy
        "::ffff:10.0.0.1",  # IPv4-mapped private, unwrapped first
        "::ffff:127.0.0.1",
    ],
)
async def test_non_public_target_is_not_queried(raw: str) -> None:
    fake = _fake([])
    calls: list[str] = []

    async def acquire(list_id: str) -> None:
        calls.append(list_id)

    engine = DnsblEngine(fake, [BOTH, V4], acquire=acquire)  # default egress classification
    report = await engine.run(_targets(raw))
    for res in report.results:
        assert (res.outcome, res.reason) in {
            (Outcome.not_applicable, Reason.non_public_address),
            (Outcome.not_applicable, Reason.ipv6_unsupported),
        }
        assert res.query_name is None and res.dns_state is None
    assert fake.questions == [] and calls == []


async def test_public_target_is_queried_with_default_policy() -> None:
    fake = _fake([])
    report = await DnsblEngine(fake, [V4]).run(_targets("8.8.8.8"))
    (res,) = report.results
    assert res.outcome is Outcome.not_listed and res.query_name == "8.8.8.8.v4.example.net"
    assert len(fake.questions) == 1


@pytest.mark.parametrize(
    ("raised", "reason"),
    [("name_too_long", Reason.name_too_long), ("invalid_name", Reason.invalid_name)],
)
async def test_query_error_reason_is_kept(
    monkeypatch: pytest.MonkeyPatch, raised: str, reason: Reason
) -> None:
    import app.checks.dnsbl_engine as engine_mod

    def boom(_lst: DnsblList, _target: DnsblTarget) -> str:
        raise DnsblQueryError(raised)

    monkeypatch.setattr(engine_mod, "build_query_name", boom)
    fake = _fake([])
    (res,) = (await _engine(fake, [BOTH]).run(_targets("192.0.2.1"))).results
    assert (res.outcome, res.reason) == (Outcome.error, reason)
    assert fake.questions == []


async def test_long_domain_gives_name_too_long() -> None:
    fake = _fake([])
    target = ".".join(["a" * 63] * 3) + "." + "b" * 40 + ".example"
    (res,) = (await _engine(fake, [DOM]).run(_targets(target))).results
    assert (res.outcome, res.reason) == (Outcome.error, Reason.name_too_long)


@pytest.mark.parametrize("fail_on", [{1}, {1, 2, 3}, {1, 2, 3, 4, 5, 6}])
async def test_raising_acquire_hook_is_error_and_never_hangs(fail_on: set[int]) -> None:
    fake = _fake([])
    count = 0

    async def acquire(_list_id: str) -> None:
        nonlocal count
        count += 1
        mine = count
        await asyncio.sleep(0)
        if mine in fail_on:
            raise RuntimeError("limiter down")

    engine = _engine(fake, [BOTH], acquire=acquire, concurrency=2, block_threshold=3)
    report = await asyncio.wait_for(
        engine.run(_targets(*(f"192.0.2.{i}" for i in range(1, 7)))), timeout=2
    )
    reasons = [r.reason for r in report.results]
    assert reasons.count(Reason.rate_limit_error) == len(fail_on)
    assert all(r in (Reason.rate_limit_error, None) for r in reasons)
    assert len(fake.questions) == 6 - len(fail_on)
    assert report.blocked_lists == frozenset()
