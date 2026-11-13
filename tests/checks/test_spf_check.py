from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.checks.models import CheckContext, CheckResult, Target
from app.checks.registry import load_builtin_checks
from app.checks.spf import (
    CODES,
    DNS_ANSWER_GUIDELINE,
    MAX_AFTER_ALL_EVIDENCE,
    NEAR_LOOKUP_THRESHOLD,
    SpfCheck,
)
from app.checks.spf_tree import LOOKUP_LIMIT, MX_ADDRESS_LIMIT
from app.core import i18n
from app.dns.types import DnsQuestion, DnsResult, ResultState
from tests.dns.conftest import _no_network_in_dns_tests  # noqa: F401  (autouse socket guard)
from tests.support.dns_zones import FakeResolver, load_zones, parse_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"
LOCALES = Path(i18n.LOCALES_DIR)
_NOW = datetime(2026, 1, 1, tzinfo=UTC)
EN: dict[str, str] = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
IT: dict[str, str] = json.loads((LOCALES / "it.json").read_text(encoding="utf-8"))


def _ctx(resolver: object) -> CheckContext:
    return CheckContext(resolver=resolver, clock=lambda: _NOW)  # type: ignore[arg-type]


def _zone(name: str) -> FakeResolver:
    return load_zones(ZONES / f"spf_{name}.yaml").resolver()


def _fake(entries: list[dict[str, Any]]) -> FakeResolver:
    return parse_zones({"zones": {"default": entries}}).resolver()


def _txt(name: str, *texts: str) -> dict[str, Any]:
    return {"name": name, "type": "TXT", "ttl": 60, "rdata": list(texts)}


def _a(name: str) -> dict[str, Any]:
    return {"name": name, "type": "A", "ttl": 60, "rdata": ["192.0.2.1"]}


def _codes(r: CheckResult) -> set[str]:
    return {f.code for f in r.findings}


def _assert_params_cover_templates(r: CheckResult) -> None:
    for f in r.findings:
        for key in (f.title_key, f.detail_key, f.remediation_key):
            assert key is not None
            assert i18n.placeholders(EN[key]) <= set(f.params), key


async def _check(resolver: object, domain: str) -> CheckResult:
    r = await SpfCheck().run(_ctx(resolver), Target(domain=domain))
    _assert_params_cover_templates(r)
    return r


# --- recorded M3-07 zones ---------------------------------------------------------------------

ZONE_CASES: list[tuple[str, str, str, set[str]]] = [
    ("counts", "simple.example.com", "ok", set()),
    (
        "counts",
        "ten.example.com",
        "warn",
        {"SPF_NEAR_LOOKUP_LIMIT", "SPF_FLATTENING_HINT", "SPF_PTR_DEPRECATED"},
    ),
    (
        "counts",
        "eleven.example.com",
        "fail",
        {"SPF_TOO_MANY_LOOKUPS", "SPF_FLATTENING_HINT", "SPF_PTR_DEPRECATED"},
    ),
    ("counts", "voids2.example.com", "ok", set()),
    (
        "counts",
        "voids3.example.com",
        "fail",
        {"SPF_TOO_MANY_VOID_LOOKUPS", "SPF_INCLUDE_NOT_FOUND"},
    ),
    ("counts", "v6only.example.com", "ok", set()),
    ("counts", "mxten.example.com", "ok", set()),
    ("counts", "mxmany.example.com", "fail", {"SPF_MX_TOO_MANY_HOSTS"}),
    ("counts", "inclplain.example.com", "fail", {"SPF_INCLUDE_NOT_FOUND"}),
    ("counts", "dup.example.com", "ok", set()),
    ("counts", "macro.example.com", "warn", {"SPF_PTR_DEPRECATED"}),
    ("loops", "loopa.example.com", "fail", {"SPF_INCLUDE_LOOP"}),
    ("loops", "self.example.com", "fail", {"SPF_INCLUDE_LOOP"}),
    ("loops", "selfredir.example.com", "fail", {"SPF_INCLUDE_LOOP"}),
    ("loops", "r1.example.com", "ok", set()),
    ("loops", "rall.example.com", "warn", {"SPF_REDIRECT_WITH_ALL"}),
    (
        "loops",
        "d0.example.com",
        "fail",
        {"SPF_TOO_MANY_LOOKUPS", "SPF_RESOLUTION_TRUNCATED", "SPF_FLATTENING_HINT"},
    ),
    ("failures", "mal.example.com", "fail", {"SPF_SYNTAX_ERROR"}),
    ("failures", "synroot.example.com", "fail", {"SPF_SYNTAX_ERROR"}),
    ("failures", "multi.example.com", "fail", {"SPF_MULTIPLE_RECORDS"}),
    ("failures", "incmulti.example.com", "fail", {"SPF_MULTIPLE_RECORDS"}),
    ("failures", "nospf.example.com", "warn", {"SPF_MISSING"}),
    ("failures", "nothing.example.com", "warn", {"SPF_MISSING"}),
    ("failures", "incmissing.example.com", "fail", {"SPF_INCLUDE_NOT_FOUND"}),
    ("failures", "redirmissing.example.com", "fail", {"SPF_INCLUDE_NOT_FOUND"}),
]


@pytest.mark.parametrize(
    ("zone", "domain", "status", "codes"), ZONE_CASES, ids=[c[1] for c in ZONE_CASES]
)
async def test_recorded_zones(zone: str, domain: str, status: str, codes: set[str]) -> None:
    r = await _check(_zone(zone), domain)
    assert _codes(r) == codes
    assert r.status == status


# --- inline records ---------------------------------------------------------------------------

HEALTHY = [
    _txt("healthy.test", "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.ok.test -all"),
    _txt("_spf.ok.test", "v=spf1 ip4:198.51.100.0/24 ~all"),
]

INLINE_CASES: list[tuple[str, list[dict[str, Any]], str, set[str]]] = [
    ("healthy", HEALTHY, "ok", set()),
    ("plus_all", [_txt("x.test", "v=spf1 ip4:192.0.2.1 +all")], "fail", {"SPF_PLUS_ALL"}),
    ("bare_all", [_txt("x.test", "v=spf1 all")], "fail", {"SPF_PLUS_ALL"}),
    (
        "plus_all_in_plus_include",
        [_txt("x.test", "v=spf1 include:i.test -all"), _txt("i.test", "v=spf1 +all")],
        "fail",
        {"SPF_PLUS_ALL"},
    ),
    (
        "plus_all_in_minus_include_not_flagged",
        [_txt("x.test", "v=spf1 -include:i.test -all"), _txt("i.test", "v=spf1 +all")],
        "ok",
        set(),
    ),
    (
        "plus_all_via_redirect",
        [_txt("x.test", "v=spf1 redirect=r.test"), _txt("r.test", "v=spf1 +all")],
        "fail",
        {"SPF_PLUS_ALL"},
    ),
    ("question_all", [_txt("x.test", "v=spf1 ip4:192.0.2.1 ?all")], "warn", {"SPF_QUESTION_ALL"}),
    (
        "softfail_all",
        [_txt("x.test", "v=spf1 ip4:192.0.2.1 ~all")],
        "info",
        {"SPF_NEUTRAL_ALL_SOFTFAIL"},
    ),
    ("no_all", [_txt("x.test", "v=spf1 ip4:192.0.2.1")], "warn", {"SPF_NO_ALL"}),
    (
        "first_all_wins",
        [_txt("x.test", "v=spf1 ip4:192.0.2.1 -all +all")],
        "warn",
        {"SPF_TERMS_AFTER_ALL"},  # R1-17: the unreachable +all is advisory only, not PLUS_ALL
    ),
    (
        "redirect_target_softfail",
        [_txt("x.test", "v=spf1 redirect=r.test"), _txt("r.test", "v=spf1 ip4:192.0.2.1 ~all")],
        "info",
        {"SPF_NEUTRAL_ALL_SOFTFAIL"},
    ),
    (
        "redirect_target_no_all",
        [_txt("x.test", "v=spf1 redirect=r.test"), _txt("r.test", "v=spf1 ip4:192.0.2.1")],
        "warn",
        {"SPF_NO_ALL"},
    ),
    (
        "macro_redirect_not_judged",
        [_txt("x.test", "v=spf1 redirect=%{d}.r.test")],
        "ok",
        set(),
    ),
    (
        "include_softfail_not_policy",
        [_txt("x.test", "v=spf1 include:i.test -all"), _txt("i.test", "v=spf1 ?all")],
        "ok",
        set(),
    ),
    (
        "invalid_target_is_syntax_error",
        [_txt("x.test", "v=spf1 include:" + "x" * 64 + ".example.com -all")],
        "fail",
        {"SPF_SYNTAX_ERROR"},
    ),
    (
        "empty_label_target_is_syntax_error",
        [_txt("x.test", "v=spf1 a:a..example.com -all")],
        "fail",
        {"SPF_SYNTAX_ERROR"},
    ),
    (
        "underscore_redirect_followed",
        [_txt("x.test", "v=spf1 redirect=_x_.example.net"), _txt("_x_.example.net", "v=spf1 -all")],
        "ok",
        set(),
    ),
    (
        "hyphen_edge_a_target_queried",
        [_txt("x.test", "v=spf1 a:x-.example.net -all"), _a("x-.example.net")],
        "ok",
        set(),
    ),
    (
        "missing_underscore_include_not_found",
        [_txt("x.test", "v=spf1 include:a__b.example.net -all")],
        "fail",
        {"SPF_INCLUDE_NOT_FOUND"},
    ),
    ("empty_record", [_txt("x.test", "v=spf1")], "warn", {"SPF_NO_ALL"}),
    ("garbage_only", [_txt("x.test", "v=spf1 \x00 -all")], "fail", {"SPF_SYNTAX_ERROR"}),
    (
        "ptr_and_a",
        [_txt("x.test", "v=spf1 a ptr:x.test -all"), _a("x.test")],
        "warn",
        {"SPF_PTR_DEPRECATED"},
    ),
]


@pytest.mark.parametrize(
    ("entries", "status", "codes"),
    [c[1:] for c in INLINE_CASES],
    ids=[c[0] for c in INLINE_CASES],
)
async def test_inline_records(entries: list[dict[str, Any]], status: str, codes: set[str]) -> None:
    domain = entries[0]["name"]
    r = await _check(_fake(entries), domain)
    assert _codes(r) == codes
    assert r.status == status


def _ip4s(n: int) -> str:
    return " ".join(f"ip4:192.0.2.{i}" for i in range(n))


# Body lengths 13..18 for one ip4 term in a documentation range (RFC 5737), by prefix and width.
_IP4_BODY = {13: ("192.0.2.", 0), 14: ("192.0.2.", 10), 15: ("192.0.2.", 100)}
_IP4_BODY |= {16: ("198.51.100.", 0), 17: ("198.51.100.", 10), 18: ("198.51.100.", 100)}


def _spf_of_length(length: int, tail: str = "-all") -> str:
    """A valid SPF record of exactly ``length`` octets made of distinct ip4 terms."""
    head = "v=spf1"
    rest = length - len(head) - len(tail) - 1  # each term adds " " + body
    k = -(-rest // 19)
    assert 14 * k <= rest, length
    used: dict[int, int] = {}
    terms = []
    for i in range(k):
        body = rest // k + (1 if i < rest % k else 0) - 1
        prefix, first = _IP4_BODY[body]
        terms.append(f"ip4:{prefix}{first + used.get(body, 0)}")
        used[body] = used.get(body, 0) + 1
    record = " ".join([head, *terms, tail])
    assert len(record) == length
    return record


def _split_255(record: str) -> list[str]:
    """RFC 7208 section 3.3: publish as strings of at most 255 octets, joined without spaces."""
    return [record[i : i + 255] for i in range(0, len(record), 255)]


_LEN_NAME = "x.test"


@pytest.mark.parametrize(
    ("answer", "severity"),
    [
        # ``answer`` is what the 450 guideline measures (RFC 7208 section 3.4): name + record text.
        (255, None),
        (256, None),
        (301, None),
        (450, None),
        (451, "medium"),
    ],
)
async def test_record_length(answer: int, severity: str | None) -> None:
    record = _spf_of_length(answer - len(_LEN_NAME))
    entry = {"name": _LEN_NAME, "type": "TXT", "ttl": 60, "rdata": [_split_255(record)]}
    r = await _check(_fake([entry]), _LEN_NAME)
    found = [f for f in r.findings if f.code == "SPF_RECORD_TOO_LONG"]
    if severity is None:
        assert found == [] and not r.findings
        assert r.status == "ok"
        return
    (f,) = found
    assert f.severity == severity
    assert f.params["limit"] == DNS_ANSWER_GUIDELINE and f.params["length"] == answer


@pytest.mark.parametrize(
    ("answer", "codes"),
    [
        (301, {"SPF_SYNTAX_ERROR"}),
        (451, {"SPF_SYNTAX_ERROR", "SPF_RECORD_TOO_LONG"}),
    ],
)
async def test_record_length_malformed(answer: int, codes: set[str]) -> None:
    record = _spf_of_length(answer - len(_LEN_NAME), tail="ip4:bogus -all")
    entry = {"name": _LEN_NAME, "type": "TXT", "ttl": 60, "rdata": [_split_255(record)]}
    r = await _check(_fake([entry]), _LEN_NAME)
    assert _codes(r) == codes
    assert r.status == "fail"


def test_length_thresholds_are_rfc_values() -> None:
    assert DNS_ANSWER_GUIDELINE == 450
    assert NEAR_LOOKUP_THRESHOLD < LOOKUP_LIMIT == 10


@pytest.mark.parametrize(("lookups", "code"), [(8, None), (9, "SPF_NEAR_LOOKUP_LIMIT")])
async def test_near_limit_threshold(lookups: int, code: str | None) -> None:
    terms = " ".join(f"a:h{i}.test" for i in range(lookups))
    entries = [_txt("n.test", f"v=spf1 {terms} -all")] + [_a(f"h{i}.test") for i in range(lookups)]
    r = await _check(_fake(entries), "n.test")
    assert r.data["lookup_count"] == lookups
    if code is None:
        assert r.status == "ok"
    else:
        assert code in _codes(r)
        # No include to rank: no flattening hint.
        assert "SPF_FLATTENING_HINT" not in _codes(r)


async def test_flattening_hint_ranks_includes_and_generates_no_addresses() -> None:
    entries = [
        _txt("f.test", "v=spf1 include:small.test include:big.test a -all"),
        _a("f.test"),
        _txt("small.test", "v=spf1 ip4:192.0.2.1 -all"),
        _txt("big.test", "v=spf1 " + " ".join(f"a:b{i}.test" for i in range(7)) + " -all"),
    ] + [_a(f"b{i}.test") for i in range(7)]
    r = await _check(_fake(entries), "f.test")
    assert r.data["lookup_count"] == 10
    hint = next(f for f in r.findings if f.code == "SPF_FLATTENING_HINT")
    assert hint.evidence == ("include:big.test: 8", "include:small.test: 1")
    assert hint.severity == "info"
    ip = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
    for text in (EN[hint.remediation_key or ""], IT[hint.remediation_key or ""], *hint.evidence):
        assert not ip.search(text)


async def test_include_with_inner_underscore_is_fetched() -> None:
    """R1-06 (DNS-02): a domain-spec label with "_" is a queryable name, not a syntax error."""
    resolver = _fake(
        [
            _txt("example.com", "v=spf1 include:spf_c.example.net -all"),
            _txt("spf_c.example.net", "v=spf1 ip4:192.0.2.0/24 -all"),
        ]
    )
    r = await _check(resolver, "example.com")
    assert DnsQuestion("spf_c.example.net", "TXT") in resolver.questions
    assert "SPF_SYNTAX_ERROR" not in _codes(r)
    assert r.status != "fail"
    assert [n["domain"] for n in r.data["nodes"]] == ["example.com", "spf_c.example.net"]


async def test_syntax_error_evidence_and_children_not_evaluated() -> None:
    r = await _check(_zone("failures"), "mal.example.com")
    (f,) = [f for f in r.findings if f.code == "SPF_SYNTAX_ERROR"]
    assert f.params["name"] == "badrec.example.net"
    assert any(e.startswith("unknown_mechanism") for e in f.evidence)
    names = [n["domain"] for n in r.data["nodes"]]
    assert "okinc.example.net" not in names


async def test_data_is_tree_summary() -> None:
    r = await _check(_zone("counts"), "simple.example.com")
    assert r.data["record"] == "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"
    assert (r.data["lookup_count"], r.data["void_count"]) == (1, 0)
    assert [n["domain"] for n in r.data["nodes"]] == ["simple.example.com", "_spf.example.net"]
    assert r.data["nodes"][1]["via"] == "include"
    json.loads(r.model_dump_json())  # serialisable


@pytest.mark.parametrize(
    ("domain", "hosts"), [("mxten.example.com", 10), ("mxmany.example.com", 11)]
)
async def test_mx_host_limit_boundary(domain: str, hosts: int) -> None:
    r = await _check(_zone("counts"), domain)
    found = [f for f in r.findings if f.code == "SPF_MX_TOO_MANY_HOSTS"]
    if hosts <= MX_ADDRESS_LIMIT:
        assert found == [] and r.status == "ok"
        return
    (f,) = found
    assert f.severity == "high" and r.status == "fail"
    assert dict(f.params) == {"name": domain, "term": "mx", "count": hosts, "limit": 10}


async def test_mx_finding_per_offending_term() -> None:
    hosts = [f"10 m{i}.test" for i in range(11)]
    entries = [
        _txt("x.test", "v=spf1 mx:big.test mx:big2.test mx:small.test -all"),
        {"name": "big.test", "type": "MX", "ttl": 60, "rdata": hosts},
        {"name": "big2.test", "type": "MX", "ttl": 60, "rdata": [*hosts, "10 m99.test"]},
        {"name": "small.test", "type": "MX", "ttl": 60, "rdata": ["10 m1.test"]},
    ]
    r = await _check(_fake(entries), "x.test")
    terms = [(f.params["term"], f.params["count"]) for f in r.findings]
    assert terms == [("mx:big.test", 11), ("mx:big2.test", 12)]


async def test_truncated_is_never_ok() -> None:
    r = await _check(_zone("loops"), "d0.example.com")
    assert r.data["truncated"] is True and r.status == "fail"
    assert r.data["lookup_count"] > LOOKUP_LIMIT


# --- DNS failures -----------------------------------------------------------------------------

FAIL_DOMAINS = [
    ("sf.example.com", "broken.example.net", "servfail"),
    ("to.example.com", "slow.example.net", "timeout"),
    ("trunc.example.com", "big.example.net", "truncated"),
    ("rootfail.example.com", "rootfail.example.com", "servfail"),
]


@pytest.mark.parametrize(("domain", "name", "state"), FAIL_DOMAINS)
async def test_recorded_dns_failures_are_error(domain: str, name: str, state: str) -> None:
    r = await _check(_zone("failures"), domain)
    assert r.status == "error"
    assert _codes(r) == {"SPF_DNS_ERROR"}
    (f,) = r.findings
    assert (f.params["name"], f.params["state"]) == (name, state)


class _Failing:
    """Answers ``state`` for one (name, rdtype); everything else from the inner fake."""

    identity = "failing"

    def __init__(self, inner: FakeResolver, name: str, rdtype: str, state: ResultState) -> None:
        self.inner, self.name, self.rdtype, self.state = inner, name, rdtype, state

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        if (question.name, question.rdtype) == (self.name, self.rdtype):
            return DnsResult(question, self.state)
        return await self.inner.resolve(question)


FAILURE_STATES = [s for s in ResultState if s.is_failure]
TREE = [
    _txt("root.test", "v=spf1 a:h.test mx:m.test exists:e.test include:i.test redirect=r.test"),
    _a("h.test"),
    {"name": "m.test", "type": "MX", "ttl": 60, "rdata": ["10 h.test"]},
    _a("e.test"),
    _txt("i.test", "v=spf1 include:deep.test -all"),
    _txt("deep.test", "v=spf1 ip4:192.0.2.1 -all"),
    _txt("r.test", "v=spf1 -all"),
]
FAIL_POINTS = [
    ("root.test", "TXT"),
    ("h.test", "A"),
    ("h.test", "AAAA"),
    ("m.test", "MX"),
    ("e.test", "A"),
    ("i.test", "TXT"),
    ("deep.test", "TXT"),
    ("r.test", "TXT"),
]


def test_failure_states_cover_blocked_and_refused() -> None:
    assert {ResultState.servfail, ResultState.timeout, ResultState.refused} <= set(FAILURE_STATES)
    assert ResultState.blocked in FAILURE_STATES


async def test_failure_tree_baseline_is_ok() -> None:
    r = await _check(_fake(TREE), "root.test")
    assert r.status == "ok" and r.data["lookup_count"] == 6


@pytest.mark.parametrize("state", FAILURE_STATES, ids=str)
@pytest.mark.parametrize(("name", "rdtype"), FAIL_POINTS, ids=lambda v: str(v))
async def test_every_failure_state_anywhere_is_error(
    name: str, rdtype: str, state: ResultState
) -> None:
    resolver = _Failing(_fake(TREE), name, rdtype, state)
    r = await _check(resolver, "root.test")
    assert r.status == "error"
    assert _codes(r) == {"SPF_DNS_ERROR"}
    (f,) = r.findings
    assert (f.params["name"], f.params["rdtype"], f.params["state"]) == (name, rdtype, str(state))


# --- R1-17: terms after the first all are never tested (RFC 7208 5.1) --------------------------

_ELEVEN = " ".join(f"include:i{i}.test" for i in range(11))
_INCLUDED = [_txt(f"i{i}.test", "v=spf1 ip4:192.0.2.1 -all") for i in range(11)]
_SERVFAIL = {"name": "sf.example.net", "type": "TXT", "state": "servfail", "rcode": 2}


@pytest.mark.parametrize(
    ("record", "status", "codes", "lookups"),
    [
        (f"v=spf1 -all {_ELEVEN}", "warn", {"SPF_TERMS_AFTER_ALL"}, 0),
        (
            f"v=spf1 ~all {_ELEVEN}",
            "warn",
            {"SPF_TERMS_AFTER_ALL", "SPF_NEUTRAL_ALL_SOFTFAIL"},
            0,
        ),
        (f"v=spf1 ?all {_ELEVEN}", "warn", {"SPF_TERMS_AFTER_ALL", "SPF_QUESTION_ALL"}, 0),
        (f"v=spf1 +all {_ELEVEN}", "fail", {"SPF_TERMS_AFTER_ALL", "SPF_PLUS_ALL"}, 0),
        # A SERVFAIL and a missing target behind all are not queried: no error, no permerror.
        (
            "v=spf1 -all include:sf.example.net include:nx.example.net",
            "warn",
            {"SPF_TERMS_AFTER_ALL"},
            0,
        ),
        # The same terms before all keep today's results.
        ("v=spf1 include:sf.example.net -all", "error", {"SPF_DNS_ERROR"}, None),
        (f"v=spf1 {_ELEVEN} -all", "fail", {"SPF_TOO_MANY_LOOKUPS", "SPF_FLATTENING_HINT"}, 11),
        # Modifiers after all are not unreachable mechanisms; redirect keeps its own finding.
        ("v=spf1 -all exp=e.example.net", "ok", set(), 0),
        ("v=spf1 -all redirect=i0.test", "warn", {"SPF_REDIRECT_WITH_ALL"}, 0),
    ],
)
async def test_terms_after_all(
    record: str, status: str, codes: set[str], lookups: int | None
) -> None:
    resolver = _fake([_txt("x.test", record), _SERVFAIL, *_INCLUDED])
    r = await _check(resolver, "x.test")
    assert (r.status, _codes(r)) == (status, codes)
    if lookups is not None:
        assert r.data["lookup_count"] == lookups
    if record.startswith("v=spf1 -all"):
        assert [q.name for q in resolver.questions] == ["x.test"]


async def test_terms_after_all_aggregated_once_per_record_with_capped_evidence() -> None:
    after = " ".join(f"ip4:192.0.2.{i}" for i in range(15))
    resolver = _fake(
        [
            _txt("x.test", f"v=spf1 include:i0.test -all {after} -all"),
            _txt("i0.test", "v=spf1 -all include:sf.example.net a"),
            _SERVFAIL,
        ]
    )
    r = await _check(resolver, "x.test")
    found = [f for f in r.findings if f.code == "SPF_TERMS_AFTER_ALL"]
    assert [(f.severity, f.params["name"], f.params["count"]) for f in found] == [
        ("low", "x.test", 16),
        ("low", "i0.test", 2),
    ]
    assert len(found[0].evidence) == MAX_AFTER_ALL_EVIDENCE
    assert found[0].evidence[0] == "ip4:192.0.2.0"
    assert found[1].evidence == ("include:sf.example.net", "a")
    assert r.status == "warn" and r.data["lookup_count"] == 1


@pytest.mark.parametrize("domain", ["a b.example.com", "a..b", "192.0.2.1", "x\x00.test"])
async def test_malformed_domain_is_error_not_crash(domain: str) -> None:
    resolver = _fake([])
    r = await _check(resolver, domain)
    assert r.status == "error" and _codes(r) == {"SPF_DNS_ERROR"}
    assert resolver.questions == []


# --- registry and i18n ------------------------------------------------------------------------


def test_registered() -> None:
    assert "spf" in load_builtin_checks().all_ids()
    assert SpfCheck.id == "spf"


@pytest.mark.parametrize("code", CODES)
def test_codes_have_complete_i18n(code: str) -> None:
    for part in ("title", "detail", "remediation"):
        k = f"finding.{code}.{part}"
        assert EN.get(k) and IT.get(k), k
        assert i18n.placeholders(EN[k]) == i18n.placeholders(IT[k]), k
    rem = f"finding.{code}.remediation"
    assert EN[rem] != IT[rem], f"{rem}: it is a copy of en"


def test_codes_are_unique_and_prefixed() -> None:
    assert len(set(CODES)) == len(CODES)
    assert all(c.startswith("SPF_") for c in CODES)
