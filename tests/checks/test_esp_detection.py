"""ESP detection (M6-13). Fixture profiles built in the test (example.com / .net / .org hosts) and
the in-memory fake resolver of the M6-04 tests: no real profile file, no network."""

from __future__ import annotations

import asyncio
import json
from datetime import date
from typing import Any

import pytest

from app.checks import esp_detection
from app.checks.esp_detection import CODES, MAX_DETECTION_DKIM_QUERIES
from app.checks.esp_profile import EspHosts, EspProfileCheck
from app.checks.models import CheckResult, Target
from app.core.i18n import LOCALES_DIR, placeholders
from app.dns.types import DnsQuestion, DnsResult, ResultState
from app.esp.profile import EspProfile, parse_esp_profile
from tests.checks.test_esp_profile import FakeDns, Zone, _ctx

TODAY = date(2026, 11, 10)
D = "client.example.com"


def _p(pid: str, includes: list[str], selectors: list[dict[str, Any]], **over: Any) -> EspProfile:
    data: dict[str, Any] = {
        "id": pid,
        "name": pid.replace("-", " ").title(),
        "homepage": "https://esp.example.com",
        "spf": {"includes": includes},
        "dkim": {"selectors": selectors},
        "verified_on": date(2026, 1, 15),
        "sources": ["https://docs.esp.example.com/dns"],
        "status": "verified",
    }
    data.update(over)
    return parse_esp_profile(data, pid, TODAY)


ALPHA = _p(
    "alpha-esp",
    ["spf.alpha.example.com"],
    [
        {"name": "a1", "type": "cname", "target_pattern": "a1.dkim.*.alpha.example.com"},
        {"name": "ak", "type": "txt"},
    ],
)
BETA = _p(
    "beta-esp",
    ["_spf.beta.example.net"],
    [{"name": "bm1", "type": "cname", "target_pattern": "bm1.*.beta.example.net"}],
)
UNVERIFIED = _p(
    "unver-esp",
    ["spf.unver.example.org"],
    [{"name": "u1", "type": "cname", "target_pattern": "u1.*.unver.example.org"}],
    status="unverified",
    unverified_fields=["spf.includes", "dkim.selectors.u1"],
)
NO_PATTERN = _p("nopat-esp", [], [{"name": "np", "type": "cname"}])
# Same selector name and target pattern as ALPHA: a hit is the assigned one's, not a candidate's.
SHARED = _p(
    "shared-esp",
    ["spf.alpha.example.com"],
    [{"name": "a1", "type": "cname", "target_pattern": "a1.dkim.*.alpha.example.com"}],
)
ALL = {p.id: p for p in (ALPHA, BETA, UNVERIFIED, NO_PATTERN, SHARED)}

SPF = (D, "TXT")
A1 = (f"a1._domainkey.{D}", "CNAME")
BM1 = (f"bm1._domainkey.{D}", "CNAME")
U1 = (f"u1._domainkey.{D}", "CNAME")
NP = (f"np._domainkey.{D}", "CNAME")


async def _run(
    zone: Zone, candidates: list[str], assigned: tuple[str, ...] = (), domain: str = D
) -> tuple[CheckResult, FakeDns]:
    dns = FakeDns(zone)
    check = EspProfileCheck(
        [ALL[i] for i in assigned],
        {i: EspHosts() for i in assigned},
        [ALL[i] for i in candidates],
    )
    return await check.run(_ctx(dns), Target(domain=domain)), dns


def _codes(r: CheckResult) -> list[str]:
    return sorted(f.code for f in r.findings)


def _detected(r: CheckResult) -> list[str]:
    return [d["id"] for d in r.data["detection"]["detected"]]


CANDIDATES = ["alpha-esp", "beta-esp", "unver-esp", "nopat-esp"]

# (id, zone, candidates, assigned, detected ids, codes, status)
CASES: list[tuple[str, Zone, list[str], tuple[str, ...], list[str], list[str], str]] = [
    (
        "spf_include_match",
        {SPF: ["v=spf1 include:spf.alpha.example.com -all"]},
        CANDIDATES,
        (),
        ["alpha-esp"],
        ["ESP_DETECTED_NOT_ASSIGNED", "ESP_NONE_ASSIGNED"],
        "warn",
    ),
    (
        "spf_nested_include_match",
        {
            SPF: [f"v=spf1 include:_spf.{D} -all"],
            (f"_spf.{D}", "TXT"): ["v=spf1 include:_spf.beta.example.net -all"],
        },
        CANDIDATES,
        (),
        ["beta-esp"],
        ["ESP_DETECTED_NOT_ASSIGNED", "ESP_NONE_ASSIGNED"],
        "warn",
    ),
    (
        "spf_redirect_match",
        {SPF: ["v=spf1 redirect=_spf.beta.example.net"]},
        CANDIDATES,
        (),
        ["beta-esp"],
        ["ESP_DETECTED_NOT_ASSIGNED", "ESP_NONE_ASSIGNED"],
        "warn",
    ),
    (
        "dkim_cname_match",
        {A1: ["a1.dkim.u42.alpha.example.com."]},
        CANDIDATES,
        (),
        ["alpha-esp"],
        ["ESP_DETECTED_NOT_ASSIGNED", "ESP_NONE_ASSIGNED"],
        "warn",
    ),
    (
        "dkim_cname_mismatch",
        {A1: ["a1.dkim.u42.other.example.com."], BM1: ["somewhere.example.org."]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "dkim_txt_at_selector_is_a_miss",
        {(f"a1._domainkey.{D}", "TXT"): ["v=DKIM1; p=AAAA"]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "unverified_include_and_selector_never_detect",
        {
            SPF: ["v=spf1 include:spf.unver.example.org -all"],
            U1: ["u1.x.unver.example.org."],
        },
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "cname_selector_without_pattern_never_detects",
        {NP: ["anything.example.net."]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "assigned_esp_excluded",
        {
            SPF: ["v=spf1 include:spf.alpha.example.com -all"],
            A1: ["a1.dkim.u42.alpha.example.com."],
            ("spf.alpha.example.com", "TXT"): ["v=spf1 -all"],
        },
        ["beta-esp", "unver-esp", "nopat-esp", "shared-esp"],
        ("alpha-esp",),
        [],
        ["ESP_DKIM_RECORD_MISSING"],  # ALPHA's own txt selector `ak`: M6-04's business
        "fail",
    ),
    (
        "no_assignment_no_detection",
        {SPF: ["v=spf1 -all"]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "no_spf_record_is_a_miss",
        {},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "no_candidates",
        {},
        [],
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
    (
        "spf_dns_failure",
        {SPF: ResultState.servfail},
        CANDIDATES,
        (),
        [],
        ["ESP_DNS_ERROR", "ESP_NONE_ASSIGNED"],
        "error",
    ),
    (
        "nested_spf_timeout",
        {
            SPF: [f"v=spf1 include:_spf.{D} -all"],
            (f"_spf.{D}", "TXT"): ResultState.timeout,
        },
        CANDIDATES,
        (),
        [],
        ["ESP_DNS_ERROR", "ESP_NONE_ASSIGNED"],
        "error",
    ),
    (
        "spf_failure_after_a_hit_still_error",
        {
            SPF: [f"v=spf1 include:spf.alpha.example.com include:_spf.{D} -all"],
            (f"_spf.{D}", "TXT"): ResultState.servfail,
        },
        CANDIDATES,
        (),
        ["alpha-esp"],
        ["ESP_DETECTED_NOT_ASSIGNED", "ESP_DNS_ERROR", "ESP_NONE_ASSIGNED"],
        "error",
    ),
    (
        "dkim_dns_failure",
        {SPF: ["v=spf1 -all"], BM1: ResultState.servfail},
        CANDIDATES,
        (),
        [],
        ["ESP_DNS_ERROR", "ESP_NONE_ASSIGNED"],
        "error",
    ),
    (
        "dkim_resolver_error",
        {SPF: ["v=spf1 -all"], A1: ResultState.network_error},
        CANDIDATES,
        (),
        [],
        ["ESP_DNS_ERROR", "ESP_NONE_ASSIGNED"],
        "error",
    ),
    (
        "malformed_spf_multiple_records",
        {SPF: ["v=spf1 -all", "v=spf1 include:spf.alpha.example.com -all"]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED", "ESP_SPF_PERMERROR"],
        "error",
    ),
    (
        "malformed_spf_syntax_error",
        {SPF: ["v=spf1 include:spf.alpha.example.com ip4:not-an-ip -all"]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED", "ESP_SPF_PERMERROR"],
        "error",
    ),
    (
        "malformed_spf_not_spf_text",
        {SPF: ["google-site-verification=abc", "\x00\xff garbage"]},
        CANDIDATES,
        (),
        [],
        ["ESP_NONE_ASSIGNED"],
        "info",
    ),
]


@pytest.mark.parametrize(
    ("zone", "candidates", "assigned", "detected", "codes", "status"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
async def test_detection(
    zone: Zone,
    candidates: list[str],
    assigned: tuple[str, ...],
    detected: list[str],
    codes: list[str],
    status: str,
) -> None:
    r, dns = await _run(zone, candidates, assigned)
    assert _detected(r) == detected
    assert _codes(r) == codes
    assert r.status == status
    assert r.data["detection"]["truncated"] is False
    # Unverified selectors and selectors without a pattern are never queried.
    assert U1 not in dns.questions and NP not in dns.questions
    # The SPF tree is resolved once per run (shared with the assigned-ESP part).
    assert dns.questions.count(SPF) <= 1


async def test_detected_finding_params_and_evidence() -> None:
    zone: Zone = {
        SPF: ["v=spf1 include:spf.alpha.example.com -all"],
        A1: ["a1.dkim.u42.alpha.example.com."],
    }
    r, _ = await _run(zone, CANDIDATES)
    (f,) = [f for f in r.findings if f.code == "ESP_DETECTED_NOT_ASSIGNED"]
    assert f.severity == "low"
    assert f.params == {"esp_id": "alpha-esp", "esp": "Alpha Esp"}
    assert f.evidence == (
        "include:spf.alpha.example.com",
        f"a1._domainkey.{D} CNAME a1.dkim.u42.alpha.example.com",
    )
    assert f.remediation_key == "finding.ESP_DETECTED_NOT_ASSIGNED.remediation"
    assert r.data["detection"]["detected"] == [
        {
            "id": "alpha-esp",
            "name": "Alpha Esp",
            "spf": ["spf.alpha.example.com"],
            "dkim": [
                {
                    "selector": "a1",
                    "name": f"a1._domainkey.{D}",
                    "target": "a1.dkim.u42.alpha.example.com",
                }
            ],
        }
    ]


async def test_assigned_esp_with_shared_include_and_selector_is_not_a_detection() -> None:
    """SHARED names ALPHA's include and selector; with ALPHA assigned, they are ALPHA's."""
    zone: Zone = {
        SPF: ["v=spf1 include:spf.alpha.example.com -all"],
        A1: ["a1.dkim.u42.alpha.example.com."],
        ("spf.alpha.example.com", "TXT"): ["v=spf1 -all"],
        (f"ak._domainkey.{D}", "TXT"): ["v=DKIM1; p=AAAA"],
    }
    r, _ = await _run(zone, ["shared-esp"], ("alpha-esp",))
    assert _detected(r) == []
    assert r.status == "ok"


async def test_dkim_failure_reports_name_and_state() -> None:
    r, _ = await _run({SPF: ["v=spf1 -all"], BM1: ResultState.servfail}, CANDIDATES)
    (f,) = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert f.params == {
        "esp": "Beta Esp",
        "part": "dkim.selectors.bm1",
        "name": BM1[0],
        "rdtype": "CNAME",
        "state": "servfail",
    }


async def test_spf_failure_names_only_candidates_not_ruled_out() -> None:
    zone: Zone = {
        SPF: [f"v=spf1 include:spf.alpha.example.com include:_spf.{D} -all"],
        (f"_spf.{D}", "TXT"): ResultState.servfail,
    }
    r, _ = await _run(zone, CANDIDATES)
    (f,) = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert f.params["esp"] == "Beta Esp" and f.params["part"] == "spf.includes"
    assert f.params["state"] == "servfail"
    assert r.data["detection"]["spf"] == "error"


async def test_spf_failure_with_every_candidate_matched_is_partial() -> None:
    """The hit stands (status follows it: warn), but the tree was incomplete: "partial", not
    "ok". Not `error`: no candidate is left unruled out."""
    zone: Zone = {
        SPF: [f"v=spf1 include:spf.alpha.example.com include:_spf.{D} -all"],
        (f"_spf.{D}", "TXT"): ResultState.servfail,
    }
    r, _ = await _run(zone, ["alpha-esp"])
    assert r.data["detection"]["spf"] == "partial"
    assert _detected(r) == ["alpha-esp"]
    assert _codes(r) == ["ESP_DETECTED_NOT_ASSIGNED", "ESP_NONE_ASSIGNED"]
    assert r.status == "warn"


@pytest.mark.parametrize(
    ("zone", "spf_state"),
    [
        ({}, None),  # no SPF record at all: the tree is complete and empty
        ({SPF: ["v=spf1 include:spf.alpha.example.com -all"]}, "ok"),
        ({SPF: ResultState.timeout}, "error"),
        ({SPF: ["v=spf1 -all", "v=spf1 ~all"]}, "permerror"),
    ],
    ids=["no_record", "complete", "root_timeout", "two_records"],
)
async def test_spf_state_values(zone: Zone, spf_state: str | None) -> None:
    r, _ = await _run(zone, ["alpha-esp"] if spf_state is not None else ["nopat-esp"])
    assert r.data["detection"]["spf"] == spf_state
    assert (r.status == "error") is (spf_state in ("error", "permerror"))


# --- bounded, fail-fast DKIM probing (M6-13b). No wall clock: asyncio.Event and sleep(0) only.

N_SELECTORS = 20
WIDE = _p(
    "wide-esp",
    [],
    [
        {"name": f"s{i:02d}", "type": "cname", "target_pattern": f"s{i:02d}.*.wide.example.net"}
        for i in range(N_SELECTORS)
    ],
)
WIDE_NAMES = [f"s{i:02d}._domainkey.{D}" for i in range(N_SELECTORS)]


HANG_GUARD_S = 5.0


class GatedDns(FakeDns):
    """`failing` names answer at once and open the gate; every other name waits for the gate,
    which also opens once `open_at` queries are in flight."""

    def __init__(
        self, zone: Zone, failing: set[str], open_at: int = 0, guard_s: float = HANG_GUARD_S
    ) -> None:
        super().__init__(zone)
        self.guard_s = guard_s
        self.failing = failing
        self.open_at = open_at
        self.gate = asyncio.Event()
        self.in_flight = 0

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.in_flight += 1
        try:
            if question.name in self.failing or self.in_flight == self.open_at:
                self.gate.set()
            else:
                # Hang guard only (no pytest-timeout): a gate that never opens fails the test
                # instead of hanging CI. No assertion depends on it.
                await asyncio.wait_for(self.gate.wait(), timeout=self.guard_s)
            return await super().resolve(question)
        finally:
            self.in_flight -= 1


def _dkim_questions(dns: FakeDns) -> list[str]:
    return [n for n, _ in dns.questions if "._domainkey." in n]


@pytest.mark.parametrize(
    "state",
    [ResultState.timeout, ResultState.servfail, ResultState.network_error, ResultState.malformed],
)
async def test_dkim_failure_stops_new_probes(
    monkeypatch: pytest.MonkeyPatch, state: ResultState
) -> None:
    monkeypatch.setattr(esp_detection, "DETECTION_CONCURRENCY", 4)
    failing = WIDE_NAMES[1]
    zone: Zone = {(failing, "CNAME"): state}
    zone.update({(n, "CNAME"): [f"{n[:3]}.x.wide.example.net."] for n in WIDE_NAMES[2:]})
    dns = GatedDns(zone, {failing})
    r = await EspProfileCheck([], {}, [WIDE]).run(_ctx(dns), Target(domain=D))
    asked = _dkim_questions(dns)
    # Bound: after the failure no new query starts, so at most one batch was ever started.
    assert len(asked) <= esp_detection.DETECTION_CONCURRENCY < N_SELECTORS
    assert failing in asked and WIDE_NAMES[-1] not in asked
    assert r.status == "error"
    detection = r.data["detection"]
    assert detection["dkim_stopped"] is True and detection["truncated"] is False
    assert detection["dkim_queries"] == len(asked)
    (f,) = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert f.params["name"] == failing and f.params["state"] == str(state)


async def test_dkim_failures_in_flight_are_all_reported_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every query that started fails; none is swallowed, findings follow selector order."""
    monkeypatch.setattr(esp_detection, "DETECTION_CONCURRENCY", 4)
    first = WIDE_NAMES[:4]
    zone: Zone = {(n, "CNAME"): ResultState.timeout for n in WIDE_NAMES}
    dns = GatedDns(zone, set(), open_at=4)  # four queries in flight, then all time out
    r = await EspProfileCheck([], {}, [WIDE]).run(_ctx(dns), Target(domain=D))
    asked = _dkim_questions(dns)
    assert sorted(asked) == first  # the first batch, nothing after it
    errors = [f.params["name"] for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert errors == first
    assert r.status == "error" and r.data["detection"]["dkim_queries"] == 4


async def test_gate_that_never_opens_fails_instead_of_hanging() -> None:
    """The hang guard of GatedDns works: nothing opens the gate, the run raises."""
    zone: Zone = {(n, "CNAME"): ResultState.timeout for n in WIDE_NAMES}
    dns = GatedDns(zone, set(), open_at=0, guard_s=0.01)
    with pytest.raises(TimeoutError):
        await EspProfileCheck([], {}, [WIDE]).run(_ctx(dns), Target(domain=D))


async def test_stop_on_failure_drops_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Over the cap and stopped on a failure: `error` only, no ESP_DETECTION_TRUNCATED."""
    monkeypatch.setattr(esp_detection, "MAX_DETECTION_DKIM_QUERIES", 1)
    r, _ = await _run({SPF: ["v=spf1 -all"], A1: ResultState.servfail}, CANDIDATES)
    detection = r.data["detection"]
    assert detection["dkim_stopped"] is True
    assert detection["truncated"] is False and detection["unprobed"] == []
    assert "ESP_DETECTION_TRUNCATED" not in _codes(r)
    assert r.status == "error"


class ReorderingDns(FakeDns):
    """Later names answer first (fewer event-loop turns); records the most queries in flight."""

    def __init__(self, zone: Zone) -> None:
        super().__init__(zone)
        self.in_flight = 0
        self.max_in_flight = 0

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            idx = WIDE_NAMES.index(question.name) if question.name in WIDE_NAMES else 0
            for _ in range(2 * (N_SELECTORS - idx)):
                await asyncio.sleep(0)
            return await super().resolve(question)
        finally:
            self.in_flight -= 1


async def _wide_run(monkeypatch: pytest.MonkeyPatch, concurrency: int) -> tuple[Any, ReorderingDns]:
    monkeypatch.setattr(esp_detection, "DETECTION_CONCURRENCY", concurrency)
    zone: Zone = {(n, "CNAME"): [f"{n[:3]}.x.wide.example.net."] for n in WIDE_NAMES}
    zone[(WIDE_NAMES[5], "CNAME")] = ["elsewhere.example.org."]  # a miss among the hits
    other = _p(
        "other-esp",
        [],
        [{"name": "s03", "type": "cname", "target_pattern": "s03.*.wide.example.net"}],
    )
    dns = ReorderingDns(zone)
    r = await EspProfileCheck([], {}, [WIDE, other]).run(_ctx(dns), Target(domain=D))
    return r, dns


async def test_concurrency_is_bounded_and_order_ignores_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r, dns = await _wide_run(monkeypatch, 4)
    assert 1 < dns.max_in_flight <= 4
    serial, serial_dns = await _wide_run(monkeypatch, 1)
    assert serial_dns.max_in_flight == 1
    assert r.findings == serial.findings
    assert r.data["detection"] == serial.data["detection"]
    detection = r.data["detection"]
    assert [d["id"] for d in detection["detected"]] == ["other-esp", "wide-esp"]
    wide = detection["detected"][1]["dkim"]
    assert [d["selector"] for d in wide] == [f"s{i:02d}" for i in range(N_SELECTORS) if i != 5]
    assert detection["dkim_queries"] == N_SELECTORS and detection["dkim_stopped"] is False
    assert len(set(_dkim_questions(dns))) == len(_dkim_questions(dns)) == N_SELECTORS


async def test_cap_reached_is_partial_and_never_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(esp_detection, "MAX_DETECTION_DKIM_QUERIES", 1)
    r, dns = await _run({SPF: ["v=spf1 -all"]}, CANDIDATES)
    dkim_queries = [q for q in dns.questions if q[0].endswith(f"._domainkey.{D}")]
    assert len(dkim_queries) == 1
    detection = r.data["detection"]
    assert detection["truncated"] is True
    assert detection["dkim_queries"] == 1 and detection["dkim_query_limit"] == 1
    assert detection["unprobed"] == ["beta-esp"]
    (f,) = [f for f in r.findings if f.code == "ESP_DETECTION_TRUNCATED"]
    assert f.severity == "low" and f.params == {"limit": 1}
    assert f.evidence == ("beta-esp",)
    assert r.status == "warn"


async def test_cap_keeps_hits_found_before_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(esp_detection, "MAX_DETECTION_DKIM_QUERIES", 1)
    r, _ = await _run({A1: ["a1.dkim.u42.alpha.example.com."]}, CANDIDATES)
    assert _detected(r) == ["alpha-esp"]
    assert "ESP_DETECTION_TRUNCATED" in _codes(r)


async def test_real_cap_bounds_queries() -> None:
    many = [
        _p(
            f"many{n}-esp",
            [],
            [
                {"name": f"m{n}x{i}", "type": "cname", "target_pattern": f"m{i}.*.example.com"}
                for i in range(15)
            ],
        )
        for n in range(3)
    ]
    assert MAX_DETECTION_DKIM_QUERIES < 3 * 15
    dns = FakeDns({SPF: ["v=spf1 -all"]})
    r = await EspProfileCheck([], {}, many).run(_ctx(dns), Target(domain=D))
    assert len([q for q in dns.questions if "._domainkey." in q[0]]) == MAX_DETECTION_DKIM_QUERIES
    assert r.data["detection"]["truncated"] is True
    assert r.status != "ok"


async def test_shared_selector_name_is_queried_once() -> None:
    other = _p(
        "other-a1-esp",
        [],
        [{"name": "a1", "type": "cname", "target_pattern": "a1.*.other.example.net"}],
    )
    dns = FakeDns({A1: ["a1.x.other.example.net."]})
    r = await EspProfileCheck([], {}, [ALPHA, other]).run(_ctx(dns), Target(domain=D))
    assert dns.questions.count(A1) == 1
    assert [d["id"] for d in r.data["detection"]["detected"]] == ["other-a1-esp"]


async def test_invalid_selector_name_is_error() -> None:
    domain = ".".join(["x" * 63] * 3 + ["y" * 41]) + ".example.com"
    assert len(domain) == 245  # a valid name, too long with "a1._domainkey." in front
    r, _ = await _run({}, ["alpha-esp"], domain=domain)
    assert r.status == "error"
    assert "ESP_DNS_ERROR" in _codes(r)


async def test_invalid_domain_is_error() -> None:
    r, dns = await _run({}, CANDIDATES, domain="bad..name")
    assert r.status == "error" and dns.questions == []


async def test_detection_off_keeps_m6_04_shape() -> None:
    dns = FakeDns({})
    r = await EspProfileCheck([]).run(_ctx(dns), Target(domain=D))
    assert _codes(r) == ["ESP_NONE_ASSIGNED"] and r.data == {"esps": []}
    assert dns.questions == []


def test_candidates_must_not_overlap_or_repeat() -> None:
    with pytest.raises(ValueError):
        EspProfileCheck([ALPHA], {}, [ALPHA])
    with pytest.raises(ValueError):
        EspProfileCheck([], {}, [BETA, BETA])


def test_codes_have_keys_in_both_languages() -> None:
    for lang in ("en", "it"):
        catalogue = json.loads((LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        for code in CODES:
            for part in ("title", "detail", "remediation"):
                assert f"finding.{code}.{part}" in catalogue, (lang, code, part)
    en = json.loads((LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
    it = json.loads((LOCALES_DIR / "it.json").read_text(encoding="utf-8"))
    for code in CODES:
        for part in ("title", "detail", "remediation"):
            key = f"finding.{code}.{part}"
            assert placeholders(en[key]) == placeholders(it[key]), key


def test_detected_wording_is_viewer_safe() -> None:
    en = json.loads((LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
    text = " ".join(en[f"finding.ESP_DETECTED_NOT_ASSIGNED.{p}"] for p in ("detail", "title"))
    assert "misconfigur" not in text.lower() and "stale" in text.lower()
