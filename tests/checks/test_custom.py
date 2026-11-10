"""M5-22 custom DNS check evaluator. Fake resolvers only; no network.

The regex engine really runs (its worker is a local subprocess) except where a test stubs it.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.checks import custom as custom_module
from app.checks.custom import (
    CODES,
    MAX_EVIDENCE_CHARS,
    MAX_EVIDENCE_ITEMS,
    MAX_RECORDS,
    MAX_REGEX_BUDGET_S,
    CustomDnsCheck,
)
from app.checks.models import CheckContext, CheckResult, Target
from app.core import custom_check_schema
from app.core.i18n import LOCALES_DIR, t
from app.core.safe_regex import Match, MatchResult, SearchFailure
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState, join_txt_strings
from app.services.checks import DEFAULT_DEADLINE_S

NAME = "_x.example.com"
TEXT = {"en": "Publish <b>it</b>.", "it": "Pubblicalo."}
NOW = datetime(2026, 11, 9, tzinfo=UTC)
FAILURES = [
    s for s in ResultState if s not in (ResultState.ok, ResultState.nxdomain, ResultState.nodata)
]


class Dns:
    """Canned answer for any question; records every question it sees."""

    identity = "fake"

    def __init__(
        self,
        state: ResultState = ResultState.ok,
        values: tuple[str, ...] = (),
        rrtype: str = "TXT",
    ) -> None:
        self.state, self.values, self.rrtype = state, values, rrtype
        self.questions: list[DnsQuestion] = []

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.questions.append(question)
        records = tuple(DnsRecord(question.name, self.rrtype, 60, value) for value in self.values)
        return DnsResult(question, self.state, records)


class Exploding:
    identity = "exploding"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        raise RuntimeError("boom")


def _spec(kind: str, **definition: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"name": "_x.{domain}", "rrtype": "TXT"}
    return {"kind": kind, "definition": base | definition}


EXISTS = _spec("dns_exists")
MATCHES = _spec("dns_matches", pattern="^v=spf1")
RANGE = _spec("dns_value_range", min=0, max=100)


async def _run(
    spec: dict[str, Any], dns: Any, domain: str = "example.com", **overrides: Any
) -> CheckResult:
    values: dict[str, Any] = {
        "check_key": "acme.check",
        "severity": "medium",
        "remediation_text": dict(TEXT),
        "scope": "tenant",
        **spec,
        **overrides,
    }
    ctx = CheckContext(resolver=dns, clock=lambda: NOW)
    return await CustomDnsCheck(**values).run(ctx, Target(domain=domain))


def _reason(result: CheckResult) -> str:
    return str(result.data["reason"])


def _assert_error(result: CheckResult, reason: str) -> None:
    assert result.status == "error"
    assert _reason(result) == reason
    assert [f.code for f in result.findings] == ["CUSTOM_CHECK_ERROR"]
    assert result.findings[0].params["reason"] == reason


def _assert_failed(result: CheckResult, reason: str, status: str = "warn") -> None:
    assert result.status == status
    assert _reason(result) == reason
    assert [f.code for f in result.findings] == ["CUSTOM_CHECK_FAILED"]
    assert result.findings[0].params["reason"] == reason


# --- DNS outcomes, every kind ---------------------------------------------------------------------


@pytest.mark.parametrize("spec", [EXISTS, MATCHES, RANGE], ids=["exists", "matches", "range"])
@pytest.mark.parametrize("state", FAILURES)
async def test_dns_failure_is_error_never_absent(spec: dict[str, Any], state: ResultState) -> None:
    result = await _run(spec, Dns(state))
    _assert_error(result, f"dns_{state}")
    assert all(f.code != "CUSTOM_CHECK_FAILED" for f in result.findings)
    assert result.data["state"] == str(state)


@pytest.mark.parametrize("spec", [EXISTS, MATCHES, RANGE], ids=["exists", "matches", "range"])
@pytest.mark.parametrize("state", [ResultState.nxdomain, ResultState.nodata])
async def test_missing_record_is_a_finding_with_distinct_reason(
    spec: dict[str, Any], state: ResultState
) -> None:
    result = await _run(spec, Dns(state))
    _assert_failed(result, str(state))
    assert result.data["state"] == str(state)


@pytest.mark.parametrize("spec", [EXISTS, MATCHES, RANGE], ids=["exists", "matches", "range"])
async def test_ok_without_a_record_of_the_asked_type_is_error(spec: dict[str, Any]) -> None:
    _assert_error(await _run(spec, Dns(values=("x",), rrtype="CNAME")), "dns_error")


async def test_resolver_exception_is_error() -> None:
    _assert_error(await _run(EXISTS, Exploding()), "internal_error")


@pytest.mark.parametrize(
    ("values", "rrtype"),
    [(("anything",), "TXT"), (("192.0.2.1",), "A"), (("a", "b"), "TXT")],
)
async def test_exists_ok(values: tuple[str, ...], rrtype: str) -> None:
    dns = Dns(values=values, rrtype=rrtype)
    result = await _run(_spec("dns_exists", rrtype=rrtype), dns)
    assert result.status == "ok" and result.findings == ()
    assert result.data["records"] == len(values)
    assert dns.questions == [DnsQuestion(NAME, rrtype)]


async def test_exists_ignores_the_record_cap() -> None:
    result = await _run(EXISTS, Dns(values=tuple("x" * (MAX_RECORDS + 1))))
    assert result.status == "ok"


@pytest.mark.parametrize(
    ("severity", "status"), [("low", "warn"), ("medium", "warn"), ("high", "fail")]
)
async def test_configured_severity_drives_status(severity: str, status: str) -> None:
    result = await _run(EXISTS, Dns(ResultState.nxdomain), severity=severity)
    _assert_failed(result, "nxdomain", status)
    assert result.findings[0].severity == severity


# --- dns_matches ---------------------------------------------------------------------------------

MATCH_CASES = [
    ("hit", ("v=spf1 -all",), "ok", None),
    ("miss", ("google-site-verification=x",), "warn", "no_match"),
    ("one of several hits", ("other", "v=spf1 -all"), "ok", None),
    ("hit first then miss", ("v=spf1 -all", "other"), "ok", None),
    ("none of several", ("other", "more"), "warn", "no_match"),
    ("empty text", ("",), "warn", "no_match"),
]


@pytest.mark.parametrize(
    ("case", "values", "status", "reason"), MATCH_CASES, ids=[c[0] for c in MATCH_CASES]
)
async def test_matches(case: str, values: tuple[str, ...], status: str, reason: str | None) -> None:
    result = await _run(MATCHES, Dns(values=values))
    assert result.status == status
    if reason is None:
        assert result.findings == ()
    else:
        _assert_failed(result, reason)


async def test_txt_multi_string_is_matched_concatenated() -> None:
    joined = join_txt_strings([b"v=sp", b"f1 ", b"-all"])
    assert joined == "v=spf1 -all"
    result = await _run(_spec("dns_matches", pattern="^v=spf1 -all$"), Dns(values=(joined,)))
    assert result.status == "ok"


async def test_txt_records_are_never_merged() -> None:
    result = await _run(_spec("dns_matches", pattern="v=spf1"), Dns(values=("v=sp", "f1")))
    _assert_failed(result, "no_match")


async def test_catastrophic_regex_is_cut_off_and_error() -> None:
    spec = _spec("dns_matches", pattern="(a+)+$")
    t0 = time.monotonic()
    result = await _run(spec, Dns(values=("a" * 64 + "!",)))
    elapsed = time.monotonic() - t0
    _assert_error(result, "regex_timeout")
    assert elapsed < 4.0  # the 1 s rule timeout plus worker start, never a longer timeout


INCOMPLETE = [
    ("timeout", MatchResult((), True, False, SearchFailure.TIMEOUT), "regex_timeout"),
    ("batch", MatchResult((), True, False, SearchFailure.BATCH_DEADLINE), "regex_budget_exceeded"),
    ("busy", MatchResult((), False, False, SearchFailure.BUSY), "regex_failed"),
    ("worker", MatchResult((), False, False, SearchFailure.WORKER_FAILED), "regex_failed"),
    ("too large", MatchResult((), False, True, SearchFailure.TEXT_TOO_LARGE), "regex_failed"),
    ("truncated", MatchResult((), False, True), "regex_failed"),
]


@pytest.mark.parametrize(("case", "outcome", "reason"), INCOMPLETE, ids=[c[0] for c in INCOMPLETE])
async def test_incomplete_regex_result_is_error(
    monkeypatch: pytest.MonkeyPatch, case: str, outcome: MatchResult, reason: str
) -> None:
    monkeypatch.setattr(custom_module, "search_many", lambda *_a, **_k: [outcome])
    _assert_error(await _run(MATCHES, Dns(values=("v=spf1",))), reason)


@pytest.mark.parametrize("values", [("v=spf1 ok", "boom"), ("boom", "v=spf1 ok")])
async def test_incomplete_search_beats_a_hit_in_any_order(
    monkeypatch: pytest.MonkeyPatch, values: tuple[str, str]
) -> None:
    real = custom_module.search_many

    def fake(rules: Any, text: str, **kwargs: Any) -> list[MatchResult]:
        if text == "boom":
            return [MatchResult((), True, False, SearchFailure.TIMEOUT)]
        return real(rules, text, **kwargs)

    monkeypatch.setattr(custom_module, "search_many", fake)
    _assert_error(await _run(MATCHES, Dns(values=values)), "regex_timeout")


CAPPED = [(MATCHES, "v=spf1"), (RANGE, "5")]


@pytest.mark.parametrize(("spec", "value"), CAPPED, ids=["matches", "range"])
@pytest.mark.parametrize("count", [17, 64])
async def test_records_up_to_the_cap_are_evaluated(
    spec: dict[str, Any], value: str, count: int
) -> None:
    result = await _run(spec, Dns(values=(value,) * count))
    assert result.status == "ok" and result.data["records"] == count


@pytest.mark.parametrize(("spec", "value"), CAPPED, ids=["matches", "range"])
async def test_too_many_records_is_error_not_a_partial_verdict(
    spec: dict[str, Any], value: str
) -> None:
    assert MAX_RECORDS == 64
    _assert_error(await _run(spec, Dns(values=(value,) * 65)), "too_many_records")


class _Budget:
    """Stubbed matcher on a fake clock: every search takes `step` seconds, no real waiting."""

    def __init__(self, step: float, hit: bool) -> None:
        self.step, self.hit, self.now = step, hit, 0.0
        self.calls: list[tuple[float, float]] = []

    def clock(self) -> float:
        return self.now

    def search(self, _rules: Any, text: str, **kwargs: Any) -> list[MatchResult]:
        self.calls.append((kwargs["timeout_s"], kwargs["total_timeout_s"]))
        self.now += self.step
        matches = (Match(0, len(text), text),) if self.hit else ()
        return [MatchResult(matches, False, False)]

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(custom_module, "_regex_clock", self.clock)
        monkeypatch.setattr(custom_module, "search_many", self.search)


BUDGET_EXCEEDED = [
    ("runs out midway, hits so far", 5, 4.0, True, 3),
    ("runs out midway, no hit so far", 5, 4.0, False, 3),
    ("last search ends past it, hit", 3, 4.0, True, 3),
    ("last search ends past it, no hit", 3, 4.0, False, 3),
    ("exactly at the budget", 2, 5.0, True, 2),
]


@pytest.mark.parametrize(
    ("case", "records", "step", "hit", "searched"),
    BUDGET_EXCEEDED,
    ids=[c[0] for c in BUDGET_EXCEEDED],
)
async def test_regex_budget_exceeded_is_error_never_a_verdict(
    monkeypatch: pytest.MonkeyPatch, case: str, records: int, step: float, hit: bool, searched: int
) -> None:
    budget = _Budget(step, hit)
    budget.install(monkeypatch)
    _assert_error(await _run(MATCHES, Dns(values=("x",) * records)), "regex_budget_exceeded")
    assert len(budget.calls) == searched


@pytest.mark.parametrize(("hit", "status"), [(True, "ok"), (False, "warn")])
async def test_verdict_within_the_regex_budget(
    monkeypatch: pytest.MonkeyPatch, hit: bool, status: str
) -> None:
    _Budget(3.0, hit).install(monkeypatch)
    assert (await _run(MATCHES, Dns(values=("x",) * 3))).status == status


async def test_each_search_gets_only_the_budget_left(monkeypatch: pytest.MonkeyPatch) -> None:
    budget = _Budget(9.5, True)
    budget.install(monkeypatch)
    await _run(MATCHES, Dns(values=("x", "y")))
    assert budget.calls == [(1.0, MAX_REGEX_BUDGET_S), (0.5, 0.5)]


def test_regex_budget_is_below_the_run_deadline() -> None:
    assert MAX_REGEX_BUDGET_S == 10.0
    assert MAX_REGEX_BUDGET_S < DEFAULT_DEADLINE_S


async def test_regex_is_recompiled_on_every_run(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = custom_check_schema.compile_checked

    def spy(pattern: str, flags: int = 0) -> Any:
        calls.append(pattern)
        return real(pattern, flags)

    monkeypatch.setattr(custom_check_schema, "compile_checked", spy)
    values: dict[str, Any] = {"severity": "low", "remediation_text": dict(TEXT), **MATCHES}
    check = CustomDnsCheck(check_key="a", **values)
    assert calls == []  # nothing compiled at construction
    ctx = CheckContext(resolver=Dns(values=("v=spf1",)), clock=lambda: NOW)
    for _ in range(2):
        await check.run(ctx, Target(domain="example.com"))
    assert calls == ["^v=spf1", "^v=spf1"]


# --- dns_value_range -----------------------------------------------------------------------------

RANGE_CASES = [
    ("inside", ("50",), "ok", None),
    ("lower bound", ("0",), "ok", None),
    ("upper bound", ("100",), "ok", None),
    ("decimal", ("99.5",), "ok", None),
    ("plus sign", ("+5",), "ok", None),
    ("surrounding blanks", (" 5\t",), "ok", None),
    ("all inside", ("1", "2"), "ok", None),
    ("above", ("100.01",), "warn", "out_of_range"),
    ("negative", ("-1",), "warn", "out_of_range"),
    ("one outside", ("5", "500"), "warn", "out_of_range"),
    ("text", ("abc",), "error", "non_numeric"),
    ("empty", ("",), "error", "non_numeric"),
    ("exponent", ("1e2",), "error", "non_numeric"),
    ("nan", ("NaN",), "error", "non_numeric"),
    ("inf", ("inf",), "error", "non_numeric"),
    ("infinity", ("Infinity",), "error", "non_numeric"),
    ("hex", ("0x10",), "error", "non_numeric"),
    ("underscore", ("1_000",), "error", "non_numeric"),
    ("arabic digits", ("١٢",), "error", "non_numeric"),
    ("trailing text", ("5 apples",), "error", "non_numeric"),
    ("too long", ("1" * 40,), "error", "non_numeric"),
    ("newline", ("5\n",), "error", "non_numeric"),
    ("one non numeric", ("5", "abc"), "error", "non_numeric"),
    ("out of range and non numeric", ("500", "abc"), "error", "non_numeric"),
]


@pytest.mark.parametrize(
    ("case", "values", "status", "reason"), RANGE_CASES, ids=[c[0] for c in RANGE_CASES]
)
async def test_range(case: str, values: tuple[str, ...], status: str, reason: str | None) -> None:
    result = await _run(RANGE, Dns(values=values))
    if status == "error":
        assert reason is not None
        _assert_error(result, reason)
    elif reason is None:
        assert result.status == "ok" and result.findings == ()
    else:
        _assert_failed(result, reason, status)


HALF = 2**53
RANGE_EDGES = [
    ("just above an int max", 0, 100, "100.00000000000000000000001", "out_of_range"),
    ("just below an int min", 100, 200, "99.99999999999999999999999", "out_of_range"),
    ("above 2**53 max", 0, HALF, "9007199254740993", "out_of_range"),
    ("below -2**53 min", -HALF, 0, "-9007199254740993", "out_of_range"),
    ("at 2**53 max", 0, HALF, "9007199254740992", None),
    ("trailing zeros at max", 0, 100, "100.000000000000000000000000", None),
    ("float min as written", 0.1, 1, "0.1", None),
    ("float max as written", 0, 0.1, "0.1", None),
    ("just above a float max", 0, 0.1, "0.1000000000000000001", "out_of_range"),
    ("just below a float min", 0.1, 1, "0.0999999999999999999", "out_of_range"),
    ("above a tiny float max", 0, 1e-300, "0.000000000000000000000000000001", "out_of_range"),
]


@pytest.mark.parametrize(
    ("case", "low", "high", "value", "reason"), RANGE_EDGES, ids=[c[0] for c in RANGE_EDGES]
)
async def test_range_compares_exactly(
    case: str, low: float, high: float, value: str, reason: str | None
) -> None:
    result = await _run(_spec("dns_value_range", min=low, max=high), Dns(values=(value,)))
    if reason is None:
        assert result.status == "ok" and result.findings == ()
    else:
        _assert_failed(result, reason)


@pytest.mark.parametrize(
    "value",
    [
        "sNaN",
        "-sNaN",
        "NaN123",
        "-NaN",
        "Inf",
        "-Infinity",
        "+Infinity",
        "1E+999999",
        "1e999999999999999999",
        "1E-999999",
        ".5",
        "5.",
        "1" * 31,
        "0." + "1" * 31,
    ],
)
async def test_range_grammar_stays_strict(value: str) -> None:
    _assert_error(await _run(RANGE, Dns(values=(value,))), "non_numeric")


async def test_stored_range_on_another_rrtype_is_error_without_a_query() -> None:
    dns = Dns(values=("10 mx.example.com",), rrtype="MX")
    result = await _run(_spec("dns_value_range", rrtype="MX", min=0, max=100), dns)
    _assert_error(result, "invalid_definition")
    assert (result.data["field"], result.data["detail"]) == (
        "definition.rrtype",
        "range_requires_txt",
    )
    assert dns.questions == []


# --- never trusts what is stored ------------------------------------------------------------------

STORED_INVALID = [
    ("not a mapping", {"kind": "dns_exists", "definition": "x"}, {}),
    ("unknown key", _spec("dns_exists", extra=1), {}),
    ("bad template", _spec("dns_exists", name="{domain}.evil.example"), {}),
    ("format trick", _spec("dns_exists", name="{domain.__class__}"), {}),
    ("no placeholder", _spec("dns_exists", name="evil.example"), {}),
    ("bad rrtype", _spec("dns_exists", rrtype="ANY"), {}),
    ("bad regex", _spec("dns_matches", pattern="(a"), {}),
    ("oversize regex", _spec("dns_matches", pattern="a" * 1025), {}),
    ("bool range", _spec("dns_value_range", min=True, max=5), {}),
    ("nan range", _spec("dns_value_range", min=float("nan"), max=5), {}),
    ("reversed range", _spec("dns_value_range", min=5, max=1), {}),
    ("unknown kind", {"kind": "glob", "definition": {"name": "{domain}", "rrtype": "A"}}, {}),
    ("severity outside the schema", EXISTS, {"severity": "critical"}),
    ("severity unknown", EXISTS, {"severity": "urgent"}),
    ("severity missing", EXISTS, {"severity": None}),
    ("no remediation", EXISTS, {"remediation_text": None}),
    ("remediation one language", EXISTS, {"remediation_text": {"en": "x"}}),
    ("remediation too long", EXISTS, {"remediation_text": {"en": "x" * 2001, "it": "y"}}),
    ("remediation nul", EXISTS, {"remediation_text": {"en": "x\x00", "it": "y"}}),
    (
        "tenant row with remediation_key",
        EXISTS,
        {"remediation_text": None, "remediation_key": "custom_check.a.remediation"},
    ),
    (
        "global row with both",
        EXISTS,
        {"remediation_key": "custom_check.a.remediation", "scope": "global"},
    ),
]


@pytest.mark.parametrize(
    ("case", "spec", "overrides"), STORED_INVALID, ids=[c[0] for c in STORED_INVALID]
)
async def test_invalid_stored_definition_is_error_and_never_queries(
    case: str, spec: dict[str, Any], overrides: dict[str, Any]
) -> None:
    dns = Dns(values=("v=spf1",))
    result = await _run(spec, dns, **overrides)
    _assert_error(result, "invalid_definition")
    assert dns.questions == []
    assert "field" in result.data and "detail" in result.data


@pytest.mark.parametrize(
    "definition", [EXISTS["definition"], {}, None, {"url": "http://x.example"}]
)
async def test_http_fetch_refused_and_never_queries(definition: object) -> None:
    dns = Dns(values=("x",))
    result = await _run({"kind": "http_fetch", "definition": definition}, dns)
    assert result.status == "error"
    assert [f.code for f in result.findings] == ["CUSTOM_KIND_UNAVAILABLE"]
    assert result.data["reason"] == "kind_unavailable"
    assert dns.questions == []


# --- record name ----------------------------------------------------------------------------------


def _long_domain(length: int) -> str:
    tail = ".example"
    room = length - len(tail)
    labels: list[str] = []
    while room > 0:
        size = min(63, room)
        if room - size == 1:
            size -= 1
        labels.append("a" * size)
        room -= size + 1
    return ".".join(labels) + tail


@pytest.mark.parametrize(
    ("domain", "reason"),
    [
        (_long_domain(251), "name_too_long"),
        ("localhost", "invalid_domain"),
        ("192.0.2.1", "invalid_domain"),
        ("a b.example", "invalid_domain"),
    ],
)
async def test_name_that_cannot_be_built_is_error_without_a_query(domain: str, reason: str) -> None:
    dns = Dns(values=("x",))
    _assert_error(await _run(EXISTS, dns, domain=domain), reason)
    assert dns.questions == []


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("EXAMPLE.com.", NAME),
        ("bücher.example", "_x.xn--bcher-kva.example"),
    ],
)
async def test_target_domain_is_normalised(domain: str, expected: str) -> None:
    dns = Dns(values=("x",))
    assert (await _run(EXISTS, dns, domain=domain)).status == "ok"
    assert dns.questions[0].name == expected


# --- evidence, remediation, i18n ------------------------------------------------------------------


async def test_evidence_is_bounded() -> None:
    big = tuple("x" * 5000 for _ in range(MAX_RECORDS))
    result = await _run(MATCHES, Dns(values=big))
    evidence = result.findings[0].evidence
    assert len(evidence) == MAX_EVIDENCE_ITEMS
    assert all(len(item) == MAX_EVIDENCE_CHARS for item in evidence)


async def test_evidence_is_printable() -> None:
    result = await _run(MATCHES, Dns(values=("bad\x00\x1b[31m\xa0text",)))
    assert result.findings[0].evidence == ("bad??[31m?text",)


async def test_error_finding_has_no_evidence_and_no_remediation() -> None:
    finding = (await _run(MATCHES, Dns(ResultState.timeout))).findings[0]
    assert finding.evidence == () and finding.remediation_key is None
    assert "remediation_text" not in finding.params


async def test_remediation_is_the_definition_text_and_not_an_i18n_key() -> None:
    finding = (await _run(EXISTS, Dns(ResultState.nxdomain))).findings[0]
    assert finding.remediation_key is None
    assert finding.params["remediation_text"] == TEXT  # raw: renderers autoescape it


async def test_global_row_with_a_key_has_no_remediation_text() -> None:
    result = await _run(
        EXISTS,
        Dns(ResultState.nodata),
        scope="global",
        remediation_text=None,
        remediation_key="custom_check.a.remediation",
    )
    _assert_failed(result, "nodata")
    assert "remediation_text" not in result.findings[0].params
    assert result.findings[0].remediation_key is None


@pytest.mark.parametrize("bad", ["Upper", "", "a b", "k" * 65, None, 5])
async def test_untrusted_check_key_is_not_echoed(bad: Any) -> None:
    result = await _run(EXISTS, Dns(ResultState.nxdomain), check_key=bad)
    assert result.check_id == "custom:invalid"
    assert result.findings[0].params["check_key"] == "invalid"


async def test_result_ids_and_serialization() -> None:
    result = await _run(EXISTS, Dns(ResultState.nxdomain))
    assert result.check_id == "custom:acme.check" and result.target == "example.com"
    assert json.loads(result.model_dump_json())["findings"][0]["code"] == "CUSTOM_CHECK_FAILED"


def test_codes_have_title_and_detail_only() -> None:
    assert len(set(CODES)) == 3
    for lang in ("en", "it"):
        data = json.loads((Path(LOCALES_DIR) / f"{lang}.json").read_text(encoding="utf-8"))
        for code in CODES:
            assert f"finding.{code}.title" in data and f"finding.{code}.detail" in data
            assert f"finding.{code}.remediation" not in data


@pytest.mark.parametrize("lang", ["en", "it"])
async def test_every_finding_renders_with_its_params(lang: str) -> None:
    cases = [
        await _run(EXISTS, Dns(ResultState.nxdomain)),
        await _run(EXISTS, Dns(ResultState.timeout)),
        await _run({"kind": "http_fetch", "definition": {}}, Dns()),
    ]
    assert {r.findings[0].code for r in cases} == set(CODES)
    for result in cases:
        item = result.findings[0]
        assert t(item.title_key, lang, **item.params)
        assert t(item.detail_key, lang, **item.params)
