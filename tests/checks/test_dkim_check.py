from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import app.checks.dkim as dkim_mod
from app.checks.dkim import CODES, PROBE_CONCURRENCY, DkimCheck, SelectorResult, probe_selectors
from app.checks.models import CheckContext, CheckResult, Target
from app.checks.registry import load_builtin_checks
from app.core import i18n
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from tests.support.dns_zones import load_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"
LOCALES = Path(i18n.LOCALES_DIR)
_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _ctx(resolver: object) -> CheckContext:
    return CheckContext(resolver=resolver, clock=lambda: _NOW)  # type: ignore[arg-type]


async def _run(fixture: str, domain: str, selectors: list[str]) -> CheckResult:
    resolver = load_zones(ZONES / fixture).resolver()
    return await DkimCheck(selectors).run(_ctx(resolver), Target(domain=domain))


def _codes(r: CheckResult) -> set[str]:
    return {f.code for f in r.findings}


def _sel(r: CheckResult, name: str) -> dict[str, object]:
    return next(s for s in r.data["selectors"] if s["selector"] == name)


CASES: list[tuple[str, str, set[str], dict[str, object]]] = [
    ("d2048", "ok", set(), {"state": "found", "key_type": "rsa", "bits": 2048}),
    ("d1024", "warn", {"DKIM_KEY_WEAK_1024"}, {"state": "found", "bits": 1024}),
    ("d512", "warn", {"DKIM_KEY_TOO_SHORT"}, {"state": "found", "bits": 512}),
    ("ded", "ok", set(), {"state": "found", "key_type": "ed25519", "bits": 256}),
    ("drev", "warn", {"DKIM_KEY_REVOKED"}, {"state": "found", "bits": None}),
    ("dtest", "warn", {"DKIM_TEST_MODE"}, {"state": "found", "bits": 2048}),
    ("dsyntax", "warn", {"DKIM_KEY_SYNTAX_ERROR"}, {"state": "found", "bits": None}),
    ("dmulti", "warn", {"DKIM_MULTIPLE_RECORDS", "DKIM_KEY_WEAK_1024"}, {"state": "found"}),
    (
        "dchain",
        "ok",
        set(),
        {"state": "found", "chain": ["hop1.dkim.example.net", "hop2.dkim.example.org"]},
    ),
    ("d8hops", "ok", set(), {"state": "found"}),
    ("nodata", "info", {"DKIM_NO_SELECTOR_FOUND"}, {"state": "not_found"}),
    ("absent", "info", {"DKIM_NO_SELECTOR_FOUND"}, {"state": "not_found"}),
    ("ddangling", "info", {"DKIM_NO_SELECTOR_FOUND"}, {"state": "not_found"}),
]


@pytest.mark.parametrize(("domain", "status", "codes", "sel"), CASES, ids=[c[0] for c in CASES])
async def test_recorded_zones(
    domain: str, status: str, codes: set[str], sel: dict[str, object]
) -> None:
    r = await _run("dkim_cases.yaml", f"{domain}.example.com", ["sel"])
    assert _codes(r) == codes
    assert r.status == status
    assert r.data["enumerable"] is False
    for k, v in sel.items():
        assert _sel(r, "sel")[k] == v


ERROR_CASES = [
    ("dloop", "DKIM_CNAME_LOOP", "cname_loop"),
    ("dself", "DKIM_CNAME_LOOP", "cname_loop"),
    ("dlong", "DKIM_CNAME_CHAIN_LONG", "cname_chain_long"),
]


@pytest.mark.parametrize(("domain", "code", "reason"), ERROR_CASES, ids=[c[0] for c in ERROR_CASES])
async def test_delegation_failures_are_selector_errors(
    domain: str, code: str | None, reason: str
) -> None:
    r = await _run("dkim_cases.yaml", f"{domain}.example.com", ["sel"])
    assert r.status == "error"
    expected = {"DKIM_PROBE_ERRORS"} | ({code} if code else set())
    assert _codes(r) == expected
    s = _sel(r, "sel")
    assert s["state"] == "error"
    assert s["reason"] == reason


async def test_loop_chain_in_evidence_and_data() -> None:
    r = await _run("dkim_cases.yaml", "dloop.example.com", ["sel"])
    f = next(f for f in r.findings if f.code == "DKIM_CNAME_LOOP")
    assert f.evidence == ("a.dkim.example.net", "b.dkim.example.net", "a.dkim.example.net")
    assert _sel(r, "sel")["chain"] == list(f.evidence)


class _DotCname:
    """CNAME to the root ('.'): fetch_cname returns state ok with an empty target. The zone
    fixture format rejects non-reserved names, so this one case is canned in code."""

    identity = "dot"

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        if q.rdtype == "CNAME":
            return DnsResult(q, ResultState.ok, (DnsRecord(q.name, "CNAME", 60, "."),))
        return DnsResult(q, ResultState.nodata)


async def test_empty_cname_target_is_malformed_delegation_error() -> None:
    r = await DkimCheck(["sel", "other"]).run(_ctx(_DotCname()), Target(domain="a.example.com"))
    assert r.status == "error"
    assert _codes(r) == {"DKIM_PROBE_ERRORS"}  # never DKIM_NO_SELECTOR_FOUND
    assert _sel(r, "sel")["state"] == "error"
    assert _sel(r, "sel")["reason"] == "empty_cname_target"


async def test_syntax_error_evidence() -> None:
    r = await _run("dkim_cases.yaml", "dsyntax.example.com", ["sel"])
    f = next(f for f in r.findings if f.code == "DKIM_KEY_SYNTAX_ERROR")
    assert f.evidence


# --- GM rule: found / failed / not_found mix ----------------------------------------------


async def test_found_plus_failed_follows_findings() -> None:
    r = await _run("dkim_cases.yaml", "mixfound.example.com", ["sel", "bad"])
    assert _codes(r) == {"DKIM_PROBE_ERRORS"}
    assert r.status == "warn"  # follows the findings, not forced to error
    assert _sel(r, "bad")["state"] == "error"


async def test_none_found_and_failed_is_error_without_no_selector_found() -> None:
    r = await _run("dkim_cases.yaml", "mixnone.example.com", ["sel", "bad"])
    assert r.status == "error"
    assert _codes(r) == {"DKIM_PROBE_ERRORS"}
    f = r.findings[0]
    assert f.params["count"] == 1 and f.params["total"] == 2
    assert f.evidence == ("bad: servfail",)


async def test_all_not_found_gives_no_selector_found() -> None:
    r = await _run("dkim_cases.yaml", "mixallnx.example.com", ["sel", "other"])
    assert _codes(r) == {"DKIM_NO_SELECTOR_FOUND"}
    assert r.status == "info"
    assert r.findings[0].severity == "info"


async def test_empty_selector_list_is_error() -> None:
    r = await _run("dkim_cases.yaml", "mixallnx.example.com", [])
    assert r.status == "error"
    assert _codes(r) == {"DKIM_NO_SELECTORS_PROBED"}  # says nothing was probed, no verdict
    assert r.data["probed"] == 0


# --- DNS failures (recorded zones) --------------------------------------------------------

STATES = ["servfail", "refused", "timeout", "truncated", "malformed", "network-error"]
FAIL_DOMAINS = [f"{p}-{s}" for s in STATES for p in ("t", "c", "m", "n")]


@pytest.mark.parametrize("domain", FAIL_DOMAINS)
async def test_recorded_dns_failures_are_error(domain: str) -> None:
    r = await _run("dkim_failures.yaml", f"{domain}.example.com", ["sel", "other"])
    assert r.status == "error"
    assert _codes(r) == {"DKIM_PROBE_ERRORS"}
    assert _sel(r, "sel")["state"] == "error"
    assert _sel(r, "other")["state"] == "not_found"


class _Map:
    """Per-name canned results; unlisted names are nxdomain. Records every question."""

    identity = "map"

    def __init__(self, states: dict[tuple[str, str], ResultState]):
        self.states = states
        self.queried: list[tuple[str, str]] = []

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        self.queried.append((q.name, q.rdtype))
        state = self.states.get((q.name, q.rdtype), ResultState.nxdomain)
        if state.is_ok:  # an "ok" answer that carries no record of the asked type
            return DnsResult(q, state, (DnsRecord(q.name, "A", 60, "192.0.2.1"),))
        return DnsResult(q, state)


@pytest.mark.parametrize("rdtype", ["TXT", "CNAME"])
@pytest.mark.parametrize("state", list(ResultState))
async def test_every_state_at_each_lookup(state: ResultState, rdtype: str) -> None:
    name = "sel._domainkey.a.example.com"
    states = {(name, rdtype): state}
    if rdtype == "CNAME":
        states[(name, "TXT")] = ResultState.nodata
    r = await DkimCheck(["sel"]).run(_ctx(_Map(states)), Target(domain="a.example.com"))
    if state.is_definitive_absence:
        assert _codes(r) == {"DKIM_NO_SELECTOR_FOUND"}
    else:  # failures and an "ok" without the asked record: never not_found
        assert r.status == "error"
        assert _codes(r) == {"DKIM_PROBE_ERRORS"}


@pytest.mark.parametrize("domain", ["a..b", "-bad-.example.com", "1.2.3.4", "a b.example.com"])
async def test_malformed_domain_error_not_crash(domain: str) -> None:
    res = _Map({})
    r = await DkimCheck(["sel"]).run(_ctx(res), Target(domain=domain))
    assert r.status == "error"
    assert _codes(r) == {"DKIM_PROBE_ERRORS"}
    assert res.queried == []


@pytest.mark.parametrize("selector", ["", "a.b", "-x", "a b", "x" * 64])
async def test_malformed_selector_error_not_crash(selector: str) -> None:
    r = await DkimCheck([selector]).run(_ctx(_Map({})), Target(domain="a.example.com"))
    assert r.status == "error"
    assert _sel(r, selector)["state"] == "error"


# --- generator behaviour ------------------------------------------------------------------


class _Gate:
    """Resolver where `slow*` selectors wait for an event; others answer at once."""

    identity = "gate"

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.inflight = 0
        self.max_inflight = 0
        self.cancelled = 0
        self.started: list[str] = []

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        sel = q.name.split(".")[0]
        self.started.append(sel)
        self.inflight += 1
        self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            if sel.startswith("slow"):
                await self.release.wait()
            else:
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        finally:
            self.inflight -= 1
        return DnsResult(q, ResultState.nxdomain)


async def test_results_are_yielded_as_ready_not_in_input_order() -> None:
    gate = _Gate()
    seen: list[str] = []
    async for res in probe_selectors(_ctx(gate), "a.example.com", ["slow1", "fast1", "fast2"]):
        seen.append(res.selector)
        if len(seen) == 2:
            gate.release.set()
    assert seen[:2] == ["fast1", "fast2"]
    assert seen[2] == "slow1"


async def test_concurrency_is_bounded_and_every_selector_is_probed() -> None:
    gate = _Gate()
    names = [f"slow{i}" for i in range(PROBE_CONCURRENCY * 3)]
    got: list[SelectorResult] = []

    async def consume() -> None:
        async for res in probe_selectors(_ctx(gate), "a.example.com", names):
            got.append(res)

    task = asyncio.create_task(consume())
    for _ in range(20):
        await asyncio.sleep(0)
    assert gate.inflight == PROBE_CONCURRENCY  # saturated but never above the bound
    gate.release.set()
    await task
    assert gate.max_inflight == PROBE_CONCURRENCY
    assert sorted(r.selector for r in got) == sorted(names)
    assert all(r.state == "not_found" for r in got)  # no early stop


async def test_duplicate_selectors_probed_once() -> None:
    got = [r async for r in probe_selectors(_ctx(_Gate()), "a.example.com", ["x", "x", "y"])]
    assert sorted(r.selector for r in got) == ["x", "y"]


async def test_cancellation_stops_inflight_probes_cleanly() -> None:
    gate = _Gate()
    names = [f"slow{i}" for i in range(PROBE_CONCURRENCY * 2)]

    async def consume() -> None:
        async for _ in probe_selectors(_ctx(gate), "a.example.com", names):
            pass

    task = asyncio.create_task(consume())
    for _ in range(20):
        await asyncio.sleep(0)
    assert gate.inflight == PROBE_CONCURRENCY
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert gate.inflight == 0
    assert gate.cancelled == PROBE_CONCURRENCY
    assert len(gate.started) == PROBE_CONCURRENCY  # nothing new was started after cancel


async def test_early_close_of_generator_cancels_workers() -> None:
    gate = _Gate()
    agen = probe_selectors(_ctx(gate), "a.example.com", ["fast1", "slow1", "slow2"])
    first = await anext(agen)
    assert first.selector == "fast1"
    await agen.aclose()
    assert gate.inflight == 0
    assert gate.cancelled == 2


async def test_run_matches_streamed_results_and_is_ordered_by_input() -> None:
    names = ["sel", "other", "bad"]
    resolver = load_zones(ZONES / "dkim_cases.yaml").resolver()
    ctx = _ctx(resolver)
    streamed = {r.selector: r async for r in probe_selectors(ctx, "mixfound.example.com", names)}
    r = await DkimCheck(names).run(ctx, Target(domain="mixfound.example.com"))
    assert [s["selector"] for s in r.data["selectors"]] == names
    for s in r.data["selectors"]:
        assert s["state"] == streamed[str(s["selector"])].state


async def test_default_selectors_come_from_seed() -> None:
    from app.checks.dkim_selectors import list_selectors

    r = await DkimCheck().run(_ctx(_Map({})), Target(domain="a.example.com"))
    assert r.data["probed"] == len(list_selectors())
    assert _codes(r) == {"DKIM_NO_SELECTOR_FOUND"}


async def test_unexpected_exception_in_probe_is_selector_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("x")

    monkeypatch.setattr(dkim_mod, "fetch_txt", boom)
    r = await DkimCheck(["sel"]).run(_ctx(_Map({})), Target(domain="a.example.com"))
    assert r.status == "error"
    assert _sel(r, "sel")["reason"] == "internal_error"


def test_messages_never_claim_dkim_is_absent() -> None:
    en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
    text = en["finding.DKIM_NO_SELECTOR_FOUND.detail"].lower()
    assert "cannot be enumerated" in text
    assert "no dkim" not in text and "not configured" not in text


def test_registered() -> None:
    assert "dkim" in load_builtin_checks().all_ids()


def test_codes_have_complete_i18n_with_matching_placeholders() -> None:
    en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
    it = json.loads((LOCALES / "it.json").read_text(encoding="utf-8"))
    for code in CODES:
        for part in ("title", "detail", "remediation"):
            k = f"finding.{code}.{part}"
            assert en.get(k) and it.get(k), k
            assert i18n.placeholders(en[k]) == i18n.placeholders(it[k]), k


# --- the caller's list: empty, or cut by a cap (M5-20) ----------------------------------------


@pytest.mark.parametrize(
    ("selectors", "dropped"),
    [(["sel"], 1), (["sel", "other"], 5)],
    ids=["one", "many"],
)
async def test_dropped_selectors_make_the_result_incomplete(
    selectors: list[str], dropped: int
) -> None:
    r = await DkimCheck(selectors, dropped=dropped).run(
        _ctx(_Map({})), Target(domain="a.example.com")
    )
    assert r.status == "error"
    assert _codes(r) == {"DKIM_SELECTORS_CAPPED"}  # never DKIM_NO_SELECTOR_FOUND
    assert r.data["dropped"] == dropped
    capped = next(f for f in r.findings if f.code == "DKIM_SELECTORS_CAPPED")
    assert capped.params == {"probed": len(selectors), "dropped": dropped}


async def test_nothing_dropped_leaves_the_result_shape_unchanged() -> None:
    r = await DkimCheck(["sel"]).run(_ctx(_Map({})), Target(domain="a.example.com"))
    assert set(r.data) == {"enumerable", "probed", "found", "selectors"}
    assert _codes(r) == {"DKIM_NO_SELECTOR_FOUND"}


# --- provider (M5-23b) ---------------------------------------------------------------------------

SELECTOR_KEYS = {"selector", "provider", "state", "key_type", "bits", "chain", "reason"}
_NONE = {"sel": None, "other": None, "bad": None}


@pytest.mark.parametrize(
    ("providers", "expected"),
    [
        ({"sel": "acme", "other": "zeta"}, {**_NONE, "sel": "acme", "other": "zeta"}),
        ({}, _NONE),
        ({"sel": ""}, _NONE),  # empty value: no provider
        ({"unprobed": "x"}, _NONE),
        ({"sel": '<b>&"x'}, {**_NONE, "sel": '<b>&"x'}),  # data as stored; templates escape
    ],
    ids=["mapped", "empty-map", "empty-value", "unprobed-name", "hostile-value"],
)
async def test_results_carry_the_mapped_provider(
    providers: dict[str, str], expected: dict[str, str | None]
) -> None:
    names = ["sel", "other", "bad"]
    resolver = load_zones(ZONES / "dkim_cases.yaml").resolver()
    ctx = _ctx(resolver)
    streamed = [r async for r in probe_selectors(ctx, "mixfound.example.com", names, providers)]
    assert {r.selector: r.provider for r in streamed} == expected
    r = await DkimCheck(names, providers=providers).run(ctx, Target(domain="mixfound.example.com"))
    assert {s["selector"]: s["provider"] for s in r.data["selectors"]} == expected
    for s in r.data["selectors"]:
        assert set(s) == SELECTOR_KEYS  # never notes


async def test_provider_does_not_change_the_verdict() -> None:
    resolver = load_zones(ZONES / "dkim_cases.yaml").resolver()
    target = Target(domain="d1024.example.com")
    a = await DkimCheck(["sel"], providers={}).run(_ctx(resolver), target)
    b = await DkimCheck(["sel"], providers={"sel": "p"}).run(_ctx(resolver), target)
    assert (a.status, a.findings) == (b.status, b.findings)


async def test_without_a_map_the_seed_providers_are_used() -> None:
    from app.checks.dkim_selectors import list_selectors

    seed = list_selectors()
    assert any(s.provider for s in seed) and any(s.provider is None for s in seed)
    r = await DkimCheck().run(_ctx(_Map({})), Target(domain="a.example.com"))
    assert {s["selector"]: s["provider"] for s in r.data["selectors"]} == {
        s.name: s.provider for s in seed
    }
    # Explicit names (CLI --selector) still get the seed provider of a seed name.
    named = next(s for s in seed if s.provider)
    r2 = await DkimCheck([named.name, "adhoc"]).run(_ctx(_Map({})), Target(domain="a.example.com"))
    assert {s["selector"]: s["provider"] for s in r2.data["selectors"]} == {
        named.name: named.provider,
        "adhoc": None,
    }


async def test_seed_notes_never_reach_a_result() -> None:
    from app.checks.dkim_selectors import list_selectors

    r = await DkimCheck().run(_ctx(_Map({})), Target(domain="a.example.com"))
    text = r.model_dump_json()
    long_notes = [s.notes for s in list_selectors() if len(s.notes) > 12]
    assert long_notes
    for notes in long_notes:
        assert notes not in text


# --- R1-08: a TXT record that is not a DKIM key is not a found selector --------------------------

KEY = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="


class _Wild:
    """Zone with a wildcard TXT: every ``*.example.com`` name answers ``wild``; ``exact`` names
    answer their own list; ``empty`` names (empty non-terminals) answer NODATA."""

    identity = "wild"

    def __init__(
        self,
        wild: list[str],
        exact: dict[str, list[str]] | None = None,
        empty: tuple[str, ...] = (),
    ) -> None:
        self.wild, self.exact, self.empty = wild, exact or {}, empty

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        if q.rdtype != "TXT" or q.name in self.empty:
            return DnsResult(q, ResultState.nodata)
        data = self.exact.get(q.name, self.wild)
        recs = tuple(DnsRecord(q.name, "TXT", 60, d) for d in data)
        return DnsResult(q, ResultState.ok, recs) if recs else DnsResult(q, ResultState.nodata)


def _count(r: CheckResult, code: str) -> int:
    return sum(f.code == code for f in r.findings)


@pytest.mark.parametrize("text", ["v=spf1 -all", "google-site-verification=abc"])
async def test_wildcard_txt_is_not_a_found_selector(text: str) -> None:
    r = await DkimCheck(["default", "google", "s1"]).run(
        _ctx(_Wild([text])), Target(domain="a.example.com")
    )
    assert r.data["found"] == 0
    assert _codes(r) == {"DKIM_NO_SELECTOR_FOUND", "DKIM_NON_KEY_TXT"}
    assert _count(r, "DKIM_NON_KEY_TXT") == 1
    f = next(f for f in r.findings if f.code == "DKIM_NON_KEY_TXT")
    assert f.severity == "info"
    assert f.params["count"] == 3
    assert f.evidence == (f"default: {text}", f"google: {text}", f"s1: {text}")
    assert r.status == "info"
    assert all(s["state"] == "not_found" for s in r.data["selectors"])


async def test_mixed_zone_real_key_and_wildcard_text() -> None:
    wild = _Wild(["v=spf1 -all"], {"google._domainkey.a.example.com": [KEY]})
    r = await DkimCheck(["default", "google", "s1"]).run(_ctx(wild), Target(domain="a.example.com"))
    assert r.data["found"] == 1
    assert _sel(r, "google")["state"] == "found"
    assert _sel(r, "default")["state"] == "not_found"
    assert "DKIM_NO_SELECTOR_FOUND" not in _codes(r)
    assert "DKIM_KEY_SYNTAX_ERROR" not in _codes(r)
    non_key = next(f for f in r.findings if f.code == "DKIM_NON_KEY_TXT")
    assert non_key.params["count"] == 2


async def test_non_key_txt_next_to_a_key_at_the_same_selector_is_ignored() -> None:
    wild = _Wild([], {"s1._domainkey.a.example.com": ["v=spf1 -all", KEY]})
    r = await DkimCheck(["s1"]).run(_ctx(wild), Target(domain="a.example.com"))
    assert _sel(r, "s1")["state"] == "found"
    assert "DKIM_MULTIPLE_RECORDS" not in _codes(r)
    assert "DKIM_NON_KEY_TXT" not in _codes(r)


@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM1; p=!!!notbase64",
        "v=DKIM1",
        "v=DKIM1; k=rsa",
        "p=!!!",
        "k=rsa; p=%%%",
        "  V = dkim1 ; k=rsa; p=@@@",
        "V=DKIM1;p=@@@",
        " p = @@@",
    ],
)
async def test_malformed_candidates_stay_found_with_syntax_error(record: str) -> None:
    r = await DkimCheck(["s1"]).run(_ctx(_Wild([record])), Target(domain="a.example.com"))
    assert _sel(r, "s1")["state"] == "found"
    assert "DKIM_NON_KEY_TXT" not in _codes(r)
    assert "DKIM_KEY_SYNTAX_ERROR" in _codes(r)


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=DKIM1; k=rsa; p=AAAA", True),
        ("V=dkim1", True),
        ("  v = DKIM1;", True),
        ("k=rsa; p=AAAA", True),
        ("p=", True),
        ("P=AAAA", True),
        ("v=spf1 -all", False),
        ("google-site-verification=abc", False),
        ("x=1; note=p=2", False),  # p= inside another value
        ("v=spf1 include:p=x.example.com -all", False),
        ("help=p", False),
        ("", False),
        (";;;", False),
        ("v=DKIM", False),
        ("=p=", False),
        ("tag-like text; not=a key", False),
    ],
)
def test_is_dkim_key_candidate(record: str, expected: bool) -> None:
    assert dkim_mod.is_dkim_key_candidate(record) is expected


async def test_empty_non_terminal_domainkey_is_not_found_without_non_key_finding() -> None:
    wild = _Wild([], empty=("s1._domainkey.a.example.com",))
    r = await DkimCheck(["s1"]).run(_ctx(wild), Target(domain="a.example.com"))
    assert _codes(r) == {"DKIM_NO_SELECTOR_FOUND"}


async def test_non_key_evidence_is_capped_truncated_and_sanitised() -> None:
    names = [f"s{i}" for i in range(250)]
    text = "v=spf1\n" + "x" * 500
    r = await DkimCheck(names).run(_ctx(_Wild([text])), Target(domain="a.example.com"))
    f = next(f for f in r.findings if f.code == "DKIM_NON_KEY_TXT")
    assert f.params["count"] == 250
    assert len(f.evidence) == dkim_mod.MAX_NON_KEY_EVIDENCE
    for line in f.evidence:
        assert "\n" not in line
        assert len(line) <= len("s249: ") + dkim_mod.MAX_NON_KEY_TEXT + 3
    assert _count(r, "DKIM_NON_KEY_TXT") == 1


async def test_dns_failure_still_error_with_non_key_selectors() -> None:
    class Mixed(_Wild):
        async def resolve(self, q: DnsQuestion) -> DnsResult:
            if q.name.startswith("bad."):
                return DnsResult(q, ResultState.servfail)
            return await super().resolve(q)

    r = await DkimCheck(["bad", "s1"]).run(
        _ctx(Mixed(["v=spf1 -all"])), Target(domain="a.example.com")
    )
    assert r.status == "error"
    assert "DKIM_PROBE_ERRORS" in _codes(r)
    assert "DKIM_NO_SELECTOR_FOUND" not in _codes(r)
