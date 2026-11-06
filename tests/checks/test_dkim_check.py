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
    assert r.findings == ()


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
