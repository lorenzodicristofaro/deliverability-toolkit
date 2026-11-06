from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.checks.dmarc import CODES, DmarcCheck
from app.checks.models import CheckContext, CheckResult, Target
from app.checks.registry import load_builtin_checks
from app.core import i18n
from app.core.domain_names import InvalidDomainName
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from tests.support.dns_zones import load_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"
LOCALES = Path(i18n.LOCALES_DIR)
_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _ctx(resolver: object) -> CheckContext:
    return CheckContext(resolver=resolver, clock=lambda: _NOW)  # type: ignore[arg-type]


async def _run(fixture: str, domain: str) -> CheckResult:
    resolver = load_zones(ZONES / fixture).resolver()
    return await DmarcCheck().run(_ctx(resolver), Target(domain=domain))


def _codes(r: CheckResult) -> set[str]:
    return {f.code for f in r.findings}


CASES: list[tuple[str, str, set[str], dict[str, object]]] = [
    ("healthy.example.com", "ok", set(), {"inherited": False}),
    ("none.example.com", "warn", {"DMARC_POLICY_NONE"}, {"effective_policy": "none"}),
    (
        "quarantine.example.com",
        "warn",
        {
            "DMARC_POLICY_QUARANTINE",
            "DMARC_PCT_PARTIAL",
            "DMARC_RUF_PRESENT",
            "DMARC_ALIGNMENT_STRICT",
        },
        {"pct": 50},
    ),
    ("weaksp.example.com", "warn", {"DMARC_SUBDOMAIN_POLICY_WEAKER"}, {}),
    ("norua.example.com", "warn", {"DMARC_NO_RUA"}, {}),
    ("multi.example.com", "warn", {"DMARC_MULTIPLE_RECORDS"}, {"record_count": 2}),
    ("mixed.example.com", "warn", {"DMARC_POLICY_NONE"}, {"found_at": "mixed.example.com"}),
    ("nodmarc.example.com", "warn", {"DMARC_MISSING"}, {"found": False}),
    ("absent.example.com", "warn", {"DMARC_MISSING"}, {"found": False}),
    (
        "malformed.example.com",
        "warn",
        {"DMARC_SYNTAX_ERROR", "DMARC_P_ASSUMED_NONE"},
        {"effective_policy": "none"},
    ),
    (
        "nop.example.com",
        "warn",
        {"DMARC_SYNTAX_ERROR", "DMARC_P_ASSUMED_NONE"},
        {"effective_policy": "none"},
    ),
    (
        "nop-norua.example.com",
        "fail",
        {"DMARC_SYNTAX_ERROR", "DMARC_NO_USABLE_POLICY"},
        {"effective_policy": None},
    ),
    (
        "badsp.example.com",
        "warn",
        {"DMARC_SYNTAX_ERROR", "DMARC_P_ASSUMED_NONE"},
        {"effective_policy": "none"},
    ),
    (
        "sub.example.net",
        "info",
        {"DMARC_INHERITED_FROM_ORG"},
        {"inherited": True, "found_at": "example.net"},
    ),
    ("own.sub.example.net", "warn", {"DMARC_POLICY_NONE"}, {"inherited": False}),
]


@pytest.mark.parametrize(("domain", "status", "codes", "data"), CASES, ids=[c[0] for c in CASES])
async def test_recorded_zones(
    domain: str, status: str, codes: set[str], data: dict[str, object]
) -> None:
    r = await _run("dmarc_cases.yaml", domain)
    assert _codes(r) == codes
    assert r.status == status
    for k, v in data.items():
        assert r.data[k] == v


async def test_syntax_error_evidence_lists_issues() -> None:
    r = await _run("dmarc_cases.yaml", "malformed.example.com")
    f = next(f for f in r.findings if f.code == "DMARC_SYNTAX_ERROR")
    assert any(e.startswith("invalid_policy") for e in f.evidence)
    assert any(e.startswith("invalid_pct") for e in f.evidence)


FAIL_DOMAINS = [
    "servfail.example.com",
    "refused.example.com",
    "timeout.example.com",
    "truncated.example.com",
    "malformed.example.com",
    "down.example.com",
    "sub.example.org",  # fallback lookup fails
]


@pytest.mark.parametrize("domain", FAIL_DOMAINS)
async def test_recorded_dns_failures_are_error(domain: str) -> None:
    r = await _run("dmarc_failures.yaml", domain)
    assert r.status == "error"
    assert _codes(r) == {"DMARC_DNS_ERROR"}


class _Map:
    """Per-name canned results; unlisted names are nxdomain. Records every question."""

    identity = "map"

    def __init__(
        self, states: dict[str, ResultState] | None = None, txt: dict[str, str] | None = None
    ):
        self.states, self.txt = states or {}, txt or {}
        self.queried: list[str] = []

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        self.queried.append(q.name)
        if q.name in self.txt:
            return DnsResult(q, ResultState.ok, (DnsRecord(q.name, "TXT", 60, self.txt[q.name]),))
        state = self.states.get(q.name, ResultState.nxdomain)
        if state.is_ok:  # an "ok" answer that carries no TXT record
            return DnsResult(q, state, (DnsRecord(q.name, "A", 60, "192.0.2.1"),))
        return DnsResult(q, state)


def _assert_state_outcome(r: CheckResult, state: ResultState) -> None:
    if state.is_definitive_absence:
        assert _codes(r) == {"DMARC_MISSING"}
    else:  # failures and an "ok" without a TXT record: could not evaluate, never missing
        assert r.status == "error"
        assert _codes(r) == {"DMARC_DNS_ERROR"}


@pytest.mark.parametrize("state", list(ResultState))
async def test_every_state_at_first_lookup(state: ResultState) -> None:
    res = _Map({"_dmarc.a.example.com": state})
    r = await DmarcCheck().run(_ctx(res), Target(domain="a.example.com"))
    _assert_state_outcome(r, state)


@pytest.mark.parametrize("state", list(ResultState))
async def test_every_state_at_fallback_lookup(state: ResultState) -> None:
    res = _Map({"_dmarc.example.com": state})
    r = await DmarcCheck().run(_ctx(res), Target(domain="a.example.com"))
    _assert_state_outcome(r, state)
    assert res.queried == ["_dmarc.a.example.com", "_dmarc.example.com"]


@pytest.mark.parametrize("domain", ["com", "co.uk", "example"])
async def test_public_suffix_or_single_label_no_fallback(domain: str) -> None:
    res = _Map()
    r = await DmarcCheck().run(_ctx(res), Target(domain=domain))
    assert _codes(r) == {"DMARC_MISSING"}
    assert res.queried == [f"_dmarc.{domain}"]


@pytest.mark.parametrize("domain", ["a..b", "-bad-.example.com", "1.2.3.4", "a b.example.com"])
async def test_malformed_domain_error_not_crash(domain: str) -> None:
    res = _Map()
    r = await DmarcCheck().run(_ctx(res), Target(domain=domain))
    assert r.status == "error"
    assert _codes(r) == {"DMARC_DNS_ERROR"}
    assert res.queried == []


def test_organizational_domain_raising_is_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    import app.checks.dmarc as mod

    def boom(_: object) -> str:
        raise InvalidDomainName("bad")

    monkeypatch.setattr(mod, "organizational_domain", boom)
    res = _Map()
    r = asyncio.run(DmarcCheck().run(_ctx(res), Target(domain="a.example.com")))
    assert _codes(r) == {"DMARC_MISSING"}
    assert res.queried == ["_dmarc.a.example.com"]


async def test_org_domain_itself_not_queried_twice() -> None:
    res = _Map()
    await DmarcCheck().run(_ctx(res), Target(domain="example.com"))
    assert res.queried == ["_dmarc.example.com"]


async def test_private_suffix_tenant_does_not_inherit_platform() -> None:
    res = _Map(txt={"_dmarc.github.io": "v=DMARC1; p=reject"})
    r = await DmarcCheck().run(_ctx(res), Target(domain="tenant.github.io"))
    assert _codes(r) == {"DMARC_MISSING"}


def test_registered() -> None:
    assert "dmarc" in load_builtin_checks().all_ids()


def test_codes_have_complete_i18n_with_matching_placeholders() -> None:
    en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
    it = json.loads((LOCALES / "it.json").read_text(encoding="utf-8"))
    for code in CODES:
        for part in ("title", "detail", "remediation"):
            k = f"finding.{code}.{part}"
            assert en.get(k) and it.get(k), k
            assert i18n.placeholders(en[k]) == i18n.placeholders(it[k]), k
