from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.checks.dmarc import CODES as DMARC_CODES
from app.checks.dmarc import DmarcCheck
from app.checks.dmarc_external import (
    CODES,
    MAX_DESTINATION_LOOKUPS,
    check_external_destinations,
)
from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.core import i18n
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.parsers.dmarc import parse_dmarc
from tests.support.dns_zones import FakeResolver, load_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"
LOCALES = Path(i18n.LOCALES_DIR)
_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _ctx(resolver: object) -> CheckContext:
    return CheckContext(resolver=resolver, clock=lambda: _NOW)  # type: ignore[arg-type]


class _Wildcard:
    """Wraps a FakeResolver and synthesises DNS wildcards (RFC 4592, closest encloser) the way
    an authoritative server would; the fake resolver itself only matches exact names."""

    identity = "wildcard"

    def __init__(self, inner: FakeResolver) -> None:
        self.inner = inner
        self.queried: list[str] = []

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        self.queried.append(q.name)
        res = await self.inner.resolve(q)
        if res.state is not ResultState.nxdomain:
            return res
        labels = q.name.split(".")
        for i in range(1, len(labels) - 1):
            encloser = ".".join(labels[i:])
            if not self.inner._exists(encloser):
                continue
            src = await self.inner.resolve(DnsQuestion(f"*.{encloser}", q.rdtype))
            if not src.state.is_ok:
                return res
            recs = tuple(DnsRecord(q.name, r.rdtype, r.ttl, r.rdata_text) for r in src.records)
            return DnsResult(q, ResultState.ok, recs, ttl_min=src.ttl_min)
        return res


async def _run(fixture: str, domain: str, wildcard: bool = False) -> tuple[CheckResult, list[str]]:
    fake = load_zones(ZONES / fixture).resolver()
    resolver: Any = _Wildcard(fake) if wildcard else fake
    r = await DmarcCheck().run(_ctx(resolver), Target(domain=domain))
    if isinstance(resolver, _Wildcard):  # what the check asked, not the synthesis lookups
        return r, resolver.queried
    return r, [q.name for q in fake.questions]


def _codes(r: CheckResult) -> list[str]:
    return sorted(f.code for f in r.findings)


def _states(r: CheckResult) -> list[tuple[str, str | None, str]]:
    return [(d["tag"], d["destination"], d["state"]) for d in r.data["report_destinations"]]


def _q(policy: str, dest: str) -> str:
    return f"{policy}._report._dmarc.{dest}"


# domain, status, finding codes, (tag, destination, state) per URI, authorization queries made
CASES: list[tuple[str, str, list[str], list[tuple[str, str | None, str]], list[str]]] = [
    (
        "auth.example.com",
        "ok",
        [],
        [("rua", "reports.example.net", "authorized")],
        [_q("auth.example.com", "reports.example.net")],
    ),
    (
        "noauth.example.com",
        "warn",
        ["DMARC_EXTERNAL_UNAUTHORIZED"],
        [("rua", "noauth.example.net", "unauthorized")],
        [_q("noauth.example.com", "noauth.example.net")],
    ),
    (
        "wrongver.example.com",
        "warn",
        ["DMARC_EXTERNAL_UNAUTHORIZED"],
        [("rua", "wrongver.example.net", "unauthorized")],
        [_q("wrongver.example.com", "wrongver.example.net")],
    ),
    (
        "notfirst.example.com",
        "warn",
        ["DMARC_EXTERNAL_UNAUTHORIZED"],
        [("rua", "notfirst.example.net", "unauthorized")],
        [_q("notfirst.example.com", "notfirst.example.net")],
    ),
    (
        "sameorg.example.com",
        "info",
        ["DMARC_RUF_PRESENT"],
        [("rua", "sub.example.com", "same_org"), ("ruf", "sameorg.example.com", "same_org")],
        [],
    ),
    (
        "multi.example.com",
        "warn",
        ["DMARC_EXTERNAL_UNAUTHORIZED", "DMARC_RUF_PRESENT"],
        [
            ("rua", "reports.example.net", "authorized"),
            ("rua", "noauth.example.net", "unauthorized"),
            ("rua", "example.com", "same_org"),
            ("ruf", "reports.example.net", "authorized"),
        ],
        [
            _q("multi.example.com", "reports.example.net"),
            _q("multi.example.com", "noauth.example.net"),
        ],
    ),
    (
        "case.example.com",
        "ok",
        [],
        [("rua", "reports.example.net", "authorized")],
        [_q("case.example.com", "reports.example.net")],
    ),
    (
        "idn.example.com",
        "ok",
        [],
        [("rua", "xn--bcher-kva.test", "authorized")],
        [_q("idn.example.com", "xn--bcher-kva.test")],
    ),
    (
        "multiaddr.example.com",
        "warn",
        ["DMARC_EXTERNAL_NOT_CHECKABLE"],
        [("rua", None, "not_checkable")],
        [],
    ),
    ("https.example.com", "ok", [], [("rua", None, "skipped")], []),
    (
        "override.example.com",
        "warn",
        ["DMARC_EXTERNAL_OVERRIDE_MISMATCH"],
        [("rua", "ov.example.net", "override_mismatch")],
        [_q("override.example.com", "ov.example.net")],
    ),
    (
        "oversame.example.com",
        "ok",
        [],
        [("rua", "ov.example.net", "authorized")],
        [_q("oversame.example.com", "ov.example.net")],
    ),
    (
        "authbad.example.com",
        "warn",
        ["DMARC_EXTERNAL_AUTH_RECORD_INVALID"],
        [("rua", "reports.example.net", "authorized")],
        [_q("authbad.example.com", "reports.example.net")],
    ),
    (
        "authjunk.example.com",
        "warn",
        ["DMARC_EXTERNAL_AUTH_RECORD_UNPARSEABLE"],
        [("rua", "reports.example.net", "unauthorized")],
        [_q("authjunk.example.com", "reports.example.net")],
    ),
    (
        "child.example.org",
        "info",
        ["DMARC_INHERITED_FROM_ORG"],
        [("rua", "reports.example.net", "authorized")],
        [_q("example.org", "reports.example.net")],
    ),
    (
        "samehost.example.com",
        "info",
        ["DMARC_RUF_PRESENT"],
        [("rua", "reports.example.net", "authorized")] * 10
        + [("ruf", "reports.example.net", "authorized")] * 10,
        [_q("samehost.example.com", "reports.example.net")],
    ),
]


@pytest.mark.parametrize(
    ("domain", "status", "codes", "states", "queries"), CASES, ids=[c[0] for c in CASES]
)
async def test_recorded_zones(
    domain: str,
    status: str,
    codes: list[str],
    states: list[tuple[str, str | None, str]],
    queries: list[str],
) -> None:
    r, asked = await _run("dmarc_external_cases.yaml", domain)
    assert _codes(r) == codes
    assert r.status == status
    assert _states(r) == states
    assert [q for q in asked if "._report._dmarc." in q] == queries


async def test_wildcard_authorization_is_honoured() -> None:
    r, asked = await _run("dmarc_external_cases.yaml", "wild.example.com", wildcard=True)
    assert r.status == "ok"
    assert _states(r) == [("rua", "wild.example.org", "authorized")]
    # Only the exact constructed name is asked; the wildcard is synthesised by DNS.
    assert _q("wild.example.com", "wild.example.org") in asked
    assert not any(q.startswith("*.") for q in asked)


async def test_wildcard_not_queried_literally_without_synthesis() -> None:
    r, asked = await _run("dmarc_external_cases.yaml", "wild.example.com")
    assert _codes(r) == ["DMARC_EXTERNAL_UNAUTHORIZED"]
    assert not any(q.startswith("*.") for q in asked)


async def test_hostile_destination_count_is_bounded() -> None:
    r, asked = await _run("dmarc_external_cases.yaml", "many.example.com")
    report_queries = [q for q in asked if "._report._dmarc." in q]
    assert len(report_queries) == MAX_DESTINATION_LOOKUPS
    too_many = [f for f in r.findings if f.code == "DMARC_EXTERNAL_TOO_MANY_DESTINATIONS"]
    assert len(too_many) == 1
    assert too_many[0].params == {"count": 12, "limit": MAX_DESTINATION_LOOKUPS}
    states = [d["state"] for d in r.data["report_destinations"]]
    assert states.count("unauthorized") == MAX_DESTINATION_LOOKUPS
    assert states.count("not_checked") == 12 - MAX_DESTINATION_LOOKUPS
    assert r.status == "warn"


async def test_destination_data_shape() -> None:
    r, _ = await _run("dmarc_external_cases.yaml", "multi.example.com")
    first, _, same, _ = r.data["report_destinations"]
    assert first["external"] is True
    assert first["query"] == _q("multi.example.com", "reports.example.net")
    assert first["uri"] == "mailto:a@reports.example.net"
    assert same["external"] is False and "query" not in same
    skipped = (await _run("dmarc_external_cases.yaml", "https.example.com"))[0]
    assert skipped.data["report_destinations"][0]["reason"] == "unsupported_scheme"
    ov = (await _run("dmarc_external_cases.yaml", "override.example.com"))[0]
    assert ov.data["report_destinations"][0]["override"] == ["mailto:x@elsewhere.example.org"]
    f = next(f for f in ov.findings if f.code == "DMARC_EXTERNAL_OVERRIDE_MISMATCH")
    assert f.evidence == ("mailto:x@elsewhere.example.org",)
    junk = (await _run("dmarc_external_cases.yaml", "authjunk.example.com"))[0]
    assert junk.data["report_destinations"][0]["reason"] == "auth_record_not_tag_list"


async def test_auth_record_errors_in_evidence_without_missing_policy() -> None:
    r, _ = await _run("dmarc_external_cases.yaml", "authbad.example.com")
    f = next(f for f in r.findings if f.code == "DMARC_EXTERNAL_AUTH_RECORD_INVALID")
    assert any(e.startswith("invalid_pct") for e in f.evidence)
    assert not any("missing_policy" in e for e in f.evidence)


FAIL_DOMAINS = [
    ("servfail.example.com", "servfail"),
    ("timeout.example.com", "timeout"),
    ("refused.example.com", "refused"),
    ("truncated.example.com", "truncated"),
    ("malformed.example.com", "malformed"),
    ("down.example.com", "network_error"),
]


@pytest.mark.parametrize(("domain", "state"), FAIL_DOMAINS)
async def test_recorded_dns_failures_are_error(domain: str, state: str) -> None:
    r, _ = await _run("dmarc_external_failures.yaml", domain)
    assert r.status == "error"
    assert _codes(r) == ["DMARC_EXTERNAL_AUTH_UNVERIFIED"]
    assert _states(r) == [("rua", "reports.example.net", "unverified")]
    assert r.findings[0].params["state"] == state
    assert r.data["report_destinations"][0]["dns_state"] == state


async def test_failure_plus_unauthorized_is_error() -> None:
    r, _ = await _run("dmarc_external_failures.yaml", "mixed.example.com")
    assert r.status == "error"
    assert _codes(r) == ["DMARC_EXTERNAL_AUTH_UNVERIFIED", "DMARC_EXTERNAL_UNAUTHORIZED"]


class _Map:
    """Canned TXT answers or states per name; unlisted names are nxdomain."""

    identity = "map"

    def __init__(
        self, states: dict[str, ResultState] | None = None, txt: dict[str, list[str]] | None = None
    ) -> None:
        self.states, self.txt = states or {}, txt or {}
        self.queried: list[str] = []

    async def resolve(self, q: DnsQuestion) -> DnsResult:
        self.queried.append(q.name)
        if q.name in self.txt:
            recs = tuple(DnsRecord(q.name, "TXT", 60, t) for t in self.txt[q.name])
            return DnsResult(q, ResultState.ok, recs)
        state = self.states.get(q.name, ResultState.nxdomain)
        if state.is_ok:  # an "ok" answer that carries no TXT record
            return DnsResult(q, state, (DnsRecord(q.name, "A", 60, "192.0.2.1"),))
        return DnsResult(q, state)


_POLICY = "v=DMARC1; p=reject; rua=mailto:r@reports.example.net"
_AUTH = _q("a.example.com", "reports.example.net")


@pytest.mark.parametrize("state", list(ResultState))
async def test_every_state_at_authorization_lookup(state: ResultState) -> None:
    res = _Map({_AUTH: state}, {"_dmarc.a.example.com": [_POLICY]})
    r = await DmarcCheck().run(_ctx(res), Target(domain="a.example.com"))
    if state.is_definitive_absence:
        assert _codes(r) == ["DMARC_EXTERNAL_UNAUTHORIZED"]
        assert r.status == "warn"
    else:  # failures (blocked included) and an "ok" without TXT: never unauthorized
        assert _codes(r) == ["DMARC_EXTERNAL_AUTH_UNVERIFIED"]
        assert r.status == "error"


# Direct table over check_external_destinations: policy record, auth answers, expected states.
DIRECT: list[tuple[str, str, dict[str, list[str]], list[str], list[str]]] = [
    ("empty-auth-txt", _POLICY, {_AUTH: [""]}, ["unauthorized"], ["DMARC_EXTERNAL_UNAUTHORIZED"]),
    (
        "lowercase-version",
        _POLICY,
        {_AUTH: ["v=dmarc1"]},
        ["unauthorized"],
        ["DMARC_EXTERNAL_UNAUTHORIZED"],
    ),
    ("spf-not-dmarc", _POLICY, {_AUTH: ["v=spf1 -all"]}, ["unauthorized"], []),
    ("two-records-one-good", _POLICY, {_AUTH: ["junk", "v=DMARC1"]}, ["authorized"], []),
    ("whitespace-version", _POLICY, {_AUTH: ["v = DMARC1 ;"]}, ["authorized"], []),
    ("invalid-uri", "v=DMARC1; p=reject; rua=mailto:nobody", {}, ["invalid"], []),
    ("bad-uri-domain", "v=DMARC1; p=reject; rua=mailto:a@-bad-.example.net", {}, ["invalid"], []),
    ("no-uris", "v=DMARC1; p=reject", {}, [], []),
    (
        "bad-size-suffix",
        "v=DMARC1; p=reject; rua=mailto:r@reports.example.net!x",
        {},
        ["invalid"],
        [],
    ),
    (
        "mixed-case-trailing-dot-external",
        "v=DMARC1; p=reject; rua=mailto:r@Reports.EXAMPLE.net.",
        {_AUTH: ["v=DMARC1"]},
        ["authorized"],
        [],
    ),
    (
        "mixed-case-same-org",
        "v=DMARC1; p=reject; rua=mailto:r@SUB.Example.COM.",
        {},
        ["same_org"],
        [],
    ),
]


@pytest.mark.parametrize(
    ("policy", "answers", "states", "codes"),
    [c[1:] for c in DIRECT],
    ids=[c[0] for c in DIRECT],
)
async def test_direct_table(
    policy: str, answers: dict[str, list[str]], states: list[str], codes: list[str]
) -> None:
    res = _Map(txt=answers)
    out = await check_external_destinations(res, "a.example.com", parse_dmarc(policy))
    assert [d["state"] for d in out.destinations] == states
    got = sorted(f.code for f in out.findings)
    assert set(codes) <= set(got)
    assert out.evaluated is True
    if states and states[0] == "invalid":
        assert res.queried == []


async def test_constructed_name_too_long_is_not_checkable() -> None:
    policy_domain = ".".join(["a" * 60, "b" * 60, "c" * 60, "example.com"])
    dest = "d" * 50 + ".example.net"
    res = _Map()
    rec = parse_dmarc(f"v=DMARC1; p=reject; rua=mailto:r@{dest}")
    out = await check_external_destinations(res, policy_domain, rec)
    assert [d["state"] for d in out.destinations] == ["not_checkable"]
    assert [f.code for f in out.findings] == ["DMARC_EXTERNAL_NOT_CHECKABLE"]
    assert out.evaluated is True
    assert res.queried == []


async def test_unverified_with_fail_level_finding_keeps_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = DmarcCheck._analyse

    def analyse(*args: Any) -> tuple[list[Finding], bool, dict[str, Any]]:
        out, ev, data = original(*args)
        return [*out, finding("DMARC_NO_USABLE_POLICY", "high")], ev, data

    monkeypatch.setattr(DmarcCheck, "_analyse", staticmethod(analyse))
    res = _Map({_AUTH: ResultState.servfail}, {"_dmarc.a.example.com": [_POLICY]})
    r = await DmarcCheck().run(_ctx(res), Target(domain="a.example.com"))
    assert r.status == "fail"
    assert "DMARC_EXTERNAL_AUTH_UNVERIFIED" in _codes(r)


def test_codes_registered_with_dmarc_check() -> None:
    assert set(CODES) <= set(DMARC_CODES)
    assert "DMARC_EXTERNAL_AUTHORIZED" not in CODES  # data only, never a finding


def test_codes_have_complete_i18n_with_matching_placeholders() -> None:
    en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
    it = json.loads((LOCALES / "it.json").read_text(encoding="utf-8"))
    for code in CODES:
        for part in ("title", "detail", "remediation"):
            k = f"finding.{code}.{part}"
            assert en.get(k) and it.get(k), k
            assert i18n.placeholders(en[k]) == i18n.placeholders(it[k]), k


@pytest.mark.parametrize("auth", ["v=DMARC1;;", "v=DMARC1; ;", "v=DMARC1; garbage", "v=DMARC1; =x"])
async def test_record_not_a_tag_list_is_found_but_unparseable(auth: str) -> None:
    res = _Map(txt={_AUTH: [auth]})
    out = await check_external_destinations(res, "a.example.com", parse_dmarc(_POLICY))
    assert [f.code for f in out.findings] == ["DMARC_EXTERNAL_AUTH_RECORD_UNPARSEABLE"]
    assert out.findings[0].evidence  # the parse issues
    assert [d["state"] for d in out.destinations] == ["unauthorized"]


async def test_unparseable_record_next_to_a_good_one_authorizes() -> None:
    res = _Map(txt={_AUTH: ["v=DMARC1;;", "v=DMARC1"]})
    out = await check_external_destinations(res, "a.example.com", parse_dmarc(_POLICY))
    assert [d["state"] for d in out.destinations] == ["authorized"]
    # The broken extra record is still reported, as a low-severity record error.
    assert [f.code for f in out.findings] == ["DMARC_EXTERNAL_AUTH_RECORD_INVALID"]


# Private PSL section (github.io is a suffix): sibling tenants are different organizations.
PSL_CASES = [
    ("a.github.io", "b.github.io", ["a.github.io._report._dmarc.b.github.io"], "unauthorized"),
    ("sub.a.github.io", "a.github.io", [], "same_org"),
]


@pytest.mark.parametrize(("target", "dest", "queries", "state"), PSL_CASES)
async def test_private_psl_section(target: str, dest: str, queries: list[str], state: str) -> None:
    res = _Map(txt={f"_dmarc.{target}": [f"v=DMARC1; p=reject; rua=mailto:r@{dest}"]})
    r = await DmarcCheck().run(_ctx(res), Target(domain=target))
    assert [q for q in res.queried if "._report._dmarc." in q] == queries
    assert _states(r) == [("rua", dest, state)]
    assert r.data["report_destinations"][0]["external"] is (state != "same_org")
