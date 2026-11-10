"""ESP profile check (M6-04). Fake profiles (example.com / example.net) and an in-memory fake
resolver: no network."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from app.checks.esp_profile import CODES, EspHosts, EspProfileCheck
from app.checks.models import Check, CheckContext, CheckResult, Target
from app.core.i18n import LOCALES_DIR, placeholders
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from app.esp.profile import EspProfile, parse_esp_profile, read_esp_profiles

FIXTURES = Path(__file__).parent.parent / "fixtures" / "esp"
TODAY = date(2026, 11, 10)
_NOW = datetime(2026, 1, 1, tzinfo=UTC)
D = "client.example.com"

Zone = dict[tuple[str, str], list[str] | ResultState]


class FakeDns:
    """(name, type) -> rdata list or a failure state. Unlisted: NODATA when the name has any
    entry, else NXDOMAIN. CNAMEs are not followed by other query types."""

    identity = "fake"

    def __init__(self, zone: Zone) -> None:
        self.zone = zone
        self.questions: list[tuple[str, str]] = []

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.questions.append((question.name, question.rdtype))
        entry = self.zone.get((question.name, question.rdtype))
        if isinstance(entry, ResultState):
            return DnsResult(question, entry)
        if entry:
            recs = tuple(DnsRecord(question.name, question.rdtype, 300, r) for r in entry)
            return DnsResult(question, ResultState.ok, recs)
        exists = any(n == question.name for n, _ in self.zone)
        return DnsResult(question, ResultState.nodata if exists else ResultState.nxdomain)


def _profile(pid: str = "example-esp", **over: Any) -> EspProfile:
    data: dict[str, Any] = {
        "id": pid,
        "name": "Example ESP" if pid == "example-esp" else pid.title(),
        "homepage": "https://esp.example.com",
        "spf": {"includes": ["spf.esp.example.com"]},
        "dkim": {
            "selectors": [
                {"name": "s1", "type": "cname", "target_pattern": "s1.dkim.*.esp.example.com"},
                {"name": "k1", "type": "txt"},
            ]
        },
        "return_path": {"type": "cname"},
        "tracking_domain": {"type": "cname", "optional": True},
        "verified_on": date(2026, 1, 15),
        "sources": ["https://docs.esp.example.com/dns"],
        "status": "verified",
    }
    data.update(over)
    return parse_esp_profile({k: v for k, v in data.items() if v is not None}, pid, TODAY)


HOSTS = EspHosts(return_path_host=f"bounce.{D}", tracking_host=f"click.{D}")


def _good() -> Zone:
    return {
        (D, "TXT"): ["v=spf1 include:spf.esp.example.com -all"],
        ("spf.esp.example.com", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        (f"s1._domainkey.{D}", "CNAME"): ["s1.dkim.abc.esp.example.com."],
        (f"k1._domainkey.{D}", "TXT"): ["v=DKIM1; k=rsa; p=AAAA"],
        (f"bounce.{D}", "CNAME"): ["bounces.esp.example.com."],
        (f"click.{D}", "CNAME"): ["track.esp.example.com."],
    }


def _ctx(resolver: object) -> CheckContext:
    return CheckContext(resolver=resolver, clock=lambda: _NOW)  # type: ignore[arg-type]


async def _run(
    zone: Zone,
    profiles: list[EspProfile] | None = None,
    hosts: dict[str, EspHosts] | None = None,
    domain: str = D,
) -> tuple[CheckResult, FakeDns]:
    dns = FakeDns(zone)
    profiles = [_profile()] if profiles is None else profiles
    if hosts is None:
        hosts = {p.id: HOSTS for p in profiles}
    r = await EspProfileCheck(profiles, hosts).run(_ctx(dns), Target(domain=domain))
    return r, dns


def _codes(r: CheckResult) -> set[str]:
    return {f.code for f in r.findings}


def _sec(r: CheckResult, pid: str = "example-esp") -> dict[str, Any]:
    return next(s for s in r.data["esps"] if s["id"] == pid)


def _dkim(r: CheckResult, sel: str) -> dict[str, Any]:
    return next(d for d in _sec(r)["dkim"] if d["selector"] == sel)


S1 = (f"s1._domainkey.{D}", "CNAME")
K1 = (f"k1._domainkey.{D}", "TXT")
RP = (f"bounce.{D}", "CNAME")
TR = (f"click.{D}", "CNAME")

# (id, zone changes (None deletes), expected codes, status, (data path, state))
CASES: list[tuple[str, Zone | dict[Any, Any], set[str], str, tuple[str, str] | None]] = [
    ("all_ok", {}, set(), "ok", ("spf", "ok")),
    (
        "spf_include_missing",
        {(D, "TXT"): ["v=spf1 -all"]},
        {"ESP_SPF_INCLUDE_MISSING"},
        "fail",
        ("spf", "missing"),
    ),
    (
        "spf_no_record_nxdomain",
        {(D, "TXT"): None},
        {"ESP_SPF_INCLUDE_MISSING"},
        "fail",
        ("spf", "missing"),
    ),
    (
        "spf_nested_include",
        {
            (D, "TXT"): [f"v=spf1 include:_spf.{D} -all"],
            (f"_spf.{D}", "TXT"): ["v=spf1 include:spf.esp.example.com ~all"],
        },
        set(),
        "ok",
        ("spf", "ok"),
    ),
    (
        "spf_redirect",
        {(D, "TXT"): ["v=spf1 redirect=spf.esp.example.com"]},
        set(),
        "ok",
        ("spf", "ok"),
    ),
    (
        "spf_uppercase_include",
        {(D, "TXT"): ["v=spf1 include:SPF.ESP.Example.COM -all"]},
        set(),
        "ok",
        ("spf", "ok"),
    ),
    (
        "spf_root_servfail",
        {(D, "TXT"): ResultState.servfail},
        {"ESP_DNS_ERROR"},
        "error",
        ("spf", "error"),
    ),
    (
        "spf_nested_timeout_include_absent",
        {(D, "TXT"): [f"v=spf1 include:_spf.{D} -all"], (f"_spf.{D}", "TXT"): ResultState.timeout},
        {"ESP_DNS_ERROR"},
        "error",
        ("spf", "error"),
    ),
    (
        "spf_nested_timeout_include_present",
        {
            (D, "TXT"): [f"v=spf1 include:_spf.{D} include:spf.esp.example.com -all"],
            (f"_spf.{D}", "TXT"): ResultState.timeout,
        },
        set(),
        "ok",
        ("spf", "ok"),
    ),
    (
        "spf_esp_record_fails_but_term_present",
        {("spf.esp.example.com", "TXT"): ResultState.servfail},
        set(),
        "ok",
        ("spf", "ok"),
    ),
    ("dkim_cname_nxdomain", {S1: None}, {"ESP_DKIM_RECORD_MISSING"}, "fail", ("s1", "missing")),
    (
        "dkim_cname_nodata_txt_present",
        {S1: None, (S1[0], "TXT"): ["v=DKIM1; p=AAAA"]},
        {"ESP_DKIM_WRONG_TYPE"},
        "warn",
        ("s1", "wrong_type"),
    ),
    (
        "dkim_cname_nodata_other_type",
        {S1: None, (S1[0], "A"): ["192.0.2.1"]},
        {"ESP_DKIM_RECORD_MISSING"},
        "fail",
        ("s1", "missing"),
    ),
    (
        "dkim_target_mismatch",
        {S1: ["s1.dkim.other.example.net."]},
        {"ESP_DKIM_TARGET_MISMATCH"},
        "warn",
        ("s1", "mismatch"),
    ),
    (
        "dkim_pattern_two_labels_for_star",
        {S1: ["s1.dkim.a.b.esp.example.com"]},
        {"ESP_DKIM_TARGET_MISMATCH"},
        "warn",
        ("s1", "mismatch"),
    ),
    (
        "dkim_pattern_star_missing",
        {S1: ["s1.dkim.esp.example.com"]},
        {"ESP_DKIM_TARGET_MISMATCH"},
        "warn",
        ("s1", "mismatch"),
    ),
    (
        "dkim_pattern_case_and_dot",
        {S1: ["S1.DKIM.Abc.ESP.example.COM."]},
        set(),
        "ok",
        ("s1", "ok"),
    ),
    ("dkim_empty_target", {S1: ["."]}, {"ESP_DKIM_TARGET_MISMATCH"}, "warn", ("s1", "mismatch")),
    (
        "dkim_chain_to_match",
        {S1: ["hop.example.net."], ("hop.example.net", "CNAME"): ["s1.dkim.x9.esp.example.com."]},
        set(),
        "ok",
        ("s1", "ok"),
    ),
    (
        "dkim_chain_loop",
        {
            S1: ["hop1.example.net"],
            ("hop1.example.net", "CNAME"): ["hop2.example.net"],
            ("hop2.example.net", "CNAME"): ["hop1.example.net"],
        },
        {"ESP_DKIM_TARGET_MISMATCH"},
        "warn",
        ("s1", "mismatch"),
    ),
    (
        "dkim_chain_hop_servfail",
        {S1: ["hop1.example.net"], ("hop1.example.net", "CNAME"): ResultState.servfail},
        {"ESP_DNS_ERROR"},
        "error",
        ("s1", "error"),
    ),
    ("dkim_txt_missing", {K1: None}, {"ESP_DKIM_RECORD_MISSING"}, "fail", ("k1", "missing")),
    (
        "dkim_txt_is_cname",
        {K1: None, (K1[0], "CNAME"): ["k1.esp.example.com"]},
        {"ESP_DKIM_WRONG_TYPE"},
        "warn",
        ("k1", "wrong_type"),
    ),
    ("dkim_txt_refused", {K1: ResultState.refused}, {"ESP_DNS_ERROR"}, "error", ("k1", "error")),
    (
        "dkim_txt_nodata_cname_timeout",
        {K1: None, (K1[0], "A"): ["192.0.2.1"], (K1[0], "CNAME"): ResultState.timeout},
        {"ESP_DNS_ERROR"},
        "error",
        ("k1", "error"),
    ),
    (
        "return_path_nxdomain",
        {RP: None},
        {"ESP_RETURN_PATH_MISSING"},
        "warn",
        ("return_path", "missing"),
    ),
    (
        "return_path_nodata",
        {RP: None, (RP[0], "TXT"): ["x"]},
        {"ESP_RETURN_PATH_MISMATCH"},
        "warn",
        ("return_path", "mismatch"),
    ),
    (
        "return_path_timeout",
        {RP: ResultState.timeout},
        {"ESP_DNS_ERROR"},
        "error",
        ("return_path", "error"),
    ),
    (
        "tracking_optional_missing",
        {TR: None},
        {"ESP_TRACKING_MISSING"},
        "info",
        ("tracking_domain", "missing"),
    ),
    (
        "tracking_optional_nodata",
        {TR: None, (TR[0], "A"): ["192.0.2.7"]},
        {"ESP_TRACKING_MISMATCH"},
        "info",
        ("tracking_domain", "mismatch"),
    ),
    (
        "tracking_blocked",
        {TR: ResultState.blocked},
        {"ESP_DNS_ERROR"},
        "error",
        ("tracking_domain", "error"),
    ),
]


def _apply(changes: dict[Any, Any]) -> Zone:
    zone = _good()
    for k, v in changes.items():
        if v is None:
            zone.pop(k, None)
        else:
            zone[k] = v
    return zone


@pytest.mark.parametrize(
    ("changes", "codes", "status", "where"), [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
async def test_cases(
    changes: dict[Any, Any], codes: set[str], status: str, where: tuple[str, str] | None
) -> None:
    r, _ = await _run(_apply(changes))
    assert _codes(r) == codes
    assert r.status == status
    if where is not None:
        part, state = where
        if part in ("s1", "k1"):
            assert _dkim(r, part)["state"] == state
        else:
            assert _sec(r)[part]["state"] == state
    _assert_params_cover_placeholders(r)


ERROR_STATES = [s for s in ResultState if s.is_failure]


@pytest.mark.parametrize("state", ERROR_STATES, ids=[str(s) for s in ERROR_STATES])
@pytest.mark.parametrize("key", [(D, "TXT"), S1, K1, RP, TR], ids=["spf", "s1", "k1", "rp", "tr"])
async def test_every_failure_state_is_error_never_missing(
    state: ResultState, key: tuple[str, str]
) -> None:
    r, _ = await _run(_apply({key: state}))
    assert r.status == "error"
    errs = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert len(errs) == 1
    assert errs[0].params["name"] == key[0]
    assert errs[0].params["state"] == str(state)
    assert not {c for c in _codes(r) if c.endswith(("_MISSING", "_MISMATCH", "_WRONG_TYPE"))}


def test_error_states_cover_blocked_and_truncated() -> None:
    assert {ResultState.blocked, ResultState.truncated, ResultState.timeout} <= set(ERROR_STATES)


@pytest.mark.parametrize(
    ("optional", "code", "severity"),
    [
        (True, "ESP_TRACKING_MISSING", "info"),
        (False, "ESP_TRACKING_MISSING", "low"),
    ],
)
async def test_tracking_severity_follows_optional(optional: bool, code: str, severity: str) -> None:
    p = _profile(tracking_domain={"type": "cname", "optional": optional})
    r, _ = await _run(_apply({TR: None}), [p])
    (f,) = [f for f in r.findings if f.code == code]
    assert f.severity == severity


async def test_return_path_optional_is_info_and_notes_key_passed() -> None:
    p = _profile(return_path={"type": "mx", "optional": True, "notes_key": "esp.example.rp"})
    r, dns = await _run(_good(), [p])
    (f,) = [f for f in r.findings if f.code == "ESP_RETURN_PATH_MISMATCH"]  # name has a CNAME
    assert f.severity == "info"
    assert f.params["notes_key"] == "esp.example.rp"
    assert (f"bounce.{D}", "MX") in dns.questions


async def test_mx_return_path_ok() -> None:
    p = _profile(return_path={"type": "mx"})
    zone = _apply({RP: None, (RP[0], "MX"): ["10 mx.esp.example.com."]})
    r, _ = await _run(zone, [p])
    assert _sec(r)["return_path"] == {"state": "ok", "host": RP[0]}


async def test_hosts_not_configured() -> None:
    r, dns = await _run(_good(), hosts={})
    nc = [f for f in r.findings if f.code == "ESP_HOST_NOT_CONFIGURED"]
    assert sorted(f.params["part"] for f in nc) == ["return_path", "tracking_domain"]
    assert all(f.severity == "info" for f in nc)
    assert r.status == "info"
    assert _sec(r)["return_path"] == {"state": "not_configured"}
    assert not any(n.startswith(("bounce.", "click.")) for n, _ in dns.questions)


@pytest.mark.parametrize("host", ["bad host.example.com", "-x.example.com", "a" * 300, "1.2.3.4"])
async def test_malformed_host_is_error(host: str) -> None:
    r, _ = await _run(_good(), hosts={"example-esp": EspHosts(return_path_host=host)})
    assert r.status == "error"
    (f,) = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert f.params["state"] == "invalid_name"


@pytest.mark.parametrize("domain", ["not a domain", "localhost", "", "x" * 300])
async def test_malformed_domain_is_error(domain: str) -> None:
    if not domain:
        with pytest.raises(ValueError):
            Target(domain=domain)
        return
    r, dns = await _run(_good(), domain=domain)
    assert r.status == "error"
    assert _codes(r) == {"ESP_DNS_ERROR"}
    assert dns.questions == []


async def test_unverified_fields_are_skipped() -> None:
    p = _profile(
        "other-esp",
        homepage="https://other.example.net",
        spf={"includes": ["spf.other.example.net"]},
        dkim={"selectors": [{"name": "mx1", "type": "cname"}, {"name": "k1", "type": "txt"}]},
        return_path={"type": "mx"},
        pitfalls=[
            {"code": "ESP_OTHER_ESP_A", "notes_key": "esp.other.a", "severity": "low"},
            {"code": "ESP_OTHER_ESP_B", "notes_key": "esp.other.b", "severity": "medium"},
        ],
        status="unverified",
        unverified_fields=[
            "return_path",
            "dkim.selectors.mx1",
            "spf.includes",
            "pitfalls.ESP_OTHER_ESP_B",
        ],
    )
    r, dns = await _run(_good(), [p], {"other-esp": HOSTS})
    sec = _sec(r, "other-esp")
    assert sec["skipped"] == [
        "dkim.selectors.mx1",
        "pitfalls.ESP_OTHER_ESP_B",
        "return_path",
        "spf.includes",
    ]
    assert sec["spf"] == {"state": "skipped_unverified"}
    assert sec["return_path"] == {"state": "skipped_unverified"}
    assert [d["state"] for d in sec["dkim"]] == ["ok", "skipped_unverified"]  # k1, mx1
    assert sec["pitfalls"] == ["ESP_OTHER_ESP_A"]
    names = {n for n, _ in dns.questions}
    assert f"mx1._domainkey.{D}" not in names
    assert f"bounce.{D}" not in names
    assert D not in names  # SPF not resolved at all
    (u,) = [f for f in r.findings if f.code == "ESP_PROFILE_UNVERIFIED"]
    assert u.severity == "info"
    assert list(u.evidence) == sorted(u.evidence) and "return_path" in u.evidence
    (pf,) = [f for f in r.findings if f.code == "ESP_PITFALL"]
    assert pf.params["pitfall"] == "ESP_OTHER_ESP_A"
    assert pf.params["declared_severity"] == "low"
    assert pf.severity == "info"


async def test_whole_dkim_unverified_skips_every_selector() -> None:
    p = _profile(status="unverified", unverified_fields=["dkim.selectors"])
    r, dns = await _run(_good(), [p])
    assert [d["state"] for d in _sec(r)["dkim"]] == ["skipped_unverified"] * 2
    assert not any("_domainkey" in n for n, _ in dns.questions)


async def test_two_esps_sorted_and_spf_resolved_once() -> None:
    second = _profile(
        "beta-esp",
        spf={"includes": ["spf.beta.example.net"]},
        dkim={"selectors": [{"name": "b1", "type": "txt"}]},
        return_path=None,
        tracking_domain=None,
    )
    zone = _apply({(D, "TXT"): ["v=spf1 include:spf.esp.example.com -all"]})
    r, dns = await _run(zone, [_profile(), second], {"example-esp": HOSTS})
    assert [s["id"] for s in r.data["esps"]] == ["beta-esp", "example-esp"]
    assert _codes(r) == {"ESP_SPF_INCLUDE_MISSING", "ESP_DKIM_RECORD_MISSING"}
    (f,) = [f for f in r.findings if f.code == "ESP_SPF_INCLUDE_MISSING"]
    assert f.params == {"esp": "Beta-Esp", "host": "spf.beta.example.net"}
    assert dns.questions.count((D, "TXT")) == 1
    assert _sec(r, "beta-esp")["return_path"] is None
    assert _sec(r)["spf"]["state"] == "ok"


async def test_profiles_from_m6_01_fixtures() -> None:
    profiles = list(read_esp_profiles(FIXTURES / "valid", TODAY))
    r, _ = await _run(_good(), profiles, {"example-esp": HOSTS})
    assert [s["id"] for s in r.data["esps"]] == ["example-esp", "other-esp"]
    assert "ESP_PROFILE_UNVERIFIED" in _codes(r)
    assert "ESP_PITFALL" in _codes(r)
    _assert_params_cover_placeholders(r)


async def test_no_esp_assigned_is_info_not_ok() -> None:
    r, dns = await _run(_good(), [], {})
    assert r.status == "info"
    assert _codes(r) == {"ESP_NONE_ASSIGNED"}
    assert r.data == {"esps": []}
    assert dns.questions == []


async def test_deterministic_output() -> None:
    profiles = [_profile(), _profile("beta-esp", tracking_domain=None)]
    zone = _apply({S1: None, RP: ResultState.timeout})
    a, _ = await _run(zone, profiles)
    b, _ = await _run(zone, list(reversed(profiles)))
    da = json.loads(a.model_dump_json(exclude={"duration_ms"}))
    db = json.loads(b.model_dump_json(exclude={"duration_ms"}))
    assert da == db


def test_constructor_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        EspProfileCheck([_profile(), _profile()])
    with pytest.raises(ValueError, match="not given"):
        EspProfileCheck([_profile()], {"nope": HOSTS})


def test_implements_check_protocol() -> None:
    check = EspProfileCheck([])
    assert isinstance(check, Check)
    assert check.id == "esp"


def _catalogue(lang: str) -> dict[str, str]:
    data = json.loads((LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.mark.parametrize("lang", ["en", "it"])
def test_every_code_has_i18n_keys(lang: str) -> None:
    cat = _catalogue(lang)
    assert len(set(CODES)) == len(CODES)
    for code in CODES:
        for part in ("title", "detail", "remediation"):
            assert f"finding.{code}.{part}" in cat, (lang, code, part)


def _assert_params_cover_placeholders(r: CheckResult) -> None:
    en = _catalogue("en")
    for f in r.findings:
        assert f.code in CODES
        for key in (f.title_key, f.detail_key, f.remediation_key):
            assert key is not None
            assert placeholders(en[key]) <= set(f.params), (key, f.params)
