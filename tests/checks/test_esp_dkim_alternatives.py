"""ESP check, alternative DKIM selector sets (M6-23). The shipped MailUp profile (ml01+ml02 CNAMEs
OR a TXT key at ml00, maintainer decision 2026-11-12) and fake profiles on reserved example
names; in-memory fake resolver, no network."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

import pytest

from app.checks.esp_profile import EspHosts, EspProfileCheck
from app.checks.finding_text import DKIM_SELECTOR_PART_KEY, display_params
from app.checks.models import CheckContext, CheckResult, Target
from app.core.i18n import t
from app.dns.types import ResultState
from app.esp.profile import PROFILES_DIR, EspProfile, load_esp_profiles, parse_esp_profile
from tests.checks.test_esp_profile import FakeDns, Zone, _assert_params_cover_placeholders
from tests.esp.dns_builder import DOMAIN, correct_zone, return_path_host, tracking_host
from tests.parsers.test_dkim import RSA_2048

MAILUP = next(p for p in load_esp_profiles(PROFILES_DIR) if p.id == "mailup")
ALL = load_esp_profiles(PROFILES_DIR)
_NOW = datetime(2026, 11, 12, tzinfo=UTC)
HOSTS = EspHosts(return_path_host=return_path_host(), tracking_host=tracking_host())
ADVISORY = frozenset({"ESP_PITFALL", "ESP_PROFILE_UNVERIFIED"})

ML00 = (f"ml00._domainkey.{DOMAIN}", "TXT")
ML01 = (f"ml01._domainkey.{DOMAIN}", "CNAME")
ML02 = (f"ml02._domainkey.{DOMAIN}", "CNAME")
KEY = f"v=DKIM1; k=rsa; p={RSA_2048}"


async def _run(
    zone: Zone, assigned: list[EspProfile], candidates: list[EspProfile] | None = None
) -> tuple[CheckResult, FakeDns]:
    dns = FakeDns(zone)
    ctx = CheckContext(resolver=dns, clock=lambda: _NOW)  # type: ignore[arg-type]
    check = EspProfileCheck(assigned, {p.id: HOSTS for p in assigned}, candidates)
    return await check.run(ctx, Target(domain=DOMAIN)), dns


def _failures(r: CheckResult) -> list[str]:
    return [f.code for f in r.findings if f.code not in ADVISORY]


def _states(parts: list[dict[str, Any]]) -> dict[str, str]:
    return {p["selector"]: p["state"] for p in parts}


def _zone(changes: dict[tuple[str, str], list[str] | ResultState | None]) -> Zone:
    zone = dict(correct_zone(MAILUP))
    for key, value in changes.items():
        if value is None:
            zone.pop(key, None)
        else:
            zone[key] = value
    return zone


NO_CNAMES: dict[tuple[str, str], list[str] | ResultState | None] = {ML01: None, ML02: None}

# (id, zone changes, non-advisory codes, status, satisfied_by, primary states, ml00 state)
MAILUP_CASES: list[
    tuple[
        str,
        dict[tuple[str, str], list[str] | ResultState | None],
        list[str],
        str,
        str | None,
        dict[str, str],
        str,
    ]
] = [
    ("cnames_only", {}, [], "info", "selectors", {"ml01": "ok", "ml02": "ok"}, "not_required"),
    (
        "txt_only",
        {**NO_CNAMES, ML00: [KEY]},
        [],
        "info",
        "alternatives.0",
        {"ml01": "missing", "ml02": "missing"},
        "ok",
    ),
    (
        "txt_only_ed25519",
        {**NO_CNAMES, ML00: ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="]},
        [],
        "info",
        "alternatives.0",
        {"ml01": "missing", "ml02": "missing"},
        "ok",
    ),
    ("both", {ML00: [KEY]}, [], "info", "selectors", {"ml01": "ok", "ml02": "ok"}, "not_required"),
    (
        "neither",
        NO_CNAMES,
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "missing",
    ),
    (
        "partial_cname_no_txt",
        {ML02: None},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "ok", "ml02": "missing"},
        "missing",
    ),
    (
        "partial_cname_with_txt",
        {ML02: None, ML00: [KEY]},
        [],
        "info",
        "alternatives.0",
        {"ml01": "ok", "ml02": "missing"},
        "ok",
    ),
    (
        "cname_mismatch_no_txt",
        {ML01: ["ml01.mismatch.example.net."]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "mismatch", "ml02": "ok"},
        "missing",
    ),
    (
        "malformed_key_bad_der",
        {**NO_CNAMES, ML00: ["v=DKIM1; k=rsa; p=AAAA"]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "invalid",
    ),
    (
        "malformed_not_dkim",
        {**NO_CNAMES, ML00: ["google-site-verification=abc"]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "invalid",
    ),
    (
        "malformed_garbage",
        {**NO_CNAMES, ML00: ["\x00;;=="]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "invalid",
    ),
    (
        "malformed_empty",
        {**NO_CNAMES, ML00: [""]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "invalid",
    ),
    (
        "revoked_key",
        {**NO_CNAMES, ML00: ["v=DKIM1; p="]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "invalid",
    ),
    (
        "two_txt_records",
        {**NO_CNAMES, ML00: [KEY, KEY]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "invalid",
    ),
    (
        "ml00_is_a_cname",
        {**NO_CNAMES, (ML00[0], "CNAME"): ["ml00.target.example.net."]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        "fail",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "wrong_type",
    ),
    (
        "ml00_dns_failure",
        {**NO_CNAMES, ML00: ResultState.servfail},
        ["ESP_DNS_ERROR"],
        "error",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "error",
    ),
    (
        "ml00_timeout",
        {**NO_CNAMES, ML00: ResultState.timeout},
        ["ESP_DNS_ERROR"],
        "error",
        None,
        {"ml01": "missing", "ml02": "missing"},
        "error",
    ),
    (
        "ml00_failure_but_cnames_ok",
        {ML00: ResultState.servfail},
        [],
        "info",
        "selectors",
        {"ml01": "ok", "ml02": "ok"},
        "not_required",
    ),
    (
        "cname_failure_no_txt",
        {ML01: ResultState.servfail},
        ["ESP_DNS_ERROR"],
        "error",
        None,
        {"ml01": "error", "ml02": "ok"},
        "missing",
    ),
    (
        "cname_failure_txt_ok",
        {ML01: ResultState.servfail, ML00: [KEY]},
        [],
        "info",
        "alternatives.0",
        {"ml01": "error", "ml02": "ok"},
        "ok",
    ),
    (
        "cname_failure_txt_malformed",
        {ML01: ResultState.timeout, ML00: ["v=DKIM1; p=AAAA"]},
        ["ESP_DNS_ERROR"],
        "error",
        None,
        {"ml01": "error", "ml02": "ok"},
        "invalid",
    ),
]


@pytest.mark.parametrize(
    ("changes", "codes", "status", "satisfied_by", "primary", "ml00"),
    [c[1:] for c in MAILUP_CASES],
    ids=[c[0] for c in MAILUP_CASES],
)
async def test_mailup_cnames_or_ml00_txt(
    changes: dict[tuple[str, str], list[str] | ResultState | None],
    codes: list[str],
    status: str,
    satisfied_by: str | None,
    primary: dict[str, str],
    ml00: str,
) -> None:
    r, dns = await _run(_zone(changes), [MAILUP])
    assert _failures(r) == codes
    assert r.status == status
    (section,) = r.data["esps"]
    assert section["dkim_satisfied_by"] == satisfied_by
    assert _states(section["dkim"]) == primary
    (alt,) = section["dkim_alternatives"]
    assert _states(alt) == {"ml00": ml00}
    assert (ML00 in dns.questions) == (ml00 != "not_required")
    _assert_params_cover_placeholders(r)
    if "ESP_DNS_ERROR" in codes:
        assert not [c for c in codes if c.endswith(("_MISSING", "_SATISFIED", "_MISMATCH"))]
    if satisfied_by is not None:
        assert not [f for f in r.findings if f.code.startswith("ESP_DKIM")]


async def test_neither_option_lists_both() -> None:
    r, _ = await _run(_zone(NO_CNAMES), [MAILUP])
    (f,) = [f for f in r.findings if f.code == "ESP_DKIM_NO_OPTION_SATISFIED"]
    assert f.severity == "high"
    assert f.params == {
        "esp": MAILUP.name,
        "domain": DOMAIN,
        "selectors": "ml01 (CNAME), ml02 (CNAME)",
        "alternatives": "ml00 (TXT)",
    }
    assert list(f.evidence) == [
        f"ml01._domainkey.{DOMAIN}",
        f"ml02._domainkey.{DOMAIN}",
        f"ml00._domainkey.{DOMAIN}",
    ]
    for lang in ("en", "it"):
        detail = t("finding.ESP_DKIM_NO_OPTION_SATISFIED.detail", lang, **f.params)
        assert "ml01 (CNAME), ml02 (CNAME)" in detail and "ml00 (TXT)" in detail


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        ("v=DKIM1; k=rsa; p=AAAA", "syntax_error"),
        ("not a key", "syntax_error"),
        ("v=DKIM1; p=", "revoked"),
        (None, "multiple_records"),
    ],
)
async def test_invalid_txt_reason(record: str | None, reason: str) -> None:
    records = [KEY, KEY] if record is None else [record]
    r, _ = await _run(_zone({**NO_CNAMES, ML00: records}), [MAILUP])
    (alt,) = r.data["esps"][0]["dkim_alternatives"]
    assert alt == [{"state": "invalid", "selector": "ml00", "reason": reason}]


async def test_ml00_dns_failure_names_the_alternative_part() -> None:
    r, _ = await _run(_zone({**NO_CNAMES, ML00: ResultState.servfail}), [MAILUP])
    (err,) = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert err.params["part"] == "dkim.alternatives.ml00"
    assert (err.params["name"], err.params["rdtype"]) == ML00
    assert err.params["state"] == str(ResultState.servfail)


# --- detection stays on the CNAME targets ---------------------------------------------------------


@pytest.mark.parametrize(
    "spf",
    [None, ["v=spf1 -all"]],
    ids=["no_spf", "spf_without_include"],
)
async def test_bare_ml00_txt_is_not_detected_as_mailup(spf: list[str] | None) -> None:
    zone: Zone = {ML00: [KEY]}
    if spf is not None:
        zone[(DOMAIN, "TXT")] = spf
    r, dns = await _run(zone, [], list(ALL))
    assert not [f for f in r.findings if f.code == "ESP_DETECTED_NOT_ASSIGNED"]
    assert r.data["detection"]["detected"] == []
    assert ML00 not in dns.questions


async def test_mailup_cnames_are_still_detected() -> None:
    zone = {ML01: correct_zone(MAILUP)[ML01], ML02: correct_zone(MAILUP)[ML02]}
    r, _ = await _run(zone, [], list(ALL))
    detected = [f.params["esp_id"] for f in r.findings if f.code == "ESP_DETECTED_NOT_ASSIGNED"]
    assert detected == ["mailup"]


# --- generic behaviour on fake profiles -----------------------------------------------------------

D = DOMAIN


def _fake(alternatives: list[list[dict[str, Any]]], **over: Any) -> EspProfile:
    data: dict[str, Any] = {
        "id": "example-esp",
        "name": "Example ESP",
        "homepage": "https://esp.example.com",
        "spf": {"includes": []},
        "dkim": {
            "selectors": [
                {"name": "s1", "type": "cname", "target_pattern": "s1.dkim.*.esp.example.com"},
                {"name": "s2", "type": "cname"},
            ],
            "alternatives": alternatives,
        },
        "verified_on": date(2026, 11, 1),
        "sources": ["https://docs.esp.example.com/dns"],
        "status": "verified",
    }
    data.update(over)
    return parse_esp_profile(data, "example-esp", date(2026, 11, 12))


TWO_SETS = [
    [{"name": "k0", "type": "txt"}],
    [
        {"name": "a1", "type": "cname", "target_pattern": "a1.dkim.esp.example.com"},
        {"name": "a2", "type": "txt"},
    ],
]
S1 = (f"s1._domainkey.{D}", "CNAME")
S2 = (f"s2._domainkey.{D}", "CNAME")
K0 = (f"k0._domainkey.{D}", "TXT")
A1 = (f"a1._domainkey.{D}", "CNAME")
A2 = (f"a2._domainkey.{D}", "TXT")
PRIMARY_OK: Zone = {S1: ["s1.dkim.x.esp.example.com."], S2: ["anything.example.net."]}

# (id, zone, codes, satisfied_by, per-set states)
FAKE_CASES: list[tuple[str, Zone, list[str], str | None, list[dict[str, str]]]] = [
    (
        "primary",
        PRIMARY_OK,
        [],
        "selectors",
        [{"k0": "not_required"}, {"a1": "not_required", "a2": "not_required"}],
    ),
    (
        "first_alternative",
        {K0: [KEY]},
        [],
        "alternatives.0",
        [{"k0": "ok"}, {"a1": "not_required", "a2": "not_required"}],
    ),
    (
        "second_alternative",
        {A1: ["a1.dkim.esp.example.com."], A2: [KEY]},
        [],
        "alternatives.1",
        [{"k0": "missing"}, {"a1": "ok", "a2": "ok"}],
    ),
    (
        "second_alternative_partial",
        {A1: ["a1.dkim.esp.example.com."]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        None,
        [{"k0": "missing"}, {"a1": "ok", "a2": "missing"}],
    ),
    (
        "second_alternative_bad_target",
        {A1: ["a1.other.example.net."], A2: [KEY]},
        ["ESP_DKIM_NO_OPTION_SATISFIED"],
        None,
        [{"k0": "missing"}, {"a1": "mismatch", "a2": "ok"}],
    ),
    (
        "first_fails_second_ok",
        {K0: ResultState.servfail, A1: ["a1.dkim.esp.example.com."], A2: [KEY]},
        [],
        "alternatives.1",
        [{"k0": "error"}, {"a1": "ok", "a2": "ok"}],
    ),
    (
        "first_fails_second_missing",
        {K0: ResultState.servfail},
        ["ESP_DNS_ERROR"],
        None,
        [{"k0": "error"}, {"a1": "missing", "a2": "missing"}],
    ),
]


@pytest.mark.parametrize(
    ("zone", "codes", "satisfied_by", "sets"),
    [c[1:] for c in FAKE_CASES],
    ids=[c[0] for c in FAKE_CASES],
)
async def test_any_alternative_set(
    zone: Zone, codes: list[str], satisfied_by: str | None, sets: list[dict[str, str]]
) -> None:
    profile = _fake(TWO_SETS)
    r, _ = await _run(zone, [profile])
    assert _failures(r) == codes
    section = r.data["esps"][0]
    assert section["dkim_satisfied_by"] == satisfied_by
    assert [_states(s) for s in section["dkim_alternatives"]] == sets
    _assert_params_cover_placeholders(r)


async def test_two_sets_listed_in_the_finding() -> None:
    r, _ = await _run({}, [_fake(TWO_SETS)])
    (f,) = [f for f in r.findings if f.code == "ESP_DKIM_NO_OPTION_SATISFIED"]
    assert f.params["selectors"] == "s1 (CNAME), s2 (CNAME)"
    assert f.params["alternatives"] == "k0 (TXT); a1 (CNAME), a2 (TXT)"


async def test_primary_txt_selector_keeps_any_txt_rule() -> None:
    """A `txt` selector in `dkim.selectors` is not key-validated (unchanged behaviour)."""
    profile = _fake(
        [[{"name": "k0", "type": "txt"}]],
        dkim={
            "selectors": [{"name": "p1", "type": "txt"}],
            "alternatives": [[{"name": "k0", "type": "txt"}]],
        },
    )
    r, _ = await _run({(f"p1._domainkey.{D}", "TXT"): ["not a key"]}, [profile])
    assert _failures(r) == []
    assert r.data["esps"][0]["dkim_satisfied_by"] == "selectors"


@pytest.mark.parametrize(
    ("unverified", "zone", "queried", "skipped"),
    [
        (["dkim.alternatives"], {}, False, ["dkim.alternatives.k0"]),
        (["dkim.alternatives.k0"], {K0: ResultState.servfail}, False, ["dkim.alternatives.k0"]),
        (["dkim.alternatives"], PRIMARY_OK, False, []),
        (["dkim.selectors.s1"], {}, True, ["dkim.selectors.s1"]),
    ],
    ids=["alt_unverified", "alt_unverified_failing", "primary_ok", "primary_unverified"],
)
async def test_unverified_set_gives_no_verdict(
    unverified: list[str], zone: Zone, queried: bool, skipped: list[str]
) -> None:
    profile = parse_esp_profile(
        {
            "id": "example-esp",
            "name": "Example ESP",
            "homepage": "https://esp.example.com",
            "spf": {"includes": []},
            "dkim": {
                "selectors": [
                    {"name": "s1", "type": "cname", "target_pattern": "s1.dkim.*.esp.example.com"},
                    {"name": "s2", "type": "cname"},
                ],
                "alternatives": [[{"name": "k0", "type": "txt"}]],
            },
            "verified_on": date(2026, 11, 1),
            "sources": ["https://docs.esp.example.com/dns"],
            "status": "unverified",
            "unverified_fields": unverified,
        },
        "example-esp",
        date(2026, 11, 12),
    )
    r, dns = await _run(zone, [profile])
    assert _failures(r) == []
    assert r.status == "info"
    assert (K0 in dns.questions) is queried
    assert r.data["esps"][0]["skipped"] == skipped


async def test_profiles_without_alternatives_keep_their_data_shape() -> None:
    others = [p for p in ALL if not p.dkim_alternatives]
    assert others
    for p in others:
        r, _ = await _run(correct_zone(p), [p])
        assert "dkim_alternatives" not in r.data["esps"][0]
        assert "dkim_satisfied_by" not in r.data["esps"][0]


# --- finding text ---------------------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["en", "it"])
@pytest.mark.parametrize(
    ("part", "selector"),
    [
        ("dkim.alternatives.ml00", "ml00"),
        ("dkim.selectors.ml01", "ml01"),
        ("dkim.alternatives.", None),
        ("dkim.alternativesml00", None),
    ],
)
def test_alternative_part_is_rendered(lang: str, part: str, selector: str | None) -> None:
    shown = display_params("ESP_DNS_ERROR", {"part": part}, lang)["part"]
    if selector is None:
        assert shown == part
    else:
        assert shown == t(DKIM_SELECTOR_PART_KEY, lang, selector=selector)
