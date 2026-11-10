"""ESP combined SPF lookup budget (M6-05). Fake ESPs on example.com / example.net /
example.org and the in-memory fake resolver from the M6-04 tests: no network."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from app.checks.esp_profile import CODES, EspProfileCheck
from app.checks.models import CheckResult, Target
from app.checks.spf import NEAR_LOOKUP_THRESHOLD
from app.checks.spf_tree import LOOKUP_LIMIT, MAX_DEPTH
from app.dns.types import ResultState
from app.esp.profile import EspProfile, parse_esp_profile
from tests.checks.test_esp_profile import FakeDns, Zone, _assert_params_cover_placeholders, _ctx

TODAY = date(2026, 11, 10)
D = "client.example.com"

# id -> (display name, SPF include host)
ESPS = {
    "alpha": ("Alpha", "spf.alpha.example.com"),
    "beta": ("Beta", "spf.beta.example.net"),
    "gamma": ("Gamma", "spf.gamma.example.org"),
}


def _esp(pid: str, unverified_spf: bool = False) -> EspProfile:
    name, host = ESPS[pid]
    data: dict[str, Any] = {
        "id": pid,
        "name": name,
        "homepage": f"https://{pid}.example.com",
        "spf": {"includes": [host]},
        "dkim": {"selectors": []},
        "verified_on": date(2026, 1, 15),
        "sources": [f"https://docs.{pid}.example.com/dns"],
        "status": "unverified" if unverified_spf else "verified",
    }
    if unverified_spf:
        data["unverified_fields"] = ["spf.includes"]
    return parse_esp_profile(data, pid, TODAY)


def _esp_zone(pid: str, cost: int) -> Zone:
    """The ESP's own record with `cost` lookup terms (each an `a:` with an A record)."""
    _, host = ESPS[pid]
    names = [f"h{i}.{host}" for i in range(cost)]
    zone: Zone = {(host, "TXT"): ["v=spf1 " + " ".join(f"a:{n}" for n in names) + " -all"]}
    for n in names:
        zone[(n, "A")] = ["192.0.2.1"]
    return zone


def _zone(root: str, costs: dict[str, int], extra: Zone | None = None) -> Zone:
    zone: Zone = {(D, "TXT"): [root]}
    for pid, cost in costs.items():
        zone.update(_esp_zone(pid, cost))
    zone.update(extra or {})
    return zone


def _inc(*pids: str) -> str:
    return " ".join(f"include:{ESPS[p][1]}" for p in pids)


def _chain(depth: int) -> Zone:
    """root includes c0 -> c1 -> ... long enough to hit MAX_DEPTH (truncation)."""
    zone: Zone = {}
    for i in range(depth):
        zone[(f"c{i}.{D}", "TXT")] = [f"v=spf1 include:c{i + 1}.{D} -all"]
    zone[(f"c{depth}.{D}", "TXT")] = ["v=spf1 -all"]
    return zone


async def _run(
    zone: Zone, pids: list[str], unverified: frozenset[str] = frozenset()
) -> CheckResult:
    profiles = [_esp(p, p in unverified) for p in pids]
    return await EspProfileCheck(profiles, {}).run(_ctx(FakeDns(zone)), Target(domain=D))


OVER = "ESP_SPF_COMBINED_OVER_LIMIT"
NEAR = "ESP_SPF_COMBINED_NEAR_LIMIT"
DNS = "ESP_DNS_ERROR"
MISSING = "ESP_SPF_INCLUDE_MISSING"

# (id, assigned, zone, unverified spf, expected codes, status, (code, esps, count) or None)
CASES: list[
    tuple[str, list[str], Zone, frozenset[str], set[str], str, tuple[str, str, int] | None]
] = [
    (
        "one_esp_over_limit_is_spf_check_business",
        ["alpha"],
        _zone(f"v=spf1 {_inc('alpha')} -all", {"alpha": 11}),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "two_esps_under",
        ["alpha", "beta"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 2, "beta": 2}),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "two_esps_over",
        ["alpha", "beta"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 5, "beta": 5}),
        frozenset(),
        {OVER},
        "fail",
        (OVER, "Alpha, Beta", 12),
    ),
    (
        "three_esps_over",
        ["alpha", "beta", "gamma"],
        _zone(f"v=spf1 {_inc('alpha', 'beta', 'gamma')} -all", {"alpha": 3, "beta": 3, "gamma": 3}),
        frozenset(),
        {OVER},
        "fail",
        (OVER, "Alpha, Beta, Gamma", 12),
    ),
    (
        "three_esps_under",
        ["alpha", "beta", "gamma"],
        _zone(f"v=spf1 {_inc('alpha', 'beta', 'gamma')} -all", {"alpha": 1, "beta": 1, "gamma": 1}),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "three_assigned_two_in_tree_over",
        ["alpha", "beta", "gamma"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} a:x1.{D} -all", {"alpha": 5, "beta": 5}),
        frozenset(),
        {OVER, MISSING},
        "fail",
        (OVER, "Alpha, Beta", 13),
    ),
    (
        "three_assigned_one_in_tree_over",
        ["alpha", "beta", "gamma"],
        _zone(f"v=spf1 {_inc('alpha')} -all", {"alpha": 11}),
        frozenset(),
        {MISSING},
        "fail",
        None,
    ),
    (
        "nested_includes_over",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 include:_spf.{D} -all",
            {"alpha": 4, "beta": 4},
            {
                (f"_spf.{D}", "TXT"): [f"v=spf1 {_inc('alpha')} include:_b.{D} -all"],
                (f"_b.{D}", "TXT"): [f"v=spf1 {_inc('beta')} -all"],
            },
        ),
        frozenset(),
        {OVER},
        "fail",
        (OVER, "Alpha, Beta", 12),
    ),
    (
        "nested_includes_under",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 include:_spf.{D} -all",
            {"alpha": 1, "beta": 1},
            {(f"_spf.{D}", "TXT"): [f"v=spf1 {_inc('alpha', 'beta')} -all"]},
        ),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "redirect_counts",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha')} redirect=_r.{D}",
            {"alpha": 5, "beta": 4},
            {(f"_r.{D}", "TXT"): [f"v=spf1 {_inc('beta')} -all"]},
        ),
        frozenset(),
        {OVER},
        "fail",
        (OVER, "Alpha, Beta", 12),
    ),
    (
        "include_loop_over",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_l.{D} -all",
            {"alpha": 4, "beta": 4},
            {(f"_l.{D}", "TXT"): [f"v=spf1 include:{D} -all"]},
        ),
        frozenset(),
        {OVER},
        "fail",
        (OVER, "Alpha, Beta", 12),
    ),
    (
        "include_loop_under",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_l.{D} -all",
            {"alpha": 1, "beta": 1},
            {(f"_l.{D}", "TXT"): [f"v=spf1 include:{D} -all"]},
        ),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "permerror_subnode_multiple_records_over",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_p.{D} -all",
            {"alpha": 5, "beta": 5},
            {(f"_p.{D}", "TXT"): ["v=spf1 -all", "v=spf1 ip4:192.0.2.0/24 -all"]},
        ),
        frozenset(),
        {OVER},
        "fail",
        (OVER, "Alpha, Beta", 13),
    ),
    (
        "permerror_subnode_syntax_error_under",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_p.{D} -all",
            {"alpha": 1, "beta": 1},
            {(f"_p.{D}", "TXT"): ["v=spf1 ip4:not-an-address -all"]},
        ),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "near_limit_9",
        ["alpha", "beta"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 4, "beta": 3}),
        frozenset(),
        {NEAR},
        "warn",
        (NEAR, "Alpha, Beta", 9),
    ),
    (
        "near_limit_10_still_within",
        ["alpha", "beta"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 4, "beta": 4}),
        frozenset(),
        {NEAR},
        "warn",
        (NEAR, "Alpha, Beta", 10),
    ),
    (
        "below_near_8",
        ["alpha", "beta"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 3, "beta": 3}),
        frozenset(),
        set(),
        "ok",
        None,
    ),
    (
        "one_esp_spf_unverified_not_attributed",
        ["alpha", "beta"],
        _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 5, "beta": 5}),
        frozenset({"beta"}),
        {"ESP_PROFILE_UNVERIFIED"},
        "info",
        None,
    ),
    (
        "nested_timeout_under_is_error",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_t.{D} -all",
            {"alpha": 1, "beta": 1},
            {(f"_t.{D}", "TXT"): ResultState.timeout},
        ),
        frozenset(),
        {DNS},
        "error",
        None,
    ),
    (
        "esp_record_servfail_under_is_error",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} -all",
            {"alpha": 1},
            {(ESPS["beta"][1], "TXT"): ResultState.servfail},
        ),
        frozenset(),
        {DNS},
        "error",
        None,
    ),
    (
        "nested_timeout_over_reports_and_errors",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_t.{D} -all",
            {"alpha": 5, "beta": 5},
            {(f"_t.{D}", "TXT"): ResultState.timeout},
        ),
        frozenset(),
        {OVER, DNS},
        "error",
        (OVER, "Alpha, Beta", 13),
    ),
    (
        "nested_timeout_near_is_error_without_near",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:_t.{D} -all",
            {"alpha": 3, "beta": 3},
            {(f"_t.{D}", "TXT"): ResultState.timeout},
        ),
        frozenset(),
        {DNS},
        "error",
        None,
    ),
    (
        "root_servfail_error_reported_once_per_esp",
        ["alpha", "beta"],
        {(D, "TXT"): ResultState.servfail},
        frozenset(),
        {DNS},
        "error",
        None,
    ),
    (
        "truncated_tree_is_error_and_over",
        ["alpha", "beta"],
        _zone(
            f"v=spf1 {_inc('alpha', 'beta')} include:c0.{D} -all",
            {"alpha": 1, "beta": 1},
            _chain(MAX_DEPTH + 2),
        ),
        frozenset(),
        {OVER, DNS},
        "error",
        (OVER, "Alpha, Beta", -1),  # count checked separately: a lower bound
    ),
]


@pytest.mark.parametrize(
    ("pids", "zone", "unverified", "codes", "status", "expect"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
async def test_cases(
    pids: list[str],
    zone: Zone,
    unverified: frozenset[str],
    codes: set[str],
    status: str,
    expect: tuple[str, str, int] | None,
) -> None:
    r = await _run(zone, pids, unverified)
    assert {f.code for f in r.findings} == codes
    assert r.status == status
    combined = [f for f in r.findings if f.code in (OVER, NEAR)]
    if expect is None:
        assert combined == []
    else:
        code, esps, count = expect
        (f,) = combined
        assert f.code == code
        assert f.severity == ("high" if code == OVER else "low")
        assert f.params["esps"] == esps
        assert f.params["limit"] == LOOKUP_LIMIT
        assert list(f.evidence) == esps.split(", ")
        if count >= 0:
            assert f.params["count"] == count
        else:
            assert f.params["count"] > LOOKUP_LIMIT
    _assert_params_cover_placeholders(r)


async def test_dns_error_params_for_lookups_part() -> None:
    zone = _zone(
        f"v=spf1 {_inc('alpha', 'beta')} include:_t.{D} -all",
        {"alpha": 1, "beta": 1},
        {(f"_t.{D}", "TXT"): ResultState.timeout},
    )
    r = await _run(zone, ["alpha", "beta"])
    (f,) = [f for f in r.findings if f.code == DNS]
    assert f.params == {
        "esp": "Alpha, Beta",
        "part": "spf.lookups",
        "name": f"_t.{D}",
        "rdtype": "TXT",
        "state": "timeout",
    }


async def test_truncated_dns_error_names_domain() -> None:
    zone = _zone(f"v=spf1 {_inc('alpha', 'beta')} include:c0.{D} -all", {}, _chain(MAX_DEPTH + 2))
    zone.update(_esp_zone("alpha", 1))
    zone.update(_esp_zone("beta", 1))
    r = await _run(zone, ["alpha", "beta"])
    (f,) = [f for f in r.findings if f.code == DNS]
    assert f.params["part"] == "spf.lookups"
    assert f.params["state"] == "truncated"
    assert f.params["name"] == D


async def test_root_failure_not_duplicated_as_lookups_error() -> None:
    r = await _run({(D, "TXT"): ResultState.servfail}, ["alpha", "beta"])
    parts = [f.params["part"] for f in r.findings if f.code == DNS]
    assert parts == ["spf.includes", "spf.includes"]


async def test_combined_finding_does_not_reuse_spf_check_text() -> None:
    assert "SPF_TOO_MANY_LOOKUPS" not in CODES
    assert "SPF_NEAR_LOOKUP_LIMIT" not in CODES
    assert NEAR_LOOKUP_THRESHOLD <= LOOKUP_LIMIT


async def test_spf_resolved_once_for_budget_and_includes() -> None:
    zone = _zone(f"v=spf1 {_inc('alpha', 'beta')} -all", {"alpha": 5, "beta": 5})
    dns = FakeDns(zone)
    profiles = [_esp("alpha"), _esp("beta")]
    await EspProfileCheck(profiles, {}).run(_ctx(dns), Target(domain=D))
    assert dns.questions.count((D, "TXT")) == 1
