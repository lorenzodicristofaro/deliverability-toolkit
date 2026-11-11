"""M6-19: the `esp` check never swallows a DNS failure on an ESP's SPF include host.

Fake ESPs (example.com / example.net) and the in-memory fake resolver of the M6-04 tests: no
network.

NXDOMAIN decision: NXDOMAIN (or NODATA) on an include host is a completed answer, not a DNS
failure (`spf_tree`: a void lookup, the node is `missing_target`). The esp check keeps its
existing semantics there: the include term is present, so the part is `ok`, no `ESP_DNS_ERROR`;
the missing target is reported by the SPF check (`SPF_INCLUDE_NOT_FOUND`).
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from app.checks.esp_profile import EspProfileCheck
from app.checks.models import CheckResult, Target
from app.checks.spf_tree import MAX_DEPTH, MAX_QUERIES
from app.dns.types import ResultState
from app.esp.profile import EspProfile, parse_esp_profile
from tests.checks.test_esp_profile import FakeDns, Zone, _assert_params_cover_placeholders, _ctx

TODAY = date(2026, 11, 11)
D = "client.example.com"
DNS = "ESP_DNS_ERROR"
A_HOST = "spf.alpha.example.com"
B_HOST = "spf.beta.example.net"
HOSTS = {"alpha": ("Alpha", A_HOST), "beta": ("Beta", B_HOST)}
ERROR_STATES = [s for s in ResultState if s.is_failure]


def _esp(pid: str, only_if_record: bool = False) -> EspProfile:
    name, host = HOSTS[pid]
    spf: dict[str, Any] = {"includes": [host]}
    if only_if_record:
        spf["only_if_record"] = True
    data: dict[str, Any] = {
        "id": pid,
        "name": name,
        "homepage": f"https://{pid}.example.com",
        "spf": spf,
        "dkim": {"selectors": []},
        "verified_on": date(2026, 1, 15),
        "sources": [f"https://docs.{pid}.example.com/dns"],
        "status": "verified",
    }
    return parse_esp_profile(data, pid, TODAY)


def _zone(root: str, extra: Zone | None = None) -> Zone:
    zone: Zone = {
        (D, "TXT"): [root],
        (A_HOST, "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        (B_HOST, "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"],
    }
    zone.update(extra or {})
    return zone


ONE = f"v=spf1 include:{A_HOST} -all"
TWO = f"v=spf1 include:{A_HOST} include:{B_HOST} -all"


def _chain(start: str, prefix: str, n: int, last: str | None = None) -> Zone:
    """`start` includes n0.<prefix> -> n1.<prefix> -> ... -> n<n-1>.<prefix> (-> `last`)."""
    names = [f"n{i}.{prefix}" for i in range(n)]
    zone: Zone = {(start, "TXT"): [f"v=spf1 include:{names[0]} -all"]}
    for i, name in enumerate(names):
        nxt = names[i + 1] if i + 1 < n else last
        zone[(name, "TXT")] = [f"v=spf1 include:{nxt} -all" if nxt else "v=spf1 -all"]
    return zone


# Truncation below the ESP host: a chain deeper than MAX_DEPTH under it; the first node not
# fetched is n<MAX_DEPTH - 1> (the ESP host is at depth 1).
DEEP_BELOW = _zone(ONE, _chain(A_HOST, A_HOST, MAX_DEPTH + 3))
DEEP_BELOW_NAME = f"n{MAX_DEPTH - 1}.{A_HOST}"
# The ESP host itself past the depth cap: root -> n0.x -> ... -> A_HOST, never fetched.
_X = f"x.{D}"
ESP_HOST_TOO_DEEP = {
    **{k: v for k, v in _chain(_X, _X, MAX_DEPTH, A_HOST).items() if k != (_X, "TXT")},
    (D, "TXT"): [f"v=spf1 include:n0.{_X} -all"],
    (A_HOST, "TXT"): ["v=spf1 -all"],
}
# Query cap below the ESP host: `a:` terms need two queries each (A, AAAA), so the cap stops
# somewhere in this record; the first skipped term is reported.
_A_TERMS = MAX_QUERIES // 2 + 5
QUERY_CAP = _zone(
    ONE,
    {
        (A_HOST, "TXT"): [
            "v=spf1 " + " ".join(f"a:h{i}.{A_HOST}" for i in range(_A_TERMS)) + " -all"
        ]
    },
)
# Queries: root TXT, ESP host TXT, then A + AAAA per term until the cap.
QUERY_CAP_NAME = f"h{(MAX_QUERIES - 2) // 2}.{A_HOST}"
# A loop below the ESP host is not a truncation (loop nodes are not fetched either).
LOOP_BELOW = _zone(
    ONE,
    {
        (A_HOST, "TXT"): [f"v=spf1 include:_l.{A_HOST} -all"],
        (f"_l.{A_HOST}", "TXT"): [f"v=spf1 include:{A_HOST} -all"],
    },
)


async def _run(zone: Zone, pids: list[str], only_if_record: bool = False) -> CheckResult:
    profiles = [_esp(p, only_if_record) for p in pids]
    return await EspProfileCheck(profiles, {}).run(_ctx(FakeDns(zone)), Target(domain=D))


# (id, assigned, only_if_record, zone, expected ESP_DNS_ERROR params or None, status)
CASES: list[tuple[str, list[str], bool, Zone, dict[str, str] | None, str]] = [
    ("one_esp_include_ok", ["alpha"], False, _zone(ONE), None, "ok"),
    (
        "one_esp_include_servfail",
        ["alpha"],
        False,
        _zone(ONE, {(A_HOST, "TXT"): ResultState.servfail}),
        {"esp": "Alpha", "name": A_HOST, "rdtype": "TXT", "state": "servfail"},
        "error",
    ),
    (
        "one_esp_include_timeout",
        ["alpha"],
        False,
        _zone(ONE, {(A_HOST, "TXT"): ResultState.timeout}),
        {"esp": "Alpha", "name": A_HOST, "rdtype": "TXT", "state": "timeout"},
        "error",
    ),
    (
        # Decision (module docstring): NXDOMAIN is an answer, not a failure.
        "one_esp_include_nxdomain_is_not_a_dns_error",
        ["alpha"],
        False,
        {(D, "TXT"): [ONE]},
        None,
        "ok",
    ),
    (
        "one_esp_failure_below_include_host",
        ["alpha"],
        False,
        _zone(
            ONE,
            {
                (A_HOST, "TXT"): [f"v=spf1 include:_n.{A_HOST} a:h.{A_HOST} -all"],
                (f"_n.{A_HOST}", "TXT"): ["v=spf1 -all"],
                (f"h.{A_HOST}", "A"): ResultState.servfail,
            },
        ),
        {"esp": "Alpha", "name": f"h.{A_HOST}", "rdtype": "A", "state": "servfail"},
        "error",
    ),
    (
        # Not under the ESP's include: no budget with one ESP, so it does not concern the ESP.
        "one_esp_failure_outside_include_host",
        ["alpha"],
        False,
        _zone(f"v=spf1 include:_o.{D} {ONE[7:]}", {(f"_o.{D}", "TXT"): ResultState.timeout}),
        None,
        "ok",
    ),
    ("one_esp_only_if_record_include_ok", ["alpha"], True, _zone(ONE), None, "ok"),
    (
        "one_esp_only_if_record_include_servfail",
        ["alpha"],
        True,
        _zone(ONE, {(A_HOST, "TXT"): ResultState.servfail}),
        {"esp": "Alpha", "name": A_HOST, "rdtype": "TXT", "state": "servfail"},
        "error",
    ),
    (
        "one_esp_truncated_below_include_host",
        ["alpha"],
        False,
        DEEP_BELOW,
        {"esp": "Alpha", "name": DEEP_BELOW_NAME, "rdtype": "TXT", "state": "truncated"},
        "error",
    ),
    (
        "one_esp_include_host_past_depth_cap",
        ["alpha"],
        False,
        ESP_HOST_TOO_DEEP,
        {"esp": "Alpha", "name": A_HOST, "rdtype": "TXT", "state": "truncated"},
        "error",
    ),
    (
        "one_esp_query_cap_below_include_host",
        ["alpha"],
        False,
        QUERY_CAP,
        {"esp": "Alpha", "name": QUERY_CAP_NAME, "rdtype": "A", "state": "truncated"},
        "error",
    ),
    (
        "one_esp_truncated_below_include_host_only_if_record",
        ["alpha"],
        True,
        DEEP_BELOW,
        {"esp": "Alpha", "name": DEEP_BELOW_NAME, "rdtype": "TXT", "state": "truncated"},
        "error",
    ),
    (
        "one_esp_include_host_past_depth_cap_only_if_record",
        ["alpha"],
        True,
        ESP_HOST_TOO_DEEP,
        {"esp": "Alpha", "name": A_HOST, "rdtype": "TXT", "state": "truncated"},
        "error",
    ),
    (
        "one_esp_query_cap_below_include_host_only_if_record",
        ["alpha"],
        True,
        QUERY_CAP,
        {"esp": "Alpha", "name": QUERY_CAP_NAME, "rdtype": "A", "state": "truncated"},
        "error",
    ),
    ("one_esp_loop_below_include_host_is_not_truncation", ["alpha"], False, LOOP_BELOW, None, "ok"),
    ("two_esps_include_ok", ["alpha", "beta"], False, _zone(TWO), None, "ok"),
    (
        "two_esps_servfail_on_one",
        ["alpha", "beta"],
        False,
        _zone(TWO, {(B_HOST, "TXT"): ResultState.servfail}),
        {"esp": "Alpha, Beta", "name": B_HOST, "rdtype": "TXT", "state": "servfail"},
        "error",
    ),
    (
        "two_esps_timeout_on_one",
        ["alpha", "beta"],
        False,
        _zone(TWO, {(A_HOST, "TXT"): ResultState.timeout}),
        {"esp": "Alpha, Beta", "name": A_HOST, "rdtype": "TXT", "state": "timeout"},
        "error",
    ),
    (
        "two_esps_nxdomain_on_one_is_not_a_dns_error",
        ["alpha", "beta"],
        False,
        {(D, "TXT"): [TWO], (A_HOST, "TXT"): ["v=spf1 -all"]},
        None,
        "ok",
    ),
]


@pytest.mark.parametrize(
    ("pids", "only", "zone", "error", "status"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
async def test_include_host_dns(
    pids: list[str], only: bool, zone: Zone, error: dict[str, str] | None, status: str
) -> None:
    r = await _run(zone, pids, only)
    errors = [f for f in r.findings if f.code == DNS]
    assert r.status == status
    if error is None:
        assert errors == []
    else:
        (f,) = errors
        assert f.severity == "low"
        assert f.params == {**error, "part": "spf.lookups"}
        assert r.status not in ("ok", "info")
    for section in r.data["esps"]:
        # The include term is present: the part is ok, never missing / no_record.
        assert section["spf"]["state"] == "ok"
    assert "ESP_SPF_INCLUDE_MISSING" not in {f.code for f in r.findings}
    _assert_params_cover_placeholders(r)


@pytest.mark.parametrize("only", [False, True], ids=["default", "only_if_record"])
@pytest.mark.parametrize("state", ERROR_STATES, ids=[str(s) for s in ERROR_STATES])
async def test_one_esp_every_failure_state_is_error(state: ResultState, only: bool) -> None:
    r = await _run(_zone(ONE, {(A_HOST, "TXT"): state}), ["alpha"], only)
    assert r.status == "error"
    (f,) = [f for f in r.findings if f.code == DNS]
    assert (f.params["part"], f.params["name"], f.params["state"]) == (
        "spf.lookups",
        A_HOST,
        str(state),
    )


async def test_one_esp_includes_error_not_duplicated_as_lookups() -> None:
    """Host not found and the tree failed: the include part reports it, once."""
    zone = {
        (D, "TXT"): [f"v=spf1 include:_o.{D} -all"],
        (f"_o.{D}", "TXT"): ResultState.servfail,
    }
    r = await _run(zone, ["alpha"])
    parts = [f.params["part"] for f in r.findings if f.code == DNS]
    assert parts == ["spf.includes"]
    assert r.status == "error"
