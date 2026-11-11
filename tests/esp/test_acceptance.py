"""M6 acceptance (M6-11): every shipped profile in `profiles/esp/` against fake zones built from
the profile itself (tests/esp/dns_builder.py). No network, no hand-typed vendor values.

Mutations that a profile cannot have (no SPF include, no DKIM selector, no selector with a
`target_pattern`, no return path or tracking domain, or the part is unverified) are emitted as
skipped parameters with id `<profile>-<mutation>-not_applicable` and the reason, so the coverage
per profile is visible in the test report; `test_mutation_kinds_are_exercised` checks that every
kind applies to at least one shipped profile.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from typing import Any

import pytest

from app.checks.esp_detection import CODES as DETECTION_CODES
from app.checks.esp_profile import CODES, EspHosts, EspProfileCheck
from app.checks.models import CheckContext, CheckResult, Target
from app.dns.types import ResultState
from app.esp.profile import PROFILES_DIR, DkimSelector, EspProfile, load_esp_profiles
from tests.checks.test_esp_profile import FakeDns
from tests.esp.dns_builder import (
    DKIM_KEY,
    DOMAIN,
    ESP_OWN_SPF,
    SYNTHETIC_ZONE,
    Zone,
    correct_zone,
    needed_names,
    non_matching_target,
    return_path_host,
    selector_name,
    selector_target,
    spf_record,
    tracking_host,
)

_NOW = datetime(2026, 11, 11, tzinfo=UTC)
PROFILES: tuple[EspProfile, ...] = load_esp_profiles(PROFILES_DIR)
BY_ID = {p.id: p for p in PROFILES}
HOSTS = EspHosts(return_path_host=return_path_host(), tracking_host=tracking_host())

ADVISORY = frozenset({"ESP_PITFALL", "ESP_PROFILE_UNVERIFIED"})
FAILURE_CODES = (frozenset(CODES) | frozenset(DETECTION_CODES)) - ADVISORY
VERDICT_SUFFIXES = ("_MISSING", "_MISMATCH", "_WRONG_TYPE")
FAILURE_STATES = [s for s in ResultState if s.is_failure]


def _ctx(dns: FakeDns) -> CheckContext:
    return CheckContext(resolver=dns, clock=lambda: _NOW)


async def _run(
    zone: Zone,
    assigned: list[EspProfile],
    candidates: list[EspProfile] | None = None,
) -> tuple[CheckResult, FakeDns]:
    dns = FakeDns(zone)
    check = EspProfileCheck(assigned, {p.id: HOSTS for p in assigned}, candidates)
    return await check.run(_ctx(dns), Target(domain=DOMAIN)), dns


def _failures(r: CheckResult) -> list[str]:
    return [f.code for f in r.findings if f.code not in ADVISORY]


def _others(profile: EspProfile) -> list[EspProfile]:
    return [p for p in PROFILES if p.id != profile.id]


# --- meta: the milestone's "each profile has verified_on + sources" criterion -------------------


def test_every_profile_file_is_loaded() -> None:
    files = sorted(f.stem for f in PROFILES_DIR.glob("*.yaml"))
    assert files and files == [p.id for p in PROFILES]


@pytest.mark.parametrize("profile", PROFILES, ids=[p.id for p in PROFILES])
def test_profile_metadata(profile: EspProfile) -> None:
    assert isinstance(profile.verified_on, date)
    assert profile.verified_on <= date.today()
    assert profile.sources
    assert all(s.startswith("https://") for s in profile.sources)
    if profile.status == "unverified":
        assert profile.unverified_fields
    else:
        assert profile.status == "verified" and not profile.unverified_fields


# --- correct zone ---------------------------------------------------------------------------------


@pytest.mark.parametrize("detection", [False, True], ids=["assigned_only", "with_detection"])
@pytest.mark.parametrize("profile", PROFILES, ids=[p.id for p in PROFILES])
async def test_correct_zone_has_no_failure(profile: EspProfile, detection: bool) -> None:
    candidates = _others(profile) if detection else None
    r, _ = await _run(correct_zone(profile), [profile], candidates)
    assert _failures(r) == []
    assert r.status in ("ok", "info")
    codes = [f.code for f in r.findings]
    assert ("ESP_PROFILE_UNVERIFIED" in codes) == (profile.status == "unverified")
    verified_pitfalls = [
        p.code for p in profile.pitfalls if profile.is_verified(f"pitfalls.{p.code}")
    ]
    pitfalls = [f.params["pitfall"] for f in r.findings if f.code == "ESP_PITFALL"]
    assert sorted(pitfalls) == sorted(verified_pitfalls)
    (section,) = r.data["esps"]
    assert section["id"] == profile.id
    for part in ("spf", "return_path", "tracking_domain"):
        if section[part] is not None:
            assert section[part]["state"] in ("ok", "skipped_unverified"), part
    assert {d["state"] for d in section["dkim"]} <= {"ok", "skipped_unverified"}
    if detection:
        assert r.data["detection"]["detected"] == []


# --- mutations ------------------------------------------------------------------------------------

KINDS = (
    "spf_include_removed",
    "dkim_record_removed",
    "dkim_wrong_type",
    "cname_target_mismatch",
    "return_path_missing",
    "tracking_missing",
)


@dataclass(frozen=True, slots=True)
class Mutation:
    item: str
    code: str
    changes: dict[tuple[str, str], list[str] | None]
    part: tuple[str, str]  # (data section key, selector name or "") whose state must change


def _not_applicable(profile: EspProfile, kind: str) -> str | None:
    """Why `kind` cannot be applied to `profile` (None: it can)."""
    if kind == "spf_include_removed":
        if not profile.spf_includes:
            return "profile has no spf.includes"
        return None if profile.is_verified("spf.includes") else "spf.includes unverified"
    if kind in ("dkim_record_removed", "dkim_wrong_type"):
        if not profile.dkim_selectors:
            return "profile has no dkim.selectors"
        if not any(profile.is_verified(f"dkim.selectors.{s.name}") for s in profile.dkim_selectors):
            return "every dkim selector unverified"
        return None
    if kind == "cname_target_mismatch":
        patterned = [s for s in profile.dkim_selectors if s.target_pattern is not None]
        if not patterned:
            return "no cname selector with target_pattern (any target fits)"
        if not any(profile.is_verified(f"dkim.selectors.{s.name}") for s in patterned):
            return "every patterned selector unverified"
        return None
    part = "return_path" if kind == "return_path_missing" else "tracking_domain"
    expect = profile.return_path if part == "return_path" else profile.tracking_domain
    if expect is None:
        return f"profile has no {part}"
    return None if profile.is_verified(part) else f"{part} unverified (see unverified test)"


def _mutations(profile: EspProfile, kind: str) -> list[Mutation]:
    if _not_applicable(profile, kind) is not None:
        return []
    if kind == "spf_include_removed":
        out = []
        for host in profile.spf_includes:
            rest = [h for h in profile.spf_includes if h != host]
            changes: dict[tuple[str, str], list[str] | None] = {(DOMAIN, "TXT"): [spf_record(rest)]}
            out.append(Mutation(host, "ESP_SPF_INCLUDE_MISSING", changes, ("spf", "")))
        return out
    sels = [s for s in profile.dkim_selectors if profile.is_verified(f"dkim.selectors.{s.name}")]
    if kind == "dkim_record_removed":
        return [
            Mutation(
                s.name,
                "ESP_DKIM_RECORD_MISSING",
                {(selector_name(s), s.type.upper()): None},
                ("dkim", s.name),
            )
            for s in sels
        ]
    if kind == "dkim_wrong_type":  # malformed setup: the record exists with the other type
        return [
            Mutation(
                s.name,
                "ESP_DKIM_WRONG_TYPE",
                {(selector_name(s), s.type.upper()): None}
                | {(selector_name(s), "TXT" if s.type == "cname" else "CNAME"): [_wrong(s)]},
                ("dkim", s.name),
            )
            for s in sels
        ]
    if kind == "cname_target_mismatch":
        return [
            Mutation(
                s.name,
                "ESP_DKIM_TARGET_MISMATCH",
                {(selector_name(s), "CNAME"): [non_matching_target(s)]},
                ("dkim", s.name),
            )
            for s in sels
            if s.target_pattern is not None
        ]
    if kind == "return_path_missing":
        assert profile.return_path is not None
        key = (return_path_host(), profile.return_path.type.upper())
        return [
            Mutation("return_path", "ESP_RETURN_PATH_MISSING", {key: None}, ("return_path", ""))
        ]
    assert profile.tracking_domain is not None
    key = (tracking_host(), profile.tracking_domain.type.upper())
    return [Mutation("tracking", "ESP_TRACKING_MISSING", {key: None}, ("tracking_domain", ""))]


def _wrong(sel: DkimSelector) -> str:
    return DKIM_KEY if sel.type == "cname" else selector_target(sel)


def _mutation_params() -> list[Any]:
    params: list[Any] = []
    for profile in PROFILES:
        for kind in KINDS:
            reason = _not_applicable(profile, kind)
            if reason is not None:
                params.append(
                    pytest.param(
                        profile.id,
                        None,
                        id=f"{profile.id}-{kind}-not_applicable",
                        marks=pytest.mark.skip(reason=f"{profile.id}: {reason}"),
                    )
                )
                continue
            for m in _mutations(profile, kind):
                params.append(pytest.param(profile.id, m, id=f"{profile.id}-{kind}-{m.item}"))
    return params


def _apply(zone: Zone, changes: dict[tuple[str, str], list[str] | None]) -> Zone:
    out = dict(zone)
    for key, value in changes.items():
        if value is None:
            assert key in out, key
            del out[key]
        else:
            out[key] = value
    return out


@pytest.mark.parametrize(("pid", "mutation"), _mutation_params())
async def test_mutation_gives_exactly_its_finding(pid: str, mutation: Mutation) -> None:
    profile = BY_ID[pid]
    r, _ = await _run(_apply(correct_zone(profile), mutation.changes), [profile])
    assert _failures(r) == [mutation.code]
    assert r.status not in ("ok", "error")
    (f,) = [f for f in r.findings if f.code == mutation.code]
    assert f.params["esp"] == profile.name
    (section,) = r.data["esps"]
    key, selector = mutation.part
    if key == "dkim":
        assert f.params["selector"] == selector
        state = next(d for d in section["dkim"] if d["selector"] == selector)["state"]
        expected = {
            "ESP_DKIM_RECORD_MISSING": "missing",
            "ESP_DKIM_WRONG_TYPE": "wrong_type",
            "ESP_DKIM_TARGET_MISMATCH": "mismatch",
        }
        assert state == expected[mutation.code]
    else:
        assert section[key]["state"] == "missing"
    if mutation.code == "ESP_SPF_INCLUDE_MISSING":
        assert f.params["host"] == mutation.item


def test_mutation_kinds_are_exercised() -> None:
    """Every mutation kind applies to at least one shipped profile, and every profile has at
    least one applicable mutation (otherwise the acceptance run proves nothing about it)."""
    for kind in KINDS:
        assert any(_mutations(p, kind) for p in PROFILES), kind
    for profile in PROFILES:
        assert any(_mutations(profile, kind) for kind in KINDS), profile.id


def test_non_matching_target_is_outside_the_synthetic_zone_only() -> None:
    for profile in PROFILES:
        for sel in profile.dkim_selectors:
            assert non_matching_target(sel).endswith(f".{SYNTHETIC_ZONE}.")


# Variants of the synthesized matching target: (id, transform, fits). A `*` stands for exactly
# one whole label, so an extra or a missing label never fits; case and the trailing dot do not
# matter.
TARGET_VARIANTS: list[tuple[str, Any, bool]] = [
    ("as_built", lambda t: t, True),
    ("upper_case", lambda t: t.upper(), True),
    ("no_trailing_dot", lambda t: t.rstrip("."), True),
    ("extra_leading_label", lambda t: "extra." + t, False),
    ("first_label_dropped", lambda t: t.split(".", 1)[1], False),
    ("empty_label", lambda t: t.replace(".", "..", 1), False),
]
PATTERNED = [(p, s) for p in PROFILES for s in p.dkim_selectors if s.target_pattern is not None]


@pytest.mark.parametrize(
    ("transform", "fits"), [v[1:] for v in TARGET_VARIANTS], ids=[v[0] for v in TARGET_VARIANTS]
)
@pytest.mark.parametrize(
    ("profile", "sel"), PATTERNED, ids=[f"{p.id}-{s.name}" for p, s in PATTERNED]
)
async def test_patterned_selector_target_variants(
    profile: EspProfile, sel: DkimSelector, transform: Any, fits: bool
) -> None:
    target = transform(selector_target(sel))
    zone = correct_zone(profile) | {(selector_name(sel), "CNAME"): [target]}
    r, _ = await _run(zone, [profile])
    state = next(d for d in r.data["esps"][0]["dkim"] if d["selector"] == sel.name)["state"]
    if fits:
        assert (state, _failures(r)) == ("ok", [])
    else:
        assert state in ("mismatch", "error")
        assert r.status != "ok"
        assert _failures(r) in (["ESP_DKIM_TARGET_MISMATCH"], ["ESP_DNS_ERROR"])


# --- DNS failure on every needed name ---------------------------------------------------------


def _failure_params() -> list[Any]:
    return [
        pytest.param(p.id, n.name, n.rdtype, id=f"{p.id}-{n.part}")
        for p in PROFILES
        for n in needed_names(p)
    ]


def test_every_profile_has_a_needed_name() -> None:
    for profile in PROFILES:
        assert list(needed_names(profile)), profile.id


@pytest.mark.parametrize("state", FAILURE_STATES, ids=[str(s) for s in FAILURE_STATES])
@pytest.mark.parametrize(("pid", "name", "rdtype"), _failure_params())
async def test_dns_failure_is_error_never_ok_or_missing(
    pid: str, name: str, rdtype: str, state: ResultState
) -> None:
    profile = BY_ID[pid]
    r, dns = await _run(correct_zone(profile) | {(name, rdtype): state}, [profile])
    assert (name, rdtype) in dns.questions
    assert r.status == "error"
    errors = [f for f in r.findings if f.code == "ESP_DNS_ERROR"]
    assert len(errors) == 1
    assert (errors[0].params["name"], errors[0].params["state"]) == (name, str(state))
    assert not [c for c in _failures(r) if c.endswith(VERDICT_SUFFIXES)]


@pytest.mark.parametrize(("pid", "name", "rdtype"), _failure_params())
async def test_dns_failure_with_detection_is_still_error(pid: str, name: str, rdtype: str) -> None:
    profile = BY_ID[pid]
    zone = correct_zone(profile) | {(name, rdtype): ResultState.servfail}
    r, _ = await _run(zone, [profile], _others(profile))
    assert r.status == "error"
    assert "ESP_DNS_ERROR" in _failures(r)
    assert not [c for c in _failures(r) if c.endswith(VERDICT_SUFFIXES)]


# --- unverified fields: ESP_PROFILE_UNVERIFIED and no verdict -----------------------------------


def _unverified_keys(profile: EspProfile) -> list[tuple[str, str]]:
    """The (name, type) records behind the profile's unverified fields."""
    keys: list[tuple[str, str]] = []
    if profile.spf_includes and not profile.is_verified("spf.includes"):
        keys.append((DOMAIN, "TXT"))
    for sel in profile.dkim_selectors:
        if not profile.is_verified(f"dkim.selectors.{sel.name}"):
            keys.append((selector_name(sel), sel.type.upper()))
    for part, expect, host in (
        ("return_path", profile.return_path, return_path_host()),
        ("tracking_domain", profile.tracking_domain, tracking_host()),
    ):
        if expect is not None and not profile.is_verified(part):
            keys.append((host, expect.type.upper()))
    return keys


def _all_unverified(profile: EspProfile) -> EspProfile:
    """The shipped profile with every part present marked unverified (M6-16: once no shipped
    profile is unverified, this keeps the skip path exercised on real profile shapes)."""
    fields = {
        name
        for name, present in (
            ("spf.includes", profile.spf_includes),
            ("dkim.selectors", profile.dkim_selectors),
            ("return_path", profile.return_path),
            ("tracking_domain", profile.tracking_domain),
            ("pitfalls", profile.pitfalls),
        )
        if present
    }
    return replace(profile, status="unverified", unverified_fields=frozenset(fields))


UNVERIFIED = [p for p in PROFILES if p.status == "unverified"] + [
    _all_unverified(p) for p in PROFILES if p.status == "verified"
]
UNVERIFIED_IDS = [
    f"{p.id}-{'shipped' if BY_ID[p.id] is p else 'all_unverified'}" for p in UNVERIFIED
]


@pytest.mark.parametrize("record", ["removed", "dns_failure"])
@pytest.mark.parametrize("profile", UNVERIFIED, ids=UNVERIFIED_IDS)
async def test_unverified_fields_get_no_verdict(profile: EspProfile, record: str) -> None:
    keys = _unverified_keys(profile)
    zone = correct_zone(profile)
    for key in keys:
        if record == "removed":
            zone.pop(key, None)
        else:
            zone[key] = ResultState.servfail
    r, dns = await _run(zone, [profile])
    (unverified,) = [f for f in r.findings if f.code == "ESP_PROFILE_UNVERIFIED"]
    assert list(unverified.evidence) == sorted(profile.unverified_fields)
    assert _failures(r) == []
    assert r.status == "info"
    assert not set(keys) & set(dns.questions)
    (section,) = r.data["esps"]
    for field in profile.unverified_fields:
        if field in ("spf.includes", "return_path", "tracking_domain"):
            assert section["spf" if field == "spf.includes" else field]["state"] == (
                "skipped_unverified"
            )
        assert field in section["skipped"] or any(
            s.startswith(field + ".") for s in section["skipped"]
        )
    skipped_pitfalls = {
        p.code for p in profile.pitfalls if not profile.is_verified(f"pitfalls.{p.code}")
    }
    assert not {f.params["pitfall"] for f in r.findings if f.code == "ESP_PITFALL"} & (
        skipped_pitfalls
    )


def test_unverified_path_has_profiles_to_run_on() -> None:
    """Otherwise the unverified test above runs on nothing. Every shipped profile is covered,
    as shipped when unverified, else with every part marked unverified."""
    assert {p.id for p in UNVERIFIED} == set(BY_ID)
    assert all(p.status == "unverified" and p.unverified_fields for p in UNVERIFIED)


# --- combined SPF over the lookup limit ---------------------------------------------------------

SPF_ESPS = [p for p in PROFILES if p.spf_includes and p.is_verified("spf.includes")]
FILL = 5  # `a:` terms in each ESP's own (synthetic) record: 2 includes + 2 * FILL > 10


def _spf_pairs() -> list[Any]:
    return [
        pytest.param(a.id, b.id, id=f"{a.id}+{b.id}")
        for a, b in itertools.combinations(SPF_ESPS, 2)
    ]


@pytest.mark.parametrize(("first", "second"), _spf_pairs())
async def test_two_esps_over_the_combined_spf_limit(first: str, second: str) -> None:
    pair = [BY_ID[first], BY_ID[second]]
    zone: Zone = {}
    for p in pair:
        zone |= correct_zone(p)
    zone[(DOMAIN, "TXT")] = [spf_record([h for p in pair for h in p.spf_includes])]
    for p in pair:
        own = p.spf_includes[0]
        names = [f"fill{i}.{p.id}.{SYNTHETIC_ZONE}" for i in range(FILL)]
        zone[(own, "TXT")] = ["v=spf1 " + " ".join(f"a:{n}" for n in names) + " -all"]
        for n in names:
            zone[(n, "A")] = ["192.0.2.1"]
    r, _ = await _run(zone, pair)
    (over,) = [f for f in r.findings if f.code == "ESP_SPF_COMBINED_OVER_LIMIT"]
    assert over.severity == "high"
    assert sorted(over.evidence) == sorted(p.name for p in pair)
    assert over.params["count"] > over.params["limit"]
    assert r.status == "fail"
    assert "ESP_SPF_INCLUDE_MISSING" not in _failures(r)


def test_combined_spf_has_a_pair_to_test() -> None:
    assert len(SPF_ESPS) >= 2
    assert ESP_OWN_SPF.startswith("v=spf1 ")


# --- detection of an unassigned shipped ESP -----------------------------------------------------


def _detectable(profile: EspProfile) -> bool:
    if profile.spf_includes and profile.is_verified("spf.includes"):
        return True
    return any(
        s.type == "cname"
        and s.target_pattern is not None
        and profile.is_verified(f"dkim.selectors.{s.name}")
        for s in profile.dkim_selectors
    )


def _detection_params() -> list[Any]:
    return [
        pytest.param(p.id, id=p.id)
        if _detectable(p)
        else pytest.param(
            p.id,
            id=f"{p.id}-not_applicable",
            marks=pytest.mark.skip(
                reason=f"{p.id}: no verified spf.includes and no verified patterned selector"
            ),
        )
        for p in PROFILES
    ]


@pytest.mark.parametrize("pid", _detection_params())
async def test_unassigned_esp_records_are_detected(pid: str) -> None:
    profile = BY_ID[pid]
    r, _ = await _run(correct_zone(profile), [], list(PROFILES))
    detected = [f for f in r.findings if f.code == "ESP_DETECTED_NOT_ASSIGNED"]
    assert [f.params["esp_id"] for f in detected] == [pid]
    assert [d["id"] for d in r.data["detection"]["detected"]] == [pid]
    assert "ESP_DETECTION_TRUNCATED" not in _failures(r)
    assert r.status == "warn"
