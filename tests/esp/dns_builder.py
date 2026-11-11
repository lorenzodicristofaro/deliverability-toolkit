"""Fake DNS zones derived from a loaded ESP profile (M6-11). No network, no vendor values typed.

Every vendor name in a zone comes from the profile itself: SPF include hosts, selector names
and `target_pattern` labels. What a profile does not specify (the content of the ESP's own SPF
record, DKIM key material, where a return-path or tracking CNAME points) is filled with
synthetic values under reserved example names (`example.net`, `192.0.2.0/24`), never with a
guess of what the vendor publishes.

A zone maps (name, type) to rdata strings or a failure `ResultState`, the shape of the
`FakeDns` of tests/checks/test_esp_profile.py. `to_fixture_records` turns it into the record
list of tests/support/dns_zones.py for the API tests.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from app.dns.types import ResultState
from app.esp.profile import DkimSelector, EspProfile, TargetPattern

DOMAIN = "client.example.com"
SYNTHETIC_ZONE = "example.net"
DKIM_KEY = "v=DKIM1; k=rsa; p=AAAA"
ESP_OWN_SPF = "v=spf1 ip4:192.0.2.0/24 -all"

Zone = dict[tuple[str, str], list[str] | ResultState]


def return_path_host(domain: str = DOMAIN) -> str:
    return f"bounce.{domain}"


def tracking_host(domain: str = DOMAIN) -> str:
    return f"click.{domain}"


def selector_name(sel: DkimSelector, domain: str = DOMAIN) -> str:
    return f"{sel.name}._domainkey.{domain}"


def matching_target(pattern: TargetPattern) -> str:
    """A CNAME target that fits `pattern`: each `*` label becomes an example label."""
    labels = [f"x{i}" if label == "*" else label for i, label in enumerate(pattern.labels)]
    target = ".".join(labels) + "."
    assert pattern.matches(target), (str(pattern), target)
    return target


def non_matching_target(sel: DkimSelector) -> str:
    """A CNAME target that fits no pattern of a shipped profile (and ends the chain)."""
    target = f"{sel.name}.mismatch.{SYNTHETIC_ZONE}."
    assert sel.target_pattern is None or not sel.target_pattern.matches(target)
    return target


def selector_target(sel: DkimSelector) -> str:
    """The CNAME target of a correct zone; any target fits a selector without a pattern."""
    if sel.target_pattern is not None:
        return matching_target(sel.target_pattern)
    return f"{sel.name}.dkim-target.{SYNTHETIC_ZONE}."


def _host_rdata(rdtype: str, part: str) -> tuple[str, list[str]]:
    kind = rdtype.upper()
    if kind == "CNAME":
        return kind, [f"{part}.target.{SYNTHETIC_ZONE}."]
    if kind == "MX":
        return kind, [f"10 {part}-mx.{SYNTHETIC_ZONE}."]
    return kind, [f"synthetic {part}"]


def spf_record(includes: tuple[str, ...] | list[str]) -> str:
    return "v=spf1 " + "".join(f"include:{h} " for h in includes) + "-all"


def correct_zone(profile: EspProfile, domain: str = DOMAIN) -> Zone:
    """Every record the profile expects, present and fitting."""
    zone: Zone = {(domain, "TXT"): [spf_record(profile.spf_includes)]}
    for host in profile.spf_includes:
        zone[(host, "TXT")] = [ESP_OWN_SPF]
    for sel in profile.dkim_selectors:
        name = selector_name(sel, domain)
        if sel.type == "cname":
            zone[(name, "CNAME")] = [selector_target(sel)]
        else:
            zone[(name, "TXT")] = [DKIM_KEY]
    for part, expect, host in (
        ("return_path", profile.return_path, return_path_host(domain)),
        ("tracking_domain", profile.tracking_domain, tracking_host(domain)),
    ):
        if expect is not None:
            rdtype, rdata = _host_rdata(expect.type, part)
            zone[(host, rdtype)] = rdata
    return zone


@dataclass(frozen=True, slots=True)
class NeededName:
    """A name the `esp` check must query for the profile (first query of that part)."""

    part: str
    name: str
    rdtype: str


def needed_names(profile: EspProfile, domain: str = DOMAIN) -> Iterator[NeededName]:
    """Verified parts only: an unverified part is never queried. The ESP's own SPF record is
    not listed: the check only needs the include term (its lookup is the SPF check's)."""
    if profile.spf_includes and profile.is_verified("spf.includes"):
        yield NeededName("spf.includes", domain, "TXT")
    for sel in profile.dkim_selectors:
        part = f"dkim.selectors.{sel.name}"
        if profile.is_verified(part):
            yield NeededName(part, selector_name(sel, domain), sel.type.upper())
    for part, expect, host in (
        ("return_path", profile.return_path, return_path_host(domain)),
        ("tracking_domain", profile.tracking_domain, tracking_host(domain)),
    ):
        if expect is not None and profile.is_verified(part):
            yield NeededName(part, host, expect.type.upper())


def to_fixture_records(zone: Zone) -> list[dict[str, Any]]:
    """The zone as a record list for `tests.support.dns_zones.parse_zones`."""
    out: list[dict[str, Any]] = []
    for (name, rdtype), entry in sorted(zone.items(), key=lambda kv: kv[0]):
        if isinstance(entry, ResultState):
            out.append({"name": name, "type": rdtype, "state": entry.value})
        else:
            out.append({"name": name, "type": rdtype, "ttl": 300, "rdata": list(entry)})
    return out
