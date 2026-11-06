"""Corpus hygiene: folder and MANIFEST.yaml agree, only reserved names/IPs, no stray NULs."""

import ipaddress
import re
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml

CORPUS = Path(__file__).parent / "messages"
RESERVED_V4 = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
RESERVED_V6 = ipaddress.ip_network("2001:db8::/32")
PROPERTY_PREFIXES = ("smtp.", "header.", "body.", "policy.")
ALLOWED_DOMAINS = ("example.com", "example.net", "example.org")

HOST_RE = re.compile(r"(?<![\w.-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?![\w-]|\.[\w-]|@)")
V4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d]|\.\d)")
V6_RE = re.compile(r"(?<![\w:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])")


def _manifest() -> list[dict[str, Any]]:
    data = yaml.safe_load((CORPUS / "MANIFEST.yaml").read_text())
    assert isinstance(data, dict)
    samples = data["samples"]
    assert isinstance(samples, list)
    return samples


def bad_hosts(text: str, allowed: tuple[str, ...] = ()) -> list[str]:
    bad = []
    for host in HOST_RE.findall(text):
        last = host.rsplit(".", 1)[1]
        if not last.isalpha() or len(last) < 2:
            continue  # version numbers and ids such as 8.14.5 or d200mr.93.1421363207
        h = host.lower()
        if h.startswith(PROPERTY_PREFIXES):
            continue  # RFC 8601 ptype.property, e.g. smtp.mailfrom
        if h in allowed:
            continue
        if not any(h == d or h.endswith("." + d) for d in ALLOWED_DOMAINS):
            bad.append(host)
    return bad


def bad_ips(text: str) -> list[str]:
    bad = []
    for cand in V4_RE.findall(text):
        try:
            ip = ipaddress.IPv4Address(cand)
        except ValueError:
            continue
        if not any(ip in n for n in RESERVED_V4):
            bad.append(cand)
    for cand in V6_RE.findall(text):
        if "::" not in cand and cand.count(":") < 3:
            continue  # a time stamp such as 15:00:01
        try:
            ip6 = ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        if ip6 not in RESERVED_V6:
            bad.append(cand)
    return bad


@pytest.mark.parametrize(
    ("text", "hosts", "ips"),
    [
        ("Received: from a.example.com ([192.0.2.1])", [], []),
        ("From: x@gmail.com", ["gmail.com"], []),
        ("by evilexample.com", ["evilexample.com"], []),
        ("by mx.example.org.", [], []),
        ("spf=pass smtp.mailfrom=example.net header.d=x", [], []),
        ("[8.8.8.8] [198.51.100.7]", [], ["8.8.8.8"]),
        ("[2001:db8::1] [2a00:1450::1]", [], ["2a00:1450::1"]),
        ("15:00:01 -0800 (8.14.5/8.14.5) id 1421363207", [], []),
        ("[999.1.1.1]", [], []),
    ],
)
def test_scanners(text: str, hosts: list[str], ips: list[str]) -> None:
    assert bad_hosts(text) == hosts
    assert bad_ips(text) == ips


def test_manifest_matches_folder() -> None:
    listed = [s["file"] for s in _manifest()]
    assert len(listed) == len(set(listed)), "duplicate manifest entries"
    on_disk = sorted(p.name for p in CORPUS.glob("*.eml"))
    assert sorted(listed) == on_disk


def test_manifest_entry_shape() -> None:
    keys = {"file", "provider_label", "status", "sources", "verified_on", "notes", "facts"}
    optional = {"allowed_hostnames", "contains_nul"}
    for s in _manifest():
        assert keys <= set(s) <= keys | optional, s["file"]
        assert s["status"] in ("verified", "unverified"), s["file"]
        assert isinstance(s["sources"], list), s["file"]
        assert isinstance(s["facts"], dict) and s["facts"], s["file"]
        assert str(s["notes"]).strip(), s["file"]
        assert re.fullmatch(
            r"(gmail|outlook|ses|sendgrid|mailup|plain-rfc|arc-rfc8617|malformed-[a-z0-9-]+)",
            s["provider_label"],
        ), s["file"]


def test_verified_and_unverified_rules() -> None:
    for s in _manifest():
        if s["status"] == "verified":
            assert s["sources"], s["file"]
            assert all(isinstance(u, str) and u.startswith("https://") for u in s["sources"]), s[
                "file"
            ]
            assert date.fromisoformat(str(s["verified_on"])), s["file"]
        else:
            assert s["sources"] == [], s["file"]
            assert s["verified_on"] is None, s["file"]
            assert "shape not confirmed against a real message of this provider" in s["notes"]


def test_corpus_is_sanitized() -> None:
    for s in _manifest():
        name = s["file"]
        data = (CORPUS / name).read_bytes()
        assert (b"\x00" in data) == bool(s.get("contains_nul", False)), f"{name}: NUL mismatch"
        text = data.decode("latin-1")
        allowed = tuple(h.lower() for h in s.get("allowed_hostnames", []))
        assert bad_hosts(text, allowed) == [], name
        assert bad_ips(text) == [], name
