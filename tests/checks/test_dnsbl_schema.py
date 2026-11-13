"""DNSBL list schema (M7-03): strict loader, malformed files rejected. Invented lists only."""

from __future__ import annotations

import copy
import ipaddress
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.checks.dnsbl_schema import (
    MAX_FILE_BYTES,
    DnsblSchemaError,
    parse_dnsbl_lists,
    read_dnsbl_lists,
)

FIXTURE = Path(__file__).parent / "fixtures" / "dnsbl_test_lists.yaml"
TODAY = date(2026, 11, 13)


def _base() -> dict[str, Any]:
    return {
        "id": "ex",
        "name": "Example",
        "zone": "bl.example.com",
        "kind": "ip",
        "ipv4": True,
        "ipv6": False,
        "return_codes": [
            {"code": "127.0.0.2", "meaning": "listed", "category": "spam_source"},
            {"code": "127.0.0.4", "meaning": "refused"},
        ],
        "verified_on": date(2026, 1, 1),
        "sources": ["https://docs.example.com/bl"],
        "status": "verified",
    }


def _doc(**changes: Any) -> dict[str, Any]:
    entry = _base()
    for key, value in changes.items():
        if value is _DROP:
            entry.pop(key)
        else:
            entry[key] = value
    return {"lists": [entry]}


_DROP = object()


def test_fixture_loads() -> None:
    lists = read_dnsbl_lists(FIXTURE, TODAY)
    assert [x.id for x in lists] == ["ip-both", "ip-v4only", "dom", "ip-unverified"]
    both = lists[0]
    assert both.ipv6 and both.refused_networks == (ipaddress.IPv4Network("127.255.255.0/24"),)
    assert both.return_codes[ipaddress.IPv4Address("127.0.0.10")].meaning == "info"
    assert lists[1].nodata_is_clean and not lists[0].nodata_is_clean
    assert lists[2].kind == "domain" and not lists[2].ipv4 and not lists[2].ipv6
    assert not lists[3].verified and lists[3].unverified_fields == {"return_codes"}


def test_valid_minimal() -> None:
    (lst,) = parse_dnsbl_lists(_doc(), TODAY)
    assert lst.verified and lst.usage_policy is None and lst.refused_networks == ()
    with pytest.raises(TypeError):
        lst.return_codes[ipaddress.IPv4Address("127.0.0.9")] = None  # type: ignore[index]


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        ({"extra": 1}, "unknown keys"),
        ({"zone": _DROP}, "missing keys"),
        ({"id": "Bad_ID"}, "must match"),
        ({"zone": "single"}, "two labels"),
        ({"zone": "bl.example.123"}, "numeric"),
        ({"zone": "bl_x.example.com"}, "invalid label"),
        ({"zone": "BL.example.com"}, "invalid label"),
        ({"zone": "bl.example.com."}, "invalid label"),
        ({"zone": "a" * 64 + ".example.com"}, "invalid label"),
        ({"kind": "uri"}, "must be one of"),
        ({"ipv6": _DROP}, "both ipv4 and ipv6"),
        ({"ipv4": False}, "ipv4 or ipv6"),
        ({"ipv4": "yes"}, "true or false"),
        ({"kind": "domain"}, "only allowed on ip lists"),
        ({"ipv6": True, "zone": ("a" * 60 + ".") * 3 + "example.com"}, "too long"),
        ({"return_codes": []}, "must not be empty"),
        ({"return_codes": "127.0.0.2"}, "must be a list"),
        ({"return_codes": [{"code": "127.0.0.4", "meaning": "refused"}]}, "at least one listed"),
        ({"return_codes": [{"code": "127.0.0.2", "meaning": "listed"}]}, "needs a category"),
        (
            {"return_codes": [{"code": "10.0.0.2", "meaning": "listed", "category": "x"}]},
            "must be a canonical address",
        ),
        (
            {"return_codes": [{"code": "127.000.0.2", "meaning": "listed", "category": "x"}]},
            "not an IPv4",
        ),
        (
            {"return_codes": [{"code": "::1", "meaning": "listed", "category": "x"}]},
            "not an IPv4",
        ),
        (
            {"return_codes": [{"code": "127.0.0.2", "meaning": "maybe", "category": "x"}]},
            "must be one of",
        ),
        (
            {"return_codes": [{"code": "127.0.0.2", "meaning": "listed", "category": "Spam"}]},
            "snake slug",
        ),
        (
            {
                "return_codes": [
                    {"code": "127.0.0.2", "meaning": "listed", "category": "x"},
                    {"code": "127.0.0.4", "meaning": "refused", "category": "x"},
                ]
            },
            "no category",
        ),
        (
            {
                "return_codes": [
                    {"code": "127.0.0.2", "meaning": "listed", "category": "x"},
                    {"code": "127.0.0.2", "meaning": "info"},
                ]
            },
            "duplicate code",
        ),
        (
            {
                "return_codes": [
                    {"code": "127.0.0.2", "meaning": "listed", "category": "x", "score": 5}
                ]
            },
            "unknown keys",
        ),
        ({"refused_networks": []}, "must not be empty"),
        ({"refused_networks": ["127.255.255.1/24"]}, "not an IPv4 network"),
        ({"refused_networks": ["10.0.0.0/24"]}, "canonical network"),
        ({"refused_networks": ["127.0.0.0/8", "127.0.0.0/8"]}, "duplicate network"),
        ({"refused_networks": ["127.0.0.0/24"]}, "lies in a refused network"),
        ({"nodata_is_clean": 1}, "true or false"),
        ({"usage_policy": "line\nbreak"}, "control characters"),
        ({"usage_policy": "x" * 2001}, "at most"),
        ({"verified_on": "2026-01-01"}, "ISO date"),
        ({"verified_on": date(2027, 1, 1)}, "future"),
        ({"sources": []}, "must not be empty"),
        ({"sources": ["http://docs.example.com"]}, "https"),
        ({"sources": ["https://docs.example.com", "https://docs.example.com"]}, "duplicate"),
        ({"status": "maybe"}, "must be one of"),
        ({"status": "unverified"}, "needs the unverified fields"),
        ({"unverified_fields": ["zone"]}, "only allowed with status: unverified"),
        ({"status": "unverified", "unverified_fields": ["usage_policy"]}, "names no field"),
        (
            {"status": "unverified", "unverified_fields": ["zone", "zone"]},
            "duplicate entry",
        ),
        ({"name": " padded"}, "surrounding whitespace"),
        # M7-03b: return_code_mode and default_enabled
        ({"return_code_mode": "mask"}, "must be one of"),
        ({"return_code_mode": "Bitmask"}, "must be one of"),
        ({"return_code_mode": True}, "must be one of"),
        ({"return_code_mode": None}, "must be one of"),
        ({"return_code_mode": ["bitmask"]}, "must be one of"),
        ({"default_enabled": "false"}, "true or false"),
        ({"default_enabled": 0}, "true or false"),
        ({"default_enabled": None}, "true or false"),
        (
            {
                "return_code_mode": "bitmask",
                "return_codes": [{"code": "127.0.0.3", "meaning": "listed", "category": "x"}],
            },
            "not a single bit",
        ),
        (
            {
                "return_code_mode": "bitmask",
                "return_codes": [
                    {"code": "127.0.0.2", "meaning": "listed", "category": "x"},
                    {"code": "127.0.1.4", "meaning": "info"},
                ],
            },
            "not a single bit",
        ),
        (
            {
                "return_code_mode": "bitmask",
                "return_codes": [{"code": "127.0.0.0", "meaning": "listed", "category": "x"}],
            },
            "not a single bit",
        ),
        (
            {"status": "unverified", "unverified_fields": ["return_code_mode"]},
            "names no field",
        ),
    ],
)
def test_invalid_list(changes: dict[str, Any], fragment: str) -> None:
    with pytest.raises(DnsblSchemaError, match=fragment):
        parse_dnsbl_lists(_doc(**changes), TODAY)


def test_mode_and_enablement_defaults() -> None:
    (lst,) = parse_dnsbl_lists(_doc(), TODAY)
    assert lst.return_code_mode == "exact" and lst.default_enabled is True


@pytest.mark.parametrize(
    ("changes", "mode", "enabled"),
    [
        ({"return_code_mode": "exact"}, "exact", True),
        ({"return_code_mode": "bitmask"}, "bitmask", True),
        ({"default_enabled": False}, "exact", False),
        ({"return_code_mode": "bitmask", "default_enabled": False}, "bitmask", False),
        # a refused code need not be a single bit, and is matched exactly
        (
            {
                "return_code_mode": "bitmask",
                "return_codes": [
                    {"code": "127.0.0.128", "meaning": "listed", "category": "x"},
                    {"code": "127.0.0.255", "meaning": "refused"},
                    {"code": "127.255.255.254", "meaning": "refused"},
                ],
            },
            "bitmask",
            True,
        ),
        (
            {"return_code_mode": "bitmask", "status": "unverified",
             "unverified_fields": ["return_code_mode"]},
            "bitmask",
            True,
        ),
    ],
)  # fmt: skip
def test_mode_and_enablement(changes: dict[str, Any], mode: str, enabled: bool) -> None:
    (lst,) = parse_dnsbl_lists(_doc(**changes), TODAY)
    assert (lst.return_code_mode, lst.default_enabled) == (mode, enabled)


def test_unverified_paths_accepted() -> None:
    doc = _doc(status="unverified", unverified_fields=["return_codes.127.0.0.2", "ipv6", "kind"])
    (lst,) = parse_dnsbl_lists(doc, TODAY)
    assert not lst.verified


@pytest.mark.parametrize(
    ("doc", "fragment"),
    [
        (None, "must be a mapping"),
        ([], "must be a mapping"),
        ({}, "missing keys"),
        ({"lists": [], "version": 1}, "unknown keys"),
        ({"lists": {}}, "must be a list"),
        ({"lists": ["x"]}, "must be a mapping"),
        ({"lists": [_base(), _base()]}, "duplicate list id"),
        ({"lists": [_base(), {**_base(), "id": "other"}]}, "duplicate zone"),
        ({"lists": [{**_base(), "id": f"l{i}", "zone": f"z{i}.example.com"} for i in range(101)]},
         "at most 100"),
    ],
)  # fmt: skip
def test_invalid_document(doc: object, fragment: str) -> None:
    with pytest.raises(DnsblSchemaError, match=fragment):
        parse_dnsbl_lists(copy.deepcopy(doc), TODAY)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("lists: [\n", "cannot parse"),
        ("lists: []\nlists: []\n", "duplicate key"),
        ("a: &x [1]\nlists: *x\n", "anchors and aliases"),
        ("base: &b {id: x}\nlists: [{<<: *b}]\n", "anchors and aliases"),
        ("lists: !!python/object:os.system {}\n", "cannot parse"),
        ("lists: " + "[" * 5000 + "]" * 5000 + "\n", "cannot parse"),
        ("\udcff", "cannot"),
        ("lists: [{id: x}]\n", "missing keys"),
    ],
)
def test_malformed_files(tmp_path: Path, text: str, fragment: str) -> None:
    path = tmp_path / "dnsbl.yaml"
    path.write_bytes(text.encode("utf-8", "surrogateescape"))
    with pytest.raises(DnsblSchemaError, match=fragment):
        read_dnsbl_lists(path, TODAY)


def test_size_cap(tmp_path: Path) -> None:
    path = tmp_path / "dnsbl.yaml"
    path.write_text("lists: []\n" + "#" * MAX_FILE_BYTES)
    with pytest.raises(DnsblSchemaError, match="larger than"):
        read_dnsbl_lists(path, TODAY)


def test_missing_and_symlink(tmp_path: Path) -> None:
    with pytest.raises(DnsblSchemaError, match="not a regular file"):
        read_dnsbl_lists(tmp_path / "nope.yaml", TODAY)
    link = tmp_path / "link.yaml"
    link.symlink_to(FIXTURE)
    with pytest.raises(DnsblSchemaError, match="not a regular file"):
        read_dnsbl_lists(link, TODAY)
