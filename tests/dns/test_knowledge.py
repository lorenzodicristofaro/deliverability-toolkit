"""Tests for app.dns.knowledge: shipped seed data and malformed-file handling (no network)."""

from __future__ import annotations

import copy
import dataclasses
import warnings
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.core.config import ResolverAddr
from app.dns import knowledge
from app.dns.egress import DEFAULT_POLICY
from app.dns.knowledge import (
    KnowledgeError,
    get_resolver,
    list_public_resolvers,
    parse_resolvers,
    parse_root_hints,
    root_hints,
)

GOOD_RESOLVER: dict[str, Any] = {
    "id": "x",
    "name": "X DNS",
    "operator": "X",
    "addresses": ["8.8.8.8", "2001:4860:4860::8888"],
    "port": 53,
    "verified_on": date(2026, 1, 1),
    "sources": ["https://example.com/dns"],
    "status": "verified",
}


def _res(**over: Any) -> dict[str, Any]:
    e = copy.deepcopy(GOOD_RESOLVER)
    for k, v in over.items():
        if v is _DEL:
            e.pop(k, None)
        else:
            e[k] = v
    return {"resolvers": [e]}


_DEL = object()


def _hints(**over: Any) -> dict[str, Any]:
    d = yaml.safe_load((knowledge.SEEDS_DIR / knowledge.ROOT_HINTS_FILE).read_text())
    for k, v in over.items():
        d[k] = v
    return d


# ---- shipped data -------------------------------------------------------------------------


def test_shipped_resolvers_load_and_are_policy_clean() -> None:
    rs = list_public_resolvers()
    assert {r.id for r in rs} >= {"google", "cloudflare", "quad9", "opendns"}
    for r in rs:
        assert r.addresses
        assert all(_ok(a) for a in r.addresses), r.id
        if r.status == "verified":
            assert r.verified_on and r.sources


def test_shipped_root_hints() -> None:
    h = root_hints()
    assert [s.name for s in h.servers] == [f"{c}.root-servers.net" for c in "abcdefghijklm"]
    assert h.source == "https://www.iana.org/domains/root/files"
    for s in h.servers:
        assert _ok(s.ipv4) and _ok(s.ipv6)


def test_lookup_and_immutability() -> None:
    assert get_resolver("google") is not None
    assert get_resolver("nope") is None
    assert list_public_resolvers() is list_public_resolvers()  # loaded once, cached
    r = list_public_resolvers()[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.id = "z"  # type: ignore[misc]
    assert isinstance(r.addresses, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        root_hints().status = "x"  # type: ignore[misc]


def test_verified_on_not_in_future_and_staleness_warning() -> None:
    today = date.today()
    dates = [r.verified_on for r in list_public_resolvers() if r.verified_on]
    dates.append(root_hints().verified_on)
    assert all(d <= today for d in dates), "verified_on is in the future"
    stale = [d for d in dates if d < today - timedelta(days=365)]
    if stale:  # non-fatal by design (ARCHITECTURE section 8 convention)
        warnings.warn(f"knowledge data verified_on older than 12 months: {stale}", stacklevel=1)


def test_load_from_directory(tmp_path: Path) -> None:
    (tmp_path / "dns_resolvers.yaml").write_text(yaml.safe_dump(_res()))
    got = list_public_resolvers(tmp_path)
    assert got[0].id == "x" and got[0].verified_on == date(2026, 1, 1)


# ---- malformed resolver data ----------------------------------------------------------------

BAD_RESOLVERS: list[tuple[str, Any]] = [
    ("not a mapping", ["a"]),
    ("none", None),
    ("empty list", {"resolvers": []}),
    ("resolvers not list", {"resolvers": "x"}),
    ("extra top key", {**_res(), "other": 1}),
    ("entry not mapping", {"resolvers": ["x"]}),
    ("extra key", _res(color="red")),
    ("missing name", _res(name=_DEL)),
    ("missing id", _res(id=_DEL)),
    ("missing verified_on", _res(verified_on=_DEL)),
    ("missing sources", _res(sources=_DEL)),
    ("empty sources", _res(sources=[])),
    ("http source", _res(sources=["http://example.com"])),
    ("sources wrong type", _res(sources="https://example.com")),
    ("unknown status", _res(status="maybe")),
    ("verified_on string", _res(verified_on="2026-01-01")),
    ("verified_on datetime", _res(verified_on=__import__("datetime").datetime(2026, 1, 1))),
    ("id wrong type", _res(id=5)),
    ("id upper", _res(id="Google")),
    ("id space", _res(id="a b")),
    ("name blank", _res(name=" ")),
    ("empty addresses", _res(addresses=[])),
    ("addresses wrong type", _res(addresses="8.8.8.8")),
    ("hostname", _res(addresses=["dns.google"])),
    ("host:port", _res(addresses=["8.8.8.8:53"])),
    ("non-canonical v6", _res(addresses=["2001:4860:4860:0:0:0:0:8888"])),
    ("address int", _res(addresses=[8888])),
    ("duplicate address", _res(addresses=["8.8.8.8", "8.8.8.8"])),
    ("private address", _res(addresses=["10.0.0.1"])),
    ("loopback", _res(addresses=["127.0.0.1"])),
    ("link-local v6", _res(addresses=["fe80::1"])),
    ("metadata ip", _res(addresses=["169.254.169.254"])),
    ("port 5353", _res(port=5353)),
    ("port string", _res(port="53")),
    ("port bool", _res(port=True)),
    ("notes_key wrong type", _res(notes_key=3)),
]


@pytest.mark.parametrize("data", [d for _, d in BAD_RESOLVERS], ids=[n for n, _ in BAD_RESOLVERS])
def test_bad_resolvers_rejected(data: Any) -> None:
    with pytest.raises(KnowledgeError):
        parse_resolvers(data)


def test_duplicate_ids_rejected() -> None:
    e = _res()["resolvers"][0]
    with pytest.raises(KnowledgeError, match="duplicate"):
        parse_resolvers({"resolvers": [e, copy.deepcopy(e)]})


def test_unverified_may_omit_verification() -> None:
    data = _res(status="unverified", verified_on=_DEL, sources=_DEL, notes_key="k")
    (r,) = parse_resolvers(data)
    assert r.status == "unverified" and r.verified_on is None and r.sources == ()
    assert r.notes_key == "k"


# ---- malformed root hints -------------------------------------------------------------------


def _servers(mut: Any) -> dict[str, Any]:
    d = _hints()
    mut(d["servers"])
    return d


BAD_HINTS: list[tuple[str, Any]] = [
    ("not mapping", []),
    ("missing key", {k: v for k, v in _hints().items() if k != "verified_on"}),
    ("extra key", _hints(extra=1)),
    ("unknown status", _hints(status="x")),
    ("bad version", _hints(root_zone_version="v1")),
    ("version int", _hints(root_zone_version=2026110301)),
    ("date string", _hints(file_last_modified="2026-11-03")),
    ("12 servers", _servers(lambda s: s.pop())),
    ("swapped order", _servers(lambda s: s.reverse())),
    ("wrong name", _servers(lambda s: s[0].update(name="z.root-servers.net"))),
    ("v6 in v4 field", _servers(lambda s: s[0].update(ipv4="2001:503:ba3e::2:30"))),
    ("v4 in v6 field", _servers(lambda s: s[0].update(ipv6="198.41.0.4"))),
    ("hostname", _servers(lambda s: s[0].update(ipv4="a.root-servers.net"))),
    ("private", _servers(lambda s: s[0].update(ipv4="192.168.0.1"))),
    ("server extra key", _servers(lambda s: s[0].update(x=1))),
    ("server missing ipv6", _servers(lambda s: s[0].pop("ipv6"))),
]


@pytest.mark.parametrize("data", [d for _, d in BAD_HINTS], ids=[n for n, _ in BAD_HINTS])
def test_bad_root_hints_rejected(data: Any) -> None:
    with pytest.raises(KnowledgeError):
        parse_root_hints(data)


# ---- malformed files ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [b"resolvers: [unclosed", b"\xff\xfe\x00bad", b"{{{", b"- a\n- b: [", b""],
    ids=["bad-yaml", "bad-utf8", "braces", "bad-seq", "empty"],
)
def test_bad_files_rejected(tmp_path: Path, content: bytes) -> None:
    (tmp_path / "dns_resolvers.yaml").write_bytes(content)
    with pytest.raises(KnowledgeError):
        list_public_resolvers(tmp_path)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(KnowledgeError):
        root_hints(tmp_path)


def _ok(addr: str) -> bool:
    return DEFAULT_POLICY.check(ResolverAddr(addr, 53), trusted=False) is None
