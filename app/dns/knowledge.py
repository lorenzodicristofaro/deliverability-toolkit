"""DNS knowledge data: public resolver list and root hints (loaded from `seeds/`).

Data files carry `verified_on` and `sources` (CLAUDE.md knowledge rules). The loader validates
the schema strictly and rejects any address that fails the untrusted-target egress policy, so
nothing loaded here can point the engine at an internal address. Results are immutable and
loaded once per path (cached); no network access.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from app.core.config import ResolverAddr
from app.dns.egress import DEFAULT_POLICY

SEEDS_DIR = Path(__file__).resolve().parents[2] / "seeds"
RESOLVERS_FILE = "dns_resolvers.yaml"
ROOT_HINTS_FILE = "root_hints.yaml"

_STATUSES = ("verified", "unverified")


class KnowledgeError(ValueError):
    """A knowledge data file is missing, unparsable or violates its schema."""


@dataclass(frozen=True, slots=True)
class PublicResolver:
    id: str
    name: str
    operator: str
    addresses: tuple[str, ...]
    port: int
    verified_on: date | None
    sources: tuple[str, ...]
    status: str
    notes_key: str | None = None


@dataclass(frozen=True, slots=True)
class RootServer:
    name: str
    ipv4: str
    ipv6: str


@dataclass(frozen=True, slots=True)
class RootHints:
    source: str
    file_url: str
    file_last_modified: date
    root_zone_version: str
    verified_on: date
    status: str
    servers: tuple[RootServer, ...]


def _fail(where: str, msg: str) -> KnowledgeError:
    return KnowledgeError(f"{where}: {msg}")


def _check_keys(
    obj: object, where: str, required: set[str], optional: frozenset[str] = frozenset()
) -> Mapping[str, Any]:
    if not isinstance(obj, dict):
        raise _fail(where, "must be a mapping")
    keys = set(obj)
    if not all(isinstance(k, str) for k in keys):
        raise _fail(where, "keys must be strings")
    missing = required - keys
    if missing:
        raise _fail(where, f"missing keys {sorted(missing)}")
    extra = keys - required - optional
    if extra:
        raise _fail(where, f"unknown keys {sorted(extra)}")
    return obj


def _str(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise _fail(where, "must be a non-empty string without surrounding whitespace")
    return value


def _date(value: object, where: str, today: date | None = None) -> date:
    if not (isinstance(value, date) and not hasattr(value, "hour")):
        raise _fail(where, "must be an ISO date (YYYY-MM-DD)")
    if today is not None and value > today:
        raise _fail(where, f"date is in the future: {value}")
    return value


def _status(value: object, where: str) -> str:
    if value not in _STATUSES:
        raise _fail(where, f"must be one of {_STATUSES}")
    assert isinstance(value, str)
    return value


def _https(value: object, where: str) -> str:
    url = _str(value, where)
    if not url.startswith("https://"):
        raise _fail(where, f"must be an https URL: {url!r}")
    return url


def _url_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise _fail(where, "must be a list")
    urls = tuple(_str(v, where) for v in value)
    for u in urls:
        if not u.startswith("https://"):
            raise _fail(where, f"source must be an https URL: {u!r}")
    return urls


def _ip(value: object, version: int | None, where: str) -> str:
    text = _str(value, where)
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise _fail(where, f"not an IP address literal: {text!r}") from None
    if version is not None and ip.version != version:
        raise _fail(where, f"expected an IPv{version} address: {text!r}")
    if str(ip) != text:
        raise _fail(where, f"address must be in canonical form {str(ip)!r}: {text!r}")
    if DEFAULT_POLICY.check(ResolverAddr(text, 53), trusted=False) is not None:
        raise _fail(where, f"address rejected by the egress policy: {text!r}")
    return text


def _load_yaml(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise KnowledgeError(f"{path.name}: cannot read/parse: {exc}") from exc


def parse_resolvers(data: object, today: date | None = None) -> tuple[PublicResolver, ...]:
    today = today or date.today()
    seen_addrs: set[str] = set()
    root = _check_keys(data, "resolvers file", {"resolvers"})
    items = root["resolvers"]
    if not isinstance(items, list) or not items:
        raise _fail("resolvers", "must be a non-empty list")
    out: list[PublicResolver] = []
    seen: set[str] = set()
    for i, raw in enumerate(items):
        w = f"resolvers[{i}]"
        e = _check_keys(
            raw,
            w,
            {"id", "name", "operator", "addresses", "port", "status"},
            frozenset({"verified_on", "sources", "notes_key"}),
        )
        rid = _str(e["id"], f"{w}.id")
        if not rid.replace("-", "").isalnum() or rid != rid.lower() or rid.startswith("-"):
            raise _fail(f"{w}.id", f"must be a lowercase slug: {rid!r}")
        if rid in seen:
            raise _fail(f"{w}.id", f"duplicate id {rid!r}")
        seen.add(rid)
        status = _status(e["status"], f"{w}.status")
        port = e["port"]
        if type(port) is not int or port != 53:
            raise _fail(f"{w}.port", "must be 53")
        addrs = e["addresses"]
        if not isinstance(addrs, list) or not addrs:
            raise _fail(f"{w}.addresses", "must be a non-empty list")
        addresses = tuple(_ip(a, None, f"{w}.addresses") for a in addrs)
        if len(set(addresses)) != len(addresses):
            raise _fail(f"{w}.addresses", "duplicate address")
        for a in addresses:
            if a in seen_addrs:
                raise _fail(f"{w}.addresses", f"address already used by another resolver: {a}")
            seen_addrs.add(a)
        verified_on = (
            _date(e["verified_on"], f"{w}.verified_on", today) if "verified_on" in e else None
        )
        sources = _url_list(e["sources"], f"{w}.sources") if "sources" in e else ()
        if status == "verified" and (verified_on is None or not sources):
            raise _fail(w, "verified entries need verified_on and a non-empty sources list")
        notes = e.get("notes_key")
        out.append(
            PublicResolver(
                id=rid,
                name=_str(e["name"], f"{w}.name"),
                operator=_str(e["operator"], f"{w}.operator"),
                addresses=addresses,
                port=53,
                verified_on=verified_on,
                sources=sources,
                status=status,
                notes_key=_str(notes, f"{w}.notes_key") if notes is not None else None,
            )
        )
    return tuple(out)


def parse_root_hints(data: object, today: date | None = None) -> RootHints:
    today = today or date.today()
    seen_addrs: set[str] = set()
    w = "root hints"
    d = _check_keys(
        data,
        w,
        {
            "source",
            "file_url",
            "file_last_modified",
            "root_zone_version",
            "verified_on",
            "status",
            "servers",
        },
    )
    servers_raw = d["servers"]
    if not isinstance(servers_raw, list) or len(servers_raw) != 13:
        raise _fail("servers", "must be a list of exactly 13 root servers")
    servers: list[RootServer] = []
    for i, letter in enumerate("abcdefghijklm"):
        sw = f"servers[{i}]"
        s = _check_keys(servers_raw[i], sw, {"name", "ipv4", "ipv6"})
        name = _str(s["name"], f"{sw}.name")
        if name != f"{letter}.root-servers.net":
            raise _fail(f"{sw}.name", f"expected {letter}.root-servers.net, got {name!r}")
        v4, v6 = _ip(s["ipv4"], 4, f"{sw}.ipv4"), _ip(s["ipv6"], 6, f"{sw}.ipv6")
        for a in (v4, v6):
            if a in seen_addrs:
                raise _fail(sw, f"duplicate address {a}")
            seen_addrs.add(a)
        servers.append(RootServer(name, v4, v6))
    version = d["root_zone_version"]
    if not isinstance(version, str) or not version.isdigit():
        raise _fail("root_zone_version", "must be a digit string")
    return RootHints(
        source=_https(d["source"], "source"),
        file_url=_https(d["file_url"], "file_url"),
        file_last_modified=_date(d["file_last_modified"], "file_last_modified", today),
        root_zone_version=version,
        verified_on=_date(d["verified_on"], "verified_on", today),
        status=_status(d["status"], "status"),
        servers=tuple(servers),
    )


@cache
def _resolvers(seeds_dir: Path) -> tuple[PublicResolver, ...]:
    return parse_resolvers(_load_yaml(seeds_dir / RESOLVERS_FILE))


@cache
def _root_hints(seeds_dir: Path) -> RootHints:
    return parse_root_hints(_load_yaml(seeds_dir / ROOT_HINTS_FILE))


def list_public_resolvers(seeds_dir: Path = SEEDS_DIR) -> tuple[PublicResolver, ...]:
    return _resolvers(seeds_dir)


def get_resolver(resolver_id: str, seeds_dir: Path = SEEDS_DIR) -> PublicResolver | None:
    for r in _resolvers(seeds_dir):
        if r.id == resolver_id:
            return r
    return None


def root_hints(seeds_dir: Path = SEEDS_DIR) -> RootHints:
    return _root_hints(seeds_dir)
