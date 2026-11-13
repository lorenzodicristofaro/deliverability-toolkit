"""DNSBL/URIBL list definitions (M7-03): strict schema for `seeds/dnsbl.yaml` (seeded in M7-04).

Follows the `app.esp.profile` pattern: the hand-written strict validator below IS the schema
(unknown keys rejected everywhere), duplicate keys, anchors/aliases and merge keys are rejected,
the file is capped at MAX_FILE_BYTES, results are immutable and the load is all-or-nothing.
Nothing about any real list (zone, return codes, policy) lives in code: it is all data.

    lists:
      - id: example-ip                    # slug [a-z0-9][a-z0-9-]{0,39}, unique
        name: Example IP list
        zone: bl.example.com              # LDH host name, unique across lists
        kind: ip                          # ip | domain
        ipv4: true                        # ip lists only (both keys required; one must be true)
        ipv6: false
        return_codes:                     # at least one `listed` code
          - {code: 127.0.0.2, meaning: listed, category: spam_source}
          - {code: 127.0.0.10, meaning: info, category: policy}   # category optional for info
          - {code: 127.255.255.254, meaning: refused}             # no category
        refused_networks: [127.255.255.0/24]  # optional: the list's "query refused" convention
        return_code_mode: exact           # optional: exact (default) | bitmask
        nodata_is_clean: false            # optional, default false (NODATA is then `error`)
        default_enabled: true             # optional, default true (applied by M7-05, not here)
        usage_policy: free text           # optional, never invented numbers
        verified_on: 2026-11-01           # mandatory, never in the future
        sources: [https://docs.example.com/bl]  # mandatory, non-empty, https
        status: verified                  # verified | unverified
        unverified_fields: [return_codes] # required (non-empty) iff status is unverified

Decisions:
- Return codes and refused networks are IPv4 inside 127.0.0.0/8 (the DNSBL answer range).
  A `listed`/`info` code may not fall inside a declared refused network.
- `unverified_fields` names what the maintainer could not confirm; allowed paths are the
  optional/data keys plus `return_codes.<code>`, each naming something present. The engine
  treats an unverified list as a whole as unable to produce `listed` (M7-03 criteria).
- `return_code_mode: bitmask` (M7-03b): the list documents its answers as bit sums in the last
  octet of 127.0.0.x. Every `listed`/`info` code must then be a single bit (127.0.0.1, .2, .4,
  ... .128); refused codes are still matched exactly. The engine decomposes the answer.
- `default_enabled` is exposed for M7-05 (lists with restrictive usage policies ship disabled);
  neither the loader nor the engine acts on it.
- Zone length is capped so the longest query name (32 IPv6 nibbles or a 253-char domain is
  checked at query time) can still fit: IPv6 lists need a zone of at most 189 characters.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal

import yaml  # type: ignore[import-untyped]

from app.dns.knowledge import SEEDS_DIR, KnowledgeError, _check_keys, _date, _fail, _status, _str
from app.esp.profile import _bool, _choice, _https_url, _list, _StrictLoader, _text

DNSBL_FILE: Final = SEEDS_DIR / "dnsbl.yaml"

MAX_FILE_BYTES: Final = 128 * 1024
MAX_LISTS: Final = 100
MAX_RETURN_CODES: Final = 64
MAX_REFUSED_NETWORKS: Final = 8
MAX_SOURCES: Final = 10
MAX_UNVERIFIED_FIELDS: Final = 80
MAX_NAME_LENGTH: Final = 100
MAX_POLICY_LENGTH: Final = 2000
MAX_CATEGORY_LENGTH: Final = 40
MAX_ZONE_LENGTH: Final = 253
MAX_LABEL_LENGTH: Final = 63
IPV6_QUERY_PREFIX_LENGTH: Final = 64  # 32 nibbles + 32 dots
IPV4_QUERY_PREFIX_LENGTH: Final = 16  # "255.255.255.255."

KINDS: Final = ("ip", "domain")
MEANINGS: Final = ("listed", "refused", "info")
RETURN_CODE_MODES: Final = ("exact", "bitmask")
BITMASK_NETWORK: Final = ipaddress.IPv4Network("127.0.0.0/24")
ANSWER_NETWORK: Final = ipaddress.IPv4Network("127.0.0.0/8")

Kind = Literal["ip", "domain"]
Meaning = Literal["listed", "refused", "info"]
ReturnCodeMode = Literal["exact", "bitmask"]

_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_LABEL: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_CATEGORY: Final = re.compile(r"[a-z][a-z0-9_]*")

_LIST_REQUIRED: Final = {
    "id",
    "name",
    "zone",
    "kind",
    "return_codes",
    "verified_on",
    "sources",
    "status",
}
_LIST_OPTIONAL: Final = frozenset(
    {
        "ipv4",
        "ipv6",
        "refused_networks",
        "nodata_is_clean",
        "usage_policy",
        "unverified_fields",
        "return_code_mode",
        "default_enabled",
    }
)


class DnsblSchemaError(KnowledgeError):
    """The DNSBL list file is missing, unparsable or violates the schema."""


@dataclass(frozen=True, slots=True)
class ReturnCode:
    code: ipaddress.IPv4Address
    meaning: Meaning
    category: str | None = None


@dataclass(frozen=True, slots=True)
class DnsblList:
    id: str
    name: str
    zone: str
    kind: Kind
    ipv4: bool
    ipv6: bool
    return_codes: Mapping[ipaddress.IPv4Address, ReturnCode]
    refused_networks: tuple[ipaddress.IPv4Network, ...]
    nodata_is_clean: bool
    usage_policy: str | None
    verified_on: date
    sources: tuple[str, ...]
    status: str
    unverified_fields: frozenset[str]
    return_code_mode: ReturnCodeMode = "exact"
    default_enabled: bool = True

    @property
    def verified(self) -> bool:
        return self.status == "verified"


def _zone(value: object, where: str) -> str:
    zone = _text(value, where, MAX_ZONE_LENGTH)
    labels = zone.split(".")
    if len(labels) < 2:
        raise _fail(where, f"must have at least two labels: {zone!r}")
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH or not _LABEL.fullmatch(label):
            raise _fail(where, f"invalid label in {zone!r} (lowercase LDH only)")
    if labels[-1].isdigit():
        raise _fail(where, f"last label must not be numeric: {zone!r}")
    return zone


def _answer_ip(value: object, where: str) -> ipaddress.IPv4Address:
    text = _str(value, where)
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        raise _fail(where, f"not an IPv4 address: {text!r}") from None
    if ip not in ANSWER_NETWORK or str(ip) != text:
        raise _fail(where, f"must be a canonical address in {ANSWER_NETWORK}: {text!r}")
    return ip


def _networks(value: object, where: str) -> tuple[ipaddress.IPv4Network, ...]:
    out: list[ipaddress.IPv4Network] = []
    for i, raw in enumerate(_list(value, where, MAX_REFUSED_NETWORKS, non_empty=True)):
        text = _str(raw, f"{where}[{i}]")
        try:
            net = ipaddress.IPv4Network(text)  # strict: host bits must be zero
        except ValueError:
            raise _fail(f"{where}[{i}]", f"not an IPv4 network: {text!r}") from None
        if not net.subnet_of(ANSWER_NETWORK) or str(net) != text:
            raise _fail(f"{where}[{i}]", f"must be a canonical network in {ANSWER_NETWORK}")
        if net in out:
            raise _fail(f"{where}[{i}]", f"duplicate network {text!r}")
        out.append(net)
    return tuple(out)


def _return_codes(
    value: object, where: str, refused: tuple[ipaddress.IPv4Network, ...]
) -> dict[ipaddress.IPv4Address, ReturnCode]:
    out: dict[ipaddress.IPv4Address, ReturnCode] = {}
    for i, raw in enumerate(_list(value, where, MAX_RETURN_CODES, non_empty=True)):
        w = f"{where}[{i}]"
        e = _check_keys(raw, w, {"code", "meaning"}, frozenset({"category"}))
        code = _answer_ip(e["code"], f"{w}.code")
        if code in out:
            raise _fail(f"{w}.code", f"duplicate code {code}")
        meaning: Meaning = _choice(e["meaning"], f"{w}.meaning", MEANINGS)  # type: ignore[assignment]
        category = None
        if "category" in e:
            if meaning == "refused":
                raise _fail(f"{w}.category", "a refused code has no category")
            category = _text(e["category"], f"{w}.category", MAX_CATEGORY_LENGTH)
            if not _CATEGORY.fullmatch(category):
                raise _fail(f"{w}.category", f"must be a lowercase snake slug: {category!r}")
        elif meaning == "listed":
            raise _fail(w, "a listed code needs a category")
        if meaning != "refused" and any(code in net for net in refused):
            raise _fail(f"{w}.code", f"{meaning} code {code} lies in a refused network")
        out[code] = ReturnCode(code=code, meaning=meaning, category=category)
    if not any(rc.meaning == "listed" for rc in out.values()):
        raise _fail(where, "needs at least one listed code")
    return out


def is_single_bit(code: ipaddress.IPv4Address) -> bool:
    """True for 127.0.0.1, .2, .4, ... .128: one bit set in the last octet of 127.0.0.x."""
    last = int(code) & 0xFF
    return code in BITMASK_NETWORK and last != 0 and last & (last - 1) == 0


def _check_bitmask(codes: Mapping[ipaddress.IPv4Address, ReturnCode], where: str) -> None:
    for rc in codes.values():
        if rc.meaning != "refused" and not is_single_bit(rc.code):
            raise _fail(
                where, f"{rc.meaning} code {rc.code} is not a single bit of 127.0.0.x (bitmask)"
            )


def _sources(value: object, where: str) -> tuple[str, ...]:
    urls = tuple(
        _https_url(u, f"{where}[{i}]")
        for i, u in enumerate(_list(value, where, MAX_SOURCES, non_empty=True))
    )
    if len(set(urls)) != len(urls):
        raise _fail(where, "duplicate source")
    return urls


def _unverified(value: object, where: str, present: set[str]) -> frozenset[str]:
    out: set[str] = set()
    for i, raw in enumerate(_list(value, where, MAX_UNVERIFIED_FIELDS, non_empty=True)):
        field = _text(raw, f"{where}[{i}]", 64)
        if field not in present:
            raise _fail(f"{where}[{i}]", f"names no field present in this list: {field!r}")
        if field in out:
            raise _fail(f"{where}[{i}]", f"duplicate entry {field!r}")
        out.add(field)
    return frozenset(out)


def _parse_list(data: object, where: str, today: date) -> DnsblList:
    d = _check_keys(data, where, _LIST_REQUIRED, _LIST_OPTIONAL)
    lid = _str(d["id"], f"{where}.id")
    if not _ID.fullmatch(lid):
        raise _fail(f"{where}.id", f"must match [a-z0-9][a-z0-9-]{{0,39}}: {lid!r}")
    where = f"list {lid!r}"
    zone = _zone(d["zone"], f"{where}.zone")
    kind: Kind = _choice(d["kind"], f"{where}.kind", KINDS)  # type: ignore[assignment]
    ipv4 = ipv6 = False
    if kind == "ip":
        if "ipv4" not in d or "ipv6" not in d:
            raise _fail(where, "an ip list needs both ipv4 and ipv6 flags")
        ipv4 = _bool(d["ipv4"], f"{where}.ipv4")
        ipv6 = _bool(d["ipv6"], f"{where}.ipv6")
        if not (ipv4 or ipv6):
            raise _fail(where, "an ip list must support ipv4 or ipv6")
        prefix = IPV6_QUERY_PREFIX_LENGTH if ipv6 else IPV4_QUERY_PREFIX_LENGTH
        if len(zone) + prefix > MAX_ZONE_LENGTH:
            raise _fail(f"{where}.zone", "too long for the query names of this list")
    elif "ipv4" in d or "ipv6" in d:
        raise _fail(where, "ipv4/ipv6 flags are only allowed on ip lists")
    refused = (
        _networks(d["refused_networks"], f"{where}.refused_networks")
        if ("refused_networks" in d)
        else ()
    )
    codes = _return_codes(d["return_codes"], f"{where}.return_codes", refused)
    mode: ReturnCodeMode = (
        _choice(d["return_code_mode"], f"{where}.return_code_mode", RETURN_CODE_MODES)  # type: ignore[assignment]
        if "return_code_mode" in d
        else "exact"
    )
    if mode == "bitmask":
        _check_bitmask(codes, f"{where}.return_codes")
    enabled = (
        _bool(d["default_enabled"], f"{where}.default_enabled") if "default_enabled" in d else True
    )
    nodata_clean = (
        _bool(d["nodata_is_clean"], f"{where}.nodata_is_clean") if "nodata_is_clean" in d else False
    )
    policy = (
        _text(d["usage_policy"], f"{where}.usage_policy", MAX_POLICY_LENGTH)
        if ("usage_policy" in d)
        else None
    )
    status = _status(d["status"], f"{where}.status")

    present = {"zone", "kind", "return_codes"} | {f"return_codes.{c}" for c in codes}
    present.update(
        k
        for k in ("ipv4", "ipv6", "refused_networks", "nodata_is_clean", "return_code_mode")
        if k in d
    )
    if policy is not None:
        present.add("usage_policy")
    unverified: frozenset[str] = frozenset()
    if "unverified_fields" in d:
        if status != "unverified":
            raise _fail(f"{where}.unverified_fields", "only allowed with status: unverified")
        unverified = _unverified(d["unverified_fields"], f"{where}.unverified_fields", present)
    elif status == "unverified":
        raise _fail(f"{where}.unverified_fields", "status: unverified needs the unverified fields")

    return DnsblList(
        id=lid,
        name=_text(d["name"], f"{where}.name", MAX_NAME_LENGTH),
        zone=zone,
        kind=kind,
        ipv4=ipv4,
        ipv6=ipv6,
        return_codes=MappingProxyType(codes),
        refused_networks=refused,
        nodata_is_clean=nodata_clean,
        usage_policy=policy,
        verified_on=_date(d["verified_on"], f"{where}.verified_on", today),
        sources=_sources(d["sources"], f"{where}.sources"),
        status=status,
        unverified_fields=unverified,
        return_code_mode=mode,
        default_enabled=enabled,
    )


def parse_dnsbl_lists(data: object, today: date | None = None) -> tuple[DnsblList, ...]:
    """Validate one decoded DNSBL document (all-or-nothing)."""
    try:
        top = _check_keys(data, "dnsbl", {"lists"})
        raw_lists = _list(top["lists"], "lists", MAX_LISTS)
        lists = tuple(
            _parse_list(raw, f"lists[{i}]", today or date.today())
            for i, raw in enumerate(raw_lists)
        )
    except DnsblSchemaError:
        raise
    except KnowledgeError as exc:
        raise DnsblSchemaError(str(exc)) from None
    ids: set[str] = set()
    zones: set[str] = set()
    for lst in lists:
        if lst.id in ids:
            raise DnsblSchemaError(f"duplicate list id {lst.id!r}")
        if lst.zone in zones:
            raise DnsblSchemaError(f"duplicate zone {lst.zone!r}")
        ids.add(lst.id)
        zones.add(lst.zone)
    return lists


def _load_yaml(path: Path) -> Any:
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise DnsblSchemaError(f"{path.name}: cannot read: {exc}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise DnsblSchemaError(f"{path.name}: file larger than {MAX_FILE_BYTES} bytes")
    try:
        return yaml.load(raw.decode("utf-8"), Loader=_StrictLoader)  # noqa: S506 - SafeLoader
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DnsblSchemaError(f"{path.name}: cannot parse: {exc}") from exc
    except RecursionError:
        raise DnsblSchemaError(f"{path.name}: cannot parse: nesting too deep") from None


def read_dnsbl_lists(path: Path, today: date | None = None) -> tuple[DnsblList, ...]:
    """Load and validate `path` (uncached)."""
    if path.is_symlink() or not path.is_file():
        raise DnsblSchemaError(f"{path.name}: not a regular file")
    data = _load_yaml(path)
    try:
        return parse_dnsbl_lists(data, today)
    except DnsblSchemaError as exc:
        raise DnsblSchemaError(f"{path.name}: {exc}") from None


@cache
def _cached(path: Path) -> tuple[DnsblList, ...]:
    return read_dnsbl_lists(path)


def load_dnsbl_lists(path: Path = DNSBL_FILE) -> tuple[DnsblList, ...]:
    """The validated lists in `path`, loaded once per path."""
    return _cached(path)
