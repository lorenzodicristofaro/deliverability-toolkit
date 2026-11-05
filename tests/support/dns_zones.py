"""Recorded-zone fixtures and an in-memory fake resolver (no sockets, no real sleeping).

Format: see docs/DNS_FIXTURES.md. Fixtures are hand-written; they never come from the live network.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.dns.types import (
    DnsQuestion,
    DnsRecord,
    DnsResult,
    ResultState,
    join_txt_strings,
)

DEFAULT_SERVER = "default"

# States an explicit failure entry may declare ("ok" is expressed with records instead).
_FAILURE_STATES = frozenset(
    {
        ResultState.servfail,
        ResultState.refused,
        ResultState.timeout,
        ResultState.nxdomain,
        ResultState.nodata,
        ResultState.truncated,
        ResultState.malformed,
        ResultState.network_error,
    }
)

RESERVED_SUFFIXES = (
    "example.com",
    "example.net",
    "example.org",
    "test",
    "invalid",
    "example",
    "localhost",
)
_RESERVED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
        "10.0.0.0/8",  # private: only for the private-referral fixture
        "127.0.0.0/8",
    )
)
_ROOT_AND_TLDS = frozenset({".", "com", "net", "org"})


class ZoneFixtureError(ValueError):
    """A fixture is malformed. The message names the source and the entry."""


@dataclass(frozen=True, slots=True)
class NsAddr:
    name: str
    addr: str


@dataclass(frozen=True, slots=True)
class Referral:
    zone: str
    ns: tuple[NsAddr, ...]


@dataclass(frozen=True, slots=True)
class ServerReply:
    """Answer of query_server: the result plus a referral when the server delegates the name."""

    result: DnsResult
    referral: Referral | None = None


@dataclass(frozen=True, slots=True)
class _Entry:
    records: tuple[DnsRecord, ...] = ()
    state: ResultState | None = None
    rcode: int | None = None
    ad: bool = False


@dataclass(slots=True)
class ZoneData:
    entries: dict[tuple[str, str], _Entry] = field(default_factory=dict)
    referrals: list[Referral] = field(default_factory=list)

    def names(self) -> set[str]:
        return {n for n, _ in self.entries}


def is_reserved_name(name: str) -> bool:
    if name in _ROOT_AND_TLDS:
        return True
    return any(name == s or name.endswith("." + s) for s in RESERVED_SUFFIXES)


def is_reserved_addr(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _RESERVED_NETWORKS if net.version == ip.version)


def _fail(source: str, where: str, msg: str) -> ZoneFixtureError:
    return ZoneFixtureError(f"{source}: {where}: {msg}")


def _parse_rdata(source: str, where: str, rdtype: str, raw: Any) -> str:
    if isinstance(raw, list) and rdtype == "TXT" and raw and all(isinstance(s, str) for s in raw):
        return join_txt_strings(s.encode("latin-1") for s in raw)
    if not isinstance(raw, str):
        raise _fail(source, where, f"rdata item must be a string, got {type(raw).__name__}")
    return raw


def _parse_ttl(source: str, where: str, raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise _fail(source, where, f"ttl must be a non-negative integer, got {raw!r}")
    return raw


def _parse_referral(source: str, where: str, raw: Any) -> Referral:
    if not isinstance(raw, dict) or not isinstance(raw.get("zone"), str):
        raise _fail(source, where, "referral needs a string `zone`")
    ns_raw = raw.get("ns")
    if not isinstance(ns_raw, list) or not ns_raw:
        raise _fail(source, where, "referral needs a non-empty `ns` list")
    ns: list[NsAddr] = []
    for item in ns_raw:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("addr"), str)
        ):
            raise _fail(source, where, "referral ns items need string `name` and `addr`")
        try:
            ipaddress.ip_address(item["addr"])
        except ValueError:
            raise _fail(source, where, f"referral addr {item['addr']!r} is not an IP") from None
        ns.append(NsAddr(item["name"], item["addr"]))
    return Referral(raw["zone"], tuple(ns))


def _parse_entry(source: str, where: str, raw: Any, zone: ZoneData) -> None:
    if not isinstance(raw, dict):
        raise _fail(source, where, "entry must be a mapping")
    if "referral" in raw:
        zone.referrals.append(_parse_referral(source, where, raw["referral"]))
        return
    for key in ("name", "type"):
        if not isinstance(raw.get(key), str):
            raise _fail(source, where, f"missing or non-string key `{key}`")
    ad = raw.get("ad", False)
    if not isinstance(ad, bool):
        raise _fail(source, where, "`ad` must be a boolean")
    try:
        question = DnsQuestion(raw["name"], raw["type"])
    except ValueError as exc:
        raise _fail(source, where, str(exc)) from None
    key = (question.name, question.rdtype)
    if key in zone.entries:
        raise _fail(source, where, f"duplicate entry for {question.name} {question.rdtype}")
    has_state, has_rdata = "state" in raw, "rdata" in raw
    if has_state == has_rdata:
        raise _fail(source, where, "entry needs exactly one of `rdata` or `state`")
    if has_state:
        try:
            state = ResultState(raw["state"])
        except ValueError:
            raise _fail(source, where, f"unknown state {raw['state']!r}") from None
        if state not in _FAILURE_STATES:
            raise _fail(source, where, f"state {state.value!r} not allowed in a failure entry")
        rcode = raw.get("rcode")
        if rcode is not None and (
            isinstance(rcode, bool) or not isinstance(rcode, int) or not 0 <= rcode <= 15
        ):
            raise _fail(source, where, f"rcode must be an integer 0..15, got {rcode!r}")
        zone.entries[key] = _Entry(state=state, rcode=rcode, ad=ad)
        return
    ttl = _parse_ttl(source, where, raw.get("ttl"))
    rdata = raw["rdata"]
    if not isinstance(rdata, list) or not rdata:
        raise _fail(source, where, "`rdata` must be a non-empty list")
    records: list[DnsRecord] = []
    for item in rdata:
        text = _parse_rdata(source, where, question.rdtype, item)
        if question.rdtype in ("A", "AAAA"):
            try:
                ipaddress.ip_address(text)
            except ValueError:
                raise _fail(source, where, f"invalid address {text!r}") from None
        records.append(DnsRecord(question.name, question.rdtype, ttl, text))
    zone.entries[key] = _Entry(records=tuple(records), ad=ad)


def parse_zones(data: Any, source: str = "<memory>") -> FakeServerSet:
    """Validate a decoded fixture and build a FakeServerSet. Raises ZoneFixtureError."""
    if not isinstance(data, dict) or not isinstance(data.get("zones"), dict) or not data["zones"]:
        raise _fail(source, "top level", "expected a non-empty mapping under `zones`")
    zones: dict[str, ZoneData] = {}
    for server, entries in data["zones"].items():
        if not isinstance(server, str):
            raise _fail(source, "zones", f"server id must be a string, got {server!r}")
        if server != DEFAULT_SERVER:
            try:
                ipaddress.ip_address(server)
            except ValueError:
                raise _fail(source, server, "server id must be `default` or an IP") from None
        if not isinstance(entries, list):
            raise _fail(source, server, "server value must be a list of entries")
        zone = ZoneData()
        for i, raw in enumerate(entries):
            _parse_entry(source, f"{server}[{i}]", raw, zone)
        zones[server] = zone
    return FakeServerSet({s: FakeResolver(z, server=s) for s, z in zones.items()})


def load_zones(path: str | Path) -> FakeServerSet:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ZoneFixtureError(f"{path}: invalid YAML: {exc}") from None
    return parse_zones(data, str(path))


class FakeResolver:
    """Implements the M2-02 Resolver protocol over a ZoneData. Never touches the network.

    Lookup: explicit entry for (name, type) wins; otherwise a name delegated by a referral entry
    (and without own data) yields a referral; otherwise `nodata` if the name has records of any
    type or is an empty non-terminal (a name with descendants that have records), else `nxdomain`.
    """

    def __init__(
        self, zones: ZoneData, server: str = DEFAULT_SERVER, latency_ms: float = 0.0
    ) -> None:
        self.zones = zones
        self.server = server
        self.identity = f"fake:{server}"
        self.latency_ms = latency_ms
        self.questions: list[DnsQuestion] = []
        self.virtual_elapsed_ms = 0.0  # virtual clock: advanced per query, never slept

    def _exists(self, name: str) -> bool:
        return any(n == name or n.endswith("." + name) for n in self.zones.names())

    def _referral_for(self, name: str) -> Referral | None:
        best: Referral | None = None
        for ref in self.zones.referrals:
            if (name == ref.zone or name.endswith("." + ref.zone) or ref.zone == ".") and (
                best is None or len(ref.zone) > len(best.zone)
            ):
                best = ref
        return best

    def _result(self, q: DnsQuestion, state: ResultState, **kw: Any) -> DnsResult:
        return DnsResult(
            question=q,
            state=state,
            server=self.identity,
            elapsed_ms=self.latency_ms,
            **kw,
        )

    def lookup(self, q: DnsQuestion) -> ServerReply:
        self.questions.append(q)
        self.virtual_elapsed_ms += self.latency_ms
        entry = self.zones.entries.get((q.name, q.rdtype))
        if entry is not None:
            if entry.state is not None:
                return ServerReply(
                    self._result(q, entry.state, rcode=entry.rcode, authenticated_data=entry.ad)
                )
            return ServerReply(
                self._result(
                    q,
                    ResultState.ok,
                    records=entry.records,
                    ttl_min=min(r.ttl for r in entry.records),
                    authenticated_data=entry.ad,
                    rcode=0,
                )
            )
        if q.name not in self.zones.names():
            ref = self._referral_for(q.name)
            if ref is not None:
                return ServerReply(self._result(q, ResultState.nodata, rcode=0), ref)
        if self._exists(q.name):
            return ServerReply(self._result(q, ResultState.nodata, rcode=0))
        return ServerReply(self._result(q, ResultState.nxdomain, rcode=3))

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        return self.lookup(question).result


class FakeServerSet:
    """Maps server id (`default` or an IP) to a FakeResolver."""

    def __init__(self, servers: Mapping[str, FakeResolver]) -> None:
        self.servers = dict(servers)

    def resolver(self, server: str = DEFAULT_SERVER) -> FakeResolver:
        return self.servers[server]

    async def query_server(self, addr: str, question: DnsQuestion) -> ServerReply:
        """Minimal shape of the M2-05 primitive (to be agreed by the GM): ask one server directly.
        An address with no fixture is unreachable (`network_error`)."""
        server = self.servers.get(addr)
        if server is None:
            return ServerReply(
                DnsResult(question=question, state=ResultState.network_error, server=addr)
            )
        return server.lookup(question)

    @property
    def all_questions(self) -> list[DnsQuestion]:
        return [q for s in self.servers.values() for q in s.questions]
