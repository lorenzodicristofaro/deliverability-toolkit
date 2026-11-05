"""dnspython-backed resolver (M2-05): one class for system / custom / Unbound / untrusted targets.

dnspython builds and parses the DNS messages; the packets go through an injected ``Transport``
(production: ``asyncio_transport``, stdlib asyncio sockets). The transport returns raw wire bytes,
so the size cap is enforced BEFORE parsing and tests can feed arbitrary bytes without sockets.

Egress: every packet passes ``TargetPolicy.check`` (app/dns/egress.py) right before it is sent.
Trusted = the nameservers the resolver was built with from operator configuration
(RESOLVER_ADDRS, or resolv.conf in ``system`` mode); everything else (``build_resolver_for_target``,
``query_server`` to an address that is not a configured nameserver) is untrusted. A rejected
target yields ``ResultState.blocked``; no packet is sent.

Mapping (never raises for network/DNS conditions):

- NOERROR + records for the question (after the server-side CNAME chain) -> ok
- NOERROR without them (incl. a CNAME chain ending nowhere)            -> nodata
- NXDOMAIN -> nxdomain; SERVFAIL -> servfail; REFUSED -> refused
- any other rcode (FORMERR, NOTIMP, YXDOMAIN, BADVERS, ...)            -> error (with ``rcode``)
- timeout / total deadline exhausted                                    -> timeout
- OSError / EOF / connection closed                                     -> network_error
- TC still set (or unparseable because truncated) after TCP fallback    -> truncated
- oversized, unparseable, ID/question mismatch, unexpected source,
  too many records, CNAME loop, out-of-bailiwick referral               -> malformed
- any other exception                                                   -> error

SERVFAIL, REFUSED, timeout and truncation are never mapped to nxdomain/nodata.

Referrals: ``query_server`` (non-recursive, for trace) returns ``ServerReply(result, referral)``.
Callers MUST check ``reply.referral`` BEFORE ``reply.result.state``: a referral reply carries the
placeholder state ``nodata`` and is never "missing". ``resolve`` is for recursive servers only; a
referral there is a lame server and yields ``error`` (detail ``unexpected_referral``).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any, Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.txtbase
import dns.rrset

from app.core.config import ResolverAddr
from app.dns.egress import DEFAULT_POLICY, BlockReason, TargetPolicy, parse_target
from app.dns.types import (
    DnsQuestion,
    DnsRecord,
    DnsResult,
    ResultState,
    join_txt_strings,
)

logger = logging.getLogger(__name__)

# Defaults (proposed in M2-05; recorded in the ticket outcome).
QUERY_TIMEOUT_S = 2.0  # one attempt (semaphore wait + send + receive, incl. TCP fallback)
TOTAL_DEADLINE_S = 5.0  # whole resolve()/query_server() call, all attempts
MAX_ATTEMPTS = 3  # first try + 2 retries, round-robin over nameservers; timeout/network only
EDNS_PAYLOAD = 1232  # advertised UDP buffer size (DNS Flag Day 2020 recommendation)
MAX_RESPONSE_BYTES = 16384  # larger responses are rejected as malformed
MAX_RECORDS_PER_SECTION = 100  # answer/authority/additional each
MAX_CNAME_CHAIN = 16  # links followed inside one response (server-side chain only)
MAX_IN_FLIGHT_PER_SERVER = 1  # concurrent queries per nameserver

RETRYABLE_STATES = frozenset({ResultState.timeout, ResultState.network_error})

# Rdata types whose presentation form contains domain names (rendered relative to the root, so
# without the trailing dot, matching the fixture convention; the root name itself stays ".").
_NAME_RDTYPES = frozenset({"MX", "NS", "CNAME", "PTR", "SRV", "SOA", "NAPTR"})


@dataclass(frozen=True, slots=True)
class NsAddr:
    name: str
    addr: str


@dataclass(frozen=True, slots=True)
class Referral:
    """Delegation returned by a non-recursive server. ``ns`` holds in-bailiwick glue (UNTRUSTED
    addresses: callers pass them back through ``query_server``, which policy-checks them);
    ``ns_names`` lists every delegated nameserver name, including glueless ones."""

    zone: str
    ns: tuple[NsAddr, ...]
    ns_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ServerReply:
    """Answer of ``query_server``. Check ``referral`` BEFORE ``result.state``."""

    result: DnsResult
    referral: Referral | None = None


@dataclass(frozen=True, slots=True)
class WireReply:
    """Raw response bytes and, when the transport knows it, the source address."""

    data: bytes
    source: ResolverAddr | None = None


class Transport(Protocol):
    """Sends one query and returns the first response. Raises on network errors. Timeouts are
    applied by the caller (``asyncio.timeout``)."""

    async def __call__(self, wire: bytes, target: ResolverAddr, *, tcp: bool) -> WireReply: ...


class ResponseTooLarge(Exception):
    """The response is larger than MAX_RESPONSE_BYTES."""


class _Blocked(Exception):
    def __init__(self, reason: BlockReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class _Bad(Exception):
    """A response that maps to a non-ok state (raised from the parsing helpers)."""

    def __init__(self, state: ResultState, detail: str, rcode: int | None = None) -> None:
        super().__init__(detail)
        self.state = state
        self.detail = detail
        self.rcode = rcode


def format_addr(addr: ResolverAddr) -> str:
    return f"[{addr.host}]:{addr.port}" if ":" in addr.host else f"{addr.host}:{addr.port}"


def _same_addr(a: ResolverAddr, b: ResolverAddr) -> bool:
    try:
        return a.port == b.port and ipaddress.ip_address(a.host) == ipaddress.ip_address(b.host)
    except ValueError:
        return False


# --- exception and rcode mapping -------------------------------------------------------------


def classify_exception(exc: BaseException) -> tuple[ResultState, str]:
    """Map a transport/parse exception to a state and a detail code. Order matters:
    TimeoutError is an OSError subclass and dns.message.Truncated a DNSException."""
    if isinstance(exc, ResponseTooLarge):
        return ResultState.malformed, "oversized"
    if isinstance(exc, (TimeoutError, dns.exception.Timeout)):
        return ResultState.timeout, "timeout"
    if isinstance(exc, dns.message.Truncated):
        return ResultState.truncated, "truncated"
    if isinstance(exc, dns.exception.FormError):
        return ResultState.malformed, "form_error"
    if isinstance(exc, (OSError, EOFError)):  # incl. ConnectionError, IncompleteReadError
        return ResultState.network_error, "network_error"
    return ResultState.error, "unexpected_exception"


_RCODE_STATES: dict[int, ResultState] = {
    dns.rcode.NXDOMAIN: ResultState.nxdomain,
    dns.rcode.SERVFAIL: ResultState.servfail,
    dns.rcode.REFUSED: ResultState.refused,
}


def rcode_state(rcode: int) -> ResultState:
    """NOERROR is handled by the caller (ok vs nodata vs referral); anything unknown is error."""
    return _RCODE_STATES.get(rcode, ResultState.error)


# --- response interpretation -----------------------------------------------------------------


def _name_text(name: dns.name.Name) -> str:
    text: str = name.to_text(omit_final_dot=True)
    return "." if name == dns.name.root else text.lower()


def _rdata_text(rdtype: str, rd: object) -> str:
    if isinstance(rd, dns.rdtypes.txtbase.TXTBase):
        return join_txt_strings(rd.strings)
    if rdtype in _NAME_RDTYPES:
        text: str = rd.to_text(origin=dns.name.root, relativize=True)  # type: ignore[attr-defined]
        return " ".join("." if tok == "@" else tok for tok in text.split(" "))
    rendered: str = rd.to_text()  # type: ignore[attr-defined]
    return rendered


def _check_counts(resp: dns.message.Message) -> None:
    for section in (resp.answer, resp.authority, resp.additional):
        if sum(len(rrset) for rrset in section) > MAX_RECORDS_PER_SECTION:
            raise _Bad(ResultState.malformed, "too_many_records")


def _follow_chain(
    resp: dns.message.Message, question: DnsQuestion
) -> tuple[dns.rrset.RRset | None, list[int]]:
    """Follow the CNAME chain the server put in the answer section. Returns the final RRset of
    the question type (None if the chain ends without one) and the TTLs of the CNAME links."""
    rdtype = dns.rdatatype.from_text(question.rdtype)
    current = dns.name.from_text(question.name)
    ttls: list[int] = []
    seen: set[dns.name.Name] = set()
    for _ in range(MAX_CNAME_CHAIN + 1):
        rrset = resp.get_rrset(resp.answer, current, dns.rdataclass.IN, rdtype)
        if rrset is not None and len(rrset) > 0:
            return rrset, ttls
        if rdtype == dns.rdatatype.CNAME:
            return None, ttls
        cname = resp.get_rrset(resp.answer, current, dns.rdataclass.IN, dns.rdatatype.CNAME)
        if cname is None or len(cname) == 0:
            return None, ttls
        if len(cname) != 1 or current in seen:
            raise _Bad(ResultState.malformed, "bad_cname_chain")
        seen.add(current)
        ttls.append(cname.ttl)
        current = cname[0].target
    raise _Bad(ResultState.malformed, "cname_chain_too_long")


def _records(question: DnsQuestion, rrset: dns.rrset.RRset) -> tuple[DnsRecord, ...]:
    owner = _name_text(rrset.name)
    try:
        texts = sorted(_rdata_text(question.rdtype, rd) for rd in rrset)  # deterministic order
        return tuple(DnsRecord(owner, question.rdtype, rrset.ttl, text) for text in texts)
    except ValueError:
        raise _Bad(ResultState.malformed, "bad_record") from None


def _referral(resp: dns.message.Message, question: DnsQuestion) -> Referral | None:
    """A non-authoritative NOERROR without answer, with NS (and no SOA) in authority."""
    if resp.flags & dns.flags.AA:
        return None
    if any(rr.rdtype == dns.rdatatype.SOA for rr in resp.authority):
        return None
    ns_sets = [rr for rr in resp.authority if rr.rdtype == dns.rdatatype.NS]
    if not ns_sets:
        return None
    zone = ns_sets[0].name
    qname = dns.name.from_text(question.name)
    if any(rr.name != zone for rr in ns_sets) or not qname.is_subdomain(zone):
        raise _Bad(ResultState.malformed, "bad_referral")
    names = {rd.target for rr in ns_sets for rd in rr}
    glue: list[NsAddr] = []
    for rr in resp.additional:
        # Glue must be an A/AAAA for a delegated NS name, in bailiwick; anything else is ignored.
        if (
            rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
            and rr.name in names
            and rr.name.is_subdomain(zone)
        ):
            glue.extend(NsAddr(_name_text(rr.name), rd.address) for rd in rr)
    return Referral(
        zone=_name_text(zone),
        ns=tuple(sorted(glue, key=lambda n: (n.name, n.addr))),
        ns_names=tuple(sorted({_name_text(n) for n in names})),
    )


@dataclass(frozen=True, slots=True)
class _Interpreted:
    state: ResultState
    records: tuple[DnsRecord, ...] = ()
    ttl_min: int | None = None
    rcode: int | None = None
    referral: Referral | None = None
    detail: str | None = None


def interpret_response(resp: dns.message.Message, question: DnsQuestion) -> _Interpreted:
    """Turn a parsed, validated response into a state. Raises _Bad for malformed content."""
    _check_counts(resp)
    rcode = resp.rcode()
    if rcode != dns.rcode.NOERROR:
        state = rcode_state(rcode)
        detail = None if state is not ResultState.error else "unexpected_rcode"
        return _Interpreted(state, rcode=rcode, detail=detail)
    final, ttls = _follow_chain(resp, question)
    if final is not None:
        records = _records(question, final)
        return _Interpreted(
            ResultState.ok, records=records, ttl_min=min([final.ttl, *ttls]), rcode=0
        )
    if not ttls:  # no CNAME link: a referral is only possible for the name itself
        referral = _referral(resp, question)
        if referral is not None:
            return _Interpreted(ResultState.nodata, rcode=0, referral=referral)
    return _Interpreted(ResultState.nodata, rcode=0)


def parse_wire(
    data: bytes, query: dns.message.Message, target: ResolverAddr, source: ResolverAddr | None
) -> dns.message.Message:
    """Validate raw response bytes against the query. Raises _Bad / dns.message.Truncated."""
    if len(data) > MAX_RESPONSE_BYTES:
        raise _Bad(ResultState.malformed, "oversized")
    if source is not None and not _same_addr(source, target):
        raise _Bad(ResultState.malformed, "unexpected_source")
    try:
        resp = dns.message.from_wire(data, raise_on_truncation=True)
    except dns.message.Truncated:
        raise
    except dns.exception.DNSException:
        raise _Bad(ResultState.malformed, "unparseable") from None
    if not query.is_response(resp):
        raise _Bad(ResultState.malformed, "mismatched_response")
    return resp


# --- production transport --------------------------------------------------------------------


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[tuple[bytes, ResolverAddr]]) -> None:
        self.future = future

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if not self.future.done():
            host = str(addr[0]).split("%", 1)[0]
            self.future.set_result((data, ResolverAddr(host, int(addr[1]))))

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.future.done():
            self.future.set_exception(exc or ConnectionError("udp socket closed"))


async def asyncio_transport(wire: bytes, target: ResolverAddr, *, tcp: bool) -> WireReply:
    """Stdlib asyncio UDP/TCP. Only reached after the egress policy allowed ``target``; the
    target is an IP literal, so no name resolution happens here."""
    loop = asyncio.get_running_loop()
    if not tcp:
        future: asyncio.Future[tuple[bytes, ResolverAddr]] = loop.create_future()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(future), remote_addr=(target.host, target.port)
        )
        try:
            transport.sendto(wire)
            data, source = await future
        finally:
            transport.close()
        return WireReply(data, source)
    reader, writer = await asyncio.open_connection(target.host, target.port)
    try:
        writer.write(len(wire).to_bytes(2, "big") + wire)
        await writer.drain()
        length = int.from_bytes(await reader.readexactly(2), "big")
        if length > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge(length)
        data = await reader.readexactly(length)
    finally:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
    return WireReply(data, None)  # connected stream: the source is the target


# --- resolver --------------------------------------------------------------------------------


class _Slots:
    """One asyncio.Semaphore per nameserver, dropped when unused (bounded memory)."""

    def __init__(self, size: int) -> None:
        self.size = size
        self._slots: dict[tuple[str, int], tuple[asyncio.Semaphore, int]] = {}

    @asynccontextmanager
    async def hold(self, addr: ResolverAddr) -> AsyncIterator[None]:
        key = (addr.host, addr.port)
        sem, users = self._slots.get(key, (asyncio.Semaphore(self.size), 0))
        self._slots[key] = (sem, users + 1)
        try:
            async with sem:
                yield
        finally:
            sem, users = self._slots[key]
            if users <= 1:
                del self._slots[key]
            else:
                self._slots[key] = (sem, users - 1)


class DnsPythonResolver:
    """Async resolver over dnspython messages. Implements the M2-02 ``Resolver`` protocol plus
    ``query_server`` (one server, non-recursive) for trace.

    ``trusted`` applies only to ``nameservers`` (operator configuration). ``dnssec_ok`` sets the
    EDNS DO bit and reports the AD flag (Unbound); otherwise ``authenticated_data`` is False.
    """

    def __init__(
        self,
        nameservers: Sequence[ResolverAddr],
        *,
        trusted: bool,
        identity: str,
        dnssec_ok: bool = False,
        policy: TargetPolicy = DEFAULT_POLICY,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.monotonic,
        query_timeout_s: float = QUERY_TIMEOUT_S,
        deadline_s: float = TOTAL_DEADLINE_S,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self.nameservers = tuple(nameservers)
        self.trusted = trusted
        self.identity = identity
        self.dnssec_ok = dnssec_ok
        self.policy = policy
        self.transport: Transport = transport or asyncio_transport
        self.clock = clock
        self.query_timeout_s = query_timeout_s
        self.deadline_s = deadline_s
        self.max_attempts = max(1, max_attempts)
        self._slots = _Slots(MAX_IN_FLIGHT_PER_SERVER)

    def _is_trusted(self, addr: ResolverAddr) -> bool:
        return self.trusted and any(_same_addr(addr, ns) for ns in self.nameservers)

    def _make_query(self, question: DnsQuestion, recursion_desired: bool) -> dns.message.Message:
        flags = dns.flags.RD if recursion_desired else 0
        return dns.message.make_query(
            question.name if question.name != "." else dns.name.root,
            question.rdtype,
            use_edns=0,
            payload=EDNS_PAYLOAD,
            want_dnssec=self.dnssec_ok,
            flags=flags,
        )

    async def _send(self, wire: bytes, target: ResolverAddr, trusted: bool, tcp: bool) -> WireReply:
        """The single place packets leave: the egress policy is checked before every send."""
        reason = self.policy.check(target, trusted=trusted)
        if reason is not None:
            raise _Blocked(reason)
        return await self.transport(wire, target, tcp=tcp)

    async def _exchange(
        self, query: dns.message.Message, target: ResolverAddr, trusted: bool
    ) -> dns.message.Message:
        wire = query.to_wire()
        reply = await self._send(wire, target, trusted, tcp=False)
        try:
            return parse_wire(reply.data, query, target, reply.source)
        except dns.message.Truncated:
            pass  # TC on UDP: retry the same server over TCP
        reply = await self._send(wire, target, trusted, tcp=True)
        try:
            return parse_wire(reply.data, query, target, reply.source)
        except dns.message.Truncated:
            raise _Bad(ResultState.truncated, "truncated_after_tcp") from None

    def _result(
        self, question: DnsQuestion, target: ResolverAddr | None, started: float, **kw: object
    ) -> DnsResult:
        elapsed = max(0.0, (self.clock() - started) * 1000.0)
        server = format_addr(target) if target is not None else self.identity
        return DnsResult(question=question, server=server, elapsed_ms=elapsed, **kw)  # type: ignore[arg-type]

    async def _attempt(
        self,
        question: DnsQuestion,
        target: ResolverAddr,
        trusted: bool,
        recursion_desired: bool,
        timeout_s: float,
        started: float,
    ) -> ServerReply:
        query = self._make_query(question, recursion_desired)
        try:
            async with asyncio.timeout(timeout_s), self._slots.hold(target):
                resp = await self._exchange(query, target, trusted)
            out = interpret_response(resp, question)
        except _Blocked as exc:
            return ServerReply(
                self._result(
                    question, target, started, state=ResultState.blocked, detail_code=exc.reason
                )
            )
        except _Bad as exc:
            return ServerReply(
                self._result(
                    question,
                    target,
                    started,
                    state=exc.state,
                    detail_code=exc.detail,
                    rcode=exc.rcode,
                )
            )
        except Exception as exc:  # mapped explicitly; unknown exceptions become `error`
            state, detail = classify_exception(exc)
            if state is ResultState.error:
                logger.warning(
                    "dns query failed: %s",
                    type(exc).__name__,
                    extra={"event": "dns.query_error", "server": format_addr(target)},
                )
            return ServerReply(
                self._result(question, target, started, state=state, detail_code=detail)
            )
        ad = self.dnssec_ok and bool(resp.flags & dns.flags.AD)
        result = self._result(
            question,
            target,
            started,
            state=out.state,
            records=out.records,
            ttl_min=out.ttl_min,
            rcode=out.rcode,
            authenticated_data=ad,
            detail_code=out.detail,
        )
        return ServerReply(result, out.referral)

    async def _run(
        self,
        question: DnsQuestion,
        targets: Sequence[tuple[ResolverAddr, bool]],
        recursion_desired: bool,
    ) -> ServerReply:
        started = self.clock()
        deadline = started + self.deadline_s
        last: ServerReply | None = None
        for i in range(self.max_attempts):
            target, trusted = targets[i % len(targets)]
            remaining = deadline - self.clock()
            if remaining <= 0:
                break
            reply = await self._attempt(
                question,
                target,
                trusted,
                recursion_desired,
                min(self.query_timeout_s, remaining),
                started,
            )
            if reply.result.state not in RETRYABLE_STATES:
                return reply
            last = reply
        if last is not None:
            return last
        return ServerReply(
            self._result(question, None, started, state=ResultState.timeout, detail_code="deadline")
        )

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        """Recursive query to the configured nameservers. Never returns a referral."""
        started = self.clock()
        if not self.nameservers:
            return self._result(
                question, None, started, state=ResultState.error, detail_code="no_nameservers"
            )
        allowed: list[tuple[ResolverAddr, bool]] = []
        first_block: tuple[ResolverAddr, BlockReason] | None = None
        for ns in self.nameservers:
            reason = self.policy.check(ns, trusted=self.trusted)
            if reason is None:
                allowed.append((ns, self.trusted))
            elif first_block is None:
                first_block = (ns, reason)
        if not allowed:
            assert first_block is not None
            return self._result(
                question,
                first_block[0],
                started,
                state=ResultState.blocked,
                detail_code=first_block[1],
            )
        reply = await self._run(question, allowed, recursion_desired=True)
        if reply.referral is not None:
            r = reply.result
            return DnsResult(
                question=question,
                state=ResultState.error,
                server=r.server,
                elapsed_ms=r.elapsed_ms,
                detail_code="unexpected_referral",
            )
        return reply.result

    async def query_server(
        self,
        addr: str | ResolverAddr,
        question: DnsQuestion,
        *,
        recursion_desired: bool = False,
    ) -> ServerReply:
        """Ask one server directly (trace). ``addr`` is UNTRUSTED unless it is one of this
        resolver's configured nameservers and the resolver is trusted. Check ``referral`` first.
        """
        started = self.clock()
        target = parse_target(addr) if isinstance(addr, str) else addr
        if target is None:
            return ServerReply(
                DnsResult(
                    question=question,
                    state=ResultState.blocked,
                    detail_code=BlockReason.malformed,
                )
            )
        trusted = self._is_trusted(target)
        reason = self.policy.check(target, trusted=trusted)
        if reason is not None:
            return ServerReply(
                self._result(
                    question, target, started, state=ResultState.blocked, detail_code=reason
                )
            )
        return await self._run(question, [(target, trusted)], recursion_desired)


class BlockedResolver:
    """Returned by the factory when an untrusted target is rejected: no packet is ever sent."""

    def __init__(self, target: str, reason: BlockReason) -> None:
        self.target = target
        self.reason = reason
        self.identity = f"blocked:{target}"

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        return DnsResult(
            question=question,
            state=ResultState.blocked,
            server=self.target,
            detail_code=self.reason,
        )

    async def query_server(
        self, addr: str | ResolverAddr, question: DnsQuestion, *, recursion_desired: bool = False
    ) -> ServerReply:
        return ServerReply(await self.resolve(question))
