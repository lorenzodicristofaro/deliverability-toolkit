"""Iterative DNS trace, dig +trace style (M2-09).

``trace`` starts at the root hints (M2-07), asks one server per step non-recursively through the
injected ``query_server`` primitive (M2-05; TCP fallback on truncation and the wire size cap
``MAX_RESPONSE_BYTES`` live there) and follows NS referrals down to an authoritative answer.

EGRESS (ARCHITECTURE section 7): every address that comes from DNS data (root hints are also
re-checked, glue, addresses of glueless NS names resolved through the configured resolver) is
UNTRUSTED. It is checked with the injected policy (``TargetPolicy.check(addr, trusted=False)``,
the same rule as ``is_allowed_untrusted_target``) BEFORE ``query_server`` is called. A rejected
address becomes a hop with ``ResultState.blocked`` and is skipped; no packet is sent to it. If no
allowed server remains, the trace ends ``error`` (outcome ``no_allowed_server``), never absence.

Referrals: ``reply.referral`` is checked BEFORE ``reply.result.state`` (a referral carries the
placeholder state ``nodata``). A referral hop is recorded as ``kind=referral, state=ok``; it is
never reported as nxdomain/nodata.

Bailiwick rule applied to a referral from a server of zone Z for query name Q to zone R:

- R must be a valid DNS name and an ancestor-or-self of Q (else ``referral_out_of_bailiwick``);
- R must be strictly below Z. R == Z (``referral_loop``) or R above Z (``referral_upward``) does
  not move closer to Q and counts as a loop for that server.

Loops: because every followed referral strictly descends, a zone is never visited twice; within a
zone an address is queried at most once (a repeated (zone, server) pair is a ``skipped`` hop with
detail ``repeated_server``). A zone whose queried servers all answered with a no-progress
referral ends with outcome ``loop``; one whose servers all refused (or mixed refused/no-progress)
ends ``lame_delegation``; any other mix ends ``all_failed``.

Glue: the trace uses whatever glue ``query_server`` hands back for the delegated NS names (the
M2-05 parser already keeps only glue inside R; nothing is cached, and every glue address is
policy-checked, so out-of-bailiwick glue can only pick which allowed server answers this hop).
NS names without glue are resolved through the configured resolver (A then AAAA). An NS name
whose answer is owned by another name (the NS name is a CNAME, RFC 2181 section 10.3) is
rejected.

Server failures: on timeout/servfail/refused/network/malformed/truncated/error/blocked the next
server of the same zone is tried (at most ``max_servers_per_zone`` queries per zone), each failure
recorded. SERVFAIL/timeout at any hop never becomes "name does not exist": only an answer from a
server we were referred to (or a root) can end the trace nxdomain/nodata.

Known limitation: ``ServerReply`` does not expose the AA flag, so a non-authoritative answer that
is not a referral cannot be told apart from an authoritative one; lame delegation is detected
from REFUSED replies and from referrals that do not move closer to the name.

Detail codes only; UI i18n keys come with M2-14.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from app.core.config import ResolverAddr
from app.dns.egress import UNTRUSTED_DNS_PORT, BlockReason
from app.dns.knowledge import RootHints, RootServer
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, Resolver, ResultState

# Limits (named constants; overridable per call through TraceLimits).
MAX_REFERRAL_DEPTH = 16  # referrals followed below the root
MAX_TOTAL_QUERIES = 64  # query_server packets plus glueless NS resolver lookups
MAX_SERVERS_PER_ZONE = 4  # servers actually queried per zone (blocked ones are not queried)
TOTAL_DEADLINE_S = 30.0  # whole trace
MAX_REFERRAL_NS = 16  # NS names in one referral
MAX_REFERRAL_GLUE = 32  # glue addresses in one referral
MAX_HOP_RECORDS = 100  # answer records accepted from one hop
MAX_GLUELESS_LOOKUPS_PER_ZONE = 3  # NS names resolved through the resolver per zone


@dataclass(frozen=True, slots=True)
class TraceLimits:
    max_depth: int = MAX_REFERRAL_DEPTH
    max_total_queries: int = MAX_TOTAL_QUERIES
    max_servers_per_zone: int = MAX_SERVERS_PER_ZONE
    deadline_s: float = TOTAL_DEADLINE_S
    max_referral_ns: int = MAX_REFERRAL_NS
    max_referral_glue: int = MAX_REFERRAL_GLUE
    max_hop_records: int = MAX_HOP_RECORDS
    max_glueless_lookups_per_zone: int = MAX_GLUELESS_LOOKUPS_PER_ZONE


DEFAULT_LIMITS = TraceLimits()


class HopKind(StrEnum):
    answer = "answer"  # final ok/nxdomain/nodata from a server
    referral = "referral"  # delegation followed (state ok, never "missing")
    failure = "failure"  # server failed / lame / loop / bad referral; next server tried
    blocked = "blocked"  # address rejected by the egress policy; nothing sent
    ns_lookup = "ns_lookup"  # glueless NS name resolved through the configured resolver
    skipped = "skipped"  # (zone, server) pair already queried; nothing sent


class TraceOutcome(StrEnum):
    ok = "ok"
    nxdomain = "nxdomain"
    nodata = "nodata"
    lame_delegation = "lame_delegation"
    all_failed = "all_failed"
    loop = "loop"
    depth_exceeded = "depth_exceeded"
    query_limit = "query_limit"
    deadline = "deadline"
    no_allowed_server = "no_allowed_server"
    no_server_address = "no_server_address"

    @property
    def state(self) -> ResultState:
        """Only ok/nxdomain/nodata are evaluations; every other outcome is ``error``."""
        return {
            TraceOutcome.ok: ResultState.ok,
            TraceOutcome.nxdomain: ResultState.nxdomain,
            TraceOutcome.nodata: ResultState.nodata,
        }.get(self, ResultState.error)


@dataclass(frozen=True, slots=True)
class TraceHop:
    kind: HopKind
    zone: str
    question: DnsQuestion
    state: ResultState
    server_name: str | None = None
    server_addr: str | None = None
    rcode: int | None = None
    detail_code: str | None = None
    referral_zone: str | None = None
    referral_ns: tuple[str, ...] = ()
    records: tuple[DnsRecord, ...] = ()
    authenticated_data: bool = False
    elapsed_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class TraceReport:
    question: DnsQuestion
    outcome: TraceOutcome
    hops: tuple[TraceHop, ...]
    answer: tuple[DnsRecord, ...] = ()
    final_zone: str | None = None
    final_server: str | None = None
    queries_sent: int = 0
    elapsed_ms: float = 0.0
    detail_code: str | None = None

    @property
    def state(self) -> ResultState:
        return self.outcome.state


# --- injected collaborators (structural, so the M2-04 fake and M2-05 resolver both fit) -------


class NsAddrLike(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def addr(self) -> str: ...


class ReferralLike(Protocol):
    @property
    def zone(self) -> str: ...
    @property
    def ns(self) -> Sequence[NsAddrLike]: ...


class ReplyLike(Protocol):
    @property
    def result(self) -> DnsResult: ...
    @property
    def referral(self) -> ReferralLike | None: ...


QueryServer = Callable[[str, DnsQuestion], Awaitable[ReplyLike]]
"""Ask one server (bare IP literal, port 53) non-recursively."""


class AddressPolicy(Protocol):
    def check(self, addr: ResolverAddr, trusted: bool) -> BlockReason | None: ...


class ServerQueryResolver(Protocol):
    def query_server(
        self, addr: str | ResolverAddr, question: DnsQuestion, *, recursion_desired: bool = False
    ) -> Awaitable[ReplyLike]: ...


def query_server_for(resolver: ServerQueryResolver) -> QueryServer:
    """Adapt the M2-05 ``query_server`` (which wants a ResolverAddr for IPv6) to QueryServer."""

    async def ask(addr: str, question: DnsQuestion) -> ReplyLike:
        return await resolver.query_server(ResolverAddr(addr, UNTRUSTED_DNS_PORT), question)

    return ask


# --- helpers ----------------------------------------------------------------------------------


def _is_under(name: str, zone: str) -> bool:
    """name equals zone or is below it (both lowercase, no trailing dot; "." is the root)."""
    return zone == "." or name == zone or name.endswith("." + zone)


def _valid_name(name: object) -> bool:
    if not isinstance(name, str):
        return False
    try:
        DnsQuestion(name, "NS")
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _Candidate:
    name: str
    addr: str | None  # None: glueless, resolve the name first


class _Abort(Exception):
    def __init__(self, outcome: TraceOutcome, detail: str | None = None) -> None:
        super().__init__(outcome.value)
        self.outcome = outcome
        self.detail = detail


@dataclass(slots=True)
class _Zone:
    """Per-zone bookkeeping: why each queried server did not lead anywhere."""

    queried: int = 0
    blocked: int = 0
    lame: int = 0
    loops: int = 0
    failures: int = 0
    glueless_lookups: int = 0
    seen_addrs: set[str] = field(default_factory=set)


_Step = TraceReport | tuple[str, list[_Candidate]] | None


class _Tracer:
    def __init__(
        self,
        question: DnsQuestion,
        query_server: QueryServer,
        policy: AddressPolicy,
        limits: TraceLimits,
        resolver: Resolver | None,
        clock: Callable[[], float],
    ) -> None:
        self.q = question
        self.query_server = query_server
        self.policy = policy
        self.limits = limits
        self.resolver = resolver
        self.clock = clock
        self.started = clock()
        self.deadline = self.started + limits.deadline_s
        self.hops: list[TraceHop] = []
        self.queries = 0

    # -- budget --

    def _spend(self) -> float:
        """Reserve one query; returns the remaining time. Raises _Abort on an exhausted budget."""
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise _Abort(TraceOutcome.deadline)
        if self.queries >= self.limits.max_total_queries:
            raise _Abort(TraceOutcome.query_limit)
        self.queries += 1
        return remaining

    def _ms(self, t0: float) -> float:
        return max(0.0, (self.clock() - t0) * 1000.0)

    def _hop(
        self,
        kind: HopKind,
        zone: str,
        state: ResultState,
        server_name: str | None,
        addr: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.hops.append(
            TraceHop(
                kind=kind,
                zone=zone,
                question=self.q,
                state=state,
                server_name=server_name,
                server_addr=addr,
                detail_code=detail,
            )
        )

    # -- egress --

    def _check(self, addr: object) -> tuple[str | None, BlockReason | None]:
        """Policy-check an UNTRUSTED address: (normalised addr, None) or (None, reason)."""
        if not isinstance(addr, str):
            return None, BlockReason.malformed
        reason = self.policy.check(ResolverAddr(addr, UNTRUSTED_DNS_PORT), trusted=False)
        if reason is not None:
            return None, reason
        try:
            return str(ipaddress.ip_address(addr)), None
        except ValueError:  # a policy that let a non-IP through: refuse anyway
            return None, BlockReason.malformed

    # -- glueless NS names --

    async def _resolve_ns(self, zone: str, name: str, info: _Zone) -> list[str]:
        if not _valid_name(name):
            self._hop(HopKind.ns_lookup, zone, ResultState.malformed, name, detail="bad_ns_name")
            return []
        if self.resolver is None:
            self._hop(HopKind.ns_lookup, zone, ResultState.error, name, detail="no_resolver")
            return []
        if info.glueless_lookups >= self.limits.max_glueless_lookups_per_zone:
            self._hop(HopKind.ns_lookup, zone, ResultState.error, name, detail="glueless_limit")
            return []
        info.glueless_lookups += 1
        addrs: list[str] = []
        for rdtype in ("A", "AAAA"):
            remaining = self._spend()
            t0 = self.clock()
            nq = DnsQuestion(name, rdtype)
            try:
                async with asyncio.timeout(remaining):
                    res = await self.resolver.resolve(nq)
            except TimeoutError:
                raise _Abort(TraceOutcome.deadline) from None
            except Exception:
                res = DnsResult(nq, ResultState.error, detail_code="resolver_exception")
            state, detail, records = res.state, res.detail_code, res.records
            if state is ResultState.ok:
                if any(r.name != name or r.rdtype != rdtype for r in records):
                    # The NS name is an alias (answer owned by another name): RFC 2181 10.3.
                    state, detail, records = ResultState.malformed, "ns_is_cname", ()
                else:
                    addrs.extend(r.rdata_text for r in records)
            self.hops.append(
                TraceHop(
                    kind=HopKind.ns_lookup,
                    zone=zone,
                    question=nq,
                    state=state,
                    server_name=name,
                    server_addr=res.server,
                    rcode=res.rcode,
                    detail_code=detail,
                    records=records,
                    elapsed_ms=self._ms(t0),
                )
            )
        return addrs

    # -- referrals --

    def _check_referral(self, zone: str, ref: ReferralLike) -> tuple[str | None, str | None]:
        """(child zone, None) when the referral may be followed, else (None, detail code)."""
        child = ref.zone
        if not _valid_name(child):
            return None, "bad_referral"
        if not _is_under(self.q.name, child):
            return None, "referral_out_of_bailiwick"
        if child == zone:
            return None, "referral_loop"
        if child == "." or not _is_under(child, zone):
            return None, "referral_upward"
        return child, None

    def _candidates(self, ref: ReferralLike) -> tuple[list[_Candidate], tuple[str, ...]] | None:
        """Glue addresses first, then glueless names. None when over the size caps."""
        ns = list(ref.ns)
        extra = getattr(ref, "ns_names", ())  # the M2-05 Referral also lists glueless names
        names = [str(n) for n in dict.fromkeys([*(n.name for n in ns), *extra])]
        if len(names) > self.limits.max_referral_ns or len(ns) > self.limits.max_referral_glue:
            return None
        out: list[_Candidate] = []
        glued: set[str] = set()
        for n in ns:
            if _valid_name(n.name):
                out.append(_Candidate(n.name, n.addr))
                glued.add(n.name)
        out.extend(_Candidate(n, None) for n in names if n not in glued)
        return out, tuple(names)

    # -- main loop --

    async def run(self, roots: Sequence[RootServer]) -> TraceReport:
        zone = "."
        candidates = [_Candidate(r.name, a) for r in roots for a in (r.ipv4, r.ipv6) if a]
        depth = 0
        try:
            while True:
                step = await self._ask_zone(zone, candidates)
                if isinstance(step, TraceReport):
                    return step
                child, candidates = step
                depth += 1
                if depth > self.limits.max_depth:
                    raise _Abort(TraceOutcome.depth_exceeded)
                zone = child
        except _Abort as abort:
            return self._report(abort.outcome, detail=abort.detail)

    async def _ask_zone(
        self, zone: str, candidates: list[_Candidate]
    ) -> TraceReport | tuple[str, list[_Candidate]]:
        info = _Zone()
        pending = list(candidates)
        while pending and info.queried < self.limits.max_servers_per_zone:
            cand = pending.pop(0)
            if cand.addr is None:
                addrs = await self._resolve_ns(zone, cand.name, info)
                pending[0:0] = [_Candidate(cand.name, a) for a in addrs]
                continue
            addr, reason = self._check(cand.addr)
            if addr is None:
                info.blocked += 1
                detail = (reason or BlockReason.malformed).value
                self._hop(HopKind.blocked, zone, ResultState.blocked, cand.name, cand.addr, detail)
                continue
            if addr in info.seen_addrs:
                # Same (zone, server) pair again (e.g. two NS names, one address): never resent.
                self._hop(
                    HopKind.skipped, zone, ResultState.error, cand.name, addr, "repeated_server"
                )
                continue
            info.seen_addrs.add(addr)
            step = await self._query(zone, cand.name, addr, info)
            if step is not None:
                return step
        return self._exhausted(info)

    async def _query(self, zone: str, server_name: str, addr: str, info: _Zone) -> _Step:
        remaining = self._spend()
        info.queried += 1
        t0 = self.clock()
        try:
            async with asyncio.timeout(remaining):
                reply = await self.query_server(addr, self.q)
        except TimeoutError:
            self._hop(
                HopKind.failure, zone, ResultState.timeout, server_name, addr, "trace_deadline"
            )
            raise _Abort(TraceOutcome.deadline) from None
        except Exception:
            info.failures += 1
            self._hop(
                HopKind.failure, zone, ResultState.error, server_name, addr, "query_exception"
            )
            return None
        elapsed = self._ms(t0)
        res = reply.result

        def record(
            kind: HopKind,
            state: ResultState,
            detail: str | None,
            *,
            referral_zone: str | None = None,
            referral_ns: tuple[str, ...] = (),
            records: tuple[DnsRecord, ...] = (),
        ) -> None:
            self.hops.append(
                TraceHop(
                    kind=kind,
                    zone=zone,
                    question=self.q,
                    state=state,
                    server_name=server_name,
                    server_addr=addr,
                    rcode=res.rcode,
                    detail_code=detail,
                    referral_zone=referral_zone,
                    referral_ns=referral_ns,
                    records=records,
                    authenticated_data=res.authenticated_data,
                    elapsed_ms=elapsed,
                )
            )

        ref = reply.referral  # BEFORE result.state: a referral is never "missing"
        if ref is not None:
            child, detail = self._check_referral(zone, ref)
            built = self._candidates(ref) if child is not None else None
            if child is None or built is None:
                detail = detail or "referral_too_large"
                if detail in ("referral_loop", "referral_upward"):
                    info.loops += 1
                else:
                    info.failures += 1
                ref_zone = ref.zone if _valid_name(ref.zone) else None
                record(HopKind.failure, ResultState.error, detail, referral_zone=ref_zone)
                return None
            cands, ns_names = built
            record(
                HopKind.referral,
                ResultState.ok,
                "referral",
                referral_zone=child,
                referral_ns=ns_names,
            )
            return child, cands
        state = res.state
        if state.is_ok or state.is_definitive_absence:
            if len(res.records) > self.limits.max_hop_records:
                info.failures += 1
                record(HopKind.failure, ResultState.malformed, "oversized_answer")
                return None
            record(HopKind.answer, state, res.detail_code, records=res.records)
            return self._report(
                TraceOutcome(state.value),
                answer=res.records,
                final_zone=zone,
                final_server=addr,
            )
        if state is ResultState.refused:
            info.lame += 1
            record(HopKind.failure, state, res.detail_code or "lame_refused")
        else:
            info.failures += 1
            record(HopKind.failure, state, res.detail_code)
        return None

    def _exhausted(self, info: _Zone) -> TraceReport:
        if info.queried == 0:
            if info.blocked:
                return self._report(TraceOutcome.no_allowed_server, detail="all_servers_blocked")
            return self._report(TraceOutcome.no_server_address)
        if info.failures == 0 and info.lame == 0:
            return self._report(TraceOutcome.loop)
        if info.failures == 0:
            return self._report(TraceOutcome.lame_delegation)
        return self._report(TraceOutcome.all_failed)

    def _report(
        self,
        outcome: TraceOutcome,
        *,
        answer: tuple[DnsRecord, ...] = (),
        final_zone: str | None = None,
        final_server: str | None = None,
        detail: str | None = None,
    ) -> TraceReport:
        if detail is None and outcome.state is ResultState.error:
            detail = outcome.value
        return TraceReport(
            question=self.q,
            outcome=outcome,
            hops=tuple(self.hops),
            answer=answer,
            final_zone=final_zone,
            final_server=final_server,
            queries_sent=self.queries,
            elapsed_ms=self._ms(self.started),
            detail_code=detail,
        )


async def trace(
    question: DnsQuestion,
    *,
    query_server: QueryServer,
    root_hints: RootHints | Sequence[RootServer],
    policy: AddressPolicy,
    limits: TraceLimits = DEFAULT_LIMITS,
    resolver: Resolver | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> TraceReport:
    """Trace ``question`` from the root. Never raises for DNS/network conditions.

    ``resolver`` is the configured (trusted) resolver used only to find addresses of glueless NS
    names; the addresses it returns are still UNTRUSTED and policy-checked.
    """
    roots = root_hints.servers if isinstance(root_hints, RootHints) else tuple(root_hints)
    tracer = _Tracer(question, query_server, policy, limits, resolver, clock)
    return await tracer.run(roots)
