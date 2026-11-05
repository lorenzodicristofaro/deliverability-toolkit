"""DNS lookup and reverse-lookup service (M2-08).

Presentation-neutral: results carry states and stable codes only (no user-facing text). Every
`ResultState` stays distinct; a failure (servfail, timeout, refused, blocked, ...) is never
reported as "missing", and `summary.evaluated` says whether every query could be evaluated.
No free-form resolver IP: the selector is `default` or `public:<id>` from the M2-07 data file,
and public resolvers are built through the untrusted-target policy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from app.core.config import ResolverAddr
from app.core.domain_names import InvalidDomainName, to_dns_name
from app.dns.cache import CachingResolver
from app.dns.factory import build_resolver_for_target
from app.dns.knowledge import PublicResolver, get_resolver
from app.dns.types import ALLOWED_RDTYPES, DnsQuestion, DnsRecord, DnsResult, Resolver, ResultState

ALL_TYPES = "ALL"
# "All common types" mode. ANY is never used (unreliable, often refused); SRV is left out because
# it needs a service-specific owner name.
COMMON_RDTYPES: tuple[str, ...] = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME")
MAX_CONCURRENCY = 4
MAX_PTR_NAMES = 8
_IP_TRIM = " \t\r\n"

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class InvalidLookupInput(ValueError):
    """Bad user input. `field` is name|rdtype|resolver|ip, `reason` a stable code (never input)."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"invalid {field}: {reason}")
        self.field = field
        self.reason = reason


def _build_public(entry: PublicResolver) -> Resolver:
    # One address is enough for an ad-hoc lookup; policy is checked by the factory.
    return build_resolver_for_target(ResolverAddr(entry.addresses[0], entry.port))


@dataclass(frozen=True, slots=True)
class LookupResolvers:
    """Resolvers available to the service: the configured default plus a builder for public
    entries (injectable so tests never touch the network)."""

    default: Resolver
    public_factory: Callable[[PublicResolver], Resolver] = _build_public


@dataclass(frozen=True, slots=True)
class TypeResult:
    rdtype: str
    state: ResultState
    records: tuple[DnsRecord, ...]
    ttl_min: int | None
    authenticated_data: bool
    elapsed_ms: float
    server: str | None
    detail_code: str | None

    @property
    def evaluated(self) -> bool:
        """False for every failure state: such a result says nothing about presence."""
        return not self.state.is_failure


@dataclass(frozen=True, slots=True)
class LookupSummary:
    evaluated: bool  # True only if no type result is a failure
    found: tuple[str, ...]
    absent: tuple[str, ...]  # nxdomain / nodata (definitive)
    failed: tuple[str, ...]  # could not evaluate


@dataclass(frozen=True, slots=True)
class LookupReport:
    name: str
    resolver_selector: str
    resolver_identity: str
    results: tuple[TypeResult, ...]
    summary: LookupSummary
    authenticated_data: bool
    elapsed_ms: float


class FcrdnsState(StrEnum):
    not_requested = "not_requested"
    no_ptr = "no_ptr"  # PTR definitively absent: nothing to confirm
    confirmed = "confirmed"
    mismatch = "mismatch"  # every step evaluated and no PTR name resolves back to the IP
    could_not_verify = "could_not_verify"  # any step failed: NOT a mismatch


@dataclass(frozen=True, slots=True)
class ForwardCheck:
    ptr_name: str
    results: tuple[TypeResult, ...]  # A and AAAA
    matches: bool | None  # None when this name could not be evaluated


@dataclass(frozen=True, slots=True)
class ReverseReport:
    ip: str
    ptr_name: str
    resolver_selector: str
    resolver_identity: str
    ptr: TypeResult
    fcrdns: FcrdnsState
    forward: tuple[ForwardCheck, ...]
    detail_code: str | None
    evaluated: bool  # PTR evaluated and (if requested) FCrDNS verdict is not could_not_verify
    elapsed_ms: float


def resolve_selector(selector: object, resolvers: LookupResolvers) -> Resolver:
    if not isinstance(selector, str):
        raise InvalidLookupInput("resolver", "not_a_string")
    if selector == "default":
        return resolvers.default
    prefix, _, rid = selector.partition(":")
    if prefix != "public" or not rid:
        raise InvalidLookupInput("resolver", "unknown_selector")
    entry = get_resolver(rid)
    if entry is None:
        raise InvalidLookupInput("resolver", "unknown_public_id")
    return resolvers.public_factory(entry)


def _normalise_rdtypes(rdtype: object) -> tuple[str, ...]:
    if not isinstance(rdtype, str):
        raise InvalidLookupInput("rdtype", "not_a_string")
    t = rdtype.strip().upper()
    if t == ALL_TYPES:
        return COMMON_RDTYPES
    if t not in ALLOWED_RDTYPES:
        raise InvalidLookupInput("rdtype", "not_allowed")
    return (t,)


def _dns_name(name_input: object) -> str:
    try:
        return to_dns_name(name_input)
    except InvalidDomainName as exc:
        raise InvalidLookupInput("name", exc.reason) from None


def _to_type_result(rdtype: str, r: DnsResult) -> TypeResult:
    return TypeResult(
        rdtype=rdtype,
        state=r.state,
        records=r.records,
        ttl_min=r.ttl_min,
        authenticated_data=r.authenticated_data,
        elapsed_ms=r.elapsed_ms,
        server=r.server,
        detail_code=r.detail_code,
    )


async def _query(
    resolver: Resolver, name: str, rdtype: str, bypass_cache: bool, sem: asyncio.Semaphore
) -> TypeResult:
    question = DnsQuestion(name, rdtype)
    async with sem:
        started = time.perf_counter()
        try:
            if bypass_cache and isinstance(resolver, CachingResolver):
                result = await resolver.resolve(question, bypass_cache=True)
            else:
                result = await resolver.resolve(question)
        except Exception:  # resolvers must not raise; if one does it is "could not evaluate"
            return TypeResult(
                rdtype,
                ResultState.error,
                (),
                None,
                False,
                (time.perf_counter() - started) * 1000,
                None,
                "resolver_exception",
            )
    return _to_type_result(rdtype, result)


def _summarise(results: Sequence[TypeResult]) -> LookupSummary:
    return LookupSummary(
        evaluated=all(r.evaluated for r in results),
        found=tuple(r.rdtype for r in results if r.state.is_ok),
        absent=tuple(r.rdtype for r in results if r.state.is_definitive_absence),
        failed=tuple(r.rdtype for r in results if r.state.is_failure),
    )


async def lookup(
    name_input: object,
    rdtype: object,
    resolver_selector: object,
    *,
    resolvers: LookupResolvers,
    bypass_cache: bool = False,
) -> LookupReport:
    name = _dns_name(name_input)
    types = _normalise_rdtypes(rdtype)
    resolver = resolve_selector(resolver_selector, resolvers)
    started = time.perf_counter()
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    results = tuple(
        await asyncio.gather(*(_query(resolver, name, t, bypass_cache, sem) for t in types))
    )
    ok = [r for r in results if r.state.is_ok]
    return LookupReport(
        name=name,
        resolver_selector=str(resolver_selector),
        resolver_identity=resolver.identity,
        results=results,
        summary=_summarise(results),
        authenticated_data=bool(ok) and all(r.authenticated_data for r in ok),
        elapsed_ms=(time.perf_counter() - started) * 1000,
    )


def parse_ip(ip_input: object) -> IPAddress:
    """Strict IP literal: no hostnames, ranges, zone ids, whitespace inside, or non-ASCII."""
    if not isinstance(ip_input, str):
        raise InvalidLookupInput("ip", "not_a_string")
    text = ip_input.strip(_IP_TRIM)
    if not text:
        raise InvalidLookupInput("ip", "empty")
    if len(text) > 45 or not text.isascii() or not text.isprintable() or " " in text:
        raise InvalidLookupInput("ip", "malformed")
    if "%" in text:
        raise InvalidLookupInput("ip", "zone_id")
    if "/" in text:
        raise InvalidLookupInput("ip", "range")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise InvalidLookupInput("ip", "malformed") from None


def _ptr_target(rdata_text: str) -> str | None:
    name = rdata_text.strip()
    if name.endswith("."):
        name = name[:-1]
    name = name.lower()
    try:
        DnsQuestion(name, "A")
    except ValueError:
        return None
    return name


async def reverse(
    ip_input: object,
    resolver_selector: object = "default",
    *,
    resolvers: LookupResolvers,
    bypass_cache: bool = False,
    forward_confirm: bool = False,
) -> ReverseReport:
    """PTR lookup. Private/reserved IPs are accepted as INPUT: the IP is only part of a query
    name sent to the chosen resolver; nothing ever connects to it."""
    ip = parse_ip(ip_input)
    resolver = resolve_selector(resolver_selector, resolvers)
    ptr_name = ip.reverse_pointer
    started = time.perf_counter()
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    ptr = await _query(resolver, ptr_name, "PTR", bypass_cache, sem)

    forward: tuple[ForwardCheck, ...] = ()
    detail: str | None = None
    if not forward_confirm:
        state = FcrdnsState.not_requested
    elif ptr.state.is_definitive_absence:
        state = FcrdnsState.no_ptr
    elif not ptr.state.is_ok:
        state, detail = FcrdnsState.could_not_verify, "ptr_not_evaluated"
    else:
        targets = [_ptr_target(r.rdata_text) for r in ptr.records]
        distinct = list(dict.fromkeys(t for t in targets if t is not None))
        forward = tuple(
            await asyncio.gather(
                *(
                    _forward_check(resolver, n, ip, bypass_cache, sem)
                    for n in distinct[:MAX_PTR_NAMES]
                )
            )
        )
        if any(t is None for t in targets):
            state, detail = FcrdnsState.could_not_verify, "invalid_ptr_name"
        elif len(distinct) > MAX_PTR_NAMES:
            state, detail = FcrdnsState.could_not_verify, "too_many_ptr_names"
        elif any(f.matches is None for f in forward):
            state, detail = FcrdnsState.could_not_verify, "forward_not_evaluated"
        elif any(f.matches for f in forward):
            state = FcrdnsState.confirmed
        else:
            state = FcrdnsState.mismatch
    return ReverseReport(
        ip=str(ip),
        ptr_name=ptr_name,
        resolver_selector=str(resolver_selector),
        resolver_identity=resolver.identity,
        ptr=ptr,
        fcrdns=state,
        forward=forward,
        detail_code=detail,
        evaluated=ptr.evaluated and state is not FcrdnsState.could_not_verify,
        elapsed_ms=(time.perf_counter() - started) * 1000,
    )


async def _forward_check(
    resolver: Resolver, name: str, ip: IPAddress, bypass_cache: bool, sem: asyncio.Semaphore
) -> ForwardCheck:
    results = tuple(
        await asyncio.gather(*(_query(resolver, name, t, bypass_cache, sem) for t in ("A", "AAAA")))
    )
    if any(r.state.is_failure for r in results):
        return ForwardCheck(name, results, None)
    addrs: set[IPAddress] = set()
    for r in results:
        for rec in r.records:
            try:
                addrs.add(ipaddress.ip_address(rec.rdata_text))
            except ValueError:
                return ForwardCheck(name, results, None)
    return ForwardCheck(name, results, ip in addrs)
