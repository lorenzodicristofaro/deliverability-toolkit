"""DNSBL/URIBL query engine (M7-03): query building, answer interpretation, run orchestration.

Everything about a specific list (zone, return codes, refusal convention, NODATA meaning)
comes from `app.checks.dnsbl_schema.DnsblList`; nothing list-specific is in this module.

Outcomes (`Outcome`):
- `not_listed`: a clean NXDOMAIN (or NODATA when the list declares `nodata_is_clean`) only;
- `listed`: every answer is a mapped `listed` (or `info`) code and at least one is `listed`;
- `info`: every answer is a mapped `info` code;
- `error`: could not evaluate; `reason` says why (see `Reason`), never mistaken for clean;
- `not_applicable`: the list does not cover this target (kind or address family); no query.

Interpretation precedence for an answer set: any non-A record or unparseable A rdata ->
`malformed_answer`; any address outside 127.0.0.0/8 -> `answer_out_of_range`; any unmapped
127.x code -> `unmapped_code`; refusal codes (mapped `refused` or inside a declared refused
network) mixed with other codes -> `conflicting_codes`; only refusal codes -> `refused`.

Resolver-level blocking: per run and per list, the first `block_threshold` queries are probes
and the list's other queries wait for them. If every probe answers with a refusal code, a
REFUSED rcode or an egress block, the list is `blocked_resolver` for the rest of the run and
its remaining queries are not sent.

An unverified list is not queried (`list_unverified`) unless `include_unverified` is set; its
results are then marked `unverified=True`.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal

from app.checks.dnsbl_schema import ANSWER_NETWORK, DnsblList
from app.core.domain_names import MAX_DOMAIN_LENGTH, InvalidDomainName, to_ascii_domain
from app.dns.types import DnsQuestion, DnsResult, Resolver, ResultState

DEFAULT_BLOCK_THRESHOLD: Final = 3
DEFAULT_CONCURRENCY: Final = 8
DEFAULT_QUERY_TIMEOUT_S: Final = 5.0
MAX_EVIDENCE_CODES: Final = 8
MAX_TARGETS: Final = 256
MAX_TARGET_INPUT_LENGTH: Final = 1024

AcquireHook = Callable[[str], Awaitable[None]]


class Outcome(StrEnum):
    listed = "listed"
    not_listed = "not_listed"
    info = "info"
    error = "error"
    not_applicable = "not_applicable"


class Reason(StrEnum):
    """Why a result is `error` (or `not_applicable`). Stable codes, localised in M7-05."""

    # answer interpretation
    refused = "refused"
    conflicting_codes = "conflicting_codes"
    unmapped_code = "unmapped_code"
    answer_out_of_range = "answer_out_of_range"
    malformed_answer = "malformed_answer"
    nodata = "nodata"
    # DNS states
    servfail = "servfail"
    rcode_refused = "rcode_refused"
    timeout = "timeout"
    truncated = "truncated"
    malformed_response = "malformed_response"
    network_error = "network_error"
    egress_blocked = "egress_blocked"
    resolver_error = "resolver_error"
    resolver_exception = "resolver_exception"
    # engine
    blocked_resolver = "blocked_resolver"
    list_unverified = "list_unverified"
    name_too_long = "name_too_long"
    # not applicable
    kind_mismatch = "kind_mismatch"
    ipv4_unsupported = "ipv4_unsupported"
    ipv6_unsupported = "ipv6_unsupported"


# Every non-ok state maps explicitly; a state added later falls to resolver_error (still error).
_STATE_REASON: Final[dict[ResultState, Reason]] = {
    ResultState.servfail: Reason.servfail,
    ResultState.refused: Reason.rcode_refused,
    ResultState.timeout: Reason.timeout,
    ResultState.truncated: Reason.truncated,
    ResultState.malformed: Reason.malformed_response,
    ResultState.network_error: Reason.network_error,
    ResultState.blocked: Reason.egress_blocked,
    ResultState.error: Reason.resolver_error,
}

# Results that count as "the list (or the path to it) refuses us" for blocked-resolver detection.
_REFUSAL_REASONS: Final = frozenset({Reason.refused, Reason.rcode_refused, Reason.egress_blocked})


class DnsblQueryError(ValueError):
    """Invalid target or query name. `reason` is a stable code; the input is never echoed."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid DNSBL query: {reason}")
        self.reason = reason


# --- targets and query names ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DnsblTarget:
    """A validated lookup target: an IP address or a normalised (A-label) domain name."""

    value: str
    kind: Literal["ip", "domain"]
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None


def parse_target(value: object) -> DnsblTarget:
    """Validate `value` as an IP literal or a host name. Raises DnsblQueryError."""
    if not isinstance(value, str):
        raise DnsblQueryError("not_a_string")
    if len(value) > MAX_TARGET_INPUT_LENGTH:
        raise DnsblQueryError("too_long")
    if not value or not value.isprintable() or value != value.strip():
        raise DnsblQueryError("forbidden_character")
    if value.isascii() and ("%" in value or ":" in value or value.replace(".", "").isdigit()):
        try:
            if "%" in value:
                raise ValueError("scope id")
            ip = ipaddress.ip_address(value)  # no leading zeros, no int forms
        except ValueError:
            raise DnsblQueryError("invalid_ip") from None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return DnsblTarget(value=str(ip), kind="ip", ip=ip)
    try:
        return DnsblTarget(value=to_ascii_domain(value), kind="domain")
    except InvalidDomainName as exc:
        raise DnsblQueryError(f"invalid_domain_{exc.reason}") from None


def not_applicable_reason(lst: DnsblList, target: DnsblTarget) -> Reason | None:
    if lst.kind != target.kind:
        return Reason.kind_mismatch
    if isinstance(target.ip, ipaddress.IPv4Address) and not lst.ipv4:
        return Reason.ipv4_unsupported
    if isinstance(target.ip, ipaddress.IPv6Address) and not lst.ipv6:
        return Reason.ipv6_unsupported
    return None


def build_query_name(lst: DnsblList, target: DnsblTarget) -> str:
    """The owner name to query. Raises DnsblQueryError (`kind_mismatch`, `ipv4_unsupported`,
    `ipv6_unsupported`, `name_too_long`); nothing is queried in that case."""
    if (na := not_applicable_reason(lst, target)) is not None:
        raise DnsblQueryError(na.value)
    if target.ip is None:
        prefix = target.value
    elif isinstance(target.ip, ipaddress.IPv4Address):
        prefix = ".".join(reversed(str(target.ip).split(".")))
    else:
        prefix = ".".join(reversed(target.ip.exploded.replace(":", "")))
    name = f"{prefix}.{lst.zone}"
    if len(name) > MAX_DOMAIN_LENGTH:
        raise DnsblQueryError(Reason.name_too_long.value)
    try:
        DnsQuestion(name, "A")
    except ValueError:
        raise DnsblQueryError("invalid_name") from None
    return name


# --- interpretation ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Interpretation:
    outcome: Outcome
    reason: Reason | None = None
    codes: tuple[str, ...] = ()  # answer addresses, bounded to MAX_EVIDENCE_CODES
    categories: tuple[str, ...] = ()  # categories of mapped listed/info codes, bounded
    codes_truncated: bool = False


def _bounded(items: Iterable[str]) -> tuple[tuple[str, ...], bool]:
    seq = list(dict.fromkeys(items))
    return tuple(seq[:MAX_EVIDENCE_CODES]), len(seq) > MAX_EVIDENCE_CODES


def _error(reason: Reason, codes: Iterable[str] = ()) -> Interpretation:
    bounded, truncated = _bounded(codes)
    return Interpretation(Outcome.error, reason, bounded, (), truncated)


def interpret(lst: DnsblList, result: DnsResult) -> Interpretation:
    """Pure mapping of one DNS result for `lst` to an outcome (see module docstring)."""
    state = result.state
    if state is ResultState.nxdomain:
        return Interpretation(Outcome.not_listed)
    if state is ResultState.nodata:
        return Interpretation(Outcome.not_listed) if lst.nodata_is_clean else _error(Reason.nodata)
    if state is not ResultState.ok:
        return _error(_STATE_REASON.get(state, Reason.resolver_error))

    texts = [r.rdata_text[:64] for r in result.records]
    if any(r.rdtype != "A" for r in result.records):
        return _error(Reason.malformed_answer, texts)
    addrs: list[ipaddress.IPv4Address] = []
    for text in texts:
        try:
            addrs.append(ipaddress.IPv4Address(text))
        except ValueError:
            return _error(Reason.malformed_answer, texts)
    codes = [str(a) for a in addrs]
    if any(a not in ANSWER_NETWORK for a in addrs):
        return _error(Reason.answer_out_of_range, codes)

    refused = listed = info = 0
    categories: list[str] = []
    for addr in addrs:
        rc = lst.return_codes.get(addr)
        if rc is None:
            is_refused = any(addr in net for net in lst.refused_networks)
        else:
            is_refused = rc.meaning == "refused"
        if is_refused:
            refused += 1
        elif rc is None:
            return _error(Reason.unmapped_code, codes)
        else:
            if rc.meaning == "listed":
                listed += 1
            else:
                info += 1
            if rc.category is not None:
                categories.append(rc.category)
    if refused and (listed or info):
        return _error(Reason.conflicting_codes, codes)
    if refused:
        return _error(Reason.refused, codes)
    bounded, truncated = _bounded(codes)
    cats, _ = _bounded(categories)
    return Interpretation(
        Outcome.listed if listed else Outcome.info, None, bounded, cats, truncated
    )


# --- run -----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DnsblResult:
    """One (list, target) lookup. `dns_state` is None when no query was sent."""

    list_id: str
    zone: str
    target: str
    outcome: Outcome
    reason: Reason | None = None
    query_name: str | None = None
    dns_state: ResultState | None = None
    codes: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    codes_truncated: bool = False
    unverified: bool = False
    elapsed_ms: float = 0.0


@dataclass(slots=True)
class _ListState:
    probes_started: int = 0
    probes_refused: int = 0
    decided: bool = False
    blocked: bool = False
    event: asyncio.Event = field(default_factory=asyncio.Event)

    def decide(self, blocked: bool) -> None:
        self.decided, self.blocked = True, blocked
        self.event.set()


async def _no_acquire(_list_id: str) -> None:
    return None


@dataclass(frozen=True, slots=True)
class DnsblRunReport:
    results: tuple[DnsblResult, ...]
    blocked_lists: frozenset[str]


class DnsblEngine:
    """One run of DNSBL lookups. Holds per-list blocked-resolver state for the run's lifetime."""

    def __init__(
        self,
        resolver: Resolver,
        lists: Sequence[DnsblList],
        *,
        include_unverified: bool = False,
        acquire: AcquireHook | None = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        query_timeout_s: float = DEFAULT_QUERY_TIMEOUT_S,
        block_threshold: int = DEFAULT_BLOCK_THRESHOLD,
    ) -> None:
        if concurrency < 1 or block_threshold < 1 or query_timeout_s <= 0:
            raise ValueError("concurrency, block_threshold and query_timeout_s must be positive")
        if len({lst.id for lst in lists}) != len(lists):
            raise ValueError("duplicate list id")
        self._resolver = resolver
        self._lists = tuple(lists)
        self._include_unverified = include_unverified
        self._acquire = acquire or _no_acquire
        self._semaphore = asyncio.Semaphore(concurrency)
        self._timeout = query_timeout_s
        self._threshold = block_threshold
        self._state: dict[str, _ListState] = {lst.id: _ListState() for lst in self._lists}

    @property
    def blocked_lists(self) -> frozenset[str]:
        return frozenset(k for k, st in self._state.items() if st.blocked)

    async def run(self, targets: Sequence[DnsblTarget]) -> DnsblRunReport:
        """Look up every target on every list, in parallel; results in (target, list) order."""
        if len(targets) > MAX_TARGETS:
            raise ValueError(f"at most {MAX_TARGETS} targets per run")
        jobs = [self._one(lst, t) for t in targets for lst in self._lists]
        results = await asyncio.gather(*jobs)
        return DnsblRunReport(tuple(results), self.blocked_lists)

    def _skip(
        self,
        lst: DnsblList,
        target: DnsblTarget,
        outcome: Outcome,
        reason: Reason,
        query_name: str | None = None,
    ) -> DnsblResult:
        return DnsblResult(
            list_id=lst.id,
            zone=lst.zone,
            target=target.value,
            outcome=outcome,
            reason=reason,
            query_name=query_name,
            unverified=not lst.verified,
        )

    async def _one(self, lst: DnsblList, target: DnsblTarget) -> DnsblResult:
        if (na := not_applicable_reason(lst, target)) is not None:
            return self._skip(lst, target, Outcome.not_applicable, na)
        if not lst.verified and not self._include_unverified:
            return self._skip(lst, target, Outcome.error, Reason.list_unverified)
        try:
            name = build_query_name(lst, target)
        except DnsblQueryError:
            return self._skip(lst, target, Outcome.error, Reason.name_too_long)

        st = self._state[lst.id]
        if not st.decided and st.probes_started < self._threshold:
            st.probes_started += 1
            res = await self._query(lst, target, name)
            if not st.decided:
                if res.reason in _REFUSAL_REASONS:
                    st.probes_refused += 1
                    if st.probes_refused >= self._threshold:
                        st.decide(blocked=True)
                else:
                    st.decide(blocked=False)
            return res
        await st.event.wait()
        if st.blocked:
            return self._skip(lst, target, Outcome.error, Reason.blocked_resolver, name)
        return await self._query(lst, target, name)

    async def _query(self, lst: DnsblList, target: DnsblTarget, name: str) -> DnsblResult:
        await self._acquire(lst.id)
        async with self._semaphore:
            result: DnsResult | None = None
            try:
                answer = await asyncio.wait_for(
                    self._resolver.resolve(DnsQuestion(name, "A")), self._timeout
                )
                result, interp = answer, interpret(lst, answer)
            except TimeoutError:
                interp = _error(Reason.timeout)
            except Exception:  # noqa: BLE001 - reported as error, never as clean
                result, interp = None, _error(Reason.resolver_exception)
        return DnsblResult(
            list_id=lst.id,
            zone=lst.zone,
            target=target.value,
            outcome=interp.outcome,
            reason=interp.reason,
            query_name=name,
            dns_state=result.state if result is not None else None,
            codes=interp.codes,
            categories=interp.categories,
            codes_truncated=interp.codes_truncated,
            unverified=not lst.verified,
            elapsed_ms=result.elapsed_ms if result is not None else 0.0,
        )
