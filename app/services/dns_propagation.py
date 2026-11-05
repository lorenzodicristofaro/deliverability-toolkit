"""DNS propagation check across public resolvers (M2-10).

Presentation-neutral: states and stable codes only. The same question is asked of the configured
default resolver and of EVERY address of each selected public-resolver entry (one row per
address, each with its own resolver and so its own cache key). Answers are always live (cache
bypassed).

Aggregation is only among rows that were evaluated (ok or definitive absence). A failure state
(servfail, timeout, refused, blocked, ...) is "not evaluated": counted separately, never "missing"
and never in agreement or disagreement.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from app.core.config import ResolverAddr
from app.core.domain_names import InvalidDomainName, to_dns_name
from app.dns.cache import CachingResolver
from app.dns.factory import build_resolver_for_target
from app.dns.knowledge import PublicResolver, list_public_resolvers
from app.dns.types import ALLOWED_RDTYPES, DnsQuestion, DnsResult, Resolver, ResultState
from app.services.dns_tools import InvalidLookupInput

MAX_RESOLVERS = 8  # selected public entries per request
MAX_CONCURRENCY = 8
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_MIN_EVALUATED = 2
DEFAULT_ID = "default"

AddressFactory = Callable[[PublicResolver, str], Resolver]


def _build_address(entry: PublicResolver, address: str) -> Resolver:
    return build_resolver_for_target(ResolverAddr(address, entry.port))


class Verdict(StrEnum):
    consistent = "consistent"
    inconsistent = "inconsistent"
    inconclusive = "inconclusive"


@dataclass(frozen=True, slots=True)
class PropagationRow:
    resolver_id: str  # "default" or the data-file id
    address: str | None  # None for the default resolver
    unverified: bool  # entry status is not "verified"
    state: ResultState
    records: tuple[tuple[str, str, str, int], ...]  # (name, rdtype, rdata_text, ttl), sorted
    ttl_min: int | None
    elapsed_ms: float
    detail_code: str | None
    group: int | None = None  # index into PropagationReport.groups; None when not evaluated

    @property
    def evaluated(self) -> bool:
        return not self.state.is_failure


@dataclass(frozen=True, slots=True)
class AnswerGroup:
    """Rows that returned the identical normalised set (TTL ignored) or the same absence."""

    index: int
    state: ResultState  # ok, nxdomain or nodata
    rdata: tuple[tuple[str, str, str], ...]  # (name, rdtype, rdata_text)
    members: tuple[int, ...]  # indices into rows


@dataclass(frozen=True, slots=True)
class PropagationReport:
    name: str
    rdtype: str
    rows: tuple[PropagationRow, ...]
    groups: tuple[AnswerGroup, ...]
    evaluated_count: int
    not_evaluated_count: int
    min_evaluated: int
    verdict: Verdict
    includes_unverified: bool
    elapsed_ms: float


def _select(ids: object, catalog: Sequence[PublicResolver]) -> list[PublicResolver]:
    if ids is None:
        return [e for e in catalog if e.status == "verified"]
    if not isinstance(ids, (list, tuple)):
        raise InvalidLookupInput("resolver", "not_a_list")
    by_id = {e.id: e for e in catalog}
    picked: dict[str, PublicResolver] = {}
    for rid in ids:
        if not isinstance(rid, str):
            raise InvalidLookupInput("resolver", "not_a_string")
        entry = by_id.get(rid)
        if entry is None:
            raise InvalidLookupInput("resolver", "unknown_public_id")
        picked[rid] = entry
    if not picked:
        raise InvalidLookupInput("resolver", "empty_selection")
    if len(picked) > MAX_RESOLVERS:
        raise InvalidLookupInput("resolver", "too_many")
    return list(picked.values())


async def _ask(resolver: Resolver, q: DnsQuestion, timeout_s: float) -> DnsResult:
    started = time.perf_counter()

    def failure(state: ResultState, code: str) -> DnsResult:
        return DnsResult(
            question=q,
            state=state,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            detail_code=code,
        )

    try:
        if isinstance(resolver, CachingResolver):
            coro = resolver.resolve(q, bypass_cache=True)
        else:
            coro = resolver.resolve(q)
        return await asyncio.wait_for(coro, timeout_s)
    except TimeoutError:
        return failure(ResultState.timeout, "propagation_timeout")
    except Exception:  # resolvers must not raise; if one does it is "could not evaluate"
        return failure(ResultState.error, "resolver_exception")


def _row(rid: str, addr: str | None, unverified: bool, r: DnsResult) -> PropagationRow:
    return PropagationRow(
        resolver_id=rid,
        address=addr,
        unverified=unverified,
        state=r.state,
        records=tuple(sorted((x.name, x.rdtype, x.rdata_text, x.ttl) for x in r.records)),
        ttl_min=r.ttl_min,
        elapsed_ms=r.elapsed_ms,
        detail_code=r.detail_code,
    )


def aggregate(
    rows: Sequence[PropagationRow], min_evaluated: int = DEFAULT_MIN_EVALUATED
) -> tuple[tuple[PropagationRow, ...], tuple[AnswerGroup, ...], Verdict]:
    """Group evaluated rows by normalised answer; failures are excluded from grouping."""
    keys: dict[tuple[ResultState, tuple[tuple[str, str, str], ...]], list[int]] = {}
    for i, row in enumerate(rows):
        if not row.evaluated:
            continue
        rdata = tuple(sorted({(n, t, d) for n, t, d, _ttl in row.records}))
        keys.setdefault((row.state, rdata), []).append(i)
    groups = tuple(
        AnswerGroup(idx, state, rdata, tuple(members))
        for idx, ((state, rdata), members) in enumerate(keys.items())
    )
    group_of = {m: g.index for g in groups for m in g.members}
    out = tuple(replace(r, group=group_of.get(i)) for i, r in enumerate(rows))
    if len(group_of) < max(min_evaluated, 1):
        verdict = Verdict.inconclusive
    elif len(groups) == 1:
        verdict = Verdict.consistent
    else:
        verdict = Verdict.inconsistent
    return out, groups, verdict


async def check_propagation(
    name_input: object,
    rdtype: object,
    resolver_ids: object = None,
    *,
    default_resolver: Resolver,
    address_factory: AddressFactory = _build_address,
    catalog: Sequence[PublicResolver] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    min_evaluated: int = DEFAULT_MIN_EVALUATED,
    max_concurrency: int = MAX_CONCURRENCY,
) -> PropagationReport:
    try:
        name = to_dns_name(name_input)
    except InvalidDomainName as exc:
        raise InvalidLookupInput("name", exc.reason) from None
    if not isinstance(rdtype, str):
        raise InvalidLookupInput("rdtype", "not_a_string")
    rtype = rdtype.strip().upper()
    if rtype not in ALLOWED_RDTYPES:
        raise InvalidLookupInput("rdtype", "not_allowed")
    entries = _select(resolver_ids, list_public_resolvers() if catalog is None else catalog)

    q = DnsQuestion(name, rtype)
    targets: list[tuple[str, str | None, bool, Resolver]] = [
        (DEFAULT_ID, None, False, default_resolver)
    ]
    for e in entries:
        for addr in e.addresses:  # every address: one row, one resolver (own cache key) each
            targets.append((e.id, addr, e.status != "verified", address_factory(e, addr)))

    sem = asyncio.Semaphore(max(max_concurrency, 1))
    started = time.perf_counter()

    async def run(resolver: Resolver) -> DnsResult:
        async with sem:
            return await _ask(resolver, q, timeout_s)

    results = await asyncio.gather(*(run(t[3]) for t in targets))
    rows, groups, verdict = aggregate(
        [_row(rid, addr, unv, r) for (rid, addr, unv, _), r in zip(targets, results, strict=True)],
        min_evaluated,
    )
    evaluated = sum(1 for r in rows if r.evaluated)
    return PropagationReport(
        name=name,
        rdtype=rtype,
        rows=rows,
        groups=groups,
        evaluated_count=evaluated,
        not_evaluated_count=len(rows) - evaluated,
        min_evaluated=min_evaluated,
        verdict=verdict,
        includes_unverified=any(r.unverified for r in rows),
        elapsed_ms=(time.perf_counter() - started) * 1000,
    )
