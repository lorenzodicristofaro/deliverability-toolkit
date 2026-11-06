"""TXT/CNAME fetch helpers for checks (M3-03).

The only job here is to make "could not evaluate" impossible to mistake for "no record".
State mapping (explicit, no default branch that means "absent"):

- ``ok``                      -> ``evaluated=True``, the records;
- ``nxdomain`` / ``nodata``   -> ``evaluated=True``, ``records=()`` (the only "absent" states);
- everything else (servfail, refused, timeout, truncated, malformed, network_error, blocked,
  error, and any state added later) -> ``evaluated=False``, original state kept.

Names are validated with ``to_dns_name`` (M2-01), so ``_dmarc.``, ``_domainkey.`` and
``_report._dmarc.`` names are accepted; an invalid name raises ``InvalidDomainName`` (a caller
bug or unvalidated input, never a DNS outcome). Parsing record content is out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.domain_names import to_dns_name
from app.dns.types import DnsQuestion, DnsResult, Resolver, ResultState


@dataclass(frozen=True, slots=True)
class TxtFetch:
    """``records`` are in resolver order, one entry per TXT record (strings joined, never
    merged across records). ``evaluated`` is False whenever the lookup did not complete."""

    state: ResultState
    records: tuple[str, ...]
    evaluated: bool
    ttl: int | None = None


@dataclass(frozen=True, slots=True)
class CnameFetch:
    state: ResultState
    target: str | None
    evaluated: bool
    ttl: int | None = None


def _classify(result: DnsResult, rdtype: str) -> tuple[ResultState, bool, list[str], int | None]:
    state = result.state
    if state.is_definitive_absence:
        return state, True, [], None
    if state.is_ok:
        matching = [r for r in result.records if r.rdtype == rdtype]
        if not matching:
            # An "ok" without a record of the asked type is not an answer we can trust.
            return ResultState.error, False, [], None
        ttl = result.ttl_min if result.ttl_min is not None else min(r.ttl for r in matching)
        return state, True, [r.rdata_text for r in matching], ttl
    return state, False, [], None


async def fetch_txt(resolver: Resolver, name: str) -> TxtFetch:
    result = await resolver.resolve(DnsQuestion(to_dns_name(name), "TXT"))
    state, evaluated, texts, ttl = _classify(result, "TXT")
    return TxtFetch(state=state, records=tuple(texts), evaluated=evaluated, ttl=ttl)


async def fetch_cname(resolver: Resolver, name: str) -> CnameFetch:
    result = await resolver.resolve(DnsQuestion(to_dns_name(name), "CNAME"))
    state, evaluated, texts, ttl = _classify(result, "CNAME")
    return CnameFetch(state=state, target=texts[0] if texts else None, evaluated=evaluated, ttl=ttl)
