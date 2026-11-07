"""Identifier alignment analysis for a parsed message (DMARC-style, RFC 7489 section 3.1).

Pure and offline: no DNS, no network. The DMARC policy of the From domain (`aspf`, `adkim`) is
NOT fetched, so BOTH relaxed and strict alignment are reported for every pair. The verdict
`state` uses relaxed alignment (the DMARC default); `strict_aligned` is reported alongside.

Nothing is verified cryptographically or re-evaluated here: a DKIM-Signature header is NOT
checked. Results are what the receiver STATED in `Authentication-Results` (stated); alignment
is computed here (computed). Trust in the authserv-id is not decided (RFC 8601 section 5); for
each method the topmost Authentication-Results field that carries that method is used.

Pairs (From domain vs identifier):
- `spf`: `smtp.mailfrom` of the stated spf result when present, else the Return-Path header.
- `dkim`: one pair per stated dkim result (`header.d`), plus one per DKIM-Signature `d=` that
  has no stated result with the same `d` (`unverified_signature=True`).

States: `aligned` (relaxed match AND stated pass), `aligned_but_not_passed` (domain match,
result not `pass` or not stated), `misaligned`, `unknown` (From or identifier missing or
unusable, see `reason`) and `not_evaluated` (no identifier at all). Never aligned on missing
data. Relaxed match = same organizational domain (`app.core.org_domain`); when either name is
a public suffix (no organizational domain) only an exact match counts.

`computed_dmarc` is `pass` when any pair is `aligned`, `fail` when no pair is aligned and none
is `unknown`, else `not_evaluated`. `dmarc_mismatch` is set when the stated dmarc result
(pass or fail) disagrees with the computed one; M4-09 turns it into a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import getaddresses
from typing import Literal

from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.core.org_domain import organizational_domain
from app.parsers.authres import AuthResHeader, ResInfo, parse_all_authentication_results
from app.parsers.message import HeaderBlock

AlignmentState = Literal[
    "aligned", "aligned_but_not_passed", "misaligned", "unknown", "not_evaluated"
]
PairKind = Literal["spf", "dkim"]
DmarcComputed = Literal["pass", "fail", "not_evaluated"]

MAX_DKIM_PAIRS = 50

_D_TAG = re.compile(r"^\s*d\s*=(.*)$", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True, slots=True)
class AlignmentPair:
    kind: PairKind
    state: AlignmentState
    reason: str | None  # stable code when state is unknown / not_evaluated
    from_domain: str | None
    identifier_domain: str | None
    identifier_source: str | None  # smtp.mailfrom | return_path | authres_header_d | dkim_signature
    from_org: str | None
    identifier_org: str | None
    relaxed_aligned: bool
    strict_aligned: bool
    stated_result: str | None  # as written by the receiver (lowercase), None when absent
    unverified_signature: bool


@dataclass(frozen=True, slots=True)
class AlignmentReport:
    pairs: tuple[AlignmentPair, ...]
    from_domains: tuple[str, ...]
    stated_dmarc: str | None
    computed_dmarc: DmarcComputed  # computed here from relaxed alignment
    dmarc_mismatch: bool
    truncated: bool


@dataclass(frozen=True, slots=True)
class _Ident:
    domain: str | None
    reason: str | None


_NONE = _Ident(None, None)


def _domain(value: str) -> _Ident:
    try:
        return _Ident(to_ascii_domain(value), None)
    except InvalidDomainName as exc:
        return _Ident(None, f"invalid_domain_{exc.reason}")


def _addr_domain(addr: str) -> _Ident:
    if "@" not in addr:
        return _Ident(None, "invalid_address")
    return _domain(addr.rsplit("@", 1)[1])


def _from_identity(block: HeaderBlock) -> tuple[_Ident, tuple[str, ...]]:
    fields = block.get_all("From")
    if not fields:
        return _Ident(None, "missing_from"), ()
    if len(fields) > 1:
        return _Ident(None, "multiple_from_headers"), ()
    if not fields[0].raw_value.strip():
        return _Ident(None, "missing_from"), ()
    addrs = [a for _, a in getaddresses([fields[0].raw_value]) if a]
    if not addrs:
        return _Ident(None, "invalid_address"), ()
    idents = [_addr_domain(a) for a in addrs]
    bad = next((i for i in idents if i.domain is None), None)
    if bad is not None:
        return bad, ()
    domains = tuple(dict.fromkeys(i.domain for i in idents if i.domain))
    if len(domains) > 1:
        return _Ident(None, "multiple_from_domains"), domains
    return _Ident(domains[0], None), domains


def _return_path_identity(block: HeaderBlock) -> _Ident | None:
    fields = block.get_all("Return-Path")
    if not fields:
        return None
    if len(fields) > 1:
        return _Ident(None, "multiple_return_path")
    text = fields[0].raw_value.strip()
    if text in ("", "<>"):
        return _Ident(None, "null_return_path")
    addrs = [a for _, a in getaddresses([text]) if a]
    if len(addrs) != 1:
        return _Ident(None, "invalid_address")
    return _addr_domain(addrs[0])


def _mailfrom_identity(value: str) -> _Ident:
    text = value.strip().strip("<>").strip()
    if not text:
        return _Ident(None, "null_return_path")
    if "@" in text:
        return _addr_domain(text)
    return _domain(text)


def _dkim_signature_d(raw_value: str) -> _Ident:
    for tag in raw_value.split(";"):
        m = _D_TAG.match(tag)
        if m:
            value = "".join(m.group(1).split())
            return _domain(value) if value else _Ident(None, "missing_d")
    return _Ident(None, "missing_d")


def _topmost(headers: tuple[AuthResHeader, ...], method: str) -> tuple[ResInfo, ...]:
    for header in headers:
        found = header.by_method().get(method)
        if found:
            return tuple(found)
    return ()


def _pair(
    kind: PairKind,
    source: str | None,
    from_id: _Ident,
    ident: _Ident,
    stated: str | None,
    unverified: bool = False,
) -> AlignmentPair:
    def make(
        state: AlignmentState,
        reason: str | None,
        f_org: str | None = None,
        i_org: str | None = None,
        relaxed: bool = False,
        strict: bool = False,
    ) -> AlignmentPair:
        return AlignmentPair(
            kind=kind,
            state=state,
            reason=reason,
            from_domain=from_id.domain,
            identifier_domain=ident.domain,
            identifier_source=source,
            from_org=f_org,
            identifier_org=i_org,
            relaxed_aligned=relaxed,
            strict_aligned=strict,
            stated_result=stated,
            unverified_signature=unverified,
        )

    if source is None:
        return make("not_evaluated", "no_identifier")
    if from_id.domain is None:
        return make("unknown", from_id.reason)
    if ident.domain is None:
        return make("unknown", ident.reason)
    f_org = organizational_domain(from_id.domain)
    i_org = organizational_domain(ident.domain)
    strict = from_id.domain == ident.domain
    relaxed = strict or (f_org is not None and f_org == i_org)
    if not relaxed:
        return make("misaligned", None, f_org, i_org, relaxed, strict)
    state: AlignmentState = "aligned" if stated == "pass" else "aligned_but_not_passed"
    return make(state, None, f_org, i_org, relaxed, strict)


def analyze_alignment(block: HeaderBlock) -> AlignmentReport:
    """Compute alignment of Return-Path and DKIM d= domains against the From domain."""
    from_id, from_domains = _from_identity(block)
    headers = parse_all_authentication_results(block)
    pairs: list[AlignmentPair] = []

    spf = _topmost(headers, "spf")
    spf_info = spf[0] if spf else None
    stated_spf = spf_info.result if spf_info else None
    mailfrom = spf_info.smtp_mailfrom if spf_info else None
    if mailfrom is not None:
        pairs.append(
            _pair("spf", "smtp.mailfrom", from_id, _mailfrom_identity(mailfrom), stated_spf)
        )
    else:
        rp = _return_path_identity(block)
        if rp is None:
            pairs.append(_pair("spf", None, from_id, _NONE, stated_spf))
        else:
            pairs.append(_pair("spf", "return_path", from_id, rp, stated_spf))

    dkim_pairs: list[AlignmentPair] = []
    stated_ds: set[str] = set()
    for info in _topmost(headers, "dkim"):
        raw_d = info.header_d
        ident = _domain(raw_d) if raw_d else _Ident(None, "missing_d")
        if ident.domain:
            stated_ds.add(ident.domain)
        dkim_pairs.append(_pair("dkim", "authres_header_d", from_id, ident, info.result))
    for field in block.get_all("DKIM-Signature"):
        ident = _dkim_signature_d(field.raw_value)
        if ident.domain is not None and ident.domain in stated_ds:
            continue
        dkim_pairs.append(_pair("dkim", "dkim_signature", from_id, ident, None, unverified=True))
    truncated = len(dkim_pairs) > MAX_DKIM_PAIRS
    pairs.extend(dkim_pairs[:MAX_DKIM_PAIRS])
    if not dkim_pairs:
        pairs.append(_pair("dkim", None, from_id, _NONE, None))

    dmarc = _topmost(headers, "dmarc")
    stated_dmarc = dmarc[0].result if dmarc else None
    states = {p.state for p in pairs}
    computed: DmarcComputed
    if "aligned" in states:
        computed = "pass"
    elif "unknown" in states or states == {"not_evaluated"}:
        computed = "not_evaluated"
    else:
        computed = "fail"
    mismatch = (
        stated_dmarc in ("pass", "fail")
        and computed != "not_evaluated"
        and stated_dmarc != computed
    )
    return AlignmentReport(
        pairs=tuple(pairs),
        from_domains=from_domains,
        stated_dmarc=stated_dmarc,
        computed_dmarc=computed,
        dmarc_mismatch=mismatch,
        truncated=truncated,
    )
