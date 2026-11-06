"""DKIM selector probe and check (M3-13).

Selectors cannot be enumerated in DNS, so the check probes a list of candidate selector
names (the seed, ``app.checks.dkim_selectors``) and reports what it found. It never claims
that DKIM is absent: ``data["enumerable"]`` is always False.

Per selector the name ``<selector>._domainkey.<domain>`` is queried for TXT; when that name
has no TXT record, a CNAME is looked up and followed (max :data:`MAX_CNAME_DEPTH` hops, loops
detected, chain recorded). Selector states:

- ``found``      a TXT key record exists at the end of the chain;
- ``not_found``  NXDOMAIN or NODATA (the only "absent" outcomes);
- ``error``      anything else: a failed lookup, a CNAME loop, a chain that is too long, a
                 malformed delegation (a CNAME with an empty target) or an invalid name.

Overall status (GM rule): failed selectors are always listed in ``DKIM_PROBE_ERRORS``. If at
least one selector is ``found`` the status follows the findings. If none is found and any
failed, the status is ``error``. ``DKIM_NO_SELECTOR_FOUND`` is emitted only when every
selector is ``not_found``.

``probe_selectors`` yields each result as soon as it is ready (completion order), with
bounded concurrency and no early stop; ``DkimCheck.run`` drains the same generator.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from app.checks.dkim_selectors import list_selectors
from app.checks.dnsutil import fetch_cname, fetch_txt
from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.parsers.dkim import DkimKey, parse_dkim_key

CODES: tuple[str, ...] = (
    "DKIM_NO_SELECTOR_FOUND",
    "DKIM_KEY_SYNTAX_ERROR",
    "DKIM_KEY_REVOKED",
    "DKIM_KEY_WEAK_1024",
    "DKIM_KEY_TOO_SHORT",
    "DKIM_TEST_MODE",
    "DKIM_MULTIPLE_RECORDS",
    "DKIM_CNAME_LOOP",
    "DKIM_CNAME_CHAIN_LONG",
    "DKIM_PROBE_ERRORS",
)

# ARCHITECTURE section 6: bounded concurrency, every selector probed.
PROBE_CONCURRENCY = 8
MAX_CNAME_DEPTH = 8
RSA_WEAK_BITS = 1024

SelectorState = Literal["found", "not_found", "error"]


@dataclass(frozen=True, slots=True)
class SelectorResult:
    selector: str
    name: str
    state: SelectorState
    chain: tuple[str, ...] = ()  # CNAME targets followed, in order
    records: tuple[str, ...] = ()  # TXT records at the end of the chain
    reason: str | None = None  # why the state is ``error``
    key_type: str | None = None
    bits: int | None = None


def _error(selector: str, name: str, chain: list[str], reason: str) -> SelectorResult:
    return SelectorResult(selector, name, "error", chain=tuple(chain), reason=reason)


async def _probe_one(ctx: CheckContext, domain: str, selector: str) -> SelectorResult:
    """Probe one selector. Never raises (except cancellation)."""
    name = f"{selector}._domainkey.{domain}"
    try:
        if "." in selector:  # seed selectors are single labels
            raise InvalidDomainName("selector_not_a_label")
        return await _follow(ctx, selector, name)
    except InvalidDomainName:
        return _error(selector, name, [], "invalid_name")
    except Exception:  # defensive: one selector must never break the stream
        return _error(selector, name, [], "internal_error")


async def _follow(ctx: CheckContext, selector: str, name: str) -> SelectorResult:
    chain: list[str] = []
    seen = {name}
    current = name
    while True:
        txt = await fetch_txt(ctx.resolver, current)
        if not txt.evaluated:
            return _error(selector, name, chain, str(txt.state))
        if txt.records:
            key = parse_dkim_key(txt.records[0])
            return SelectorResult(
                selector,
                name,
                "found",
                chain=tuple(chain),
                records=txt.records,
                key_type=key.key_type,
                bits=key.bits,
            )
        cname = await fetch_cname(ctx.resolver, current)
        if not cname.evaluated:
            return _error(selector, name, chain, str(cname.state))
        if cname.target is None:
            return SelectorResult(selector, name, "not_found", chain=tuple(chain))
        if not cname.target:  # '.' CNAME: malformed delegation, never found/not_found
            return _error(selector, name, chain, "empty_cname_target")
        if cname.target in seen:
            chain.append(cname.target)
            return _error(selector, name, chain, "cname_loop")
        if len(chain) >= MAX_CNAME_DEPTH:
            chain.append(cname.target)
            return _error(selector, name, chain, "cname_chain_long")
        chain.append(cname.target)
        seen.add(cname.target)
        current = cname.target


async def probe_selectors(
    ctx: CheckContext, domain: str, selectors: Iterable[str]
) -> AsyncIterator[SelectorResult]:
    """Yield one :class:`SelectorResult` per distinct selector as soon as it is ready.

    At most :data:`PROBE_CONCURRENCY` selectors are in flight; none is skipped. Closing or
    cancelling the generator cancels the in-flight probes and waits for them.
    """
    pending = deque(dict.fromkeys(selectors))
    total = len(pending)
    done: asyncio.Queue[SelectorResult] = asyncio.Queue()

    async def worker() -> None:
        while pending:
            selector = pending.popleft()
            await done.put(await _probe_one(ctx, domain, selector))

    workers = [asyncio.create_task(worker()) for _ in range(min(PROBE_CONCURRENCY, total))]
    try:
        for _ in range(total):
            yield await done.get()
    finally:
        pending.clear()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)


def _selector_findings(res: SelectorResult) -> list[Finding]:
    out: list[Finding] = []
    sel = {"selector": res.selector, "name": res.name}
    if res.reason == "cname_loop":
        out.append(finding("DKIM_CNAME_LOOP", "medium", sel, res.chain))
    elif res.reason == "cname_chain_long":
        out.append(
            finding("DKIM_CNAME_CHAIN_LONG", "low", {**sel, "max": MAX_CNAME_DEPTH}, res.chain)
        )
    if res.state != "found":
        return out
    if len(res.records) > 1:
        out.append(finding("DKIM_MULTIPLE_RECORDS", "medium", sel, res.records))
    for raw in res.records:
        out.extend(_key_findings(sel, parse_dkim_key(raw)))
    return out


def _key_findings(sel: dict[str, Any], key: DkimKey) -> list[Finding]:
    errors = [
        f"{i.code}: {i.term}" if i.term else i.code for i in key.issues if i.severity == "error"
    ]
    if errors:
        return [finding("DKIM_KEY_SYNTAX_ERROR", "medium", sel, errors)]
    out: list[Finding] = []
    if key.revoked:
        out.append(finding("DKIM_KEY_REVOKED", "low", sel))
    if key.testing:
        out.append(finding("DKIM_TEST_MODE", "low", sel))
    if key.key_type == "rsa" and key.bits is not None:
        if key.bits < RSA_WEAK_BITS:
            out.append(finding("DKIM_KEY_TOO_SHORT", "medium", {**sel, "bits": key.bits}))
        elif key.bits == RSA_WEAK_BITS:
            out.append(finding("DKIM_KEY_WEAK_1024", "low", {**sel, "bits": key.bits}))
    return out


def _selector_data(res: SelectorResult) -> dict[str, Any]:
    return {
        "selector": res.selector,
        "state": res.state,
        "key_type": res.key_type,
        "bits": res.bits,
        "chain": list(res.chain),
        "reason": res.reason,
    }


def summarize(
    target: str,
    results: Sequence[SelectorResult],
    names: Sequence[str],
    *,
    started_at: datetime,
    duration_ms: int,
    complete: bool = True,
) -> CheckResult:
    """The single source of the DKIM result (check, API, CLI and the SSE ``done`` event).

    ``names`` is the probe order; results are sorted by it. With ``complete=False`` (the probe
    was cut short) the result is never evaluated, so its status is ``error``, and the aggregate
    findings (which need every selector) are not emitted.
    """
    order = {n: i for i, n in enumerate(names)}
    ordered = sorted(results, key=lambda r: order.get(r.selector, len(order)))
    findings: list[Finding] = []
    for r in ordered:
        findings.extend(_selector_findings(r))
    failed = [r for r in ordered if r.state == "error"]
    found = [r for r in ordered if r.state == "found"]
    if complete:
        if failed:
            findings.append(
                finding(
                    "DKIM_PROBE_ERRORS",
                    "low",
                    {"count": len(failed), "total": len(ordered)},
                    [f"{r.selector}: {r.reason}" for r in failed],
                )
            )
        elif ordered and not found:  # every selector is not_found
            findings.append(finding("DKIM_NO_SELECTOR_FOUND", "info", {"count": len(ordered)}))
    evaluated = complete and bool(ordered) and (bool(found) or not failed)
    return CheckResult.build(
        check_id=DkimCheck.id,
        target=target,
        findings=findings,
        evaluated=evaluated,
        started_at=started_at,
        duration_ms=duration_ms,
        data={
            "enumerable": False,
            "probed": len(ordered),
            "found": len(found),
            "selectors": [_selector_data(r) for r in ordered],
        },
    )


class DkimCheck:
    id = "dkim"

    def __init__(self, selectors: Sequence[str] | None = None) -> None:
        self._selectors = tuple(selectors) if selectors is not None else None

    def _names(self) -> tuple[str, ...]:
        if self._selectors is not None:
            return tuple(dict.fromkeys(self._selectors))
        return tuple(s.name for s in list_selectors())

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        try:
            domain = to_ascii_domain(target.domain)
        except InvalidDomainName:
            domain = target.domain.strip().lower().removesuffix(".")  # probes report the error
        names = self._names()
        results = [r async for r in probe_selectors(ctx, domain, names)]
        return summarize(
            target.domain,
            results,
            names,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
