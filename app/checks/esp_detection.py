"""ESP detection (M6-13): DNS records of a loaded ESP profile that is not assigned to the domain.

Runs inside the `esp` check (`app.checks.esp_profile.EspProfileCheck`, `candidates`), after the
assigned profiles. Read only: it never assigns anything. DNS goes through `ctx.resolver` only.

- SPF: the domain's SPF tree is the one the assigned-ESP part resolved (the caller hands it over
  as an `SpfView`, resolved at most once per run). A candidate's verified `spf.includes` host
  found among the tree's `include:` / `redirect=` targets is a hit. Hosts that a verified
  `spf.includes` of an assigned profile also names are not attributed to a candidate.
  Candidates with verified includes and no hit cannot be ruled out when the tree has a DNS
  failure or was truncated (`ESP_DNS_ERROR`, part `spf.includes`) or holds a record that
  `resolve_spf` could not follow (`ESP_SPF_PERMERROR`); either makes the result `error`.
- DKIM: only verified `cname` selectors with a `target_pattern` are probed (a TXT key or a CNAME
  without a pattern cannot be attributed to one ESP). One CNAME query at
  `<selector>._domainkey.<domain>`; a target fitting the pattern is a hit (the first target
  only, no chain following). NXDOMAIN and NODATA are misses. Any other state is `ESP_DNS_ERROR`
  and `error`. A target that a same-named verified selector of an assigned profile also fits is
  not attributed to a candidate. Names are queried once per run, started in (profile id,
  selector) order with at most `DETECTION_CONCURRENCY` in flight (M6-13b); at most
  `MAX_DETECTION_DKIM_QUERIES` names. When the cap stops probing, the result is partial:
  `data["detection"]["truncated"]` is true and an `ESP_DETECTION_TRUNCATED` (low) finding keeps
  the status from being `ok`. The first query that is not evaluated (timeout, SERVFAIL, invalid
  name, ...) stops probing: no new query starts, the ones in flight finish and are reported,
  `data["detection"]["dkim_stopped"]` is true and the result is `error`. `dkim_queries` counts
  the queries started. Findings and data follow (profile id, selector) order, never completion
  order.
- `data["detection"]["spf"]`: None (no candidate with verified includes), "ok", "partial" (every
  such candidate matched, but the tree had a DNS failure, was truncated or holds a permerror
  record: the hits stand, the tree is incomplete; the status follows the hit findings), "error"
  or "permerror" (a candidate could not be ruled out; the result is `error`).
- Fields a profile marks unverified are never used for matching.

One `ESP_DETECTED_NOT_ASSIGNED` (low) per candidate with a hit: params `esp_id` and `esp`,
evidence in DNS notation (`include:<host>`, `<name> CNAME <target>`).
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from app.checks.dnsutil import CnameFetch, fetch_cname
from app.checks.models import CheckContext, Finding, finding
from app.core.domain_names import InvalidDomainName
from app.esp.profile import DkimSelector, EspProfile

CODES: tuple[str, ...] = ("ESP_DETECTED_NOT_ASSIGNED", "ESP_DETECTION_TRUNCATED")

MAX_DETECTION_DKIM_QUERIES: Final = 32
# ARCHITECTURE section 6: bounded concurrency, as `app.checks.dkim.PROBE_CONCURRENCY`.
DETECTION_CONCURRENCY: Final = 8


@dataclass(frozen=True, slots=True)
class SpfView:
    """What detection needs from the domain's resolved SPF tree.

    `failure` (name, rdtype, state): the tree is incomplete (DNS failure, truncation, invalid
    name). `broken` (name, reason): a record `resolve_spf` did not follow (permerror)."""

    targets: frozenset[str]
    failure: tuple[str, str, str] | None = None
    broken: tuple[str, str] | None = None


@dataclass(slots=True)
class Detection:
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    evaluated: bool = True


def verified_spf_includes(profile: EspProfile) -> tuple[str, ...]:
    if not profile.spf_includes or not profile.is_verified("spf.includes"):
        return ()
    return tuple(sorted(profile.spf_includes))


def detectable_selectors(profile: EspProfile) -> tuple[DkimSelector, ...]:
    """Verified cname selectors with a target pattern, sorted by name."""
    return tuple(
        s
        for s in sorted(profile.dkim_selectors, key=lambda s: s.name)
        if s.type == "cname"
        and s.target_pattern is not None
        and profile.is_verified(f"dkim.selectors.{s.name}")
    )


def _dns_error(esp: str, part: str, name: str, rdtype: str, state: str) -> Finding:
    return finding(
        "ESP_DNS_ERROR",
        "low",
        {"esp": esp, "part": part, "name": name, "rdtype": rdtype, "state": state},
    )


async def detect(
    ctx: CheckContext,
    domain: str,
    candidates: Sequence[EspProfile],
    assigned: Sequence[EspProfile],
    spf: Callable[[], Awaitable[SpfView]],
) -> Detection:
    """Detection over `candidates` (loaded, not assigned) for the ASCII `domain`."""
    out = Detection()
    ordered = sorted(candidates, key=lambda p: p.id)
    spf_hits: dict[str, list[str]] = {}
    dkim_hits: dict[str, list[dict[str, str]]] = {}

    # --- SPF
    claimed = {h for p in assigned for h in verified_spf_includes(p)}
    with_includes = [
        (p, [h for h in verified_spf_includes(p) if h not in claimed]) for p in ordered
    ]
    with_includes = [(p, hosts) for p, hosts in with_includes if hosts]
    spf_state = None
    if with_includes:
        view = await spf()
        unseen: list[str] = []
        for p, hosts in with_includes:
            matched = [h for h in hosts if h in view.targets]
            if matched:
                spf_hits[p.id] = matched
            else:
                unseen.append(p.name)
        spf_state = "ok" if view.failure is None and view.broken is None else "partial"
        if unseen and view.failure is not None:
            out.evaluated = False
            spf_state = "error"
            out.findings.append(_dns_error(", ".join(unseen), "spf.includes", *view.failure))
        elif unseen and view.broken is not None:
            out.evaluated = False
            spf_state = "permerror"
            name, reason = view.broken
            out.findings.append(
                finding(
                    "ESP_SPF_PERMERROR",
                    "high",
                    {"esp": ", ".join(unseen), "name": name, "reason": reason},
                )
            )

    # --- DKIM
    plan = [
        (p, sel, f"{sel.name}._domainkey.{domain}")
        for p in ordered
        for sel in detectable_selectors(p)
    ]
    names = list(dict.fromkeys(name for _, _, name in plan))
    probe = names[:MAX_DETECTION_DKIM_QUERIES]
    capped = set(names[MAX_DETECTION_DKIM_QUERIES:])
    cache, queries, stopped = await _probe_dkim(ctx, probe)
    reported: set[str] = set()
    truncated = False
    unprobed: list[str] = []
    for p, sel, name in plan:
        if name in capped:
            truncated = True
            if p.id not in unprobed:
                unprobed.append(p.id)
            continue
        if name not in cache:  # not started: probing stopped on a failure (already reported)
            continue
        res = cache[name]
        part = f"dkim.selectors.{sel.name}"
        if res is None or not res.evaluated:
            out.evaluated = False
            if name not in reported:
                reported.add(name)
                state = "invalid_name" if res is None else str(res.state)
                out.findings.append(_dns_error(p.name, part, name, "CNAME", state))
            continue
        target = res.target
        if target is None or sel.target_pattern is None:
            continue
        if not sel.target_pattern.matches(target):
            continue
        if _claimed_by_assigned(assigned, sel.name, target):
            continue
        dkim_hits.setdefault(p.id, []).append(
            {"selector": sel.name, "name": name, "target": target}
        )

    detected: list[dict[str, Any]] = []
    for p in ordered:
        includes = spf_hits.get(p.id, [])
        selectors = dkim_hits.get(p.id, [])
        if not includes and not selectors:
            continue
        detected.append({"id": p.id, "name": p.name, "spf": includes, "dkim": selectors})
        evidence = [f"include:{h}" for h in includes] + [
            f"{d['name']} CNAME {d['target']}" for d in selectors
        ]
        out.findings.append(
            finding("ESP_DETECTED_NOT_ASSIGNED", "low", {"esp_id": p.id, "esp": p.name}, evidence)
        )
    if truncated:
        out.findings.append(
            finding(
                "ESP_DETECTION_TRUNCATED",
                "low",
                {"limit": MAX_DETECTION_DKIM_QUERIES},
                unprobed,
            )
        )
    out.data = {
        "detected": detected,
        "spf": spf_state,
        "dkim_queries": queries,
        "dkim_query_limit": MAX_DETECTION_DKIM_QUERIES,
        "truncated": truncated,
        "unprobed": unprobed,
        "dkim_stopped": stopped,
    }
    return out


async def _probe_dkim(
    ctx: CheckContext, names: Sequence[str]
) -> tuple[dict[str, CnameFetch | None], int, bool]:
    """CNAME of each name, at most `DETECTION_CONCURRENCY` in flight, started in `names` order.

    Returns (name -> result, None when the name cannot be built; probes started; stopped). The
    first result that is not evaluated stops probing: no new probe starts after it, the probes in
    flight finish and their results are kept. Same bounded-worker pattern as
    `app.checks.dkim.probe_selectors`; the caller reads the results in its own order.
    """
    pending = deque(names)
    results: dict[str, CnameFetch | None] = {}
    started = 0
    stopped = False

    async def worker() -> None:
        nonlocal started, stopped
        while pending and not stopped:
            name = pending.popleft()
            started += 1
            res: CnameFetch | None
            try:
                res = await fetch_cname(ctx.resolver, name)
            except InvalidDomainName:
                res = None
            results[name] = res
            if res is None or not res.evaluated:
                stopped = True
                pending.clear()

    workers = [
        asyncio.create_task(worker()) for _ in range(min(DETECTION_CONCURRENCY, len(pending)))
    ]
    try:
        await asyncio.gather(*workers)
    finally:
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    return results, started, stopped


def _claimed_by_assigned(assigned: Sequence[EspProfile], selector: str, target: str) -> bool:
    return any(
        s.name == selector and s.target_pattern is not None and s.target_pattern.matches(target)
        for p in assigned
        for s in detectable_selectors(p)
    )
