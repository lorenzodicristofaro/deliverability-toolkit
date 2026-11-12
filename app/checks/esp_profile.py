"""ESP profile check (M6-04): is the domain's DNS set up the way each assigned ESP expects?

The check is built per domain run with the assigned profiles (`app.esp.profile.EspProfile`) and,
per profile id, the optional hosts the tenant entered for that assignment (`EspHosts`). It has no
DB handle and is not in `load_builtin_checks` (wiring is M6-06). DNS is read only through
`ctx.resolver` via `fetch_txt` / `fetch_cname` / `classify` (`app.checks.dnsutil`) and
`resolve_spf` (`app.checks.spf_tree`).

Parts evaluated per profile (each skipped, and listed in `skipped`, when the profile marks it
unverified with `EspProfile.is_verified`):

- `spf.includes`: every include host must appear as an `include:` (or `redirect=`) target
  anywhere in the domain's resolved SPF tree, so nested includes count. The term only has to be
  present for the part to be `ok`; a DNS failure on the ESP's own record is still reported, as
  `ESP_DNS_ERROR` part `spf.lookups` (see the lookup budget below). A host not found
  while the tree has DNS failures or was truncated by a cap is not evaluated (`ESP_DNS_ERROR`).
  Otherwise, a host not found while some record in the tree is a permerror that `resolve_spf`
  does not follow (several SPF records at one name, or a syntax error) is not evaluated either:
  state `permerror`, `ESP_SPF_PERMERROR` naming that record; never "missing".
  A profile with `spf.only_if_record` (M6-17) expects its includes only when the domain already
  publishes an SPF record: when the domain's TXT query completed (NXDOMAIN, NODATA, or TXT
  records none of which is SPF) the part is `no_record`, each include `not_required`, and no
  finding is added. A failed root lookup is still `ESP_DNS_ERROR` / `error`, never `no_record`.
- `dkim.selectors.<name>` at `<name>._domainkey.<domain>`:
  - `cname`: NXDOMAIN is missing; NODATA is `wrong_type` when the name holds a TXT record, else
    missing. A CNAME is followed hop by hop (at most MAX_CNAME_HOPS, loops stop it) until one
    target fits `target_pattern` (any target fits when there is no pattern); none fitting is
    `ESP_DKIM_TARGET_MISMATCH`, whose `reason` says why the chain stopped: `chain_end`,
    `loop`, `empty_target` or `hop_limit` (the chain may continue past the limit).
  - `txt`: a TXT record is ok (also when served through a CNAME); none and a CNAME at the name
    is `wrong_type`; none and no CNAME is missing.
- `dkim.alternatives` (M6-23), only for a profile that declares alternative selector sets: the
  DKIM part is satisfied when every primary selector is `ok`, OR every selector of one
  alternative set is. Each set is evaluated apart and its findings are kept only as decided
  here. Primary satisfied: no alternative is queried (`not_required`). Otherwise the fully
  verified sets are tried in order until one is satisfied (the rest are `not_required`). In an
  alternative, a `txt` selector is `ok` only for exactly one TXT record that `parse_dkim_key`
  finds valid and not revoked, else `invalid` with `reason` `multiple_records`, `revoked` or
  `syntax_error`; `cname` follows the rules above. Outcome:
  - a set satisfied: no DKIM finding (DNS errors of the sets tried before it are dropped: the
    OR is decided); their `error` parts in `data` keep `name`, `rdtype` and `failure` (the DNS
    state, e.g. `servfail`), as every DKIM `error` part does;
  - none satisfied and a DNS error in a set tried: only the `ESP_DNS_ERROR` findings (part
    `dkim.selectors.<name>` or `dkim.alternatives.<name>`), result `error`;
  - none satisfied, all answered and every set verified: one `ESP_DKIM_NO_OPTION_SATISFIED`
    (high) whose params list the primary set (`selectors`) and the alternatives
    (`alternatives`), evidence the names queried; the per-selector DKIM findings are not added;
  - none satisfied and a set skipped as unverified: no verdict (the skip is listed).
  `data` adds `dkim_alternatives` (one list of parts per set) and `dkim_satisfied_by`
  (`selectors`, `alternatives.<index>` or None) for such profiles only.
- `return_path` / `tracking_domain` at the assignment's host (`ESP_HOST_NOT_CONFIGURED` when
  unknown): the expected type is queried; NXDOMAIN is missing, NODATA (the name exists but holds
  no record of that type) is a mismatch. Profiles carry no target for these, so the type is all
  that is compared.

Error discipline: any state other than ok/nxdomain/nodata on a name the check needs makes the
part `error` with `ESP_DNS_ERROR` (name, record type, state) and the result `error`; it is never
`ok` and never "missing". A name that cannot be built (invalid host, too long) is reported the
same way with state `invalid_name`.

Profile-level findings: `ESP_PROFILE_UNVERIFIED` (info) for a profile with status `unverified`,
evidence its unverified fields; one `ESP_PITFALL` (info) per verified static pitfall, its own
code, notes key and declared severity in `params` (pitfalls have no condition, so they are advice
and never raise the status).

Combined SPF lookup budget (M6-05, SPEC 4.2), evaluated once per run when two or more profiles
have verified `spf.includes`. It reuses `SpfTree.lookup_count` (no recount) and the SPF check's
`NEAR_LOOKUP_THRESHOLD`, and only adds ESP attribution to `SPF_TOO_MANY_LOOKUPS` /
`SPF_NEAR_LOOKUP_LIMIT`:

- "Attributed" ESPs have at least one include host among the tree's include/redirect targets;
  nothing fires unless two or more are attributed (one ESP is the SPF check's business).
- Tree truncated or over `LOOKUP_LIMIT`: `ESP_SPF_COMBINED_OVER_LIMIT` (high), params `esps`,
  `count`, `limit`, evidence the ESP names. A truncated count is a lower bound (as for
  `SPF_RESOLUTION_TRUNCATED`): the limit is exceeded, but the attribution may be incomplete.
- Count from `NEAR_LOOKUP_THRESHOLD` to `LOOKUP_LIMIT` on a tree with no DNS failure:
  `ESP_SPF_COMBINED_NEAR_LIMIT` (low).
- One ESP with verified includes (M6-19): no budget, but a DNS failure (servfail, timeout, ...)
  or a truncation by a cap (state `truncated`) at or below one of its include hosts adds
  `ESP_DNS_ERROR` part `spf.lookups` (that ESP, first failing name in breadth-first order) and
  makes the run `error`, unless an `spf.includes` part of that ESP already reported one.
  NXDOMAIN/NODATA there is an answer, not a failure: the include is `ok` and the missing target
  is the SPF check's (`SPF_INCLUDE_NOT_FOUND`) business. Failures elsewhere in the tree do not
  concern the single ESP.
- Two or more: a DNS failure in the tree or truncation makes the run `error` (count and
  attribution are lower bounds, so "within budget" cannot be stated); an `ESP_DNS_ERROR` with
  part `spf.lookups` naming all of them is added unless an `spf.includes` part already reported
  one. A permerror record (several SPF records, syntax error) is not a reason for `error` here:
  receivers stop at it, and the SPF check and the include part report it.

Detection (M6-13, `app.checks.esp_detection`): with `candidates` (the loaded profiles not
assigned to the domain; None turns detection off) the check also reports DNS records of those
ESPs (`ESP_DETECTED_NOT_ASSIGNED`), on this run's SPF tree, and adds `data["detection"]`.

No assigned profile: one `ESP_NONE_ASSIGNED` info finding (plus any detection findings).
`CheckResult` derives `ok` from an empty finding list and accepts no other status for it, so
"info with no findings" cannot be expressed without changing the shared model.

`data["esps"]` has one section per profile, sorted by id; selectors are sorted by name.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from app.checks.dnsutil import classify, fetch_cname, fetch_txt
from app.checks.esp_detection import SpfView, detect
from app.checks.models import CheckContext, CheckResult, Finding, Severity, Target, finding
from app.checks.spf import NEAR_LOOKUP_THRESHOLD
from app.checks.spf_tree import LOOKUP_LIMIT, SpfTree, resolve_spf
from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_dns_name
from app.dns.types import DnsQuestion
from app.esp.profile import DkimSelector, EspProfile, RecordExpectation
from app.parsers.dkim import parse_dkim_key

CODES: tuple[str, ...] = (
    "ESP_SPF_INCLUDE_MISSING",
    "ESP_SPF_PERMERROR",
    "ESP_DKIM_RECORD_MISSING",
    "ESP_DKIM_TARGET_MISMATCH",
    "ESP_DKIM_WRONG_TYPE",
    "ESP_DKIM_NO_OPTION_SATISFIED",
    "ESP_RETURN_PATH_MISSING",
    "ESP_RETURN_PATH_MISMATCH",
    "ESP_TRACKING_MISSING",
    "ESP_TRACKING_MISMATCH",
    "ESP_HOST_NOT_CONFIGURED",
    "ESP_PROFILE_UNVERIFIED",
    "ESP_PITFALL",
    "ESP_NONE_ASSIGNED",
    "ESP_DNS_ERROR",
    "ESP_SPF_COMBINED_OVER_LIMIT",
    "ESP_SPF_COMBINED_NEAR_LIMIT",
)

MAX_CNAME_HOPS: Final = 8

PartState = Literal[
    "ok",
    "missing",
    "mismatch",
    "wrong_type",
    "error",
    "permerror",
    "not_configured",
    "skipped_unverified",
    "no_record",
    "invalid",
    "not_required",
]


@dataclass(frozen=True, slots=True)
class EspHosts:
    """Hosts the tenant entered for one ESP assignment; None means unknown."""

    return_path_host: str | None = None
    tracking_host: str | None = None


class _Run:
    """Collects findings for one check run; tracks whether everything needed was evaluated."""

    def __init__(self, ctx: CheckContext, domain: str) -> None:
        self.ctx = ctx
        self.domain = domain
        self.findings: list[Finding] = []
        self.evaluated = True
        self._spf: SpfTree | None = None
        self._spf_failed: str | None = None
        self._spf_done = False

    def dns_error(self, esp: EspProfile, part: str, name: str, rdtype: str, state: str) -> None:
        self.evaluated = False
        self.findings.append(
            finding(
                "ESP_DNS_ERROR",
                "low",
                {"esp": esp.name, "part": part, "name": name, "rdtype": rdtype, "state": state},
            )
        )

    async def spf_tree(self) -> tuple[SpfTree | None, str | None]:
        if not self._spf_done:
            self._spf_done = True
            try:
                self._spf = await resolve_spf(self.ctx.resolver, self.domain)
            except InvalidDomainName:
                self._spf_failed = "invalid_name"
        return self._spf, self._spf_failed


async def _spf_view(run: _Run) -> SpfView:
    """The run's SPF tree as detection needs it (resolved at most once per run)."""
    tree, failed = await run.spf_tree()
    if tree is None:
        return SpfView(frozenset(), failure=(run.domain, "TXT", failed or "error"))
    failure: tuple[str, str, str] | None = None
    if tree.errors:
        name, rdtype, state = tree.errors[0]
        failure = (name, rdtype, str(state))
    elif tree.truncated:
        failure = (run.domain, "TXT", "truncated")
    return SpfView(frozenset(_spf_targets(tree)), failure, _broken_node(tree))


def _part(state: PartState, **extra: Any) -> dict[str, Any]:
    return {"state": state, **extra}


# --- SPF ----------------------------------------------------------------------------------------


def _spf_targets(tree: SpfTree) -> set[str]:
    return {
        lk.target
        for node in tree.nodes()
        for lk in node.lookups
        if lk.target is not None and lk.term.name in ("include", "redirect")
    }


def _broken_node(tree: SpfTree) -> tuple[str, str] | None:
    """(name, reason) of the first record `resolve_spf` could not follow (permerror)."""
    for node in tree.nodes():
        if node.multiple_records:
            return node.domain, "multiple_records"
        if node.syntax_error:
            return node.domain, "syntax_error"
    return None


async def _spf(run: _Run, esp: EspProfile) -> dict[str, Any]:
    tree, failed = await run.spf_tree()
    if tree is None:
        run.dns_error(esp, "spf.includes", run.domain, "TXT", failed or "error")
        return _part("error", includes=[])
    if esp.spf_only_if_record and tree.root.no_record and not tree.errors:
        # The root TXT query completed without an SPF record (a failure never sets no_record).
        return _part(
            "no_record",
            includes=[{"host": h, "state": "not_required"} for h in sorted(esp.spf_includes)],
        )
    targets = _spf_targets(tree)
    broken = _broken_node(tree)
    unknown: PartState | None = None
    if tree.errors or tree.truncated:
        unknown = "error"
    elif broken is not None:
        unknown = "permerror"
    includes: list[dict[str, Any]] = []
    for host in sorted(esp.spf_includes):
        if host in targets:
            includes.append({"host": host, "state": "ok"})
        elif unknown is not None:
            includes.append({"host": host, "state": unknown})
        else:
            includes.append({"host": host, "state": "missing"})
            run.findings.append(
                finding("ESP_SPF_INCLUDE_MISSING", "high", {"esp": esp.name, "host": host})
            )
    not_found = any(i["state"] == unknown for i in includes) if unknown else False
    if not_found and unknown == "error":
        if tree.errors:
            name, rdtype, failure = tree.errors[0]
            run.dns_error(esp, "spf.includes", name, rdtype, str(failure))
        else:
            run.dns_error(esp, "spf.includes", run.domain, "TXT", "truncated")
    elif not_found and broken is not None:
        run.evaluated = False
        run.findings.append(
            finding(
                "ESP_SPF_PERMERROR",
                "high",
                {"esp": esp.name, "name": broken[0], "reason": broken[1]},
            )
        )
    state: PartState = "ok"
    if not_found and unknown is not None:
        state = unknown
    elif any(i["state"] == "missing" for i in includes):
        state = "missing"
    return _part(state, includes=includes)


async def _spf_budget(run: _Run, profiles: Sequence[EspProfile]) -> None:
    """Combined lookup budget over the ESPs with verified SPF includes (module docstring)."""
    eligible = [p for p in profiles if p.spf_includes and p.is_verified("spf.includes")]
    if not eligible:
        return
    tree, _ = await run.spf_tree()
    if tree is None:  # already reported per ESP by the include part
        return
    if len(eligible) == 1:
        _one_esp_lookups(run, eligible[0], tree)
        return
    targets = _spf_targets(tree)
    names = [p.name for p in eligible if any(h in targets for h in p.spf_includes)]
    count = tree.lookup_count
    params: dict[str, Any] = {"esps": ", ".join(names), "count": count, "limit": LOOKUP_LIMIT}
    incomplete = bool(tree.errors) or tree.truncated
    if len(names) >= 2:
        if tree.truncated or tree.lookup_limit_exceeded:
            run.findings.append(finding("ESP_SPF_COMBINED_OVER_LIMIT", "high", params, names))
        elif not incomplete and count >= NEAR_LOOKUP_THRESHOLD:
            run.findings.append(finding("ESP_SPF_COMBINED_NEAR_LIMIT", "low", params, names))
    if not incomplete:
        return
    run.evaluated = False
    if any(
        f.code == "ESP_DNS_ERROR" and f.params.get("part") == "spf.includes" for f in run.findings
    ):
        return
    if tree.errors:
        name, rdtype, failure = tree.errors[0]
        state = str(failure)
    else:
        name, rdtype, state = run.domain, "TXT", "truncated"
    run.findings.append(
        finding(
            "ESP_DNS_ERROR",
            "low",
            {
                "esp": ", ".join(p.name for p in eligible),
                "part": "spf.lookups",
                "name": name,
                "rdtype": rdtype,
                "state": state,
            },
        )
    )


_CAP_RDTYPE: Final[dict[str, str]] = {"a": "A", "mx": "MX", "exists": "A"}


def _include_failure(tree: SpfTree, hosts: frozenset[str]) -> tuple[str, str, str] | None:
    """(name, rdtype, state) of the first DNS failure or truncation at or below an
    include/redirect of one of `hosts` (the ESP's own record or anything it includes), breadth
    first; None if none. Truncation: a node not fetched because of a depth/node/query cap, or an
    a/mx/exists term skipped by the query cap (state `truncated`)."""
    queue = [
        lk
        for node in tree.nodes()
        for lk in node.lookups
        if lk.term.name in ("include", "redirect") and lk.target in hosts
    ]
    while queue:
        lk = queue.pop(0)
        if lk.error is not None:
            rdtype = next((rt for rt, st in lk.states if st.is_failure), "TXT")
            return lk.target or tree.domain, rdtype, str(lk.error)
        if lk.child is not None and lk.child.truncated:
            return lk.child.domain, "TXT", "truncated"
        if (
            lk.child is None
            and not lk.resolved
            and lk.target is not None
            and lk.term.name in _CAP_RDTYPE
        ):
            # Target known but never queried: only the query cap does that (ptr, macros and
            # invalid targets have no target).
            return lk.target, _CAP_RDTYPE[lk.term.name], "truncated"
        if lk.child is not None:
            queue.extend(lk.child.lookups)
    return None


def _one_esp_lookups(run: _Run, esp: EspProfile, tree: SpfTree) -> None:
    """M6-19: with one ESP, a DNS failure on (or below) its include host is never swallowed."""
    if any(
        f.code == "ESP_DNS_ERROR"
        and f.params.get("part") == "spf.includes"
        and f.params.get("esp") == esp.name
        for f in run.findings
    ):
        return
    failure = _include_failure(tree, frozenset(esp.spf_includes))
    if failure is not None:
        run.dns_error(esp, "spf.lookups", *failure)


# --- DKIM ---------------------------------------------------------------------------------------


def _dkim_error(
    run: _Run,
    esp: EspProfile,
    part: str,
    sel: DkimSelector,
    name: str,
    rdtype: str,
    failure: str,
    **extra: Any,
) -> dict[str, Any]:
    """Report the DNS failure and return the `error` part with its detail (name, record type,
    failure state), kept in `data` even when a later DKIM set decides the result (M6-23)."""
    run.dns_error(esp, part, name, rdtype, failure)
    return _part("error", selector=sel.name, name=name, rdtype=rdtype, failure=failure, **extra)


async def _follow_cname(
    run: _Run, esp: EspProfile, sel: DkimSelector, name: str, first: str, part: str
) -> dict[str, Any]:
    """Follow the chain from `first` until a target fits the selector's pattern."""
    pattern = sel.target_pattern
    chain = [first]
    seen = {name, first}
    current = first
    reason = "chain_end"
    while True:
        if pattern is None or pattern.matches(current):
            return _part("ok", selector=sel.name, chain=chain)
        if not current:
            reason = "empty_target"
            break
        if len(chain) >= MAX_CNAME_HOPS:
            reason = "hop_limit"
            break
        try:
            nxt = await fetch_cname(run.ctx.resolver, current)
        except InvalidDomainName:
            return _dkim_error(run, esp, part, sel, current, "CNAME", "invalid_name", chain=chain)
        if not nxt.evaluated:
            return _dkim_error(run, esp, part, sel, current, "CNAME", str(nxt.state), chain=chain)
        if nxt.target is None:
            break
        chain.append(nxt.target)
        if nxt.target in seen:
            reason = "loop"
            break
        seen.add(nxt.target)
        current = nxt.target
    run.findings.append(
        finding(
            "ESP_DKIM_TARGET_MISMATCH",
            "medium",
            {
                "esp": esp.name,
                "selector": sel.name,
                "name": name,
                "pattern": str(pattern),
                "reason": reason,
            },
            chain,
        )
    )
    return _part("mismatch", selector=sel.name, chain=chain, reason=reason)


def _key_problem(records: Sequence[str]) -> str | None:
    """Why the TXT records at an alternative `txt` selector are not one usable DKIM key."""
    if len(records) != 1:
        return "multiple_records"
    key = parse_dkim_key(records[0])
    if not key.is_valid:
        return "syntax_error"
    if key.revoked:
        return "revoked"
    return None


async def _dkim_one(
    run: _Run,
    esp: EspProfile,
    sel: DkimSelector,
    part_prefix: str = "dkim.selectors",
    *,
    validate_key: bool = False,
) -> dict[str, Any]:
    part = f"{part_prefix}.{sel.name}"
    name = f"{sel.name}._domainkey.{run.domain}"
    params = {"esp": esp.name, "selector": sel.name, "name": name, "type": sel.type.upper()}
    try:
        if sel.type == "cname":
            cname = await fetch_cname(run.ctx.resolver, name)
            if not cname.evaluated:
                return _dkim_error(run, esp, part, sel, name, "CNAME", str(cname.state))
            if cname.target is not None:
                return await _follow_cname(run, esp, sel, name, cname.target, part)
            if cname.state == "nodata":
                txt = await fetch_txt(run.ctx.resolver, name)
                if not txt.evaluated:
                    return _dkim_error(run, esp, part, sel, name, "TXT", str(txt.state))
                if txt.records:
                    run.findings.append(
                        finding("ESP_DKIM_WRONG_TYPE", "medium", {**params, "found": "TXT"})
                    )
                    return _part("wrong_type", selector=sel.name)
        else:
            txt = await fetch_txt(run.ctx.resolver, name)
            if not txt.evaluated:
                return _dkim_error(run, esp, part, sel, name, "TXT", str(txt.state))
            if txt.records:
                problem = _key_problem(txt.records) if validate_key else None
                if problem is not None:
                    return _part("invalid", selector=sel.name, reason=problem)
                return _part("ok", selector=sel.name)
            if txt.state == "nodata":
                cname = await fetch_cname(run.ctx.resolver, name)
                if not cname.evaluated:
                    return _dkim_error(run, esp, part, sel, name, "CNAME", str(cname.state))
                if cname.target is not None:
                    run.findings.append(
                        finding("ESP_DKIM_WRONG_TYPE", "medium", {**params, "found": "CNAME"})
                    )
                    return _part("wrong_type", selector=sel.name)
    except InvalidDomainName:
        return _dkim_error(run, esp, part, sel, name, sel.type.upper(), "invalid_name")
    run.findings.append(finding("ESP_DKIM_RECORD_MISSING", "high", params))
    return _part("missing", selector=sel.name)


def _options_text(sels: Sequence[DkimSelector]) -> str:
    return ", ".join(f"{s.name} ({s.type.upper()})" for s in sels)


async def _dkim_set(
    run: _Run, esp: EspProfile, sels: Sequence[DkimSelector], prefix: str, *, validate_key: bool
) -> tuple[list[dict[str, Any]], _Run]:
    """Evaluate one selector set on its own collector (findings decided by the caller)."""
    sub = _Run(run.ctx, run.domain)
    parts = [
        await _dkim_one(sub, esp, s, prefix, validate_key=validate_key)
        for s in sorted(sels, key=lambda s: s.name)
    ]
    return parts, sub


async def _dkim_with_alternatives(
    run: _Run, esp: EspProfile, section: dict[str, Any], skipped: list[str]
) -> None:
    """Primary selectors OR one alternative set (module docstring)."""
    sorted_primary = sorted(esp.dkim_selectors, key=lambda s: s.name)
    verified = [s for s in sorted_primary if esp.is_verified(f"dkim.selectors.{s.name}")]
    primary_verified = len(verified) == len(sorted_primary)
    evaluated, sub = await _dkim_set(run, esp, verified, "dkim.selectors", validate_key=False)
    done = {p["selector"]: p for p in evaluated}
    primary: list[dict[str, Any]] = []
    for s in sorted_primary:
        if s.name in done:
            primary.append(done[s.name])
        else:
            primary.append(_part("skipped_unverified", selector=s.name))
            skipped.append(f"dkim.selectors.{s.name}")
    section["dkim"] = primary
    tried: list[_Run] = [sub]
    unverified_set = not primary_verified
    satisfied_by: str | None = None
    if primary_verified and all(p["state"] == "ok" for p in primary):
        satisfied_by = "selectors"
    alternatives: list[list[dict[str, Any]]] = []
    for i, alt in enumerate(esp.dkim_alternatives):
        names = sorted(s.name for s in alt)
        if satisfied_by is not None:
            alternatives.append([_part("not_required", selector=n) for n in names])
            continue
        paths = [f"dkim.alternatives.{n}" for n in names]
        if not all(esp.is_verified(p) for p in paths):
            unverified_set = True
            skipped.extend(paths)
            alternatives.append([_part("skipped_unverified", selector=n) for n in names])
            continue
        parts, alt_run = await _dkim_set(run, esp, alt, "dkim.alternatives", validate_key=True)
        alternatives.append(parts)
        tried.append(alt_run)
        if all(p["state"] == "ok" for p in parts):
            satisfied_by = f"alternatives.{i}"
    section["dkim_alternatives"] = alternatives
    section["dkim_satisfied_by"] = satisfied_by
    if satisfied_by is not None:
        return
    failed = [r for r in tried if not r.evaluated]
    if failed:
        run.evaluated = False
        run.findings.extend(f for r in failed for f in r.findings if f.code == "ESP_DNS_ERROR")
        return
    if unverified_set:
        return
    run.findings.append(
        finding(
            "ESP_DKIM_NO_OPTION_SATISFIED",
            "high",
            {
                "esp": esp.name,
                "domain": run.domain,
                "selectors": _options_text(sorted_primary),
                "alternatives": "; ".join(
                    _options_text(sorted(alt, key=lambda s: s.name))
                    for alt in esp.dkim_alternatives
                ),
            },
            [f"{s.name}._domainkey.{run.domain}" for s in sorted_primary]
            + [
                f"{s.name}._domainkey.{run.domain}"
                for alt in esp.dkim_alternatives
                for s in sorted(alt, key=lambda s: s.name)
            ],
        )
    )


# --- return path / tracking domain --------------------------------------------------------------

_HOST_PARTS: Final[dict[str, tuple[str, str, Severity]]] = {
    "return_path": ("ESP_RETURN_PATH_MISSING", "ESP_RETURN_PATH_MISMATCH", "medium"),
    "tracking_domain": ("ESP_TRACKING_MISSING", "ESP_TRACKING_MISMATCH", "low"),
}


async def _host_part(
    run: _Run, esp: EspProfile, part: str, expect: RecordExpectation, host: str | None
) -> dict[str, Any]:
    if host is None:
        run.findings.append(
            finding("ESP_HOST_NOT_CONFIGURED", "info", {"esp": esp.name, "part": part})
        )
        return _part("not_configured")
    rdtype = expect.type.upper()
    try:
        name = to_dns_name(host)
        result = await run.ctx.resolver.resolve(DnsQuestion(name, rdtype))
    except InvalidDomainName:
        run.dns_error(esp, part, host, rdtype, "invalid_name")
        return _part("error", host=host)
    state, evaluated, records, _ = classify(result, rdtype)
    if not evaluated:
        run.dns_error(esp, part, name, rdtype, str(state))
        return _part("error", host=name)
    if records:
        return _part("ok", host=name)
    missing_code, mismatch_code, severity = _HOST_PARTS[part]
    params = {"esp": esp.name, "host": name, "type": rdtype}
    if expect.notes_key:
        params["notes_key"] = expect.notes_key
    sev: Severity = "info" if expect.optional else severity
    if state == "nxdomain":
        run.findings.append(finding(missing_code, sev, params))
        return _part("missing", host=name)
    run.findings.append(finding(mismatch_code, sev, params))
    return _part("mismatch", host=name)


# --- per profile --------------------------------------------------------------------------------


async def _profile(run: _Run, esp: EspProfile, hosts: EspHosts) -> dict[str, Any]:
    section: dict[str, Any] = {"id": esp.id, "name": esp.name, "status": esp.status}
    skipped: list[str] = []
    if esp.status == "unverified":
        run.findings.append(
            finding(
                "ESP_PROFILE_UNVERIFIED",
                "info",
                {"esp": esp.name},
                sorted(esp.unverified_fields),
            )
        )

    if not esp.spf_includes:
        section["spf"] = None
    elif esp.is_verified("spf.includes"):
        section["spf"] = await _spf(run, esp)
    else:
        section["spf"] = _part("skipped_unverified")
        skipped.append("spf.includes")

    if esp.dkim_alternatives:
        await _dkim_with_alternatives(run, esp, section, skipped)
    else:
        dkim: list[dict[str, Any]] = []
        for sel in sorted(esp.dkim_selectors, key=lambda s: s.name):
            if esp.is_verified(f"dkim.selectors.{sel.name}"):
                dkim.append(await _dkim_one(run, esp, sel))
            else:
                dkim.append(_part("skipped_unverified", selector=sel.name))
                skipped.append(f"dkim.selectors.{sel.name}")
        section["dkim"] = dkim

    for part, expect, host in (
        ("return_path", esp.return_path, hosts.return_path_host),
        ("tracking_domain", esp.tracking_domain, hosts.tracking_host),
    ):
        if expect is None:
            section[part] = None
        elif esp.is_verified(part):
            section[part] = await _host_part(run, esp, part, expect, host)
        else:
            section[part] = _part("skipped_unverified")
            skipped.append(part)

    pitfalls: list[str] = []
    for p in esp.pitfalls:
        if not esp.is_verified(f"pitfalls.{p.code}"):
            skipped.append(f"pitfalls.{p.code}")
            continue
        pitfalls.append(p.code)
        run.findings.append(
            finding(
                "ESP_PITFALL",
                "info",
                {
                    "esp": esp.name,
                    "pitfall": p.code,
                    "notes_key": p.notes_key,
                    "declared_severity": p.severity,
                },
            )
        )
    section["pitfalls"] = pitfalls
    section["skipped"] = sorted(skipped)
    return section


class EspProfileCheck:
    """`Check` for the ESPs assigned to one domain. `assignments` maps profile id -> hosts; a
    profile without an entry has both hosts unknown. `candidates`: the loaded profiles that are
    not assigned, for detection (M6-13); None turns detection off."""

    id = "esp"

    def __init__(
        self,
        profiles: Sequence[EspProfile],
        assignments: Mapping[str, EspHosts] | None = None,
        candidates: Sequence[EspProfile] | None = None,
    ) -> None:
        ids = [p.id for p in profiles]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate ESP profile id")
        extra = set(assignments or {}) - set(ids)
        if extra:
            raise ValueError(f"assignment for an ESP profile not given: {sorted(extra)}")
        if candidates is not None:
            cids = [p.id for p in candidates]
            if len(set(cids)) != len(cids):
                raise ValueError("duplicate ESP candidate id")
            if set(cids) & set(ids):
                raise ValueError("an assigned ESP profile is also a detection candidate")
        self._profiles = tuple(sorted(profiles, key=lambda p: p.id))
        self._hosts = dict(assignments or {})
        self._candidates = None if candidates is None else tuple(candidates)

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        findings: list[Finding]
        data: dict[str, Any]
        evaluated = True
        if not self._profiles and self._candidates is None:
            findings = [finding("ESP_NONE_ASSIGNED", "info")]
            data = {"esps": []}
        else:
            try:
                domain = to_ascii_domain(target.domain)
            except InvalidDomainName:
                domain = None
            if domain is None:
                findings = [
                    finding(
                        "ESP_DNS_ERROR",
                        "low",
                        {
                            "esp": "-",
                            "part": "domain",
                            "name": target.domain,
                            "rdtype": "-",
                            "state": "invalid_name",
                        },
                    )
                ]
                data = {"esps": []}
                evaluated = False
            else:
                run = _Run(ctx, domain)
                if not self._profiles:
                    run.findings.append(finding("ESP_NONE_ASSIGNED", "info"))
                sections = [
                    await _profile(run, p, self._hosts.get(p.id, EspHosts()))
                    for p in self._profiles
                ]
                await _spf_budget(run, self._profiles)
                data = {"esps": sections}
                if self._candidates is not None:
                    found = await detect(
                        ctx, domain, self._candidates, self._profiles, lambda: _spf_view(run)
                    )
                    run.findings.extend(found.findings)
                    run.evaluated = run.evaluated and found.evaluated
                    data["detection"] = found.data
                findings, evaluated = run.findings, run.evaluated
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=findings,
            evaluated=evaluated,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            data=data,
        )
