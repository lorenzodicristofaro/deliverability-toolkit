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
  present: a failing lookup of the ESP's own record is the SPF check's business. A host not found
  while the tree has DNS failures or was truncated by a cap is not evaluated (`ESP_DNS_ERROR`).
  Otherwise, a host not found while some record in the tree is a permerror that `resolve_spf`
  does not follow (several SPF records at one name, or a syntax error) is not evaluated either:
  state `permerror`, `ESP_SPF_PERMERROR` naming that record; never "missing".
- `dkim.selectors.<name>` at `<name>._domainkey.<domain>`:
  - `cname`: NXDOMAIN is missing; NODATA is `wrong_type` when the name holds a TXT record, else
    missing. A CNAME is followed hop by hop (at most MAX_CNAME_HOPS, loops stop it) until one
    target fits `target_pattern` (any target fits when there is no pattern); none fitting is
    `ESP_DKIM_TARGET_MISMATCH`, whose `reason` says why the chain stopped: `chain_end`,
    `loop`, `empty_target` or `hop_limit` (the chain may continue past the limit).
  - `txt`: a TXT record is ok (also when served through a CNAME); none and a CNAME at the name
    is `wrong_type`; none and no CNAME is missing.
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

No assigned profile: one `ESP_NONE_ASSIGNED` info finding. `CheckResult` derives `ok` from an
empty finding list and accepts no other status for it, so "info with no findings" cannot be
expressed without changing the shared model.

`data["esps"]` has one section per profile, sorted by id; selectors are sorted by name.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from app.checks.dnsutil import classify, fetch_cname, fetch_txt
from app.checks.models import CheckContext, CheckResult, Finding, Severity, Target, finding
from app.checks.spf_tree import SpfTree, resolve_spf
from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_dns_name
from app.dns.types import DnsQuestion
from app.esp.profile import DkimSelector, EspProfile, RecordExpectation

CODES: tuple[str, ...] = (
    "ESP_SPF_INCLUDE_MISSING",
    "ESP_SPF_PERMERROR",
    "ESP_DKIM_RECORD_MISSING",
    "ESP_DKIM_TARGET_MISMATCH",
    "ESP_DKIM_WRONG_TYPE",
    "ESP_RETURN_PATH_MISSING",
    "ESP_RETURN_PATH_MISMATCH",
    "ESP_TRACKING_MISSING",
    "ESP_TRACKING_MISMATCH",
    "ESP_HOST_NOT_CONFIGURED",
    "ESP_PROFILE_UNVERIFIED",
    "ESP_PITFALL",
    "ESP_NONE_ASSIGNED",
    "ESP_DNS_ERROR",
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


# --- DKIM ---------------------------------------------------------------------------------------


async def _follow_cname(
    run: _Run, esp: EspProfile, sel: DkimSelector, name: str, first: str
) -> dict[str, Any]:
    """Follow the chain from `first` until a target fits the selector's pattern."""
    part = f"dkim.selectors.{sel.name}"
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
            run.dns_error(esp, part, current, "CNAME", "invalid_name")
            return _part("error", selector=sel.name, chain=chain)
        if not nxt.evaluated:
            run.dns_error(esp, part, current, "CNAME", str(nxt.state))
            return _part("error", selector=sel.name, chain=chain)
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


async def _dkim_one(run: _Run, esp: EspProfile, sel: DkimSelector) -> dict[str, Any]:
    part = f"dkim.selectors.{sel.name}"
    name = f"{sel.name}._domainkey.{run.domain}"
    params = {"esp": esp.name, "selector": sel.name, "name": name, "type": sel.type.upper()}
    try:
        if sel.type == "cname":
            cname = await fetch_cname(run.ctx.resolver, name)
            if not cname.evaluated:
                run.dns_error(esp, part, name, "CNAME", str(cname.state))
                return _part("error", selector=sel.name)
            if cname.target is not None:
                return await _follow_cname(run, esp, sel, name, cname.target)
            if cname.state == "nodata":
                txt = await fetch_txt(run.ctx.resolver, name)
                if not txt.evaluated:
                    run.dns_error(esp, part, name, "TXT", str(txt.state))
                    return _part("error", selector=sel.name)
                if txt.records:
                    run.findings.append(
                        finding("ESP_DKIM_WRONG_TYPE", "medium", {**params, "found": "TXT"})
                    )
                    return _part("wrong_type", selector=sel.name)
        else:
            txt = await fetch_txt(run.ctx.resolver, name)
            if not txt.evaluated:
                run.dns_error(esp, part, name, "TXT", str(txt.state))
                return _part("error", selector=sel.name)
            if txt.records:
                return _part("ok", selector=sel.name)
            if txt.state == "nodata":
                cname = await fetch_cname(run.ctx.resolver, name)
                if not cname.evaluated:
                    run.dns_error(esp, part, name, "CNAME", str(cname.state))
                    return _part("error", selector=sel.name)
                if cname.target is not None:
                    run.findings.append(
                        finding("ESP_DKIM_WRONG_TYPE", "medium", {**params, "found": "CNAME"})
                    )
                    return _part("wrong_type", selector=sel.name)
    except InvalidDomainName:
        run.dns_error(esp, part, name, sel.type.upper(), "invalid_name")
        return _part("error", selector=sel.name)
    run.findings.append(finding("ESP_DKIM_RECORD_MISSING", "high", params))
    return _part("missing", selector=sel.name)


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
    profile without an entry has both hosts unknown."""

    id = "esp"

    def __init__(
        self,
        profiles: Sequence[EspProfile],
        assignments: Mapping[str, EspHosts] | None = None,
    ) -> None:
        ids = [p.id for p in profiles]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate ESP profile id")
        extra = set(assignments or {}) - set(ids)
        if extra:
            raise ValueError(f"assignment for an ESP profile not given: {sorted(extra)}")
        self._profiles = tuple(sorted(profiles, key=lambda p: p.id))
        self._hosts = dict(assignments or {})

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        findings: list[Finding]
        data: dict[str, Any]
        evaluated = True
        if not self._profiles:
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
                sections = [
                    await _profile(run, p, self._hosts.get(p.id, EspHosts()))
                    for p in self._profiles
                ]
                findings, data, evaluated = run.findings, {"esps": sections}, run.evaluated
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=findings,
            evaluated=evaluated,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            data=data,
        )
