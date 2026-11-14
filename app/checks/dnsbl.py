"""DNSBL/URIBL check (M7-05): the `dnsbl` check over the M7-03 engine and the M7-04 list data.

Target: a domain name runs the `domain` lists; an IP literal runs the `ip` lists. An IP target is
accepted only where the caller allows it (the tenant-less free API route and the CLI, see
`app.services.checks`); the domain routes always pass a registered domain name. The IPs a
domain's MX/A records resolve to are not checked (out of scope, docs/CHECKS.md).

Enablement: a list with `default_enabled: false` runs only if its id is in `enabled_ids` (the
instance-admin setting). A disabled list is `not_applicable` (`list_disabled`): no query is sent.
The registered check has no enabled ids; every run path (API domain and free routes, CLI) loads the
instance's ids per request (M7-05c, `app.services.checks.with_dnsbl_enabled`) and runs a copy made
by `with_enabled`, which keeps the lists of the registered check. When the caller could not read
the enablement (`enabled_ids=None`, the CLI with an unreadable database), the check sends no query
and is `error` with `DNSBL_ENABLEMENT_UNAVAILABLE` (reason `enablement_unavailable`): which lists
should run is unknown, so neither a fallback set nor "nothing applicable" is reported.

Status mapping (never `ok` when any list could not be evaluated):
- any list `error` -> status `error` AND a finding naming the list: `DNSBL_LIST_REFUSED`
  (refused, resolver refused, blocked resolver), `DNSBL_LIST_UNVERIFIED` (list data unconfirmed)
  or `DNSBL_LIST_ERROR` (anything else), with the reason code as a param;
- any list `listed` -> `DNSBL_LISTED`, severity from the list's category (the highest one);
- nothing was evaluated at all (all lists disabled or not applicable) -> info finding
  `DNSBL_NO_LISTS_APPLICABLE`, so "no query was made" is never shown as a clean result;
- otherwise `ok`. An `info` outcome (a mapped informational code) is only recorded in `data`.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any, Final

from app.checks.dnsbl_engine import (
    DnsblEngine,
    DnsblQueryError,
    DnsblResult,
    Outcome,
    Reason,
    parse_target,
)
from app.checks.dnsbl_schema import DnsblList, load_dnsbl_lists
from app.checks.models import CheckContext, CheckResult, Finding, Severity, Target, finding

CODES: tuple[str, ...] = (
    "DNSBL_ENABLEMENT_UNAVAILABLE",
    "DNSBL_LISTED",
    "DNSBL_LIST_ERROR",
    "DNSBL_LIST_REFUSED",
    "DNSBL_LIST_UNVERIFIED",
    "DNSBL_NO_LISTS_APPLICABLE",
)

# Our own severity per category label (not vendor data); an unknown category is `medium`.
CATEGORY_SEVERITY: Final[dict[str, Severity]] = {
    "malware": "high",
    "phishing": "high",
    "cracked_site": "high",
    "spam_source": "medium",
    "spam_domain": "medium",
    "exploited_host": "medium",
    "abuse": "medium",
    "red": "medium",
    "dynamic_range": "low",
    "disposable_email": "low",
    "click_tracker": "low",
    "grey": "low",
    "policy": "low",
}
DEFAULT_SEVERITY: Final[Severity] = "medium"
_RANK: Final[dict[str, int]] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ENABLEMENT_UNAVAILABLE: Final = "enablement_unavailable"
_REFUSED_REASONS: Final = frozenset({Reason.refused, Reason.rcode_refused, Reason.blocked_resolver})


def is_enabled(lst: DnsblList, enabled_ids: frozenset[str]) -> bool:
    return lst.default_enabled or lst.id in enabled_ids


def listed_severity(categories: Iterable[str]) -> Severity:
    found = [CATEGORY_SEVERITY.get(c, DEFAULT_SEVERITY) for c in categories]
    return min(found, key=lambda s: _RANK[s]) if found else DEFAULT_SEVERITY


class DnsblCheck:
    id = "dnsbl"

    def __init__(
        self,
        lists: tuple[DnsblList, ...] | None = None,
        enabled_ids: Iterable[str] | None = (),
    ) -> None:
        self._lists = lists
        self._enabled = None if enabled_ids is None else frozenset(enabled_ids)

    def with_enabled(self, enabled_ids: Iterable[str] | None) -> DnsblCheck:
        """A copy over the same lists with `enabled_ids` in place of this check's ids; None means
        the enablement could not be read (the run is then `error`)."""
        return DnsblCheck(self._lists, enabled_ids)

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        try:
            parsed = parse_target(target.domain)
        except DnsblQueryError:
            raise ValueError("invalid DNSBL target") from None
        if self._enabled is None:
            return CheckResult.build(
                check_id=self.id,
                target=target.domain,
                findings=[
                    finding(
                        "DNSBL_ENABLEMENT_UNAVAILABLE",
                        "medium",
                        {"target": parsed.value, "reason": ENABLEMENT_UNAVAILABLE},
                    )
                ],
                evaluated=False,
                started_at=started,
                duration_ms=int((time.monotonic() - t0) * 1000),
                data={"lists": [], "reason": ENABLEMENT_UNAVAILABLE},
            )
        enabled = self._enabled
        lists = self._lists if self._lists is not None else load_dnsbl_lists()
        by_id = {lst.id: lst for lst in lists}
        active = [lst for lst in lists if is_enabled(lst, enabled)]
        results: list[DnsblResult] = [
            DnsblResult(
                list_id=lst.id,
                zone=lst.zone,
                target=parsed.value,
                outcome=Outcome.not_applicable,
                reason=Reason.list_disabled,
                unverified=not lst.verified,
            )
            for lst in lists
            if not is_enabled(lst, enabled)
        ]
        if active:
            report = await DnsblEngine(ctx.resolver, active).run([parsed])
            results.extend(report.results)

        findings: list[Finding] = []
        evaluated_any = False
        errored = False
        for r in results:
            if r.outcome is Outcome.not_applicable:
                continue
            evaluated_any = True
            if r.outcome is Outcome.error:
                errored = True
            f = _finding(by_id[r.list_id], r)
            if f is not None:
                findings.append(f)
        if not evaluated_any:
            findings.append(finding("DNSBL_NO_LISTS_APPLICABLE", "info", {"target": parsed.value}))
        data: dict[str, Any] = {
            "lists": [
                {
                    "id": r.list_id,
                    "outcome": r.outcome.value,
                    "reason": r.reason.value if r.reason else None,
                    "codes": list(r.codes),
                    "unverified": r.unverified,
                }
                for r in sorted(results, key=lambda x: x.list_id)
            ]
        }
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=findings,
            evaluated=not errored,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            data=data,
        )


def _finding(lst: DnsblList, r: DnsblResult) -> Finding | None:
    params: dict[str, Any] = {
        "list": lst.name,
        "list_id": lst.id,
        "target": r.target,
        "return_code": ", ".join(r.codes),
        "reason": r.reason.value if r.reason else "",
    }
    evidence = [f"{lst.zone} {c}" for c in r.codes]
    if r.outcome is Outcome.listed:
        params["category"] = ", ".join(r.categories)
        return finding("DNSBL_LISTED", listed_severity(r.categories), params, evidence)
    if r.outcome is not Outcome.error:
        return None
    if r.reason is Reason.list_unverified:
        return finding("DNSBL_LIST_UNVERIFIED", "medium", params, evidence)
    if r.reason in _REFUSED_REASONS:
        return finding("DNSBL_LIST_REFUSED", "medium", params, evidence)
    return finding("DNSBL_LIST_ERROR", "medium", params, evidence)
