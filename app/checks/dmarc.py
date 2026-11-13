"""DMARC check (M3-10): policy discovery (RFC 7489 section 6.6.3) and findings.

Discovery: query ``_dmarc.<domain>``; TXT records that do not start with ``v=DMARC1`` are
ignored; if none is left and the domain is a strict subdomain of its organizational domain
(full PSL), query ``_dmarc.<organizational domain>``. Several DMARC records at one name end
discovery (RFC: DMARC processing is not applied). A DNS failure at any lookup the check
depends on gives status ``error`` (``evaluated=False``), never "missing".

Missing or invalid ``p`` (or an invalid ``sp``), RFC 7489 section 6.6.3 step 6: with at least
one syntactically valid ``rua`` URI a receiver SHOULD act as if ``p=none`` was retrieved;
otherwise it applies no DMARC processing.
"""

from __future__ import annotations

import time
from typing import Any

from app.checks.dmarc_external import CODES as EXTERNAL_CODES
from app.checks.dmarc_external import check_external_destinations
from app.checks.dnsutil import fetch_txt
from app.checks.models import CheckContext, CheckResult, Finding, Target, finding
from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.core.org_domain import organizational_domain
from app.parsers.dmarc import DmarcRecord, is_dmarc_record, parse_dmarc

CODES: tuple[str, ...] = (
    "DMARC_MISSING",
    "DMARC_MULTIPLE_RECORDS",
    "DMARC_SYNTAX_ERROR",
    "DMARC_POLICY_NONE",
    "DMARC_POLICY_QUARANTINE",
    "DMARC_SUBDOMAIN_POLICY_WEAKER",
    "DMARC_PCT_PARTIAL",
    "DMARC_NO_RUA",
    "DMARC_RUF_PRESENT",
    "DMARC_ALIGNMENT_STRICT",
    "DMARC_INHERITED_FROM_ORG",
    "DMARC_DNS_ERROR",
    "DMARC_P_ASSUMED_NONE",
    "DMARC_NO_USABLE_POLICY",
    *EXTERNAL_CODES,
)

_RANK = {"none": 0, "quarantine": 1, "reject": 2}


class DmarcCheck:
    id = "dmarc"

    async def run(self, ctx: CheckContext, target: Target) -> CheckResult:
        started = ctx.clock()
        t0 = time.monotonic()
        findings, evaluated, data = await self._evaluate(ctx, target)
        return CheckResult.build(
            check_id=self.id,
            target=target.domain,
            findings=findings,
            evaluated=evaluated,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
            data=data,
        )

    async def _evaluate(
        self, ctx: CheckContext, target: Target
    ) -> tuple[list[Finding], bool, dict[str, Any]]:
        try:
            domain = to_ascii_domain(target.domain)
        except InvalidDomainName:
            # Single label or malformed: no organizational domain (no fallback); the lookup
            # below validates the name and reports an error for malformed input.
            domain = target.domain.strip().lower().removesuffix(".")
        try:
            org = organizational_domain(domain)
        except InvalidDomainName:
            org = None  # no fallback; never crash
        names = [domain]
        if org is not None and org != domain:
            names.append(org)

        found_at: str | None = None
        records: list[str] = []
        for name in names:
            qname = f"_dmarc.{name}"
            try:
                fetch = await fetch_txt(ctx.resolver, qname)
            except InvalidDomainName:
                err = finding("DMARC_DNS_ERROR", "medium", {"name": qname, "state": "invalid_name"})
                return [err], False, {}
            if not fetch.evaluated:
                err = finding("DMARC_DNS_ERROR", "medium", {"name": qname, "state": fetch.state})
                return [err], False, {"queried": qname}
            records = [r for r in fetch.records if is_dmarc_record(r)]
            if records:
                found_at = name
                break

        if not records or found_at is None:
            return [finding("DMARC_MISSING", "medium")], True, {"found": False}
        inherited = found_at != domain
        data: dict[str, Any] = {"found": True, "found_at": found_at, "inherited": inherited}
        if len(records) > 1:
            data["record_count"] = len(records)
            return (
                [
                    finding(
                        "DMARC_MULTIPLE_RECORDS", "medium", {"name": f"_dmarc.{found_at}"}, records
                    )
                ],
                True,
                data,
            )
        data["record"] = records[0]
        rec = parse_dmarc(records[0])
        out, evaluated, data = self._analyse(rec, inherited, found_at, data)
        # RFC 7489 section 7.1 (M3-11): external rua/ruf destinations need authorization.
        ext = await check_external_destinations(ctx.resolver, found_at, rec)
        data["report_destinations"] = list(ext.destinations)
        out.extend(ext.findings)
        if not ext.evaluated and not any(f.severity in ("critical", "high") for f in out):
            evaluated = False  # a destination could not be evaluated and nothing worse found
        return out, evaluated, data

    @staticmethod
    def _analyse(
        rec: DmarcRecord, inherited: bool, found_at: str, data: dict[str, Any]
    ) -> tuple[list[Finding], bool, dict[str, Any]]:
        out: list[Finding] = []
        errors = [
            f"{i.code}: {i.term}" if i.term else i.code for i in rec.issues if i.severity == "error"
        ]
        if errors:
            out.append(finding("DMARC_SYNTAX_ERROR", "medium", evidence=errors))
        if inherited:
            out.append(finding("DMARC_INHERITED_FROM_ORG", "info", {"found_at": found_at}))

        sp_invalid = rec.tag("sp") is not None and rec.sp is None
        has_valid_rua = any(u.valid for u in rec.rua)
        p = rec.p
        data["p"] = p
        data["sp"] = rec.sp
        if p is None or sp_invalid:
            # RFC 7489 section 6.6.3 step 6.
            if has_valid_rua:
                out.append(finding("DMARC_P_ASSUMED_NONE", "low"))
                data["effective_policy"] = "none"
            else:
                out.append(finding("DMARC_NO_USABLE_POLICY", "high"))
                data["effective_policy"] = None
            return out, True, data

        # RFC 7489 section 6.3: a subdomain that inherits the record is governed by sp when it
        # is present and valid, else by p. data["p"] and data["sp"] stay as published.
        applied = rec.sp if inherited and rec.sp is not None else p
        data.update(pct=rec.pct, effective_policy=applied)
        if applied == "none":
            out.append(finding("DMARC_POLICY_NONE", "low"))
        elif applied == "quarantine":
            out.append(finding("DMARC_POLICY_QUARANTINE", "info"))
        sp = rec.sp
        if not inherited and sp is not None and _RANK[sp] < _RANK[p]:
            out.append(finding("DMARC_SUBDOMAIN_POLICY_WEAKER", "low", {"p": p, "sp": sp}))
        pct = rec.pct
        if pct is not None and pct < 100 and applied != "none":
            out.append(finding("DMARC_PCT_PARTIAL", "low", {"pct": pct, "p": applied}))
        if not has_valid_rua:
            out.append(finding("DMARC_NO_RUA", "low"))
        if rec.ruf:
            out.append(finding("DMARC_RUF_PRESENT", "info"))
        if rec.adkim == "s" or rec.aspf == "s":
            out.append(
                finding(
                    "DMARC_ALIGNMENT_STRICT",
                    "info",
                    {"adkim": rec.adkim or "r", "aspf": rec.aspf or "r"},
                )
            )
        return out, True, data
