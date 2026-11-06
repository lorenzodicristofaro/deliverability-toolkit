"""DMARC external report destination authorization (M3-11), RFC 7489 section 7.1.

Deciding text, quoted from RFC 7489 section 7.1 (https://www.rfc-editor.org/rfc/rfc7489.txt,
read 2026-11-06):

- When to check: "When a Mail Receiver discovers a DMARC policy in the DNS, and the
  Organizational Domain at which that record was discovered is not identical to the
  Organizational Domain of the host part of the authority component of a [URI] specified in
  the "rua" or "ruf" tag, the following verification steps are to be taken". Same
  organizational domain (full PSL, ``app.core.org_domain``): no query.
- Query name: "1. Extract the host portion of the authority component of the URI. Call this
  the "destination host" [...] 2. Prepend the string "_report._dmarc". 3. Prepend the domain
  name from which the policy was retrieved, after conversion to an A-label if needed."
  The prefix is therefore the domain where the policy was found (the organizational domain
  when the policy was inherited), not necessarily the checked domain.
- DNS failure: "4. [...] If the result of this request is a temporary DNS error of some kind
  (e.g., a timeout), the Mail Receiver MAY elect to temporarily fail the delivery so the
  verification test can be repeated later." Here: the destination is ``unverified`` and the
  check status is ``error``, never "unauthorized".
- Records: "5. [...] In particular, the "v=DMARC1" tag is mandatory and MUST appear first in
  the list. Discard any that do not pass this test. 6. If the result includes no TXT resource
  records that pass basic parsing, a positive determination of the external reporting
  relationship cannot be made; stop. 7. If at least one TXT resource record remains in the
  set after parsing, then the external reporting arrangement was authorized by the Report
  Receiver." Authorization records normally carry only ``v=DMARC1``, so the parser's
  ``missing_policy`` issue is ignored. Interpretation (the RFC does not define "basic
  parsing" further): a record that is not a ``tag=value`` list (``invalid_tag``,
  ``empty_tag``) is discarded; other parse errors are reported but do not void the record.
- Override: "8. [...] However, to prevent loops or indirect abuse, the overriding URI MUST use
  the same destination host from the first step." and "if the confirming record includes a
  URI whose host is again different than the domain publishing that override, the Mail
  Receiver generating the report MUST NOT generate a report to either the original or the
  override URI." An override (``rua``/``ruf`` in the authorization record, same tag) whose
  host is not the destination host makes the destination ``unauthorized``.
- Unconfirmed: "Where the above algorithm fails to confirm that the external reporting was
  authorized by the Report Receiver, the URI MUST be ignored by the Mail Receiver generating
  the report."
- Wildcard: "A Report Receiver that is willing to receive reports for any domain can use a
  wildcard DNS record. For example, a TXT resource record at "*._report._dmarc.example.com"
  containing at least "v=DMARC1" confirms that example.com is willing to receive DMARC
  reports for any domain." This is a DNS wildcard (synthesised by the destination's name
  servers), so only the exact constructed name is queried; a literal ``*`` name is never
  queried.

Bounds: at most :data:`MAX_DESTINATION_LOOKUPS` distinct external destination hosts are
queried per run (the parser allows up to 20 URIs); the rest are reported ``not_checked`` with
``DMARC_EXTERNAL_TOO_MANY_DESTINATIONS``. A ``mailto`` URI listing several addresses has no
single host: it is ``not_checkable`` and never counts as authorized. Non-``mailto`` schemes are
skipped with a note in the data.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.checks.dnsutil import fetch_txt
from app.checks.models import Finding, finding
from app.core.domain_names import InvalidDomainName
from app.core.org_domain import organizational_domain
from app.dns.types import Resolver
from app.parsers.dmarc import (
    EMPTY_TAG,
    INVALID_TAG,
    MISSING_POLICY,
    DmarcRecord,
    DmarcUri,
    is_dmarc_record,
    parse_dmarc,
)

CODES: tuple[str, ...] = (
    "DMARC_EXTERNAL_UNAUTHORIZED",
    "DMARC_EXTERNAL_AUTH_UNVERIFIED",
    "DMARC_EXTERNAL_TOO_MANY_DESTINATIONS",
    "DMARC_EXTERNAL_NOT_CHECKABLE",
    "DMARC_EXTERNAL_AUTH_RECORD_INVALID",
)

MAX_DESTINATION_LOOKUPS = 8

# Per-destination states stored in ``data["report_destinations"][i]["state"]``.
SAME_ORG = "same_org"
AUTHORIZED = "authorized"  # DMARC_EXTERNAL_AUTHORIZED: data only, never a finding
UNAUTHORIZED = "unauthorized"
UNVERIFIED = "unverified"
NOT_CHECKABLE = "not_checkable"
NOT_CHECKED = "not_checked"
SKIPPED = "skipped"
INVALID = "invalid"

_NOT_TAG_LIST = frozenset({INVALID_TAG, EMPTY_TAG})


@dataclass(frozen=True, slots=True)
class ExternalResult:
    findings: tuple[Finding, ...]
    evaluated: bool
    destinations: tuple[dict[str, Any], ...]


@dataclass(slots=True)
class _Lookup:
    query: str
    state: str
    dns_state: str | None = None
    errors: list[str] = field(default_factory=list)
    overrides: dict[str, list[DmarcUri]] = field(default_factory=lambda: {"rua": [], "ruf": []})


def _org(name: str) -> str | None:
    try:
        return organizational_domain(name)
    except InvalidDomainName:
        return None


async def _lookup(resolver: Resolver, policy_domain: str, dest: str) -> _Lookup:
    qname = f"{policy_domain}._report._dmarc.{dest}"
    try:
        fetch = await fetch_txt(resolver, qname)
    except InvalidDomainName:  # e.g. the constructed name exceeds 253 octets
        return _Lookup(qname, NOT_CHECKABLE, dns_state="invalid_name")
    if not fetch.evaluated:
        return _Lookup(qname, UNVERIFIED, dns_state=fetch.state.value)
    out = _Lookup(qname, UNAUTHORIZED, dns_state=fetch.state.value)
    for text in fetch.records:
        if not is_dmarc_record(text):  # step 5: v=DMARC1 must come first
            continue
        rec = parse_dmarc(text)
        errors = [
            f"{i.code}: {i.term}" if i.term else i.code
            for i in rec.issues
            if i.severity == "error" and i.code != MISSING_POLICY
        ]
        out.errors.extend(errors)
        if any(i.code in _NOT_TAG_LIST for i in rec.issues):
            continue  # not a tag=value list: fails basic parsing (step 6)
        out.state = AUTHORIZED
        out.overrides["rua"].extend(rec.rua)
        out.overrides["ruf"].extend(rec.ruf)
    return out


def _entry(tag: str, uri: DmarcUri) -> dict[str, Any]:
    return {"tag": tag, "uri": uri.uri, "destination": uri.domain, "external": None}


async def check_external_destinations(
    resolver: Resolver, policy_domain: str, record: DmarcRecord
) -> ExternalResult:
    """Verify every rua/ruf destination of ``record`` (found at ``policy_domain``, ASCII)."""
    policy_org = _org(policy_domain)
    findings: dict[tuple[str, str], Finding] = {}
    entries: list[dict[str, Any]] = []
    pending: list[tuple[dict[str, Any], str]] = []  # (entry, tag) awaiting a lookup
    external: dict[str, None] = {}  # ordered set of destination hosts

    for tag, uris in (("rua", record.rua), ("ruf", record.ruf)):
        for uri in uris:
            e = _entry(tag, uri)
            entries.append(e)
            if not uri.valid:
                e["state"] = INVALID  # reported by DMARC_SYNTAX_ERROR (M3-10)
            elif uri.scheme != "mailto":
                e.update(state=SKIPPED, reason="unsupported_scheme")
            elif uri.domain is None:
                e.update(state=NOT_CHECKABLE, reason="multiple_addresses")
                findings[("DMARC_EXTERNAL_NOT_CHECKABLE", uri.uri)] = finding(
                    "DMARC_EXTERNAL_NOT_CHECKABLE", "low", {"uri": uri.uri}
                )
            elif policy_org is not None and _org(uri.domain) == policy_org:
                e.update(external=False, state=SAME_ORG)
            else:
                e["external"] = True
                pending.append((e, tag))
                external[uri.domain] = None

    hosts = list(external)
    checked = hosts[:MAX_DESTINATION_LOOKUPS]
    if len(hosts) > len(checked):
        findings[("DMARC_EXTERNAL_TOO_MANY_DESTINATIONS", "")] = finding(
            "DMARC_EXTERNAL_TOO_MANY_DESTINATIONS",
            "low",
            {"count": len(hosts), "limit": MAX_DESTINATION_LOOKUPS},
        )
    results = await asyncio.gather(*(_lookup(resolver, policy_domain, h) for h in checked))
    lookups = dict(zip(checked, results, strict=True))

    evaluated = True
    for e, tag in pending:
        dest: str = e["destination"]
        lk = lookups.get(dest)
        if lk is None:
            e.update(state=NOT_CHECKED, reason="lookup_limit")
            continue
        e["query"] = lk.query
        if lk.errors:
            findings[("DMARC_EXTERNAL_AUTH_RECORD_INVALID", dest)] = finding(
                "DMARC_EXTERNAL_AUTH_RECORD_INVALID",
                "low",
                {"destination": dest, "query": lk.query},
                lk.errors,
            )
        if lk.state == UNVERIFIED:
            evaluated = False
            e.update(state=UNVERIFIED, dns_state=lk.dns_state)
            findings[("DMARC_EXTERNAL_AUTH_UNVERIFIED", dest)] = finding(
                "DMARC_EXTERNAL_AUTH_UNVERIFIED",
                "medium",
                {"destination": dest, "query": lk.query, "state": lk.dns_state},
            )
            continue
        if lk.state == NOT_CHECKABLE:
            e.update(state=NOT_CHECKABLE, reason="invalid_query_name")
            findings[("DMARC_EXTERNAL_NOT_CHECKABLE", e["uri"])] = finding(
                "DMARC_EXTERNAL_NOT_CHECKABLE", "low", {"uri": e["uri"]}
            )
            continue
        state = lk.state
        overrides = lk.overrides[tag]
        if overrides:
            e["override"] = [o.uri for o in overrides]
            if state == AUTHORIZED and any(o.domain != dest for o in overrides):
                state = UNAUTHORIZED  # step 8: override must use the same destination host
                e["reason"] = "override_host_mismatch"
        e["state"] = state
        if state == UNAUTHORIZED:
            findings[("DMARC_EXTERNAL_UNAUTHORIZED", dest)] = finding(
                "DMARC_EXTERNAL_UNAUTHORIZED", "medium", {"destination": dest, "query": lk.query}
            )

    return ExternalResult(tuple(findings.values()), evaluated, tuple(entries))
