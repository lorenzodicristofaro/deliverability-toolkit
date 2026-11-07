"""Pure message analysis service (M4-10).

``analyze_message(raw)`` composes the public APIs of the M4 parsers
(:mod:`app.parsers.message`, ``mime``, ``received``, ``authres``, ``arc``),
:func:`app.services.message_alignment.analyze_alignment` and
:mod:`app.services.message_findings` into one immutable :class:`MessageAnalysis`.

Hard rules (ticket M4-10):

- No clock, DNS, network, filesystem or DB. Nothing is stored and message content is never
  logged (this module has no logger).
- It never raises on bad input. Input the header parser rejects (empty, not bytes, over cap,
  NUL in the header block, too many headers, no header block) returns status ``error`` with a
  ``MSG_PARSER_LIMIT`` finding and no partial data (every section ``None``).
- A failure in one sub-parser is isolated: its section is ``None``, an error finding
  (``MSG_PARSER_LIMIT``, ``limits="<section>_failed"``) is added and the overall status is
  ``error``; the other sections are still produced. The findings builder then sees an empty
  stand-in for the failed section, so it may add "missing data" findings for it; the error
  finding is the authoritative signal.
- Every string taken from the message is passed through :func:`message_findings.excerpt`
  (control characters removed, bounded; NOT HTML-escaped, escaping is done at render time).
- The ``for <addr>`` clause of a Received hop is redacted from the returned ``raw`` excerpt.
- Output is deterministic and contains no mappings: the same bytes give byte-identical
  ``model_dump_json()``. That JSON is the single wire format for API, UI and CLI.

Findings are sorted and the overall status derived by :class:`app.checks.models.CheckResult`
(severity then code, ``derive_status``), with a fixed placeholder timestamp because the
analysis has no clock; only ``findings`` and ``status`` are taken from it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.checks.models import CheckResult, Finding, Status, finding
from app.parsers.arc import ArcChain, ArcSet, parse_arc_chain
from app.parsers.authres import AuthResHeader, parse_all_authentication_results
from app.parsers.message import (
    MAX_RAW_BYTES,
    HeaderBlock,
    MessageParseError,
    parse_header_block,
)
from app.parsers.mime import MimeSummary, parse_mime
from app.parsers.received import ReceivedChain, ReceivedHop, parse_received_chain
from app.parsers.spf import ParseIssue
from app.services.message_alignment import AlignmentReport, analyze_alignment
from app.services.message_findings import (
    build_message_findings,
    excerpt,
    rejected_input_findings,
)

__all__ = ["MessageAnalysis", "analyze_message", "redact_received"]

CHECK_ID = "message_analysis"
INVALID_INPUT = "invalid_input"
EMPTY_INPUT = "empty_input"
NO_HEADER_BLOCK = "no_header_block"
INTERNAL_ERROR = "internal_error"

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_FOR_CLAUSE = re.compile(r"\bfor\s", re.IGNORECASE)
_REDACTED = "for [redacted]"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True)


class Summary(_Model):
    subject: str | None
    from_header: str | None
    to_count: int
    cc_count: int
    date_header: str | None
    date_utc: str | None
    header_count: int
    size_bytes: int


class HopView(_Model):
    index: int
    raw: str
    parsed: bool
    from_host: str | None
    from_ip: str | None
    from_ip_reserved: bool | None
    by_host: str | None
    via: str | None
    with_protocol: str | None
    id: str | None
    has_for: bool
    timestamp: str | None
    delay_seconds: int | None
    warnings: tuple[str, ...]


class ReceivedView(_Model):
    hops: tuple[HopView, ...]
    total_transit_seconds: int | None
    truncated: bool
    received_count: int


class PropertyView(_Model):
    ptype: str
    property: str
    value: str


class ResultView(_Model):
    method: str
    result: str
    reason: str | None
    unknown_value: bool
    properties: tuple[PropertyView, ...]


class AuthHeaderView(_Model):
    index: int
    authserv_id: str | None
    version: int | None
    no_result: bool
    truncated: bool
    results: tuple[ResultView, ...]
    issues: tuple[str, ...]


class ArcSetView(_Model):
    instance: int
    domain: str | None
    selector: str | None
    cv: str | None
    timestamp: str | None
    results: tuple[ResultView, ...]


class ArcView(_Model):
    status: str
    instance_count: int
    field_count: int
    truncated: bool
    verified: bool | None
    crypto_checked: bool
    sets: tuple[ArcSetView, ...]
    issues: tuple[str, ...]


class PairView(_Model):
    kind: str
    state: str
    reason: str | None
    from_domain: str | None
    identifier_domain: str | None
    identifier_source: str | None
    from_org: str | None
    identifier_org: str | None
    relaxed_aligned: bool
    strict_aligned: bool
    stated_result: str | None
    unverified_signature: bool
    authserv_id: str | None
    authres_index: int | None


class AlignmentView(_Model):
    pairs: tuple[PairView, ...]
    from_domains: tuple[str, ...]
    stated_dmarc: str | None
    stated_dmarc_authserv_id: str | None
    stated_dmarc_index: int | None
    computed_dmarc: str
    dmarc_mismatch: bool
    truncated: bool


class PartView(_Model):
    index: int
    parent: int | None
    depth: int
    content_type: str
    category: str
    charset: str | None
    disposition: str | None
    has_filename: bool
    transfer_encoding: str
    header_bytes: int
    encoded_size: int
    estimated_decoded_size: int
    nul_bytes: int


class SizeBreakdown(_Model):
    total_bytes: int
    header_bytes: int
    body_bytes: int
    text_bytes: int
    html_bytes: int
    attachment_bytes: int
    inline_image_bytes: int
    other_bytes: int
    nul_bytes: int


class MimeView(_Model):
    parts: tuple[PartView, ...]
    sizes: SizeBreakdown
    has_text_plain: bool
    has_text_html: bool
    has_alternative: bool
    max_depth: int
    truncated: bool
    warnings: tuple[str, ...]


class MessageAnalysis(_Model):
    """Result of :func:`analyze_message`. Sections are ``None`` when not produced."""

    status: Status
    summary: Summary | None
    received: ReceivedView | None
    authentication: tuple[AuthHeaderView, ...] | None
    arc: ArcView | None
    alignment: AlignmentView | None
    mime: MimeView | None
    findings: tuple[Finding, ...]


# --- helpers ---------------------------------------------------------------------------------


def _x(value: str | None) -> str | None:
    return None if value is None else excerpt(value)


def _codes(issues: tuple[ParseIssue, ...]) -> tuple[str, ...]:
    return tuple(i.code for i in issues)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.isoformat()
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def redact_received(raw: str) -> str:
    """Remove the ``for <addr>`` clause (and anything after it up to a trailing date).

    Conservative on purpose: everything from the first ``for`` keyword is dropped; only the
    text after the last ``;`` survives, and only when it cannot contain an address.
    """
    m = _FOR_CLAUSE.search(raw)
    if m is None:
        return raw
    rest = raw[m.end() :]
    tail = ""
    if ";" in rest:
        cand = rest[rest.rfind(";") + 1 :].strip()
        if not any(c in cand for c in '@<>"'):
            tail = cand
    out = raw[: m.start()] + _REDACTED
    return f"{out}; {tail}" if tail else out


def _hop(h: ReceivedHop) -> HopView:
    return HopView(
        index=h.index,
        raw=excerpt(redact_received(h.raw)),
        parsed=h.parsed,
        from_host=_x(h.from_host),
        from_ip=_x(h.from_ip),
        from_ip_reserved=h.from_ip_reserved,
        by_host=_x(h.by_host),
        via=_x(h.via),
        with_protocol=_x(h.with_protocol),
        id=_x(h.id),
        has_for=h.has_for,
        timestamp=_iso(h.timestamp),
        delay_seconds=h.delay_seconds,
        warnings=_codes(h.warnings),
    )


def _received_view(c: ReceivedChain) -> ReceivedView:
    return ReceivedView(
        hops=tuple(_hop(h) for h in c.hops),
        total_transit_seconds=c.total_transit_seconds,
        truncated=c.truncated,
        received_count=c.received_count,
    )


def _results(h: AuthResHeader) -> tuple[ResultView, ...]:
    return tuple(
        ResultView(
            method=excerpt(r.method),
            result=excerpt(r.result),
            reason=_x(r.reason),
            unknown_value=r.unknown_value,
            properties=tuple(
                PropertyView(
                    ptype=excerpt(p.ptype), property=excerpt(p.property), value=excerpt(p.value)
                )
                for p in r.properties
            ),
        )
        for r in h.resinfo
    )


def _auth_view(headers: tuple[AuthResHeader, ...]) -> tuple[AuthHeaderView, ...]:
    return tuple(
        AuthHeaderView(
            index=h.index,
            authserv_id=_x(h.authserv_id),
            version=h.version,
            no_result=h.no_result,
            truncated=h.truncated,
            results=_results(h),
            issues=_codes(h.issues),
        )
        for h in headers
    )


def _arc_set(s: ArcSet) -> ArcSetView:
    res = s.results
    return ArcSetView(
        instance=s.instance,
        domain=_x(s.domain),
        selector=_x(s.selector),
        cv=_x(s.cv),
        timestamp=_iso(s.timestamp),
        results=_results(res) if res is not None else (),
    )


def _arc_view(c: ArcChain) -> ArcView:
    return ArcView(
        status=c.status,
        instance_count=c.instance_count,
        field_count=c.field_count,
        truncated=c.truncated,
        verified=c.verified,
        crypto_checked=c.crypto_checked,
        sets=tuple(_arc_set(s) for s in c.sets),
        issues=_codes(c.issues),
    )


def _alignment_view(a: AlignmentReport) -> AlignmentView:
    return AlignmentView(
        pairs=tuple(
            PairView(
                kind=p.kind,
                state=p.state,
                reason=_x(p.reason),
                from_domain=_x(p.from_domain),
                identifier_domain=_x(p.identifier_domain),
                identifier_source=_x(p.identifier_source),
                from_org=_x(p.from_org),
                identifier_org=_x(p.identifier_org),
                relaxed_aligned=p.relaxed_aligned,
                strict_aligned=p.strict_aligned,
                stated_result=_x(p.stated_result),
                unverified_signature=p.unverified_signature,
                authserv_id=_x(p.authserv_id),
                authres_index=p.authres_index,
            )
            for p in a.pairs
        ),
        from_domains=tuple(excerpt(d) for d in a.from_domains),
        stated_dmarc=_x(a.stated_dmarc),
        stated_dmarc_authserv_id=_x(a.stated_dmarc_authserv_id),
        stated_dmarc_index=a.stated_dmarc_index,
        computed_dmarc=a.computed_dmarc,
        dmarc_mismatch=a.dmarc_mismatch,
        truncated=a.truncated,
    )


def _mime_view(m: MimeSummary) -> MimeView:
    t = m.totals
    return MimeView(
        parts=tuple(
            PartView(
                index=p.index,
                parent=p.parent,
                depth=p.depth,
                content_type=excerpt(p.content_type),
                category=p.category,
                charset=_x(p.charset),
                disposition=_x(p.disposition),
                has_filename=p.has_filename,
                transfer_encoding=excerpt(p.transfer_encoding),
                header_bytes=p.header_bytes,
                encoded_size=p.encoded_size,
                estimated_decoded_size=p.estimated_decoded_size,
                nul_bytes=p.nul_bytes,
            )
            for p in m.parts
        ),
        sizes=SizeBreakdown(
            total_bytes=t.total_bytes,
            header_bytes=t.header_bytes,
            body_bytes=t.body_bytes,
            text_bytes=t.text_bytes,
            html_bytes=t.html_bytes,
            attachment_bytes=t.attachment_bytes,
            inline_image_bytes=t.inline_image_bytes,
            other_bytes=t.other_bytes,
            nul_bytes=t.nul_bytes,
        ),
        has_text_plain=m.has_text_plain,
        has_text_html=m.has_text_html,
        has_alternative=m.has_alternative,
        max_depth=m.max_depth,
        truncated=m.truncated,
        warnings=_codes(m.warnings),
    )


def _count_addresses(block: HeaderBlock, name: str) -> int:
    values = [f.decoded_value for f in block.get_all(name)]
    return sum(1 for _, addr in getaddresses(values) if addr)


def _first(block: HeaderBlock, name: str) -> str | None:
    fields = block.get_all(name)
    return fields[0].decoded_value if fields else None


def _date_utc(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return _iso(parsed)


def _summary(block: HeaderBlock, size: int) -> Summary:
    date = _first(block, "Date")
    return Summary(
        subject=_x(_first(block, "Subject")),
        from_header=_x(_first(block, "From")),
        to_count=_count_addresses(block, "To"),
        cc_count=_count_addresses(block, "Cc"),
        date_header=_x(date),
        date_utc=_date_utc(date),
        header_count=len(block.fields),
        size_bytes=size,
    )


# --- orchestration ---------------------------------------------------------------------------


def _finish(parts: list[Finding], evaluated: bool) -> tuple[Status, tuple[Finding, ...]]:
    # CheckResult owns the sorting rule and status derivation; the timestamp is a placeholder.
    result = CheckResult.build(
        check_id=CHECK_ID,
        target="message",
        findings=parts,
        evaluated=evaluated,
        started_at=_EPOCH,
        duration_ms=0,
    )
    return result.status, result.findings


def _rejected(code: str) -> MessageAnalysis:
    mf = rejected_input_findings(code)
    status, findings = _finish(list(mf.findings), mf.evaluated)
    return MessageAnalysis(
        status=status,
        summary=None,
        received=None,
        authentication=None,
        arc=None,
        alignment=None,
        mime=None,
        findings=findings,
    )


def _section[T](name: str, failed: list[str], fn: Callable[[], T]) -> T | None:
    """Run one section; any exception stays inside it (recorded in ``failed``)."""
    try:
        return fn()
    except Exception:
        failed.append(name)
        return None


def _parse_and_view[T, V](
    name: str,
    failed: list[str],
    parse: Callable[[], T],
    view: Callable[[Any], V],
) -> tuple[T | None, V | None]:
    def both() -> tuple[T, V]:
        parsed = parse()
        return parsed, view(parsed)

    out = _section(name, failed, both)
    return (None, None) if out is None else out


def analyze_message(raw: bytes) -> MessageAnalysis:
    """Analyse one raw RFC 5322 message. Pure, deterministic and never raises."""
    try:
        return _analyze(raw)
    except Exception:  # last resort: the contract is "never raises"
        return _rejected(INTERNAL_ERROR)


def _analyze(raw: bytes) -> MessageAnalysis:
    if not isinstance(raw, bytes | bytearray):
        return _rejected(INVALID_INPUT)
    raw = bytes(raw)
    if not raw:
        return _rejected(EMPTY_INPUT)
    if len(raw) > MAX_RAW_BYTES:
        return _rejected("message_too_large")
    try:
        block = parse_header_block(raw)
    except MessageParseError as e:
        return _rejected(e.code)
    if not block.fields:
        return _rejected(NO_HEADER_BLOCK)

    failed: list[str] = []
    received, received_v = _parse_and_view(
        "received", failed, lambda: parse_received_chain(block), _received_view
    )
    headers, auth_v = _parse_and_view(
        "authentication_results",
        failed,
        lambda: parse_all_authentication_results(block),
        _auth_view,
    )
    arc, arc_v = _parse_and_view("arc", failed, lambda: parse_arc_chain(block), _arc_view)
    alignment, alignment_v = _parse_and_view(
        "alignment", failed, lambda: analyze_alignment(block), _alignment_view
    )
    mime, mime_v = _parse_and_view("mime", failed, lambda: parse_mime(raw), _mime_view)
    summary = _section("summary", failed, lambda: _summary(block, len(raw)))

    findings: list[Finding] = []
    evaluated = True
    mf = _section(
        "findings",
        failed,
        lambda: build_message_findings(
            block,
            received=received or ReceivedChain((), None, False, 0),
            mime=mime,
            arc=arc or ArcChain("none", (), (), (), (), 0, False),
            alignment=alignment
            or AlignmentReport((), (), None, None, None, "not_evaluated", False, False),
        ),
    )
    if mf is not None:
        findings.extend(mf.findings)
        evaluated = mf.evaluated
    for name in failed:
        findings.append(finding("MSG_PARSER_LIMIT", "medium", {"limits": f"{name}_failed"}))
        evaluated = False
    _ = headers  # parsed once here for isolation; build_message_findings re-reads the block

    status, ordered = _finish(findings, evaluated)
    return MessageAnalysis.model_validate(
        {
            "status": status,
            "summary": summary,
            "received": received_v,
            "authentication": auth_v,
            "arc": arc_v,
            "alignment": alignment_v,
            "mime": mime_v,
            "findings": ordered,
        }
    )
