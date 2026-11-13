"""Pure message analysis service (M4-10).

``analyze_message(raw)`` composes the public APIs of the M4 parsers
(:mod:`app.parsers.message`, ``mime``, ``received``, ``authres``, ``arc``),
:func:`app.services.message_alignment.analyze_alignment`,
:func:`app.services.message_hops.build_hop_view` (per-hop view, display only) and
:mod:`app.services.message_findings` into one immutable :class:`MessageAnalysis`.

Hard rules (ticket M4-10):

- No clock, DNS, network, filesystem or DB. Nothing is stored and message content is never
  logged (this module has no logger).
- It never raises on bad input. Input the header parser rejects (empty, not bytes, over cap,
  NUL in the header block, too many headers, no header block) returns status ``error`` with a
  ``MSG_PARSER_LIMIT`` finding and no partial data (every section ``None``).
- A failure in one sub-parser is isolated: its section is ``None``, an error finding
  (``MSG_PARSER_LIMIT``, ``limits="<section>_failed"``) is added and the overall status is
  ``error``; the other sections are still produced. The findings builder sees an empty
  stand-in for the failed section, and every finding that depends on that section is dropped
  afterwards (:data:`_DEPENDENT_CODES`), so a failure never produces false "missing data"
  findings. A failed Authentication-Results parse is hidden from the builder (the fields are
  removed from the block it sees) so the unrelated findings survive.
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
import unicodedata
from collections.abc import Callable
from dataclasses import replace
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
from app.services.message_hops import HopEntry, HopTimeline, build_hop_view

__all__ = ["MessageAnalysis", "analyze_message", "redact_received"]

CHECK_ID = "message_analysis"
INVALID_INPUT = "invalid_input"
EMPTY_INPUT = "empty_input"
NO_HEADER_BLOCK = "no_header_block"
INTERNAL_ERROR = "internal_error"

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_FOR_CLAUSE = re.compile(r"\bfor\b", re.IGNORECASE)
_REDACTED = "for [redacted]"
_REDACTED_TOKEN = "[redacted]"

_RECEIVED_CODES = frozenset(
    {
        "MSG_RECEIVED_NONE",
        "MSG_RECEIVED_UNPARSED",
        "MSG_RECEIVED_CLOCK_SKEW",
        "MSG_HOP_DELAY_HIGH",
        "MSG_RECEIVED_PRIVATE_IP_ORIGIN",
        "MSG_DATE_FAR_FROM_RECEIVED",
    }
)
_AUTH_CODES = frozenset(
    {
        "MSG_AUTHRES_MISSING",
        "MSG_AUTHRES_AUTHSERV_MISMATCH",
        "MSG_SPF_NOT_PASS",
        "MSG_DKIM_NOT_PASS",
        "MSG_DMARC_NOT_PASS",
    }
)
_ALIGNMENT_CODES = frozenset(
    {"MSG_ALIGNMENT_FAIL", "MSG_ALIGNMENT_STATED_MISMATCH", "MSG_UNVERIFIED_DKIM_SIGNATURE"}
)
# Findings that cannot be trusted when the named section failed (alignment is computed from
# the Authentication-Results too, auth findings read the alignment report).
_DEPENDENT_CODES: dict[str, frozenset[str]] = {
    "received": _RECEIVED_CODES,
    "authentication_results": _AUTH_CODES | _ALIGNMENT_CODES,
    "alignment": _AUTH_CODES | _ALIGNMENT_CODES | {"MSG_REPLY_TO_DIFFERS", "MSG_REPLY_TO_UNUSABLE"},
    "arc": frozenset({"MSG_ARC_INVALID", "MSG_ARC_CV_FAIL"}),
    "hops": frozenset({"MSG_AUTH_BROKE_AFTER_HOP"}),
}


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


class HopResultView(_Model):
    method: str
    result: str


class HopEntryView(_Model):
    """One entry of the per-hop view (see :mod:`app.services.message_hops`)."""

    order: int
    kind: str
    position: int
    hop: int | None
    parsed: bool
    authserv_id: str | None
    authres_index: int | None
    arc_instance: int | None
    arc_domain: str | None
    arc_cv: str | None
    results: tuple[HopResultView, ...]
    stated_not_verifiable: bool
    issues: tuple[str, ...]


class HopsView(_Model):
    entries: tuple[HopEntryView, ...]
    received_truncated: bool
    arc_truncated: bool


class MessageAnalysis(_Model):
    """Result of :func:`analyze_message`. Sections are ``None`` when not produced."""

    status: Status
    summary: Summary | None
    received: ReceivedView | None
    authentication: tuple[AuthHeaderView, ...] | None
    arc: ArcView | None
    alignment: AlignmentView | None
    mime: MimeView | None
    hops: HopsView | None
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
    out = raw[: m.start()]
    if out and out[-1].isalnum():
        out += " "
    out += _REDACTED
    return f"{out}; {tail}" if tail else out


HOP_FIELD_REDACTED = "hop_field_redacted"
_MAX_QUOTE_WALK = 8


def _normalize(text: str) -> str:
    """Whitespace and control characters become one space; format characters are dropped."""
    out: list[str] = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue
        if cat[0] in "CZ" or ch.isspace():
            if not out or out[-1] != " ":
                out.append(" ")
            continue
        out.append(ch)
    return "".join(out)


def _mask_addresses(text: str) -> str:
    """Replace every space-delimited token containing ``@`` (and the opening part of a
    quoted local-part such as ``"x y"@z``) with ``[redacted]``. Linear in the input."""
    tokens = text.split(" ")
    masked = [False] * len(tokens)
    for i, tok in enumerate(tokens):
        at = tok.find("@")
        if at < 0:
            continue
        masked[i] = True
        if at == 0 and i > 0:  # "local @domain": whitespace was inserted before the "@"
            masked[i - 1] = True
        if tok.endswith("@") and i + 1 < len(tokens):
            masked[i + 1] = True
        if tok.count('"', 0, at) % 2 == 1:
            # a quote is still open before "@": it was opened in an earlier token
            j = i - 1
            while j >= 0 and i - j <= _MAX_QUOTE_WALK:
                masked[j] = True
                if '"' in tokens[j]:
                    break
                j -= 1
    return " ".join(_REDACTED_TOKEN if m else t for t, m in zip(tokens, masked, strict=True))


def _clean_raw(raw: str) -> str:
    """Display form of a Received hop: normalised, ``for`` clause and addresses removed."""
    return excerpt(_mask_addresses(redact_received(_normalize(raw))))


def _hop(h: ReceivedHop) -> HopView:
    warnings = list(_codes(h.warnings))
    redacted = False

    def field(value: str | None) -> str | None:
        nonlocal redacted
        if value is None:
            return None
        norm = _normalize(value)
        if "@" in norm or "<" in norm:
            redacted = True
            return None
        return excerpt(norm)

    from_host = field(h.from_host)
    from_ip = field(h.from_ip)
    by_host = field(h.by_host)
    via = field(h.via)
    with_protocol = field(h.with_protocol)
    hop_id = field(h.id)
    if redacted:
        warnings.append(HOP_FIELD_REDACTED)
    return HopView(
        index=h.index,
        raw=_clean_raw(h.raw),
        parsed=h.parsed,
        from_host=from_host,
        from_ip=from_ip,
        from_ip_reserved=h.from_ip_reserved,
        by_host=by_host,
        via=via,
        with_protocol=with_protocol,
        id=hop_id,
        has_for=h.has_for,
        timestamp=_iso(h.timestamp),
        delay_seconds=h.delay_seconds,
        warnings=tuple(warnings),
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


def _hop_entry(e: HopEntry) -> HopEntryView:
    return HopEntryView(
        order=e.order,
        kind=e.kind,
        position=e.position,
        hop=e.hop,
        parsed=e.parsed,
        authserv_id=_x(e.authserv_id),
        authres_index=e.authres_index,
        arc_instance=e.arc_instance,
        arc_domain=_x(e.arc_domain),
        arc_cv=_x(e.arc_cv),
        results=tuple(
            HopResultView(method=excerpt(r.method), result=excerpt(r.result)) for r in e.results
        ),
        stated_not_verifiable=e.stated_not_verifiable,
        issues=tuple(excerpt(c) for c in e.issues),
    )


def _hops_view(t: HopTimeline) -> HopsView:
    return HopsView(
        entries=tuple(_hop_entry(e) for e in t.entries),
        received_truncated=t.received_truncated,
        arc_truncated=t.arc_truncated,
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
    values = [f.raw_value for f in block.get_all(name)]
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
        hops=None,
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
    if not any(f.name for f in block.fields):  # colon-less text parses to empty names
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
    hops, hops_v = _parse_and_view(
        "hops", failed, lambda: build_hop_view(block, received, headers, arc), _hops_view
    )

    findings: list[Finding] = []
    evaluated = True
    builder_block = block
    if headers is None:  # hide the unparseable fields so the builder does not fail on them
        builder_block = replace(
            block,
            fields=tuple(f for f in block.fields if f.name.lower() != "authentication-results"),
        )
    failed_before = set(failed)
    mf = _section(
        "findings",
        failed,
        lambda: build_message_findings(
            builder_block,
            received=received or ReceivedChain((), None, False, 0),
            mime=mime,
            arc=arc or ArcChain("none", (), (), (), (), 0, False),
            alignment=alignment
            or AlignmentReport((), (), None, None, None, "not_evaluated", False, False),
            hops=hops,
        ),
    )
    if mf is not None:
        dropped: frozenset[str] = frozenset().union(
            *(_DEPENDENT_CODES.get(n, frozenset()) for n in failed_before)
        )
        findings.extend(f for f in mf.findings if f.code not in dropped)
        evaluated = mf.evaluated
    for name in failed:
        findings.append(finding("MSG_PARSER_LIMIT", "medium", {"limits": f"{name}_failed"}))
        evaluated = False

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
            "hops": hops_v,
            "findings": ordered,
        }
    )
