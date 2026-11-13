"""Header anomaly findings for an uploaded raw message (M4-09).

Pure and offline: no DNS, no network. Everything here turns the output of the public
parsers (`app.parsers.message`, `received`, `authres`, `arc`, `mime`) and of
`app.services.message_alignment` into :class:`app.checks.models.Finding` objects built with
:func:`app.checks.models.finding`. Nothing is stored.

Principles:

- Missing or unevaluable data is never a pass. An absent header yields a finding; input
  that is malformed or capped so that a header could not be evaluated is recorded in
  :attr:`MessageFindings.unevaluated` and makes :attr:`MessageFindings.status` ``error``
  (never ``ok``). ``Finding`` has no status, so the caller (M4-10) builds the
  ``CheckResult`` with ``evaluated=result.evaluated``.
- Nothing is verified cryptographically. ``Authentication-Results`` and ARC fields are
  untrusted text written by whoever handled the message (RFC 8601 section 5); results are
  reported as "stated". Mixed authserv-ids are flagged, never trusted.
- No vendor expectation: only RFC-defined or structural observations.
- The Received ``for`` address is never read or reported (the parser only exposes
  ``has_for``).
- Header-derived text in params is limited to a bounded excerpt: control and format
  characters removed (NOT escaped: the template layer, e.g. Jinja autoescape, does that),
  at most :data:`MAX_EXCERPT` characters
  (:func:`excerpt`). Raw header values are never embedded.

Severity per code (``status`` follows ``derive_status``: high/critical fail, medium/low
warn, info info):

======================================== ======== =========================================
Code                                     Severity Meaning
======================================== ======== =========================================
MSG_MISSING_FROM                         high     no (or empty) From (RFC 5322 3.6)
MSG_MULTIPLE_FROM                        high     more than one From
MSG_MISSING_DATE                         medium   no (or empty) Date
MSG_DATE_INVALID                         medium   Date cannot be parsed (error-class)
MSG_DATE_NO_TIMEZONE                     low      Date without zone (error-class)
MSG_DATE_FAR_FROM_RECEIVED               medium   Date vs first hop differs > 24 h
MSG_MISSING_MESSAGE_ID                   low      no Message-ID
MSG_DUPLICATE_SINGLETON_HEADER           medium   Subject/Date/Message-ID repeated
MSG_RECEIVED_NONE                        low      no Received header
MSG_RECEIVED_UNPARSED                    low      hops not parsed (error-class)
MSG_RECEIVED_CLOCK_SKEW                  low      a hop is older than the previous one
MSG_HOP_DELAY_HIGH                       low      a hop delay over HOP_DELAY_HIGH_SECONDS
MSG_RECEIVED_PRIVATE_IP_ORIGIN           info     first hop address is not global
MSG_AUTHRES_MISSING                      medium   no Authentication-Results at all
MSG_AUTHRES_AUTHSERV_MISMATCH            medium   used results carry different authserv-ids
MSG_SPF_NOT_PASS                         high/    stated spf: fail -> high; other results
                                         medium/  -> medium; not stated -> low
                                         low
MSG_DKIM_NOT_PASS                        same     no stated dkim pass
MSG_DMARC_NOT_PASS                       same     stated dmarc is not pass
MSG_ALIGNMENT_FAIL                       high     computed: no usable aligned pass
MSG_ALIGNMENT_STATED_MISMATCH            medium   stated dmarc disagrees with computed
MSG_UNVERIFIED_DKIM_SIGNATURE            low      DKIM-Signature with no stated result
MSG_ARC_INVALID                          low      ARC chain structurally invalid
MSG_ARC_CV_FAIL                          medium   an ARC seal says cv=fail
MSG_RETURN_PATH_MISSING                  info     no Return-Path
MSG_REPLY_TO_DIFFERS                     info     Reply-To organizational domain differs
MSG_REPLY_TO_UNUSABLE                    info     Reply-To has no usable address
MSG_LIST_UNSUBSCRIBE_MISSING             info     no List-Unsubscribe
MSG_LIST_UNSUBSCRIBE_NO_ONECLICK         info     List-Unsubscribe without RFC 8058 post
MSG_ENCODED_HEADER_BROKEN                low      undecodable RFC 2047 encoded-word
MSG_MIME_TRUNCATED                       low      MIME walk stopped at a cap (detail)
MSG_NO_TEXT_PART                         low      no text/plain part
MSG_PARSER_LIMIT                         medium   input rejected or capped (error-class)
MSG_AUTHRES_UNPARSED                     medium   Authentication-Results unusable (error-class)
MSG_ALIGNMENT_NOT_EVALUATED              medium   no identifier to align (error-class)
MSG_ALIGNMENT_LOWER_FIELD_NOT_USED       low      an aligned pass from a lower
                                                  Authentication-Results field was not used
MSG_AUTH_BROKE_AFTER_HOP                 info     a stated pass became a failure in a newer
                                                  field (per-hop view, display only)
======================================== ======== =========================================

``MSG_DUPLICATE_SINGLETON_HEADER`` is reported for Subject, Date and Message-ID; a repeated
From is reported as ``MSG_MULTIPLE_FROM`` only (one finding per problem).

Error-class conditions (``unevaluated``): ``date`` (invalid, or without a zone), ``received``
(any unparsed hop), ``authres`` (an Authentication-Results field that could not be parsed),
``alignment`` (alignment not computable although Authentication-Results exist),
``list_unsubscribe`` (a List-Unsubscribe field capped or unreadable, so One-Click is unknown;
explained by ``MSG_PARSER_LIMIT`` with the ``list_unsubscribe`` limit),
and ``parser`` (input rejected
or capped).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import timedelta
from email.utils import getaddresses

from app.checks.models import Finding, Status, derive_status, finding
from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.core.org_domain import organizational_domain
from app.parsers import received as received_mod
from app.parsers.arc import ArcChain
from app.parsers.authres import (
    AuthResHeader,
    AuthResParseError,
    parse_all_authentication_results,
)
from app.parsers.list_unsubscribe import analyze_list_unsubscribe
from app.parsers.message import (
    ENCODED_WORD_INVALID,
    ENCODED_WORD_MALFORMED,
    ENCODED_WORD_UNKNOWN_CHARSET,
    TOO_MANY_WARNINGS,
    HeaderBlock,
)
from app.parsers.mime import MimeSummary
from app.parsers.received import ReceivedChain, parse_received_values
from app.services.message_alignment import LOWER_AUTHRES_FIELD, AlignmentReport
from app.services.message_hops import HopTimeline, find_auth_breaks

MAX_EXCERPT = 200
MAX_DATE_SKEW = timedelta(hours=24)
# Heuristic, not an RFC value: a single hop that holds the message for over one hour is
# unusual enough to look at (greylisting, queueing, retries). Tune with real data.
HOP_DELAY_HIGH_SECONDS = 3600
_LISTED_ITEMS = 5
_SINGLETONS = ("Subject", "Date", "Message-ID")
_ENCODED_WORD_CODES = frozenset(
    {ENCODED_WORD_INVALID, ENCODED_WORD_MALFORMED, ENCODED_WORD_UNKNOWN_CHARSET}
)

CODES: tuple[str, ...] = (
    "MSG_MISSING_FROM",
    "MSG_MULTIPLE_FROM",
    "MSG_MISSING_DATE",
    "MSG_DATE_INVALID",
    "MSG_DATE_NO_TIMEZONE",
    "MSG_DATE_FAR_FROM_RECEIVED",
    "MSG_MISSING_MESSAGE_ID",
    "MSG_DUPLICATE_SINGLETON_HEADER",
    "MSG_RECEIVED_NONE",
    "MSG_RECEIVED_UNPARSED",
    "MSG_RECEIVED_CLOCK_SKEW",
    "MSG_HOP_DELAY_HIGH",
    "MSG_RECEIVED_PRIVATE_IP_ORIGIN",
    "MSG_AUTHRES_MISSING",
    "MSG_AUTHRES_AUTHSERV_MISMATCH",
    "MSG_SPF_NOT_PASS",
    "MSG_DKIM_NOT_PASS",
    "MSG_DMARC_NOT_PASS",
    "MSG_ALIGNMENT_FAIL",
    "MSG_ALIGNMENT_STATED_MISMATCH",
    "MSG_UNVERIFIED_DKIM_SIGNATURE",
    "MSG_ARC_INVALID",
    "MSG_ARC_CV_FAIL",
    "MSG_RETURN_PATH_MISSING",
    "MSG_REPLY_TO_DIFFERS",
    "MSG_REPLY_TO_UNUSABLE",
    "MSG_LIST_UNSUBSCRIBE_MISSING",
    "MSG_LIST_UNSUBSCRIBE_NO_ONECLICK",
    "MSG_ENCODED_HEADER_BROKEN",
    "MSG_MIME_TRUNCATED",
    "MSG_NO_TEXT_PART",
    "MSG_PARSER_LIMIT",
    "MSG_AUTHRES_UNPARSED",
    "MSG_ALIGNMENT_NOT_EVALUATED",
    "MSG_ALIGNMENT_LOWER_FIELD_NOT_USED",
    "MSG_AUTH_BROKE_AFTER_HOP",
)


def excerpt(text: object) -> str:
    """Bounded, display-safe excerpt of untrusted text.

    Control, format (bidi, zero width), surrogate, private-use and line/paragraph separator
    characters are removed and the result is cut at :data:`MAX_EXCERPT` characters. The text is
    NOT escaped: output layers (Jinja autoescape, JSON) do that, and escaping here would
    double-escape it.
    """
    out: list[str] = []
    size = 0
    for ch in str(text):
        cat = unicodedata.category(ch)
        if cat[0] == "C" or cat in ("Zl", "Zp"):
            continue
        if size >= MAX_EXCERPT:
            break
        out.append(ch)
        size += 1
    return "".join(out)


@dataclass(frozen=True, slots=True)
class MessageFindings:
    """Findings plus the areas that could not be evaluated (see the module docstring)."""

    findings: tuple[Finding, ...]
    unevaluated: tuple[str, ...]

    @property
    def evaluated(self) -> bool:
        return not self.unevaluated

    @property
    def status(self) -> Status:
        return derive_status(self.findings, self.evaluated)


class _Acc:
    def __init__(self) -> None:
        self.items: list[Finding] = []
        self.unevaluated: list[str] = []

    def add(
        self,
        code: str,
        severity: str,
        params: dict[str, object] | None = None,
        detail_variant: str | None = None,
    ) -> None:
        f = finding(code, severity, params)  # type: ignore[arg-type]
        if detail_variant:
            f = f.model_copy(update={"detail_key": f"finding.{code}.detail_{detail_variant}"})
        self.items.append(f)

    def skip(self, area: str) -> None:
        if area not in self.unevaluated:
            self.unevaluated.append(area)

    def result(self) -> MessageFindings:
        return MessageFindings(tuple(self.items), tuple(self.unevaluated))


def _joined(values: list[str]) -> str:
    shown = [excerpt(v) for v in values[:_LISTED_ITEMS]]
    if len(values) > _LISTED_ITEMS:
        shown.append("...")
    return ", ".join(shown)


# --- header level -----------------------------------------------------------------------------


def _non_empty(block: HeaderBlock, name: str) -> bool:
    return any(f.raw_value.strip() for f in block.get_all(name))


def _date_findings(block: HeaderBlock, chain: ReceivedChain, acc: _Acc) -> None:
    fields = block.get_all("Date")
    if not fields or not fields[0].raw_value.strip():
        acc.add("MSG_MISSING_DATE", "medium")
        return
    value = fields[0].raw_value
    stamp = None
    no_zone = False
    if ";" not in value:  # the Received date parser reads what follows the last ";"
        hop = parse_received_values([f"by x; {value}"]).hops[0]
        stamp = hop.timestamp
        no_zone = any(w.code == received_mod.DATE_NO_TIMEZONE for w in hop.warnings)
    if stamp is None and no_zone:
        acc.add("MSG_DATE_NO_TIMEZONE", "low")
        acc.skip("date")
        return
    if stamp is None:
        acc.add("MSG_DATE_INVALID", "medium")
        acc.skip("date")
        return
    first = chain.hops[0] if chain.hops else None
    if first is not None and first.timestamp is not None:
        skew = abs(stamp - first.timestamp)
        if skew > MAX_DATE_SKEW:
            acc.add(
                "MSG_DATE_FAR_FROM_RECEIVED",
                "medium",
                {"skew_hours": int(skew.total_seconds() // 3600), "max_hours": 24},
            )


def _header_part(block: HeaderBlock, chain: ReceivedChain, acc: _Acc) -> None:
    froms = block.get_all("From")
    if not _non_empty(block, "From"):
        acc.add("MSG_MISSING_FROM", "high")
    if len(froms) > 1:
        acc.add("MSG_MULTIPLE_FROM", "high", {"count": len(froms)})
    _date_findings(block, chain, acc)
    if not _non_empty(block, "Message-ID"):
        acc.add("MSG_MISSING_MESSAGE_ID", "low")
    for name in _SINGLETONS:
        count = len(block.get_all(name))
        if count > 1:
            acc.add("MSG_DUPLICATE_SINGLETON_HEADER", "medium", {"header": name, "count": count})


# --- Received ---------------------------------------------------------------------------------


def _received_part(chain: ReceivedChain, acc: _Acc) -> None:
    if not chain.hops:
        acc.add("MSG_RECEIVED_NONE", "low")
        return
    unparsed = sum(1 for h in chain.hops if not h.parsed or h.timestamp is None)
    if unparsed:
        acc.add("MSG_RECEIVED_UNPARSED", "low", {"unparsed": unparsed, "total": len(chain.hops)})
        acc.skip("received")
    skewed = sum(
        1 for h in chain.hops if any(w.code == received_mod.CLOCK_SKEW for w in h.warnings)
    )
    if skewed:
        acc.add("MSG_RECEIVED_CLOCK_SKEW", "low", {"count": skewed})
    slowest = max(
        (h for h in chain.hops if h.delay_seconds is not None),
        key=lambda h: h.delay_seconds or 0,
        default=None,
    )
    if (
        slowest is not None
        and slowest.delay_seconds is not None
        and slowest.delay_seconds > HOP_DELAY_HIGH_SECONDS
    ):
        acc.add(
            "MSG_HOP_DELAY_HIGH",
            "low",
            {
                "hop": slowest.index + 1,
                "delay_seconds": slowest.delay_seconds,
                "threshold_seconds": HOP_DELAY_HIGH_SECONDS,
            },
        )
    first = chain.hops[0]
    if first.from_ip is not None and first.from_ip_reserved:
        acc.add("MSG_RECEIVED_PRIVATE_IP_ORIGIN", "info", {"ip": excerpt(first.from_ip)})


# --- authentication ---------------------------------------------------------------------------


def _topmost_results(headers: tuple[AuthResHeader, ...], method: str) -> list[str]:
    """Stated results of ``method`` from the topmost field that states it.

    That may be a lower field (R1-22 QA input, GM decision 2026-11-13): display only. It
    selects the MSG_SPF_NOT_PASS / MSG_DKIM_NOT_PASS warnings and their wording and never
    feeds ``computed_dmarc`` or the alignment pairs, which apply the topmost-field rule in
    :mod:`app.services.message_alignment`. Behaviour unchanged, pinned by a test.
    """
    for header in headers:
        found = header.by_method().get(method)
        if found:
            return [r.result for r in found]
    return []


def _not_pass_severity(results: list[str]) -> str:
    if not results:
        return "low"
    return "high" if "fail" in results else "medium"


def _norm_id(value: str) -> str:
    return value.strip().rstrip(".").casefold()


def _auth_part(alignment: AlignmentReport, headers: tuple[AuthResHeader, ...], acc: _Acc) -> None:
    if not headers:
        acc.add("MSG_AUTHRES_MISSING", "medium")
        return
    unusable = [
        h for h in headers if h.authserv_id is None or any(i.severity == "error" for i in h.issues)
    ]
    if unusable:
        issue_codes = [i.code for h in unusable for i in h.issues if i.severity == "error"]
        if any(h.authserv_id is None for h in unusable):
            issue_codes.append("missing_authserv_id")
        acc.add(
            "MSG_AUTHRES_UNPARSED",
            "medium",
            {"issues": _joined(list(dict.fromkeys(issue_codes))), "count": len(unusable)},
        )
        acc.skip("authres")

    ids: dict[str, str] = {}
    candidates = [p.authserv_id for p in alignment.pairs] + [alignment.stated_dmarc_authserv_id]
    for ident in candidates:
        if ident:
            ids.setdefault(_norm_id(ident), ident)
    if len(ids) > 1:
        acc.add(
            "MSG_AUTHRES_AUTHSERV_MISMATCH",
            "medium",
            {"count": len(ids), "ids": _joined(list(ids.values()))},
        )

    spf = _topmost_results(headers, "spf")
    if not spf or spf[0] != "pass":
        acc.add(
            "MSG_SPF_NOT_PASS",
            _not_pass_severity(spf[:1]),
            {"result": excerpt(spf[0])} if spf else None,
            None if spf else "not_stated",
        )
    dkim = _topmost_results(headers, "dkim")
    if "pass" not in dkim:
        acc.add(
            "MSG_DKIM_NOT_PASS",
            _not_pass_severity(dkim),
            {"result": _joined(list(dict.fromkeys(dkim)))} if dkim else None,
            None if dkim else "not_stated",
        )
    if alignment.stated_dmarc != "pass":
        stated = alignment.stated_dmarc
        acc.add(
            "MSG_DMARC_NOT_PASS",
            _not_pass_severity([stated] if stated else []),
            {"result": excerpt(stated)} if stated else None,
            None if stated else "not_stated",
        )


def _alignment_part(alignment: AlignmentReport, have_authres: bool, acc: _Acc) -> None:
    if alignment.computed_dmarc == "fail":
        misaligned = [
            p.identifier_domain
            for p in alignment.pairs
            if p.state in ("misaligned", "aligned_but_not_passed") and p.identifier_domain
        ]
        acc.add(
            "MSG_ALIGNMENT_FAIL",
            "high",
            {
                "from_domain": excerpt(alignment.from_domains[0]) if alignment.from_domains else "",
                "identifiers": _joined(list(dict.fromkeys(misaligned))),
            },
        )
    elif alignment.computed_dmarc == "not_evaluated" and have_authres:
        reasons = [
            p.reason
            for p in alignment.pairs
            if p.state in ("unknown", "not_evaluated") and p.reason
        ]
        acc.add(
            "MSG_ALIGNMENT_NOT_EVALUATED",
            "medium",
            {"reasons": _joined(list(dict.fromkeys(reasons)))},
        )
        acc.skip("alignment")
    if alignment.dmarc_mismatch:
        acc.add(
            "MSG_ALIGNMENT_STATED_MISMATCH",
            "medium",
            {
                "stated": excerpt(alignment.stated_dmarc),
                "computed": alignment.computed_dmarc,
            },
        )
    # R1-22: say why a pair shown as aligned did not make the computed result pass.
    lower = [p for p in alignment.pairs if p.state == "aligned" and p.reason == LOWER_AUTHRES_FIELD]
    if lower and alignment.computed_dmarc != "pass":
        acc.add(
            "MSG_ALIGNMENT_LOWER_FIELD_NOT_USED",
            "low",
            {
                "methods": _joined(list(dict.fromkeys(p.kind for p in lower))),
                "domains": _joined(list(dict.fromkeys(p.identifier_domain or "" for p in lower))),
            },
        )
    unverified = [p.identifier_domain or "" for p in alignment.pairs if p.unverified_signature]
    if unverified:
        acc.add(
            "MSG_UNVERIFIED_DKIM_SIGNATURE",
            "low",
            {"count": len(unverified), "domains": _joined([d for d in unverified if d])},
        )


def _hop_part(hops: HopTimeline, acc: _Acc) -> None:
    """MSG_AUTH_BROKE_AFTER_HOP, one per older/newer entry pair. Info only: derived from the
    display-only per-hop view, it never changes a verdict."""
    grouped: dict[tuple[int, int], list[tuple[str, str, int | None, str | None]]] = {}
    for b in find_auth_breaks(hops):
        grouped.setdefault((b.from_order, b.to_order), []).append(
            (b.method, b.result, b.hop, b.authserv_id)
        )
    for items in grouped.values():
        hop, authserv_id = items[0][2], items[0][3]
        params: dict[str, object] = {
            "results": ", ".join(f"{m}={r}" for m, r, _, _ in items),
            "authserv_id": excerpt(authserv_id or ""),
        }
        if hop is not None:
            params["hop"] = hop
        acc.add("MSG_AUTH_BROKE_AFTER_HOP", "info", params, None if hop is not None else "no_hop")


def _arc_part(arc: ArcChain, acc: _Acc) -> None:
    if arc.status == "invalid":
        codes = list(dict.fromkeys(i.code for i in arc.issues if i.severity == "error"))
        acc.add("MSG_ARC_INVALID", "low", {"issues": _joined(codes)})
    elif arc.status == "cv_fail":
        acc.add("MSG_ARC_CV_FAIL", "medium")


# --- other headers ----------------------------------------------------------------------------


def _address_orgs(value: str) -> set[str] | None:
    """Organizational (or exact) domains of every address in ``value``; None if unusable."""
    orgs: set[str] = set()
    addrs = [a for _, a in getaddresses([value]) if a]
    if not addrs:
        return None
    for addr in addrs:
        if "@" not in addr:
            return None
        try:
            domain = to_ascii_domain(addr.rsplit("@", 1)[1])
            orgs.add(organizational_domain(domain) or domain)
        except InvalidDomainName:
            return None
    return orgs


def _other_part(block: HeaderBlock, alignment: AlignmentReport, acc: _Acc) -> None:
    if not block.get_all("Return-Path"):
        acc.add("MSG_RETURN_PATH_MISSING", "info")
    reply = block.get_all("Reply-To")
    if reply:
        theirs = _address_orgs(reply[0].raw_value)
        mine: set[str] = set()
        for d in alignment.from_domains:
            try:
                mine.add(organizational_domain(d) or d)
            except InvalidDomainName:
                continue
        if theirs is None:
            acc.add("MSG_REPLY_TO_UNUSABLE", "info")
        elif mine and not theirs <= mine:
            other = sorted(theirs - mine)
            acc.add(
                "MSG_REPLY_TO_DIFFERS",
                "info",
                {
                    "from_domain": excerpt(alignment.from_domains[0]),
                    "reply_to_domain": _joined(other),
                },
            )
    unsub = block.get_all("List-Unsubscribe")
    if not unsub:
        acc.add("MSG_LIST_UNSUBSCRIBE_MISSING", "info")
    else:
        # RFC 8058 section 3.1 / 5 verdict from the shared parser (same as the content analyzer).
        # A capped or unreadable field only leaves One-Click unknown when the https answer is
        # unknown (the parser stops at the first good https URI, as the content analyzer relies
        # on) and the field is not duplicated (RFC 8058 needs exactly one, so never One-Click).
        facts = analyze_list_unsubscribe(block)
        if facts.https_uri_present is None and not facts.duplicated:
            acc.skip("list_unsubscribe")
        elif not facts.one_click_eligible:
            acc.add("MSG_LIST_UNSUBSCRIBE_NO_ONECLICK", "info")
    broken = [w for w in block.warnings if w.code in _ENCODED_WORD_CODES]
    if broken:
        acc.add("MSG_ENCODED_HEADER_BROKEN", "low", {"count": len(broken)})


_MIME_CAP_LIMITS = (
    ("too_many_parts", "mime_parts"),
    ("mime_depth_exceeded", "mime_depth"),
    ("boundary_too_long", "mime_boundary"),
)


def _mime_part(mime: MimeSummary, acc: _Acc) -> None:
    if mime.truncated:
        acc.add("MSG_MIME_TRUNCATED", "low")
    if not mime.has_text_plain:
        acc.add("MSG_NO_TEXT_PART", "low")


# --- entry points -----------------------------------------------------------------------------


def build_message_findings(
    block: HeaderBlock,
    *,
    received: ReceivedChain,
    mime: MimeSummary | None,
    arc: ArcChain,
    alignment: AlignmentReport,
    hops: HopTimeline | None = None,
) -> MessageFindings:
    """Turn already parsed outputs into findings. ``mime`` None means it was not parsed;
    ``hops`` None means the per-hop view was not built (no MSG_AUTH_BROKE_AFTER_HOP)."""
    acc = _Acc()
    limits: list[str] = []
    try:
        headers = parse_all_authentication_results(block)
    except AuthResParseError:
        headers = ()
        limits.append("authentication_results")
        acc.skip("authres")
    _header_part(block, received, acc)
    _received_part(received, acc)
    if headers or "authres" not in acc.unevaluated:
        _auth_part(alignment, headers, acc)
    _alignment_part(alignment, bool(headers), acc)
    _arc_part(arc, acc)
    if hops is not None:
        _hop_part(hops, acc)
    _other_part(block, alignment, acc)
    if "list_unsubscribe" in acc.unevaluated:
        limits.append("list_unsubscribe")
    if mime is not None:
        _mime_part(mime, acc)

    if received.truncated:
        limits.append("received")
    if arc.truncated:
        limits.append("arc")
    if alignment.truncated:
        limits.append("alignment")
    if any(h.truncated for h in headers):
        limits.append("authentication_results")
    if any(w.code == TOO_MANY_WARNINGS for w in block.warnings):
        limits.append("warnings")
    if mime is not None:
        # One rule: any MIME cap (parts, depth, boundary length) is error-class.
        mime_codes = {w.code for w in mime.warnings}
        for warning_code, label in _MIME_CAP_LIMITS:
            if warning_code in mime_codes:
                limits.append(label)
        if mime.truncated and not (mime_codes & {c for c, _ in _MIME_CAP_LIMITS}):
            # The warning list is capped, so the specific cap warning may have been dropped.
            limits.append("mime")
    if limits:
        acc.add("MSG_PARSER_LIMIT", "medium", {"limits": ", ".join(dict.fromkeys(limits))})
        acc.skip("parser")
    return acc.result()


def rejected_input_findings(code: str) -> MessageFindings:
    """Result for input a parser rejected (``MessageParseError.code``); status is error."""
    acc = _Acc()
    acc.add("MSG_PARSER_LIMIT", "medium", {"limits": code})
    acc.skip("parser")
    return acc.result()
