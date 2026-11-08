"""Content analysis service (M5-14): composes the content parsers, the rules engine and findings.

`analyze_content(ctx, session, content)` is synchronous, like `analyze_message` and the
repositories (sync SQLAlchemy session). It blocks while the rules run (at most the engine budget,
about 15 s) and parses up to 2 MB of HTML, so async callers run the whole call in a worker
thread with `run_in_threadpool`, exactly as `/message/analyze` does. For that reason it calls
`evaluate_rules` directly: `evaluate_rules_async` is for code running on the event loop.

Input: html and/or text, optional subject, optional raw `.eml`. A field given explicitly wins
over the same value extracted from the `.eml`, so edited HTML can be checked against the real
headers. Without an `.eml` there are no headers, so List-Unsubscribe is `not_evaluated`.

Not a `Check` (app/checks/content.py is deliberately absent): `Check.run` takes a `CheckContext`,
which has no database handle by design, and a `Target`, which requires a domain. This analysis
needs a tenant session for the rules and takes message content instead of a domain.

Hard rules:

- Nothing is stored and this module has no logger, so request content cannot reach the logs.
  No DNS or sockets: every parser here is offline.
- Tenant rules are read only through `repo_for(ctx, session).content_rules`, every page, without
  `enabled_only`, and always merged with `merge_tenant_rules`, so a disabled tenant override
  suppresses its global rule wherever it sits in the id order.
- It does not raise on bad content: a failure stays inside its section. A wrong `ctx` type is a
  programming error and raises `TypeError`, as does anything but a `ContentInput`.

Status mapping:

- Per-rule results keep the engine's values.
- A section is `error` when it could not be fully evaluated: a parser cap, an undecodable `.eml`,
  unknown DKIM coverage of One-Click headers, or for the rules a capped body, `input_capped`,
  `busy`, `budget_exceeded`, `too_many_rules` or any rule `error`. Any such section makes the
  overall status `error`.
- A section is `not_evaluated` when it had no input (no headers, no HTML, no subject, no content
  for the rules) or, for the rules, when no enabled rule applied: `RulesFacts` then shows zero
  rules evaluated, so "no match" cannot be read as "the rules ran and passed".
- Otherwise a section's status derives from its own findings. The overall status does too, and
  is `not_evaluated` only when every section is; `complete` is False and
  `not_evaluated_sections` names them whenever one was skipped.
- `complete` is also False, with the status unchanged and a reason on the section, when part of
  a section was skipped: an unreadable link (a low finding, so `warn`), links with no sender
  domain to compare them with, or, with no language hint, enabled rules left out because they
  have a language. A hint that excludes other languages is
  a choice and stays complete. A too-long DKIM signature list only affects link alignment.

Reading an `.eml`: `parse_mime` reports offsets and never decodes, so the transfer encoding and
charset of the body parts are decoded here. Every non-attachment text/plain and text/html part
outside an attached message is used, joined by a newline (a footer part is still body). Parts
of an attached message/rfc822 are not the body of this message.

The rules need the visible HTML text, which `parse_content` only measures. `_VisibleText` extends
its collector, so what counts as visible cannot drift from M5-08. Text runs are joined by a
space: adjacent blocks do not merge into false words, and a word split across inline tags is
not matched (known limit).

DKIM: signatures are not verified here. The `h=` lists of all DKIM-Signature fields are passed to
the M5-10 analysis, so `False` is reliable (no signature lists the field at all) while `True` only
means "listed"; `UnsubscribeFacts.signature_verified` is always False and says so.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import quopri
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.checks.models import CheckResult, Finding, Status, derive_status
from app.core.tenancy import TenantContext
from app.parsers import mime as mime_mod
from app.parsers.content_html import (
    _SKIP_TEXT,
    ContentLimits,
    ContentStructure,
    _Collector,
    parse_content,
)
from app.parsers.content_links import LinkAnalysis, analyze_links
from app.parsers.content_subject import SubjectFacts, analyze_subject
from app.parsers.list_unsubscribe import ListUnsubscribeFacts, analyze_list_unsubscribe
from app.parsers.message import (
    HeaderBlock,
    MessageParseError,
    _lookup_charset,
    parse_header_block,
)
from app.parsers.mime import MimePart, MimeSummary, parse_mime
from app.parsers.url_shorteners import list_shorteners
from app.repositories import repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.content_rules import ContentRuleRecord
from app.services import content_findings as cf
from app.services.content_findings import SectionFindings
from app.services.content_rules_engine import (
    RuleResults,
    RuleStatus,
    evaluate_rules,
    merge_tenant_rules,
)
from app.services.message_alignment import analyze_alignment
from app.services.message_findings import excerpt

__all__ = ["ContentAnalysis", "ContentInput", "analyze_content", "load_tenant_rules"]

CHECK_ID = "content_analysis"
RULE_PAGE_SIZE = MAX_LIMIT

SectionStatus = Literal["ok", "warn", "fail", "info", "error", "not_evaluated"]

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_LISTED_DOMAINS = 20
_H_TAG = re.compile(r"^\s*h\s*=(.*)$", re.DOTALL)
_IDENTITY_ENCODINGS = frozenset({"7bit", "8bit", "binary"})
# MIME warnings after which the body parts found cannot be trusted to be the whole body.
_STRUCTURE_WARNINGS = frozenset(
    {
        mime_mod.PART_HEADERS_UNPARSEABLE,
        mime_mod.ENCODED_COMPOSITE,
        mime_mod.MISSING_BOUNDARY,
        mime_mod.MULTIPART_NO_PARTS,
    }
)


@dataclass(frozen=True, slots=True)
class ContentInput:
    html: str | None = None
    text: str | None = None
    subject: str | None = None
    eml: bytes | None = None
    # Rules with a language run only when it equals this hint (M5-13); None: NULL-language only.
    language_hint: str | None = None


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True)


class MessageFacts(_Model):
    from_domains: tuple[str, ...]
    dkim_domains: tuple[str, ...]
    body_parts: int


class BodyFacts(_Model):
    has_html: bool
    has_plain_text: bool
    html_bytes: int | None
    text_bytes: int | None
    visible_text_length: int
    image_count: int
    images_missing_alt: int
    images_empty_alt: int
    inline_style_bytes: int
    style_tag_bytes: int
    hidden_candidates: int
    malformed: tuple[str, ...]
    charset: str | None
    clip_risk_threshold_bytes: int
    exceeds_clip_risk_threshold: bool
    capped: bool
    cap_reason: str | None


class LinkFacts(_Model):
    total_anchors: int
    analyzed_links: int
    web_links: int
    masked: int
    shorteners: int
    non_https: int
    ip_literals: int
    sender_domains: tuple[str, ...]
    unaligned_count: int | None  # None: no sender domain, or no link with a host
    unevaluated_count: int
    alignment_evaluated: bool  # True only when every link was compared with a sender domain
    other_domains: tuple[str, ...]
    capped: bool
    cap_reason: str | None


class SubjectView(_Model):
    present: bool
    length_graphemes: int | None
    length_bytes: int | None
    is_long: bool | None
    empty: bool | None
    caps_ratio: float | None
    all_caps: bool | None
    max_punct_run: int | None
    emoji_count: int | None
    reply_prefix: str | None
    control_chars: int | None
    has_bidi_override: bool | None
    mixed_script_word: bool | None
    capped: bool | None


class UnsubscribeFacts(_Model):
    present: bool
    field_count: int
    duplicated: bool
    https_uri_present: bool | None
    http_uri_present: bool | None
    mailto_uri_present: bool | None
    nonstandard_authority: bool
    post_present: bool
    post_value_exact: bool | None
    post_value_matches_abnf: bool | None
    one_click_eligible: bool
    list_unsubscribe_signed: bool | None
    post_signed: bool | None
    one_click_signed: bool | None
    signature_verified: Literal[False]  # `*_signed` only mean "named in a DKIM h= list"


class RuleView(_Model):
    rule_id: int
    seed_key: str | None
    name: str
    category: str
    severity: str
    weight: int
    status: str  # the engine's per-rule value
    issue: str | None
    part: str | None
    evidence: str | None


class CategoryView(_Model):
    category: str
    score: int
    matched: int


class RulesFacts(_Model):
    enabled_rules: int  # effective for this tenant, after the merge
    skipped_by_language: int
    evaluated_rules: int  # reached a verdict: matched or ok
    matched_rules: int
    error_rules: int
    not_evaluated_rules: int
    score: int
    complete: bool
    capped_parts: tuple[str, ...]
    categories: tuple[CategoryView, ...]
    results: tuple[RuleView, ...]


class _Section(_Model):
    status: SectionStatus
    reasons: tuple[str, ...]  # why it is `error`, `not_evaluated` or partly skipped
    facts: BaseModel | None = None


class MessageSection(_Section):
    facts: MessageFacts | None = None


class BodySection(_Section):
    facts: BodyFacts | None = None


class LinksSection(_Section):
    facts: LinkFacts | None = None


class SubjectSection(_Section):
    facts: SubjectView | None = None


class UnsubscribeSection(_Section):
    facts: UnsubscribeFacts | None = None


class RulesSection(_Section):
    facts: RulesFacts | None = None


class ContentAnalysis(_Model):
    """Result of :func:`analyze_content`; `model_dump_json()` is the wire format."""

    status: SectionStatus
    complete: bool  # every section was fully evaluated; `status` alone does not say so
    not_evaluated_sections: tuple[str, ...]
    message: MessageSection | None  # None when no .eml was given
    body: BodySection
    links: LinksSection
    subject: SubjectSection
    unsubscribe: UnsubscribeSection
    rules: RulesSection
    findings: tuple[Finding, ...]


@dataclass(slots=True)
class _Eml:
    block: HeaderBlock | None = None
    html: str | None = None
    text: str | None = None
    subject: str | None = None
    has_reply_headers: bool | None = None  # In-Reply-To or References
    from_domains: tuple[str, ...] = ()
    dkim_domains: tuple[str, ...] = ()
    body_parts: int = 0
    # Stable reason codes. All of them mean the body may be incomplete.
    problems: list[str] = field(default_factory=list)
    dkim_truncated: bool = False  # sender domains may be missing some DKIM d= values

    def problem(self, reason: str) -> None:
        if reason not in self.problems:
            self.problems.append(reason)


# --- .eml ------------------------------------------------------------------------------------


def _decode_body(raw: bytes, part: MimePart, eml: _Eml) -> str | None:
    start = part.offset + part.header_bytes
    body = raw[start : start + part.encoded_size]
    encoding = part.transfer_encoding
    if encoding == "base64":
        try:
            data = base64.b64decode(b"".join(body.split()), validate=True)
        except (binascii.Error, ValueError):
            eml.problem("undecodable_part")
            return None
    elif encoding == "quoted-printable":
        data = quopri.decodestring(body)
    elif encoding in _IDENTITY_ENCODINGS:
        data = body
    else:
        eml.problem("unknown_transfer_encoding")
        return None
    codec = "utf-8"  # RFC 2045 default is US-ASCII, which UTF-8 contains
    if part.charset is not None:
        looked_up = _lookup_charset(part.charset)
        if looked_up is None:
            eml.problem("unknown_charset")
        else:
            codec = looked_up
    try:
        return data.decode(codec)
    except (UnicodeDecodeError, LookupError):
        eml.problem("undecodable_part")
        return data.decode("utf-8", "replace")


def _body_parts(summary: MimeSummary) -> list[MimePart]:
    inside_attached: set[int] = set()
    chosen: list[MimePart] = []
    for part in summary.parts:  # pre-order: a parent is always seen before its children
        if part.parent in inside_attached or part.category == mime_mod.CATEGORY_MESSAGE:
            inside_attached.add(part.index)
        elif part.category in (mime_mod.CATEGORY_TEXT, mime_mod.CATEGORY_HTML):
            chosen.append(part)
    return chosen


def _read_body(raw: bytes, eml: _Eml) -> None:
    summary = parse_mime(raw)
    if summary.truncated:
        eml.problem("mime_truncated")
    for warning in summary.warnings:
        if warning.code in _STRUCTURE_WARNINGS:
            eml.problem(f"mime_{warning.code}")
    texts: dict[str, list[str]] = {mime_mod.CATEGORY_TEXT: [], mime_mod.CATEGORY_HTML: []}
    for part in _body_parts(summary):
        decoded = _decode_body(raw, part, eml)
        if decoded is not None:
            texts[part.category].append(decoded)
            eml.body_parts += 1
    eml.text = "\n".join(texts[mime_mod.CATEGORY_TEXT]) or None
    eml.html = "\n".join(texts[mime_mod.CATEGORY_HTML]) or None


def _read_identities(block: HeaderBlock, eml: _Eml) -> None:
    report = analyze_alignment(block)
    eml.from_domains = tuple(report.from_domains)
    eml.dkim_domains = tuple(
        dict.fromkeys(
            pair.identifier_domain
            for pair in report.pairs
            if pair.identifier_source == "dkim_signature" and pair.identifier_domain
        )
    )
    eml.dkim_truncated = report.truncated


def _read_eml(raw: object) -> _Eml:
    eml = _Eml()
    if not isinstance(raw, bytes | bytearray):
        eml.problem("invalid_input")
        return eml
    data = bytes(raw)
    if not data:
        eml.problem("empty_input")
        return eml
    try:
        block = parse_header_block(data)
    except MessageParseError as exc:
        eml.problem(exc.code)
        return eml
    if not any(f.name for f in block.fields):  # colon-less text parses to empty names
        eml.problem("no_header_block")
        return eml
    eml.block = block
    subject = block.get_all("Subject")
    if subject:
        eml.subject = subject[0].decoded_value
    eml.has_reply_headers = bool(block.get_all("In-Reply-To") or block.get_all("References"))
    steps: tuple[tuple[str, Callable[[], None]], ...] = (
        ("identities", lambda: _read_identities(block, eml)),
        ("mime", lambda: _read_body(data, eml)),
    )
    for name, step in steps:
        try:
            step()
        except MessageParseError as exc:
            eml.problem(exc.code)
        except Exception:
            eml.problem(f"{name}_failed")
    return eml


def _dkim_header_lists(block: HeaderBlock) -> list[list[str]] | None:
    """The `h=` names of each DKIM-Signature; None when one cannot be read (unknown coverage)."""
    lists: list[list[str]] = []
    for signature in block.get_all("DKIM-Signature"):
        tags = (_H_TAG.match(tag) for tag in signature.raw_value.split(";"))
        match = next((m for m in tags if m is not None), None)
        if match is None:
            return None
        lists.append(["".join(name.split()) for name in match.group(1).split(":")])
    return lists


# --- sections --------------------------------------------------------------------------------


class _VisibleText(_Collector):
    def __init__(self, limits: ContentLimits) -> None:
        super().__init__(limits)
        self.chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        super().handle_data(data)
        if data.strip() and not _SKIP_TEXT.intersection(self.stack):
            self.chunks.append(data)


def _visible_text(html: str, structure: ContentStructure) -> str | None:
    if not structure.has_html_part or structure.cap_reason == "input_size":
        return None
    collector = _VisibleText(ContentLimits())
    # A cap raises here exactly as in parse_content, which reports it; the partial text is kept.
    with contextlib.suppress(Exception):
        collector.feed(html.replace("\x00", "�"))
        collector.close()
    return " ".join(collector.chunks)


def load_tenant_rules(ctx: TenantContext, session: Session) -> list[ContentRuleRecord]:
    """All global and tenant rows visible to `ctx`: enabled or not, every page.

    `list()` defaults to one page of 100, so without paging a disabled override past page 1 would
    be lost and its global rule would wrongly run.
    """
    repository = repo_for(ctx, session).content_rules
    rows: list[ContentRuleRecord] = []
    while True:
        page = repository.list(limit=RULE_PAGE_SIZE, offset=len(rows))
        rows.extend(page)
        if len(page) < RULE_PAGE_SIZE:
            return rows


def _section_status(found: SectionFindings) -> Status:
    return derive_status(found.findings, not found.unevaluated)


def _body_view(s: ContentStructure) -> BodyFacts:
    return BodyFacts(
        has_html=s.has_html_part,
        has_plain_text=s.has_plain_text_part,
        html_bytes=s.html_bytes,
        text_bytes=s.text_bytes,
        visible_text_length=s.visible_text_length,
        image_count=s.image_count,
        images_missing_alt=s.images_missing_alt,
        images_empty_alt=s.images_empty_alt,
        inline_style_bytes=s.inline_style_bytes,
        style_tag_bytes=s.style_tag_bytes,
        hidden_candidates=len(s.hidden_candidates),
        malformed=s.malformed,
        charset=None if s.charset is None else excerpt(s.charset),
        clip_risk_threshold_bytes=s.gmail_clip_threshold_bytes,
        exceeds_clip_risk_threshold=s.exceeds_gmail_clip_threshold,
        capped=s.capped,
        cap_reason=s.cap_reason,
    )


def _link_view(a: LinkAnalysis, senders_complete: bool) -> LinkFacts:
    links = a.links
    return LinkFacts(
        total_anchors=a.total_anchors,
        analyzed_links=len(links),
        web_links=sum(1 for ln in links if ln.kind == "web"),
        masked=sum(1 for ln in links if ln.masked),
        shorteners=sum(1 for ln in links if ln.shortener),
        non_https=sum(1 for ln in links if ln.non_https),
        ip_literals=sum(1 for ln in links if ln.ip_literal),
        sender_domains=a.sender_domains,
        unaligned_count=a.unaligned_count,
        unevaluated_count=a.unevaluated_count,
        alignment_evaluated=(
            senders_complete and a.unaligned_count is not None and a.unevaluated_count == 0
        ),
        other_domains=tuple(excerpt(d) for d in a.other_domains[:_LISTED_DOMAINS]),
        capped=a.capped,
        cap_reason=a.cap_reason,
    )


def _subject_view(f: SubjectFacts) -> SubjectView:
    return SubjectView(
        present=f.present,
        length_graphemes=f.length_graphemes,
        length_bytes=f.length_bytes,
        is_long=f.is_long,
        empty=f.empty,
        caps_ratio=f.caps_ratio,
        all_caps=f.all_caps,
        max_punct_run=f.max_punct_run,
        emoji_count=f.emoji_count,
        reply_prefix=f.reply_prefix,
        control_chars=f.control_chars,
        has_bidi_override=f.has_bidi_override,
        mixed_script_word=f.mixed_script_word,
        capped=f.capped,
    )


def _unsubscribe_view(f: ListUnsubscribeFacts) -> UnsubscribeFacts:
    return UnsubscribeFacts(
        present=f.present,
        field_count=f.field_count,
        duplicated=f.duplicated,
        https_uri_present=f.https_uri_present,
        http_uri_present=f.http_uri_present,
        mailto_uri_present=f.mailto_uri_present,
        nonstandard_authority=any(u.nonstandard_authority for x in f.fields for u in x.uris),
        post_present=f.post_present,
        post_value_exact=f.post_value_exact,
        post_value_matches_abnf=f.post_value_matches_abnf,
        one_click_eligible=f.one_click_eligible,
        list_unsubscribe_signed=f.list_unsubscribe_signed,
        post_signed=f.post_signed,
        one_click_signed=f.one_click_signed,
        signature_verified=False,
    )


def _rules_view(enabled: int, results: RuleResults | None) -> RulesFacts:
    rows = results.results if results is not None else ()
    verdicts = (RuleStatus.MATCHED, RuleStatus.OK)
    return RulesFacts(
        enabled_rules=enabled,
        skipped_by_language=enabled - len(rows) if results is not None else 0,
        evaluated_rules=sum(1 for r in rows if r.status in verdicts),
        matched_rules=sum(1 for r in rows if r.status is RuleStatus.MATCHED),
        error_rules=results.error_count if results is not None else 0,
        not_evaluated_rules=results.not_evaluated_count if results is not None else 0,
        score=results.score if results is not None else 0,
        complete=results.complete if results is not None else False,
        capped_parts=tuple(p.value for p in results.capped_parts) if results is not None else (),
        categories=tuple(
            CategoryView(category=c.category, score=c.score, matched=c.matched)
            for c in (results.categories if results is not None else ())
        ),
        results=tuple(
            RuleView(
                rule_id=r.rule_id,
                seed_key=r.seed_key,
                name=r.name,
                category=r.category,
                severity=r.severity,
                weight=r.weight,
                status=r.status.value,
                issue=None if r.issue is None else r.issue.value,
                part=None if r.part is None else r.part.value,
                evidence=r.evidence,
            )
            for r in rows
        ),
    )


def _attempt[T](fail: str, step: Callable[[], T]) -> T | SectionFindings:
    """Run a section's parser; any exception becomes that section's error result."""
    try:
        return step()
    except Exception:
        return cf.failed_section(fail)


@dataclass(slots=True)
class _Outcome:
    """What the sections produced so far, for the overall status."""

    findings: list[Finding] = field(default_factory=list)
    not_evaluated: list[str] = field(default_factory=list)
    errors: int = 0
    evaluated: int = 0
    partial: bool = False

    def section[S: _Section](
        self,
        kind: type[S],
        name: str,
        found: SectionFindings,
        facts: BaseModel | None,
        *,
        extra_reasons: tuple[str, ...] = (),
        idle_reason: str | None = None,
    ) -> S:
        """Record one section. `extra_reasons` make it `error`; else `idle_reason` skips it."""
        self.findings.extend(found.findings)
        self.partial = self.partial or bool(found.partial)
        reasons = tuple(dict.fromkeys((*found.unevaluated, *extra_reasons)))
        if reasons:
            self.errors += 1
            return kind(status="error", reasons=(*reasons, *found.partial), facts=facts)
        if idle_reason is not None:
            self.not_evaluated.append(name)
            return kind(status="not_evaluated", reasons=(idle_reason,), facts=facts)
        self.evaluated += 1
        return kind(status=_section_status(found), reasons=found.partial, facts=facts)


def _rules_section(
    ctx: TenantContext,
    session: Session,
    outcome: _Outcome,
    *,
    subject: str | None,
    text: str | None,
    visible_text: str | None,
    language: str | None,
    incomplete_body: tuple[str, ...],
) -> RulesSection:
    def failed(reason: str, enabled: int) -> RulesSection:
        return outcome.section(
            RulesSection,
            "rules",
            cf.rules_unavailable(reason),
            _rules_view(enabled, None),
            extra_reasons=incomplete_body,
        )

    try:
        merged = merge_tenant_rules(load_tenant_rules(ctx, session), tenant_id=ctx.tenant_id)
    except Exception:
        return failed("rules_unavailable", 0)
    enabled = sum(1 for rule in merged if rule.enabled)
    try:
        results = evaluate_rules(
            merged,
            subject=subject,
            text=text,
            html_visible_text=visible_text,
            language_hint=language,
        )
        found = cf.rule_findings(results, {rule.id: rule for rule in merged})
    except Exception:
        return failed("rules_engine_failed", enabled)
    idle: str | None = None
    if not (subject or text or visible_text):
        idle = "no_input"
    elif enabled == 0:
        idle = "no_enabled_rules"
    elif not results.results:
        idle = "no_applicable_rules"
    elif not (language or "").strip() and len(results.results) < enabled:
        found = replace(found, partial=("language_rules_skipped",))
    return outcome.section(
        RulesSection,
        "rules",
        found,
        _rules_view(enabled, results),
        extra_reasons=incomplete_body,
        idle_reason=idle,
    )


def _text_or_problem(value: object, problems: list[str], name: str) -> str | None:
    if value is None or isinstance(value, str):
        return value
    problems.append(f"invalid_{name}")
    return None


def analyze_content(ctx: TenantContext, session: Session, content: ContentInput) -> ContentAnalysis:
    """Analyse one message. Blocking: see the module docstring. Stores nothing."""
    if not isinstance(ctx, TenantContext):
        raise TypeError("analyze_content requires a TenantContext")
    if not isinstance(content, ContentInput):
        raise TypeError("analyze_content requires a ContentInput")
    outcome = _Outcome()
    input_problems: list[str] = []
    html = _text_or_problem(content.html, input_problems, "html")
    text = _text_or_problem(content.text, input_problems, "text")
    subject = _text_or_problem(content.subject, input_problems, "subject")
    language = _text_or_problem(content.language_hint, input_problems, "language_hint")

    eml = _read_eml(content.eml) if content.eml is not None else None
    if eml is not None:
        html = html if html else eml.html
        text = text if text else eml.text
        subject = subject if subject is not None else eml.subject

    message: MessageSection | None = None
    if eml is not None:
        message = outcome.section(
            MessageSection,
            "message",
            cf.input_findings(
                [*eml.problems, *(["dkim_signatures_truncated"] if eml.dkim_truncated else [])]
            ),
            MessageFacts(
                from_domains=tuple(excerpt(d) for d in eml.from_domains),
                dkim_domains=tuple(excerpt(d) for d in eml.dkim_domains),
                body_parts=eml.body_parts,
            ),
        )

    # Body
    structure = _attempt("body_parser_failed", lambda: parse_content(html, text))
    body_problems = (*(eml.problems if eml is not None else ()), *input_problems)
    has_input = bool((html and html.strip()) or (text and text.strip()))
    body_reasons: tuple[str, ...] = tuple(body_problems)
    body_view: BodyFacts | None = None
    if isinstance(structure, SectionFindings):
        found_body = structure
        structure_ok: ContentStructure | None = None
    else:
        structure_ok = structure
        found_body = cf.body_findings(structure) if has_input else SectionFindings()
        body_view = _body_view(structure) if has_input else None
    if input_problems:
        found_body = SectionFindings(
            (*found_body.findings, *cf.input_findings(input_problems).findings),
            found_body.unevaluated,
        )
    body = outcome.section(
        BodySection,
        "body",
        found_body,
        body_view,
        extra_reasons=body_reasons,
        idle_reason=None if has_input else "no_input",
    )

    # Links
    body_capped = tuple(found_body.unevaluated)
    incomplete_body = tuple(dict.fromkeys((*body_capped, *body_problems)))
    links_section = _links_section(outcome, structure_ok, eml, incomplete_body)

    # Subject
    subject_known = subject is not None or (eml is not None and eml.block is not None)
    facts_subject = _attempt(
        "subject_parser_failed",
        lambda: analyze_subject(
            subject, has_in_reply_to=eml.has_reply_headers if eml is not None else None
        ),
    )
    if isinstance(facts_subject, SectionFindings):
        subject_section = outcome.section(SubjectSection, "subject", facts_subject, None)
    else:
        subject_section = outcome.section(
            SubjectSection,
            "subject",
            cf.subject_findings(facts_subject) if subject_known else SectionFindings(),
            _subject_view(facts_subject),
            idle_reason=None if subject_known else "no_subject",
        )

    # List-Unsubscribe
    unsubscribe = _unsubscribe_section(outcome, eml)

    # Rules
    visible = _visible_text(html, structure_ok) if html and structure_ok is not None else None
    rules = _rules_section(
        ctx,
        session,
        outcome,
        subject=subject,
        text=text,
        visible_text=visible,
        language=language,
        incomplete_body=incomplete_body,
    )

    return _finish(outcome, message, body, links_section, subject_section, unsubscribe, rules)


def _links_section(
    outcome: _Outcome,
    structure: ContentStructure | None,
    eml: _Eml | None,
    incomplete_body: tuple[str, ...],
) -> LinksSection:
    if structure is None or not structure.has_html_part:
        return outcome.section(
            LinksSection,
            "links",
            SectionFindings(),
            None,
            extra_reasons=incomplete_body,
            idle_reason="no_html",
        )
    senders = (*eml.from_domains, *eml.dkim_domains) if eml is not None else ()
    facts = _attempt(
        "links_parser_failed",
        lambda: analyze_links(
            structure.anchors, sender_domains=senders, shorteners=list_shorteners()
        ),
    )
    if isinstance(facts, SectionFindings):
        return outcome.section(LinksSection, "links", facts, None, extra_reasons=incomplete_body)
    return outcome.section(
        LinksSection,
        "links",
        cf.link_findings(facts),
        _link_view(facts, senders_complete=eml is None or not eml.dkim_truncated),
        extra_reasons=incomplete_body,
    )


def _unsubscribe_section(outcome: _Outcome, eml: _Eml | None) -> UnsubscribeSection:
    if eml is None or eml.block is None:
        reasons = tuple(eml.problems) if eml is not None else ()
        return outcome.section(
            UnsubscribeSection,
            "unsubscribe",
            SectionFindings(),
            None,
            extra_reasons=reasons,
            idle_reason="no_headers",
        )
    block = eml.block
    facts = _attempt(
        "unsubscribe_parser_failed",
        lambda: analyze_list_unsubscribe(block, dkim_signed_headers=_dkim_header_lists(block)),
    )
    if isinstance(facts, SectionFindings):
        return outcome.section(UnsubscribeSection, "unsubscribe", facts, None)
    return outcome.section(
        UnsubscribeSection, "unsubscribe", cf.unsubscribe_findings(facts), _unsubscribe_view(facts)
    )


def _finish(
    outcome: _Outcome,
    message: MessageSection | None,
    body: BodySection,
    links: LinksSection,
    subject: SubjectSection,
    unsubscribe: UnsubscribeSection,
    rules: RulesSection,
) -> ContentAnalysis:
    # CheckResult owns the sorting rule and status derivation; the timestamp is a placeholder.
    ordered = CheckResult.build(
        check_id=CHECK_ID,
        target="content",
        findings=outcome.findings,
        evaluated=outcome.errors == 0,
        started_at=_EPOCH,
        duration_ms=0,
    )
    status: SectionStatus = ordered.status
    if outcome.errors == 0 and outcome.evaluated == 0:
        status = "not_evaluated"
    return ContentAnalysis(
        status=status,
        complete=outcome.errors == 0 and not outcome.not_evaluated and not outcome.partial,
        not_evaluated_sections=tuple(outcome.not_evaluated),
        message=message,
        body=body,
        links=links,
        subject=subject,
        unsubscribe=unsubscribe,
        rules=rules,
        findings=ordered.findings,
    )
