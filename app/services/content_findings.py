"""Verdicts over the content parser facts: CONTENT_* findings (M5-14).

Pure and offline. Each function turns the facts of one section into :class:`SectionFindings`;
`app.services.content_analysis` composes them. Nothing here reads the database or logs.

Rules:

- `SectionFindings.unevaluated` lists stable reasons why a section could not be fully evaluated.
  Any reason makes the section and the overall status `error` (CLAUDE.md: error, not ok).
- Text from the message reaches findings only through `excerpt` and only as hosts, tags and
  bounded snippets: never a full URL (it can carry tokens or addresses) and never the body.
- Every `*_THRESHOLD`-style constant below is a heuristic chosen by this project and `unverified`:
  no official mailbox provider source has been checked for any of them, none is attributed to a
  provider, and their texts say "advisory" (en) / "indicativa" (it).

Severity per code:

=================================== ======== ==============================================
Code                                Severity Meaning
=================================== ======== ==============================================
CONTENT_INPUT_CAPPED                medium   input capped, rejected or undecodable (error-class)
CONTENT_RULE_ERROR                  medium   rules failed or left unevaluated (error-class)
CONTENT_RULE_MATCH                  rule's   one finding per matched rule
CONTENT_LINK_UNEVALUATED            low      link address unreadable (error-class)
CONTENT_MASKED_LINK                 high     link text names another domain
CONTENT_IP_LITERAL_LINK             high     link host is an IP address
CONTENT_URL_SHORTENER               medium   link host is on the shortener list
CONTENT_HIDDEN_TEXT                 medium   inline styles that may hide content
CONTENT_SUBJECT_BIDI_OVERRIDE       medium   bidi override characters in the Subject
CONTENT_SUBJECT_CONTROL_CHARS       medium   control characters in the Subject
CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER medium   unsubscribe fields in no DKIM h= list
CONTENT_NON_HTTPS_LINK              low      link uses http
CONTENT_UNALIGNED_LINK_DOMAIN       low      link domain differs from the sender domains
CONTENT_MANY_LINK_DOMAINS           low      many distinct link domains (advisory)
CONTENT_MISSING_PLAIN_TEXT          low      HTML without a plain text version
CONTENT_LOW_TEXT_IMAGE_RATIO        low      little text per image (advisory)
CONTENT_IMAGES_MISSING_ALT          low      images without an alt attribute
CONTENT_MALFORMED_HTML              low      structural HTML problems
CONTENT_GMAIL_CLIP_RISK             low      HTML size over the clipping heuristic (advisory)
CONTENT_EXCESS_CSS                  low      CSS is most of the HTML (advisory)
CONTENT_SUBJECT_EMPTY               low      Subject absent or blank
CONTENT_SUBJECT_ALL_CAPS            low      mostly capitals (advisory)
CONTENT_SUBJECT_PUNCTUATION         low      runs of ! or ? (advisory)
CONTENT_SUBJECT_LONG                low      long Subject (advisory)
CONTENT_SUBJECT_REPLY_PREFIX        low      Re:/Fwd: without In-Reply-To
CONTENT_SUBJECT_MIXED_SCRIPT        low      one word mixes scripts
CONTENT_NO_LIST_UNSUBSCRIBE         low      no List-Unsubscribe header
CONTENT_NO_ONE_CLICK                low      RFC 8058 one-click not offered
CONTENT_HTTP_ONLY_UNSUBSCRIBE       low      unsubscribe by http only
=================================== ======== ==============================================
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from app.checks.models import Finding, Severity, finding
from app.core.i18n import DEFAULT_LANGUAGE, load_catalogue
from app.parsers.content_html import ContentStructure
from app.parsers.content_links import LinkAnalysis
from app.parsers.content_subject import SubjectFacts
from app.parsers.list_unsubscribe import ListUnsubscribeFacts
from app.repositories.content_rules import ContentRuleRecord
from app.services.content_rules_engine import RuleIssue, RuleResult, RuleResults, RuleStatus
from app.services.message_findings import excerpt

# Advisory heuristics, chosen by this project; unverified against any provider documentation.
MIN_VISIBLE_CHARS_PER_IMAGE: Final = 100
MANY_LINK_DOMAINS_THRESHOLD: Final = 5
EXCESS_CSS_MIN_HTML_BYTES: Final = 10_240  # below this a high CSS share means little
EXCESS_CSS_PERCENT: Final = 50

_LISTED_ITEMS: Final = 5
_INCOMPLETE_ISSUES: Final = frozenset(
    {RuleIssue.BUSY, RuleIssue.BUDGET_EXCEEDED, RuleIssue.TOO_MANY_RULES}
)

CODES: tuple[str, ...] = (
    "CONTENT_INPUT_CAPPED",
    "CONTENT_RULE_ERROR",
    "CONTENT_RULE_MATCH",
    "CONTENT_LINK_UNEVALUATED",
    "CONTENT_MASKED_LINK",
    "CONTENT_IP_LITERAL_LINK",
    "CONTENT_URL_SHORTENER",
    "CONTENT_HIDDEN_TEXT",
    "CONTENT_SUBJECT_BIDI_OVERRIDE",
    "CONTENT_SUBJECT_CONTROL_CHARS",
    "CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER",
    "CONTENT_NON_HTTPS_LINK",
    "CONTENT_UNALIGNED_LINK_DOMAIN",
    "CONTENT_MANY_LINK_DOMAINS",
    "CONTENT_MISSING_PLAIN_TEXT",
    "CONTENT_LOW_TEXT_IMAGE_RATIO",
    "CONTENT_IMAGES_MISSING_ALT",
    "CONTENT_MALFORMED_HTML",
    "CONTENT_GMAIL_CLIP_RISK",
    "CONTENT_EXCESS_CSS",
    "CONTENT_SUBJECT_EMPTY",
    "CONTENT_SUBJECT_ALL_CAPS",
    "CONTENT_SUBJECT_PUNCTUATION",
    "CONTENT_SUBJECT_LONG",
    "CONTENT_SUBJECT_REPLY_PREFIX",
    "CONTENT_SUBJECT_MIXED_SCRIPT",
    "CONTENT_NO_LIST_UNSUBSCRIBE",
    "CONTENT_NO_ONE_CLICK",
    "CONTENT_HTTP_ONLY_UNSUBSCRIBE",
)

# Codes whose thresholds are heuristics: their texts must say "advisory".
ADVISORY_CODES: tuple[str, ...] = (
    "CONTENT_LOW_TEXT_IMAGE_RATIO",
    "CONTENT_MANY_LINK_DOMAINS",
    "CONTENT_GMAIL_CLIP_RISK",
    "CONTENT_EXCESS_CSS",
    "CONTENT_SUBJECT_ALL_CAPS",
    "CONTENT_SUBJECT_PUNCTUATION",
    "CONTENT_SUBJECT_LONG",
)

# Alternative text keys, beyond the title/detail/remediation of every code.
ONE_CLICK_VARIANTS: tuple[str, ...] = (
    "duplicated",
    "post_value",
    "no_https_uri",
    "nonstandard_authority",
)
RULE_MATCH_CUSTOM_ADVICE: Final = "remediation_custom"


@dataclass(frozen=True, slots=True)
class SectionFindings:
    findings: tuple[Finding, ...] = ()
    unevaluated: tuple[str, ...] = ()  # stable reasons; any makes the section `error`


class _Acc:
    def __init__(self) -> None:
        self.items: list[Finding] = []
        self.unevaluated: list[str] = []

    def add(
        self,
        code: str,
        severity: Severity,
        params: dict[str, object] | None = None,
        evidence: Iterable[str] = (),
        detail_variant: str | None = None,
    ) -> None:
        shown = [excerpt(e) for e in dict.fromkeys(evidence)][:_LISTED_ITEMS]
        built = finding(code, severity, params, evidence=[e for e in shown if e])
        if detail_variant:
            built = built.model_copy(
                update={"detail_key": f"finding.{code}.detail_{detail_variant}"}
            )
        self.items.append(built)

    def capped(self, reason: str) -> None:
        """Record an input that could not be fully read: one finding per distinct reason."""
        if reason not in self.unevaluated:
            self.unevaluated.append(reason)
            self.add("CONTENT_INPUT_CAPPED", "medium", {"reason": excerpt(reason)})

    def result(self) -> SectionFindings:
        return SectionFindings(tuple(self.items), tuple(self.unevaluated))


def input_findings(reasons: Iterable[str]) -> SectionFindings:
    """CONTENT_INPUT_CAPPED for input problems found before the section parsers ran."""
    acc = _Acc()
    for reason in reasons:
        acc.capped(reason)
    return acc.result()


def failed_section(reason: str) -> SectionFindings:
    """A section whose parser raised: nothing is known, so it is an error."""
    return input_findings([reason])


def _percent(part: int, whole: int) -> int:
    return part * 100 // whole if whole else 0


def body_findings(facts: ContentStructure) -> SectionFindings:
    acc = _Acc()
    if facts.capped:
        acc.capped(f"body_{facts.cap_reason or 'unknown'}")
    if facts.has_html_part and not facts.has_plain_text_part:
        acc.add("CONTENT_MISSING_PLAIN_TEXT", "low")
    # Ratio and CSS share compare totals, which are not known for a capped body.
    if not facts.capped and facts.image_count:
        per_image = facts.visible_text_length // facts.image_count
        if per_image < MIN_VISIBLE_CHARS_PER_IMAGE:
            acc.add(
                "CONTENT_LOW_TEXT_IMAGE_RATIO",
                "low",
                {
                    "images": facts.image_count,
                    "visible_chars": facts.visible_text_length,
                    "chars_per_image": per_image,
                    "threshold": MIN_VISIBLE_CHARS_PER_IMAGE,
                },
            )
    if facts.images_missing_alt:
        acc.add(
            "CONTENT_IMAGES_MISSING_ALT",
            "low",
            {"missing": facts.images_missing_alt, "total": facts.image_count},
        )
    issues = [*facts.malformed, *(["nul_byte"] if facts.has_nul else [])]
    if issues:
        acc.add("CONTENT_MALFORMED_HTML", "low", {"issues": ", ".join(issues)}, evidence=issues)
    if facts.hidden_candidates:
        acc.add(
            "CONTENT_HIDDEN_TEXT",
            "medium",
            {"count": len(facts.hidden_candidates)},
            evidence=[f"{c.tag}: {c.reason}" for c in facts.hidden_candidates],
        )
    if facts.exceeds_gmail_clip_threshold:
        size = facts.html_bytes if facts.html_bytes is not None else facts.html_bytes_at_least
        acc.add(
            "CONTENT_GMAIL_CLIP_RISK",
            "low",
            {"size": size or 0, "threshold": facts.gmail_clip_threshold_bytes},
        )
    html_bytes = facts.html_bytes or 0
    css_bytes = facts.inline_style_bytes + facts.style_tag_bytes
    if (
        not facts.capped
        and html_bytes >= EXCESS_CSS_MIN_HTML_BYTES
        and _percent(css_bytes, html_bytes) >= EXCESS_CSS_PERCENT
    ):
        acc.add(
            "CONTENT_EXCESS_CSS",
            "low",
            {
                "css_bytes": css_bytes,
                "html_bytes": html_bytes,
                "percent": _percent(css_bytes, html_bytes),
                "threshold": EXCESS_CSS_PERCENT,
            },
        )
    return acc.result()


def link_findings(facts: LinkAnalysis) -> SectionFindings:
    acc = _Acc()
    if facts.capped:
        acc.capped(f"links_{facts.cap_reason or 'unknown'}")
    if facts.malformed_count:
        acc.add("CONTENT_LINK_UNEVALUATED", "low", {"count": facts.unevaluated_count})
        acc.unevaluated.append("links_malformed")

    def simple(code: str, severity: Severity, hosts: list[str]) -> None:
        if hosts:
            acc.add(code, severity, {"count": len(hosts)}, evidence=hosts)

    links = facts.links
    masked = [link for link in links if link.masked]
    simple(
        "CONTENT_MASKED_LINK",
        "high",
        [f"{link.text_host} -> {link.host or f'{link.scheme}:'}" for link in masked],
    )
    simple(
        "CONTENT_IP_LITERAL_LINK", "high", [ln.host for ln in links if ln.ip_literal and ln.host]
    )
    simple("CONTENT_URL_SHORTENER", "medium", [ln.shortener for ln in links if ln.shortener])
    simple(
        "CONTENT_NON_HTTPS_LINK",
        "low",
        [ln.host or "http:" for ln in links if ln.non_https],
    )
    # Not all_aligned: it is None when one link is unaligned and another could not be checked.
    if facts.unaligned_count:
        domains = [
            ln.registrable_domain for ln in links if ln.registrable_domain and ln.aligned is False
        ]
        acc.add(
            "CONTENT_UNALIGNED_LINK_DOMAIN",
            "low",
            {
                "count": facts.unaligned_count,
                "senders": ", ".join(facts.sender_domains),
                "unevaluated": facts.unevaluated_count,
            },
            evidence=domains,
        )
    if len(facts.other_domains) > MANY_LINK_DOMAINS_THRESHOLD:
        acc.add(
            "CONTENT_MANY_LINK_DOMAINS",
            "low",
            {"count": len(facts.other_domains), "threshold": MANY_LINK_DOMAINS_THRESHOLD},
            evidence=facts.other_domains,
        )
    return acc.result()


def subject_findings(facts: SubjectFacts) -> SectionFindings:
    acc = _Acc()
    if facts.capped:
        acc.capped("subject_too_long")
    if not facts.present or facts.empty:
        acc.add("CONTENT_SUBJECT_EMPTY", "low")
        return acc.result()
    if facts.all_caps:
        percent = int((facts.caps_ratio or 0) * 100)
        acc.add("CONTENT_SUBJECT_ALL_CAPS", "low", {"percent": percent})
    if facts.has_punct_run:
        acc.add("CONTENT_SUBJECT_PUNCTUATION", "low", {"run": facts.max_punct_run or 0})
    if facts.is_long:
        acc.add("CONTENT_SUBJECT_LONG", "low", {"length": facts.length_graphemes or 0})
    if facts.reply_prefix_without_in_reply_to:
        acc.add("CONTENT_SUBJECT_REPLY_PREFIX", "low", {"prefix": facts.reply_prefix or ""})
    if facts.control_chars:
        acc.add("CONTENT_SUBJECT_CONTROL_CHARS", "medium", {"count": facts.control_chars})
    if facts.has_bidi_override:
        acc.add("CONTENT_SUBJECT_BIDI_OVERRIDE", "medium", {"count": facts.bidi_controls or 0})
    if facts.mixed_script_word:
        scripts = ", ".join(facts.scripts or ())
        acc.add("CONTENT_SUBJECT_MIXED_SCRIPT", "low", {"scripts": excerpt(scripts)})
    return acc.result()


def _one_click_problem(facts: ListUnsubscribeFacts) -> str | None:
    """Why One-Click is not offered: None when offered, "post_missing" for the plain detail."""
    if not facts.post_present:
        return "post_missing"
    if facts.duplicated or facts.post_duplicated:
        return "duplicated"
    if facts.post_value_exact is False:
        return "post_value"
    if facts.https_uri_present is False:
        nonstandard = any(
            uri.kind == "https" and uri.nonstandard_authority
            for field in facts.fields
            for uri in field.uris
        )
        return "nonstandard_authority" if nonstandard else "no_https_uri"
    return None


def unsubscribe_findings(facts: ListUnsubscribeFacts) -> SectionFindings:
    """Verdicts for a message whose headers were available."""
    acc = _Acc()
    if not facts.present:
        acc.add("CONTENT_NO_LIST_UNSUBSCRIBE", "low")
        return acc.result()
    # https_uri_present stops at the first good URI, so it can be True on a capped field.
    if (
        facts.https_uri_present is None
        or facts.field_count > len(facts.fields)
        or any(not f.evaluated or f.capped for f in facts.fields)
    ):
        acc.capped("list_unsubscribe_unevaluated")
    if facts.https_uri_present is not None:
        problem = _one_click_problem(facts)
        if problem is not None:
            variant = None if problem == "post_missing" else problem
            acc.add("CONTENT_NO_ONE_CLICK", "low", detail_variant=variant)
        if facts.https_uri_present is False and facts.http_uri_present is True:
            acc.add("CONTENT_HTTP_ONLY_UNSUBSCRIBE", "low")
    signed = (facts.list_unsubscribe_signed, facts.post_signed, facts.one_click_signed)
    if False in signed:
        acc.add("CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER", "medium")
    return acc.result()


def _is_incomplete(result: RuleResult) -> bool:
    return result.status is RuleStatus.ERROR or (
        result.status is RuleStatus.NOT_EVALUATED and result.issue in _INCOMPLETE_ISSUES
    )


def _rule_match(
    acc: _Acc, result: RuleResult, record: ContentRuleRecord | None, catalogue: Mapping[str, str]
) -> None:
    """Text comes from the rule's own title, else from CONTENT_RULE.<seed_key>, else its name.

    A tenant rule whose global row was removed can have neither title nor catalogue text.
    """
    title = record.title if record is not None else None
    advice = record.advice if record is not None else None
    params: dict[str, object] = {
        "rule": title or result.name,
        "category": result.category,
        "weight": result.weight,
        "part": result.part.value if result.part is not None else "",
    }
    if advice:
        params["advice"] = advice
    evidence = [result.evidence] if result.evidence else []
    built = finding("CONTENT_RULE_MATCH", result.severity, params, evidence=evidence)  # type: ignore[arg-type]
    update: dict[str, str] = {}
    prefix = f"CONTENT_RULE.{result.seed_key}" if result.seed_key else None
    if title is None and prefix is not None and f"{prefix}.title" in catalogue:
        update["title_key"] = f"{prefix}.title"
    if advice:
        update["remediation_key"] = f"finding.CONTENT_RULE_MATCH.{RULE_MATCH_CUSTOM_ADVICE}"
    elif prefix is not None and f"{prefix}.advice" in catalogue:
        update["remediation_key"] = f"{prefix}.advice"
    acc.items.append(built.model_copy(update=update) if update else built)


def rule_findings(
    results: RuleResults, records: Mapping[int, ContentRuleRecord]
) -> SectionFindings:
    """Findings of an engine run. `records` are the evaluated rules by id, for their texts."""
    acc = _Acc()
    catalogue = load_catalogue(DEFAULT_LANGUAGE)
    for result in results.results:
        if result.status is RuleStatus.MATCHED:
            _rule_match(acc, result, records.get(result.rule_id), catalogue)
    if results.capped_parts or any(r.issue is RuleIssue.INPUT_CAPPED for r in results.results):
        acc.capped("rules_input_capped")
    failed = [r for r in results.results if _is_incomplete(r)]
    if failed:
        reasons = sorted({r.issue.value for r in failed if r.issue is not None})
        acc.add(
            "CONTENT_RULE_ERROR",
            "medium",
            {"count": len(failed), "reasons": ", ".join(reasons)},
            evidence=[r.name for r in failed],
        )
        acc.unevaluated.append("rules_failed")
    return acc.result()


def rules_unavailable(reason: str) -> SectionFindings:
    """The rules could not be loaded or the engine failed: nothing was evaluated."""
    acc = _Acc()
    acc.add("CONTENT_RULE_ERROR", "medium", {"count": 0, "reasons": reason})
    acc.unevaluated.append(reason)
    return acc.result()
