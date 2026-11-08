"""Content rules engine (M5-13): evaluate keyword and regex rules against message content.

The engine takes already-loaded rules as input and does no DB access, DNS or network. Text of
the findings is M5-14's job: results carry stable reason codes, never user-facing strings.

Async use: `evaluate_rules` is synchronous and can block for up to its total budget (at most
`safe_regex.MAX_BATCH_S`, about 15 s). Async code must call `evaluate_rules_async`, which runs it
in a thread pool. A cancelled await does not stop the thread; the budget bounds it.

Tenant merge (`merge_tenant_rules`, run it before `evaluate_rules`):
- Only global rows and rows of the given tenant are kept; another tenant's row is always dropped,
  so tenant rules cannot affect other tenants.
- A tenant rule overrides a global rule only through `seed_key`, never through `name`. The tenant
  row replaces the global row for that tenant: `enabled: false` turns the global rule off, an
  enabled row applies the tenant's own pattern, weight and category.
- GM decision: an override references an existing global seed_key, which the repository enforces
  on write. A tenant row whose seed_key no longer names a global row overrides nothing and stays
  an ordinary tenant rule.
- Pass every visible row, disabled ones included (not `enabled_only=True`, and all pages), or a
  disabled override cannot suppress its global rule.

Evaluation:
- Only enabled rules whose `language` is NULL or equals the hint (exact match after trim and
  lowercase; no hint means NULL-language rules only). Others are absent from the results.
- Rules have no target field (see the M5-13 GM note), so each rule is searched in the subject,
  the text and the visible HTML text separately, in that order, and stops at its first match.
  Separate searches keep anchors meaningful and prevent matches across parts.
- Keywords run in-process first, so a slow regex cannot starve them: case-folded substring search
  with no Unicode normalization. With `word_boundary` (engine-wide, since rows have no such
  column) an edge of the keyword made of a word character must not touch another word character.
- Regexes are built with `compile_checked` and run through `search_many`, highest weight first.

Statuses (`RuleStatus`):
- `matched`: found; `ok`: searched everything and found nothing.
- `error`: the rule is invalid or failed (timeout, worker failure, more matches than
  `max_matches`, which `safe_regex` reports as incomplete).
- `not_evaluated`: no verdict for this rule: total budget used up, busy worker pool, beyond
  `max_rules`, no content at all, or no match in a part that was capped (the tail is unseen).

Only `matched` rules score. When `RuleResults.complete` is False the score is a lower bound, and
`error_count`, `not_evaluated_count` and `capped_parts` say why.

Results are ordered by weight (descending), then rule id. Evidence is a snippet of at most
`max_evidence_chars`, without control or format characters, never the full body.
"""

from __future__ import annotations

import asyncio
import enum
import time
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from app.core.safe_regex import (
    DEFAULT_TEXT_BYTES,
    DEFAULT_TIMEOUT_S,
    MAX_BATCH_S,
    MAX_MATCHES,
    MAX_PATTERN_LENGTH,
    MAX_RULES,
    MAX_TEXT_BYTES,
    MAX_TIMEOUT_S,
    MIN_TIMEOUT_S,
    CompiledRule,
    MatchResult,
    RegexRuleError,
    SearchFailure,
    compile_checked,
    search_many,
)
from app.models.content_rule import MAX_WEIGHT, MIN_WEIGHT
from app.repositories.content_rules import ContentRuleRecord

DEFAULT_BUDGET_S: Final = 10.0
DEFAULT_EVIDENCE_CHARS: Final = 160
MAX_EVIDENCE_CHARS: Final = 500
DEFAULT_MAX_SCORE: Final = 100
HARD_MAX_SCORE: Final = 1000
_EVIDENCE_CONTEXT: Final = 20  # characters kept before the match


class RuleStatus(enum.StrEnum):
    MATCHED = "matched"
    OK = "ok"
    ERROR = "error"
    NOT_EVALUATED = "not_evaluated"


class RuleIssue(enum.StrEnum):
    INVALID_RULE = "invalid_rule"
    INVALID_PATTERN = "invalid_pattern"
    TIMEOUT = "timeout"
    WORKER_FAILED = "worker_failed"
    TOO_MANY_MATCHES = "too_many_matches"
    TEXT_TOO_LARGE = "text_too_large"
    BUDGET_EXCEEDED = "budget_exceeded"
    BUSY = "busy"
    TOO_MANY_RULES = "too_many_rules"
    NO_INPUT = "no_input"
    INPUT_CAPPED = "input_capped"


class ContentPart(enum.StrEnum):
    SUBJECT = "subject"
    TEXT = "text"
    HTML_VISIBLE_TEXT = "html_visible_text"


@dataclass(frozen=True, slots=True)
class RuleLimits:
    """Caller limits; clamped to the hard caps at evaluation time."""

    per_rule_timeout_s: float = DEFAULT_TIMEOUT_S
    total_budget_s: float = DEFAULT_BUDGET_S
    max_rules: int = MAX_RULES
    max_text_bytes: int = DEFAULT_TEXT_BYTES  # per content part, UTF-8
    max_matches: int = MAX_MATCHES
    max_evidence_chars: int = DEFAULT_EVIDENCE_CHARS
    max_score: int = DEFAULT_MAX_SCORE


@dataclass(frozen=True, slots=True)
class RuleResult:
    rule_id: int
    seed_key: str | None
    name: str
    category: str
    severity: str
    weight: int
    status: RuleStatus
    issue: RuleIssue | None = None
    part: ContentPart | None = None
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class CategoryScore:
    category: str
    score: int  # capped at `RuleLimits.max_score`
    matched: int


@dataclass(frozen=True, slots=True)
class RuleResults:
    results: tuple[RuleResult, ...]
    score: int  # capped; a lower bound when `complete` is False
    categories: tuple[CategoryScore, ...]  # by category name
    capped_parts: tuple[ContentPart, ...]
    error_count: int
    not_evaluated_count: int
    complete: bool


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: RuleStatus
    issue: RuleIssue | None = None
    part: ContentPart | None = None
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class _Part:
    name: ContentPart
    text: str


_NOT_EVALUATED: Final = frozenset(
    {RuleIssue.BUDGET_EXCEEDED, RuleIssue.BUSY, RuleIssue.TOO_MANY_RULES}
)
_FAILURE_ISSUES: Final[dict[SearchFailure, RuleIssue]] = {
    SearchFailure.TIMEOUT: RuleIssue.TIMEOUT,
    SearchFailure.BATCH_DEADLINE: RuleIssue.BUDGET_EXCEEDED,
    SearchFailure.TEXT_TOO_LARGE: RuleIssue.TEXT_TOO_LARGE,
    SearchFailure.TOO_MANY_RULES: RuleIssue.TOO_MANY_RULES,
    SearchFailure.BUSY: RuleIssue.BUSY,
    SearchFailure.WORKER_FAILED: RuleIssue.WORKER_FAILED,
}


def _not_evaluated(issue: RuleIssue) -> _Outcome:
    return _Outcome(RuleStatus.NOT_EVALUATED, issue=issue)


def _error(issue: RuleIssue) -> _Outcome:
    return _Outcome(RuleStatus.ERROR, issue=issue)


def merge_tenant_rules(
    rules: Sequence[ContentRuleRecord], *, tenant_id: int
) -> list[ContentRuleRecord]:
    """Effective rules of one tenant; the merge rule is stated in the module docstring."""
    if isinstance(tenant_id, bool) or not isinstance(tenant_id, int):
        raise TypeError("tenant_id must be an int")
    own = [r for r in rules if r.scope == "tenant" and r.tenant_id == tenant_id]
    overridden = {r.seed_key for r in own if r.seed_key is not None}
    shared = [
        r
        for r in rules
        if r.scope == "global" and r.tenant_id is None and r.seed_key not in overridden
    ]
    return shared + own


def _clamp_int(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _clamp_float(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))


def _clamped(limits: RuleLimits) -> RuleLimits:
    if not isinstance(limits, RuleLimits):
        raise TypeError("limits must be a RuleLimits")
    return RuleLimits(
        per_rule_timeout_s=_clamp_float(limits.per_rule_timeout_s, MIN_TIMEOUT_S, MAX_TIMEOUT_S),
        total_budget_s=_clamp_float(limits.total_budget_s, MIN_TIMEOUT_S, MAX_BATCH_S),
        max_rules=_clamp_int(limits.max_rules, 0, MAX_RULES),
        max_text_bytes=_clamp_int(limits.max_text_bytes, 1, MAX_TEXT_BYTES),
        max_matches=_clamp_int(limits.max_matches, 1, MAX_MATCHES),
        max_evidence_chars=_clamp_int(limits.max_evidence_chars, 1, MAX_EVIDENCE_CHARS),
        max_score=_clamp_int(limits.max_score, 0, HARD_MAX_SCORE),
    )


def _cap_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    """`text` cut to at most `max_bytes` of UTF-8 on a character boundary; True if it was cut."""
    if len(text) * 4 <= max_bytes:
        return text, False
    data = text.encode("utf-8", "surrogatepass")
    if len(data) <= max_bytes:
        return text, False
    end = max_bytes
    while end > 0 and data[end] & 0xC0 == 0x80:  # data[end] is the first byte left out
        end -= 1
    return data[:end].decode("utf-8", "surrogatepass"), True


def _prepare_parts(
    subject: str | None, text: str | None, html_visible_text: str | None, max_bytes: int
) -> tuple[list[_Part], tuple[ContentPart, ...]]:
    parts: list[_Part] = []
    capped: list[ContentPart] = []
    for name, value in (
        (ContentPart.SUBJECT, subject),
        (ContentPart.TEXT, text),
        (ContentPart.HTML_VISIBLE_TEXT, html_visible_text),
    ):
        if value is None:
            continue
        if not isinstance(value, str):
            raise TypeError(f"{name.value} must be a string or None")
        if value == "":
            continue
        kept, was_cut = _cap_utf8(value, max_bytes)
        parts.append(_Part(name, kept))
        if was_cut:
            capped.append(name)
    return parts, tuple(capped)


def _is_valid_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _weight(rule: ContentRuleRecord) -> int:
    return rule.weight if _is_valid_int(rule.weight) else 0


def _order(rule: ContentRuleRecord) -> tuple[int, int]:
    return (-_weight(rule), rule.id if _is_valid_int(rule.id) else 0)


def _select(
    rules: Sequence[ContentRuleRecord], language_hint: str | None
) -> list[ContentRuleRecord]:
    if language_hint is not None and not isinstance(language_hint, str):
        raise TypeError("language_hint must be a string or None")
    hint = None if language_hint is None else language_hint.strip().lower()
    for rule in rules:
        if not isinstance(rule, ContentRuleRecord):
            raise TypeError("rules must contain ContentRuleRecord items")
    chosen = [r for r in rules if r.enabled and (r.language is None or r.language == hint)]
    return sorted(chosen, key=_order)


def _record_is_valid(rule: ContentRuleRecord) -> bool:
    return (
        _is_valid_int(rule.id)
        and _is_valid_int(rule.weight)
        and MIN_WEIGHT <= rule.weight <= MAX_WEIGHT
        and isinstance(rule.category, str)
        and rule.category != ""
    )


def _keyword_is_valid(pattern: object) -> bool:
    return (
        isinstance(pattern, str)
        and pattern.strip() != ""
        and len(pattern) <= MAX_PATTERN_LENGTH
        and "\x00" not in pattern
    )


def _is_word(char: str) -> bool:
    # Combining marks count, so "cafe" does not end inside a decomposed "café".
    return char.isalnum() or char == "_" or unicodedata.category(char).startswith("M")


def _fold(text: str) -> tuple[str, list[int] | None]:
    """Case-folded text and, when folding changed its length, folded-to-original offsets."""
    folded = text.casefold()
    if len(folded) == len(text):
        return folded, None
    offsets: list[int] = []
    for index, char in enumerate(text):
        offsets.extend([index] * len(char.casefold()))
    return folded, offsets


def _find_keyword(haystack: str, needle: str, word_boundary: bool) -> int | None:
    """Offset of the first acceptable occurrence of the case-folded `needle`."""
    if not word_boundary:
        found = haystack.find(needle)
        return None if found < 0 else found
    check_left = _is_word(needle[0])
    check_right = _is_word(needle[-1])
    start = 0
    while (found := haystack.find(needle, start)) >= 0:
        end = found + len(needle)
        left_ok = not check_left or found == 0 or not _is_word(haystack[found - 1])
        right_ok = not check_right or end == len(haystack) or not _is_word(haystack[end])
        if left_ok and right_ok:
            return found
        start = found + 1
    return None


def _evidence(text: str, start: int, max_chars: int) -> str:
    """Bounded, single-line snippet around `start`. The raw window is bounded before cleaning."""
    context = min(_EVIDENCE_CONTEXT, max_chars // 4)
    window = text[max(0, start - context) : start + max_chars]
    cleaned: list[str] = []
    for char in window:
        category = unicodedata.category(char)
        if char.isspace():
            cleaned.append(" ")
        elif not category.startswith("C"):
            cleaned.append(char)
    return "".join(cleaned)[:max_chars]


def _matched(part: _Part, start: int, limits: RuleLimits) -> _Outcome:
    evidence = _evidence(part.text, start, limits.max_evidence_chars)
    return _Outcome(RuleStatus.MATCHED, part=part.name, evidence=evidence)


def _run_keywords(
    jobs: list[tuple[int, str]],
    parts: list[_Part],
    outcomes: list[_Outcome | None],
    limits: RuleLimits,
    deadline: float,
    word_boundary: bool,
) -> None:
    if not jobs:
        return
    folded = [_fold(part.text) for part in parts]
    for index, keyword in jobs:
        if time.monotonic() >= deadline:
            outcomes[index] = _not_evaluated(RuleIssue.BUDGET_EXCEEDED)
            continue
        needle = keyword.casefold()
        for part, (haystack, offsets) in zip(parts, folded, strict=True):
            found = _find_keyword(haystack, needle, word_boundary)
            if found is not None:
                start = found if offsets is None else offsets[found]
                outcomes[index] = _matched(part, start, limits)
                break


def _incomplete(result: MatchResult) -> _Outcome:
    """The outcome of a `MatchResult` whose `complete` is False."""
    if result.failure is not None:
        issue = _FAILURE_ISSUES.get(result.failure, RuleIssue.WORKER_FAILED)
        if issue in _NOT_EVALUATED:
            return _not_evaluated(issue)
        return _error(issue)
    return _error(RuleIssue.TIMEOUT if result.timed_out else RuleIssue.TOO_MANY_MATCHES)


def _run_regexes(
    jobs: list[tuple[int, CompiledRule]],
    parts: list[_Part],
    outcomes: list[_Outcome | None],
    limits: RuleLimits,
    deadline: float,
) -> None:
    pending = jobs
    for part in parts:
        if not pending:
            return
        remaining = deadline - time.monotonic()
        if remaining < MIN_TIMEOUT_S:  # search_many would raise it to this minimum
            for index, _ in pending:
                outcomes[index] = _not_evaluated(RuleIssue.BUDGET_EXCEEDED)
            return
        try:
            results = search_many(
                [compiled for _, compiled in pending],
                part.text,
                timeout_s=limits.per_rule_timeout_s,
                max_matches=limits.max_matches,
                max_text_bytes=limits.max_text_bytes,
                total_timeout_s=remaining,
            )
        except OSError:  # the worker could not be spawned (out of processes or memory)
            for index, _ in pending:
                outcomes[index] = _error(RuleIssue.WORKER_FAILED)
            return
        still_pending: list[tuple[int, CompiledRule]] = []
        for job, result in zip(pending, results, strict=True):
            if not result.complete:
                outcomes[job[0]] = _incomplete(result)
            elif result.matches:
                outcomes[job[0]] = _matched(part, result.matches[0].start, limits)
            else:
                still_pending.append(job)
        pending = still_pending


def _build_results(
    selected: list[ContentRuleRecord],
    outcomes: list[_Outcome],
    capped_parts: tuple[ContentPart, ...],
    max_score: int,
) -> RuleResults:
    results: list[RuleResult] = []
    total = 0
    by_category: dict[str, tuple[int, int]] = {}
    for rule, outcome in zip(selected, outcomes, strict=True):
        weight = _weight(rule)
        results.append(
            RuleResult(
                rule_id=rule.id,
                seed_key=rule.seed_key,
                name=rule.name,
                category=rule.category,
                severity=rule.severity,
                weight=weight,
                status=outcome.status,
                issue=outcome.issue,
                part=outcome.part,
                evidence=outcome.evidence,
            )
        )
        if outcome.status is RuleStatus.MATCHED:
            total += weight
            score, matched = by_category.get(rule.category, (0, 0))
            by_category[rule.category] = (score + weight, matched + 1)
    errors = sum(r.status is RuleStatus.ERROR for r in results)
    not_evaluated = sum(r.status is RuleStatus.NOT_EVALUATED for r in results)
    return RuleResults(
        results=tuple(results),
        score=min(total, max_score),
        categories=tuple(
            CategoryScore(category, min(score, max_score), matched)
            for category, (score, matched) in sorted(by_category.items())
        ),
        capped_parts=capped_parts,
        error_count=errors,
        not_evaluated_count=not_evaluated,
        complete=errors == 0 and not_evaluated == 0 and not capped_parts,
    )


def evaluate_rules(
    rules: Sequence[ContentRuleRecord],
    *,
    subject: str | None = None,
    text: str | None = None,
    html_visible_text: str | None = None,
    language_hint: str | None = None,
    limits: RuleLimits = RuleLimits(),  # noqa: B008  (immutable)
    word_boundary: bool = True,
) -> RuleResults:
    """Evaluate `rules` (see the module docstring). Blocks: async callers use the async variant.

    One rule's failure never stops the others and never raises. `TypeError` is raised only for
    arguments of the wrong type, which is a programming error rather than a rule problem.
    """
    bounds = _clamped(limits)
    deadline = time.monotonic() + bounds.total_budget_s
    parts, capped_parts = _prepare_parts(subject, text, html_visible_text, bounds.max_text_bytes)
    selected = _select(rules, language_hint)

    outcomes: list[_Outcome | None] = [None] * len(selected)
    keyword_jobs: list[tuple[int, str]] = []
    regex_jobs: list[tuple[int, CompiledRule]] = []
    for index, rule in enumerate(selected):
        if index >= bounds.max_rules:
            outcomes[index] = _not_evaluated(RuleIssue.TOO_MANY_RULES)
        elif not _record_is_valid(rule):
            outcomes[index] = _error(RuleIssue.INVALID_RULE)
        elif rule.kind == "keyword":
            if _keyword_is_valid(rule.pattern):
                keyword_jobs.append((index, rule.pattern))
            else:
                outcomes[index] = _error(RuleIssue.INVALID_PATTERN)
        elif rule.kind == "regex":
            try:
                regex_jobs.append((index, compile_checked(rule.pattern, rule.flags)))
            except RegexRuleError:
                outcomes[index] = _error(RuleIssue.INVALID_PATTERN)
        else:
            outcomes[index] = _error(RuleIssue.INVALID_RULE)

    if parts:
        _run_keywords(keyword_jobs, parts, outcomes, bounds, deadline, word_boundary)
        _run_regexes(regex_jobs, parts, outcomes, bounds, deadline)
        unfinished = _not_evaluated(RuleIssue.INPUT_CAPPED) if capped_parts else None
    else:
        unfinished = _not_evaluated(RuleIssue.NO_INPUT)
    finished = [o or unfinished or _Outcome(RuleStatus.OK) for o in outcomes]
    return _build_results(selected, finished, capped_parts, bounds.max_score)


async def evaluate_rules_async(
    rules: Sequence[ContentRuleRecord],
    *,
    subject: str | None = None,
    text: str | None = None,
    html_visible_text: str | None = None,
    language_hint: str | None = None,
    limits: RuleLimits = RuleLimits(),  # noqa: B008  (immutable)
    word_boundary: bool = True,
) -> RuleResults:
    """`evaluate_rules` in a thread pool, so the event loop is not blocked while it runs."""
    return await asyncio.to_thread(
        evaluate_rules,
        rules,
        subject=subject,
        text=text,
        html_visible_text=html_visible_text,
        language_hint=language_hint,
        limits=limits,
        word_boundary=word_boundary,
    )
