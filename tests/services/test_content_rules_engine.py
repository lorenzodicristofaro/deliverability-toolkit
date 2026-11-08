"""M5-13 content rules engine. Regex workers are local subprocesses; no network."""

import ast
import dataclasses
import re
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.core import safe_regex
from app.core.safe_regex import MAX_LIVE_WORKERS, MAX_TEXT_BYTES, MatchResult, SearchFailure
from app.repositories.content_rules import ContentRuleRecord
from app.services import content_rules_engine as engine
from app.services.content_rules_engine import (
    ContentPart,
    RuleIssue,
    RuleLimits,
    RuleResult,
    RuleResults,
    RuleStatus,
    evaluate_rules,
    evaluate_rules_async,
    merge_tenant_rules,
)

NOW = datetime(2026, 11, 8, tzinfo=UTC)
FAST = RuleLimits(per_rule_timeout_s=0.3, total_budget_s=5.0)
CATASTROPHIC_PATTERN = "(a+)+$"
CATASTROPHIC_TEXT = "a" * 40 + "!"
# Far above every timeout used here, far below what the pattern would take unattended.
WALL_LIMIT_S = 4.0


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network access in a unit test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    yield


def rule(rule_id: int = 1, **overrides: Any) -> ContentRuleRecord:
    values: dict[str, Any] = {
        "id": rule_id,
        "scope": "global",
        "tenant_id": None,
        "name": f"rule{rule_id}",
        "kind": "keyword",
        "pattern": "free",
        "flags": 0,
        "weight": 10,
        "category": "spam",
        "language": None,
        "enabled": True,
        "severity": "low",
        "title": None,
        "advice": None,
        "sources": None,
        "verified_on": None,
        "status": None,
        "seed_key": None,
        "locally_modified": False,
        "created_at": NOW,
        "updated_at": NOW,
        "created_by": None,
    }
    return ContentRuleRecord(**{**values, **overrides})


def regex(rule_id: int = 1, pattern: str = "free", **overrides: Any) -> ContentRuleRecord:
    return rule(rule_id, kind="regex", pattern=pattern, **overrides)


def by_id(results: RuleResults) -> dict[int, RuleResult]:
    return {r.rule_id: r for r in results.results}


# --- keywords ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("keyword", "body", "word_boundary", "expected"),
    [
        ("free", "this is FREE money", True, RuleStatus.MATCHED),
        ("free", "freedom fries", True, RuleStatus.OK),
        ("free", "freedom fries", False, RuleStatus.MATCHED),
        ("free", "free_of charge", True, RuleStatus.OK),
        ("free", "(free)", True, RuleStatus.MATCHED),
        ("strasse", "Die STRAßE ist lang", True, RuleStatus.MATCHED),
        ("straße", "die STRASSE ist lang", True, RuleStatus.MATCHED),
        ("ΣΑΣ", "σας φίλε", True, RuleStatus.MATCHED),
        ("gratuit", "c'est GRATUIT!", True, RuleStatus.MATCHED),
        ("cafe", "un café caldo", True, RuleStatus.OK),
        ("$$$", "earn$$$now", True, RuleStatus.MATCHED),
        ("c++", "learn c++today", True, RuleStatus.MATCHED),
        ("buy now", "please BUY  NOW", True, RuleStatus.OK),
        ("buy now", "please Buy Now!", True, RuleStatus.MATCHED),
    ],
)
def test_keyword_matching(
    keyword: str, body: str, word_boundary: bool, expected: RuleStatus
) -> None:
    results = evaluate_rules(
        [rule(pattern=keyword)], text=body, limits=FAST, word_boundary=word_boundary
    )
    assert results.results[0].status is expected
    assert results.complete


def test_keyword_evidence_maps_offsets_through_expanding_case_folds() -> None:
    body = "ß" * 50 + " buy now " + "x" * 400
    results = evaluate_rules([rule(pattern="buy now")], text=body, limits=FAST)
    evidence = results.results[0].evidence
    assert evidence is not None
    assert "buy now" in evidence


@pytest.mark.parametrize(
    "pattern",
    [None, 7, "", "   ", "a\x00b", "k" * (safe_regex.MAX_PATTERN_LENGTH + 1)],
)
def test_malformed_keyword_is_an_error(pattern: object) -> None:
    results = evaluate_rules([rule(pattern=pattern)], text="free", limits=FAST)
    assert results.results[0].status is RuleStatus.ERROR
    assert results.results[0].issue is RuleIssue.INVALID_PATTERN
    assert not results.complete


# --- regexes -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "flags", "body", "expected"),
    [
        ("fr.e", 0, "a free gift", RuleStatus.MATCHED),
        ("FREE", 0, "a free gift", RuleStatus.OK),
        ("FREE", int(re.IGNORECASE), "a free gift", RuleStatus.MATCHED),
        (r"\bgift\b", 0, "giftcard", RuleStatus.OK),
        (r"\Agift", 0, "a gift", RuleStatus.OK),
        (r"(?=gift)", 0, "a gift", RuleStatus.MATCHED),
    ],
)
def test_regex_matching(pattern: str, flags: int, body: str, expected: RuleStatus) -> None:
    results = evaluate_rules([regex(pattern=pattern, flags=flags)], text=body, limits=FAST)
    assert results.results[0].status is expected


@pytest.mark.parametrize(
    ("pattern", "flags"),
    [
        (None, 0),
        (5, 0),
        ("", 0),
        ("(", 0),
        ("a\x00", 0),
        ("a" * (safe_regex.MAX_PATTERN_LENGTH + 1), 0),
        ("a", int(re.LOCALE)),
        ("a", "i"),
        ("a", True),
    ],
)
def test_invalid_regex_is_an_error_and_others_still_run(pattern: object, flags: object) -> None:
    results = evaluate_rules(
        [regex(1, pattern=pattern, flags=flags), regex(2, pattern="free")],
        text="free",
        limits=FAST,
    )
    found = by_id(results)
    assert found[1].status is RuleStatus.ERROR
    assert found[1].issue is RuleIssue.INVALID_PATTERN
    assert found[2].status is RuleStatus.MATCHED
    assert results.score == 10
    assert not results.complete


@pytest.mark.parametrize(
    "overrides",
    [
        {"kind": "nope"},
        {"kind": None},
        {"weight": "ten"},
        {"weight": True},
        {"weight": None},
        {"weight": -1},
        {"weight": 101},
        {"category": ""},
        {"category": None},
        {"id": "x"},
    ],
)
def test_malformed_rule_record_is_an_error(overrides: dict[str, Any]) -> None:
    results = evaluate_rules(
        [rule(9, **overrides), rule(10, pattern="free")], text="free", limits=FAST
    )
    statuses = sorted(r.status.value for r in results.results)
    assert statuses == ["error", "matched"]
    assert results.score == 10
    assert not results.complete


def test_module_uses_no_re_on_rule_patterns() -> None:
    source = Path(engine.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not imported & {"re", "regex", "sre_compile", "sre_parse"}
    called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_name(n.func)}
    assert "CompiledRule" not in called


def _is_name(node: ast.expr) -> bool:
    return isinstance(node, ast.Name)


# --- ReDoS, budget, saturation -------------------------------------------------------------------


def test_catastrophic_rule_is_error_others_fine_real_worker() -> None:
    rules = [
        regex(1, pattern=CATASTROPHIC_PATTERN, weight=50),
        regex(2, pattern="a!", weight=20),
        rule(3, pattern="nomatch", weight=5),
    ]
    started = time.monotonic()
    results = evaluate_rules(rules, text=CATASTROPHIC_TEXT, limits=FAST)
    assert time.monotonic() - started < WALL_LIMIT_S
    found = by_id(results)
    assert found[1].status is RuleStatus.ERROR
    assert found[1].issue is RuleIssue.TIMEOUT
    assert found[2].status is RuleStatus.MATCHED
    assert found[3].status is RuleStatus.OK
    assert results.score == 20
    assert results.error_count == 1
    assert not results.complete


def test_failed_rule_is_not_retried_on_later_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def spy(rules: Any, text: str, **kwargs: Any) -> list[MatchResult]:
        calls.append(text)
        return safe_regex.search_many(rules, text, **kwargs)

    monkeypatch.setattr(engine, "search_many", spy)
    results = evaluate_rules(
        [regex(1, pattern=CATASTROPHIC_PATTERN)],
        subject=CATASTROPHIC_TEXT,
        text=CATASTROPHIC_TEXT,
        html_visible_text=CATASTROPHIC_TEXT,
        limits=FAST,
    )
    assert len(calls) == 1
    assert results.results[0].issue is RuleIssue.TIMEOUT


def test_total_budget_marks_the_rest_not_evaluated_real_worker() -> None:
    rules = [regex(i, pattern=CATASTROPHIC_PATTERN) for i in range(1, 11)]
    limits = RuleLimits(per_rule_timeout_s=0.2, total_budget_s=0.5)
    started = time.monotonic()
    results = evaluate_rules(rules, text=CATASTROPHIC_TEXT, limits=limits)
    assert time.monotonic() - started < WALL_LIMIT_S
    # Which rule is the first victim depends on host load; that the budget ran out does not.
    assert RuleIssue.BUDGET_EXCEEDED in [r.issue for r in results.results]
    assert all(r.status is not RuleStatus.OK for r in results.results)
    assert results.not_evaluated_count + results.error_count == 10
    assert results.score == 0
    assert not results.complete


def test_budget_exhausted_between_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow_search(rules: Any, _text: str, **_kwargs: Any) -> list[MatchResult]:
        time.sleep(0.12)
        return [MatchResult((), timed_out=False, truncated=False)] * len(rules)

    monkeypatch.setattr(engine, "search_many", slow_search)
    results = evaluate_rules(
        [regex()], subject="a", text="b", limits=RuleLimits(total_budget_s=0.1)
    )
    assert results.results[0].status is RuleStatus.NOT_EVALUATED
    assert results.results[0].issue is RuleIssue.BUDGET_EXCEEDED


def test_budget_exhausted_before_keywords(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([100.0, 101.0, 500.0, 500.0])
    monkeypatch.setattr(engine, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    results = evaluate_rules(
        [rule(1, weight=20), rule(2, weight=10)],
        text="free",
        limits=RuleLimits(total_budget_s=10.0),
    )
    found = by_id(results)
    assert found[1].status is RuleStatus.MATCHED
    assert found[2].status is RuleStatus.NOT_EVALUATED
    assert found[2].issue is RuleIssue.BUDGET_EXCEEDED
    assert results.score == 20
    assert not results.complete


def test_busy_pool_is_not_evaluated_real_semaphore() -> None:
    held = 0
    try:
        for _ in range(MAX_LIVE_WORKERS):
            assert safe_regex._WORKER_SLOTS.acquire(timeout=5)
            held += 1
        results = evaluate_rules(
            [regex(1, pattern="free", weight=30), rule(2, pattern="free", weight=5)],
            text="free",
            limits=RuleLimits(per_rule_timeout_s=0.05, total_budget_s=2.0),
        )
    finally:
        for _ in range(held):
            safe_regex._WORKER_SLOTS.release()
    found = by_id(results)
    assert found[1].status is RuleStatus.NOT_EVALUATED
    assert found[1].issue is RuleIssue.BUSY
    assert found[2].status is RuleStatus.MATCHED  # keywords need no worker
    assert results.score == 5  # the unevaluated rule's weight is not counted
    assert results.not_evaluated_count == 1
    assert not results.complete


@pytest.mark.parametrize(
    ("result", "status", "issue"),
    [
        (
            MatchResult((), timed_out=True, truncated=False, failure=SearchFailure.TIMEOUT),
            RuleStatus.ERROR,
            RuleIssue.TIMEOUT,
        ),
        (
            MatchResult((), timed_out=True, truncated=False, failure=SearchFailure.BATCH_DEADLINE),
            RuleStatus.NOT_EVALUATED,
            RuleIssue.BUDGET_EXCEEDED,
        ),
        (
            MatchResult((), timed_out=False, truncated=False, failure=SearchFailure.BUSY),
            RuleStatus.NOT_EVALUATED,
            RuleIssue.BUSY,
        ),
        (
            MatchResult((), timed_out=False, truncated=False, failure=SearchFailure.WORKER_FAILED),
            RuleStatus.ERROR,
            RuleIssue.WORKER_FAILED,
        ),
        (
            MatchResult((), timed_out=False, truncated=True, failure=SearchFailure.TEXT_TOO_LARGE),
            RuleStatus.ERROR,
            RuleIssue.TEXT_TOO_LARGE,
        ),
        (
            MatchResult((), timed_out=False, truncated=False, failure=SearchFailure.TOO_MANY_RULES),
            RuleStatus.NOT_EVALUATED,
            RuleIssue.TOO_MANY_RULES,
        ),
        (
            MatchResult((safe_regex.Match(0, 1, "f"),), timed_out=False, truncated=True),
            RuleStatus.ERROR,
            RuleIssue.TOO_MANY_MATCHES,
        ),
        (
            MatchResult((), timed_out=True, truncated=False),
            RuleStatus.ERROR,
            RuleIssue.TIMEOUT,
        ),
    ],
)
def test_incomplete_search_results_never_score(
    monkeypatch: pytest.MonkeyPatch, result: MatchResult, status: RuleStatus, issue: RuleIssue
) -> None:
    monkeypatch.setattr(engine, "search_many", lambda rules, *_a, **_k: [result] * len(rules))
    results = evaluate_rules([regex()], text="free", limits=FAST)
    assert results.results[0].status is status
    assert results.results[0].issue is issue
    assert results.score == 0
    assert results.categories == ()
    assert not results.complete


def test_worker_spawn_failure_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> list[MatchResult]:
        raise OSError("no processes")

    monkeypatch.setattr(engine, "search_many", fail)
    results = evaluate_rules([regex(1), rule(2)], text="free", limits=FAST)
    found = by_id(results)
    assert found[1].status is RuleStatus.ERROR
    assert found[1].issue is RuleIssue.WORKER_FAILED
    assert found[2].status is RuleStatus.MATCHED


def test_max_matches_exceeded_is_an_error_real_worker() -> None:
    results = evaluate_rules(
        [regex(pattern="a")], text="a" * 20, limits=replace(FAST, max_matches=5)
    )
    assert results.results[0].status is RuleStatus.ERROR
    assert results.results[0].issue is RuleIssue.TOO_MANY_MATCHES
    assert results.score == 0


def test_rules_beyond_max_rules_are_not_evaluated() -> None:
    rules = [rule(i, weight=20 - i) for i in range(1, 6)]
    results = evaluate_rules(rules, text="free", limits=replace(FAST, max_rules=2))
    assert [r.status for r in results.results] == [
        RuleStatus.MATCHED,
        RuleStatus.MATCHED,
        RuleStatus.NOT_EVALUATED,
        RuleStatus.NOT_EVALUATED,
        RuleStatus.NOT_EVALUATED,
    ]
    assert results.results[-1].issue is RuleIssue.TOO_MANY_RULES
    assert results.score == 19 + 18
    assert not results.complete


# --- selection and parts -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_language", "hint", "selected"),
    [
        (None, None, True),
        (None, "en", True),
        ("en", "en", True),
        ("en", "EN ", True),
        ("en", "it", False),
        ("en", None, False),
        ("en", "", False),
        ("pt", "pt-br", False),
    ],
)
def test_language_filter(rule_language: str | None, hint: str | None, selected: bool) -> None:
    results = evaluate_rules(
        [rule(language=rule_language)], text="free", language_hint=hint, limits=FAST
    )
    assert bool(results.results) is selected


def test_disabled_rules_are_absent() -> None:
    disabled = regex(1, pattern=CATASTROPHIC_PATTERN, enabled=False)
    results = evaluate_rules([disabled, rule(2)], text=CATASTROPHIC_TEXT + " free", limits=FAST)
    assert [r.rule_id for r in results.results] == [2]
    assert results.complete


@pytest.mark.parametrize(
    ("kwargs", "part"),
    [
        ({"subject": "free"}, ContentPart.SUBJECT),
        ({"text": "free"}, ContentPart.TEXT),
        ({"html_visible_text": "free"}, ContentPart.HTML_VISIBLE_TEXT),
        ({"subject": "x", "text": "free", "html_visible_text": "free"}, ContentPart.TEXT),
    ],
)
@pytest.mark.parametrize("kind", ["keyword", "regex"])
def test_match_reports_first_part(kwargs: dict[str, str], part: ContentPart, kind: str) -> None:
    results = evaluate_rules([rule(kind=kind)], limits=FAST, **kwargs)
    assert results.results[0].part is part


def test_regex_anchors_apply_per_part_and_matches_do_not_cross_parts() -> None:
    rules = [regex(1, pattern=r"\Abody"), regex(2, pattern=r"subject\s+body")]
    found = by_id(evaluate_rules(rules, subject="subject", text="body", limits=FAST))
    assert found[1].status is RuleStatus.MATCHED
    assert found[1].part is ContentPart.TEXT
    assert found[2].status is RuleStatus.OK


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"subject": None, "text": None}, {"subject": "", "text": "", "html_visible_text": ""}],
)
def test_empty_input_is_not_evaluated_never_ok(kwargs: dict[str, str | None]) -> None:
    results = evaluate_rules([rule(1), regex(2), regex(3, pattern="(")], limits=FAST, **kwargs)
    found = by_id(results)
    assert found[1].issue is RuleIssue.NO_INPUT
    assert found[2].status is RuleStatus.NOT_EVALUATED
    assert found[3].status is RuleStatus.ERROR
    assert results.score == 0
    assert not results.complete


def test_no_rules_is_complete() -> None:
    results = evaluate_rules([], text="free", limits=FAST)
    assert results.results == ()
    assert results.complete


@pytest.mark.parametrize(
    "kwargs",
    [
        {"subject": b"bytes"},
        {"text": 12},
        {"html_visible_text": ["x"]},
        {"language_hint": 1},
        {"limits": {"max_rules": 1}},
    ],
)
def test_wrong_argument_types_raise(kwargs: dict[str, Any]) -> None:
    with pytest.raises(TypeError):
        evaluate_rules([rule()], **{"text": "free", **kwargs})


@pytest.mark.parametrize("rules", [[None], ["rule"], "ab"])
def test_non_record_rules_raise(rules: Any) -> None:
    with pytest.raises(TypeError):
        evaluate_rules(rules, text="free", limits=FAST)


@pytest.mark.parametrize("body", ["\ud800 free", "free\x00\x01", "‮free"])
def test_hostile_text_is_handled(body: str) -> None:
    results = evaluate_rules([rule(1), regex(2)], text=body, limits=FAST)
    assert all(r.status is RuleStatus.MATCHED for r in results.results)
    for result in results.results:
        assert result.evidence is not None
        result.evidence.encode("utf-8")


# --- caps ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("filler", ["x", "é", "€", "😀"])
def test_one_megabyte_input_is_capped_on_a_character_boundary(filler: str) -> None:
    body = "free " + filler * MAX_TEXT_BYTES
    results = evaluate_rules(
        [rule(1), regex(2), regex(3, pattern="absent"), rule(4, pattern="absent")],
        text=body,
        limits=RuleLimits(per_rule_timeout_s=2.0, total_budget_s=10.0),
    )
    found = by_id(results)
    assert found[1].status is RuleStatus.MATCHED
    assert found[2].status is RuleStatus.MATCHED
    # No match in a capped part is not an `ok`: the tail was not read.
    assert found[3].status is RuleStatus.NOT_EVALUATED
    assert found[3].issue is RuleIssue.INPUT_CAPPED
    assert found[4].issue is RuleIssue.INPUT_CAPPED
    assert results.capped_parts == (ContentPart.TEXT,)
    assert results.score == 20
    assert not results.complete


def test_match_beyond_the_cap_is_not_seen() -> None:
    body = "x " * 1000 + "free"
    results = evaluate_rules([rule()], text=body, limits=replace(FAST, max_text_bytes=100))
    assert results.results[0].status is RuleStatus.NOT_EVALUATED
    assert results.capped_parts == (ContentPart.TEXT,)


@pytest.mark.parametrize(
    ("value", "limit", "kept", "was_cut"),
    [
        ("abc", 3, "abc", False),
        ("abcd", 3, "abc", True),
        ("aé", 2, "a", True),
        ("aé", 3, "aé", False),
        ("€€", 5, "€", True),
        ("😀", 3, "", True),
        ("\ud800a", 3, "\ud800", True),
    ],
)
def test_cap_utf8(value: str, limit: int, kept: str, was_cut: bool) -> None:
    assert engine._cap_utf8(value, limit) == (kept, was_cut)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("per_rule_timeout_s", 999, safe_regex.MAX_TIMEOUT_S),
        ("per_rule_timeout_s", 0, safe_regex.MIN_TIMEOUT_S),
        ("total_budget_s", 999, safe_regex.MAX_BATCH_S),
        ("max_rules", 10**6, safe_regex.MAX_RULES),
        ("max_rules", -1, 0),
        ("max_text_bytes", 10**12, MAX_TEXT_BYTES),
        ("max_matches", 10**6, safe_regex.MAX_MATCHES),
        ("max_evidence_chars", 10**6, engine.MAX_EVIDENCE_CHARS),
        ("max_score", 10**9, engine.HARD_MAX_SCORE),
    ],
)
def test_limits_are_clamped(field: str, value: float, expected: float) -> None:
    assert getattr(engine._clamped(replace(RuleLimits(), **{field: value})), field) == expected


@pytest.mark.parametrize("cap", [1, 40, 160])
def test_evidence_is_bounded_and_cleaned(cap: int) -> None:
    body = "a\x07b\nc‮d\x00 " * 500 + "free " + "\x1b[31m tail " * 500
    results = evaluate_rules([rule()], text=body, limits=replace(FAST, max_evidence_chars=cap))
    evidence = results.results[0].evidence
    assert evidence is not None
    assert len(evidence) <= cap
    assert not set(evidence) & {"\x07", "\n", "‮", "\x00", "\x1b"}


def test_evidence_of_a_huge_match_is_bounded() -> None:
    results = evaluate_rules([regex(pattern=r"x+")], text="x" * 100_000, limits=FAST)
    assert results.results[0].status is RuleStatus.MATCHED
    evidence = results.results[0].evidence
    assert evidence is not None
    assert len(evidence) <= engine.DEFAULT_EVIDENCE_CHARS


# --- scoring and ordering ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("weights", "cap", "score"),
    [
        ([10, 20], 100, 30),
        ([60, 70], 100, 100),
        ([60, 70], 90, 90),
        ([0], 100, 0),
        ([30], 0, 0),
    ],
)
def test_score_sums_matched_weights_and_is_capped(weights: list[int], cap: int, score: int) -> None:
    rules = [rule(i, weight=w) for i, w in enumerate(weights, start=1)]
    results = evaluate_rules(rules, text="free", limits=replace(FAST, max_score=cap))
    assert results.score == score
    assert all(c.score <= cap for c in results.categories)


def test_score_grouped_by_category() -> None:
    rules = [
        rule(1, category="b", weight=70),
        rule(2, category="b", weight=60),
        rule(3, category="a", weight=5),
        rule(4, category="c", pattern="absent", weight=50),
    ]
    results = evaluate_rules(rules, text="free", limits=FAST)
    assert [(c.category, c.score, c.matched) for c in results.categories] == [
        ("a", 5, 1),
        ("b", 100, 2),
    ]
    assert results.score == 100


def test_results_ordered_by_weight_then_id_regardless_of_input_order() -> None:
    rules = [rule(5, weight=10), regex(1, weight=10), rule(3, weight=99), rule(2, weight=1)]
    expected = [3, 1, 5, 2]
    first = evaluate_rules(rules, text="free", limits=FAST)
    second = evaluate_rules(list(reversed(rules)), text="free", limits=FAST)
    assert [r.rule_id for r in first.results] == expected
    assert first == second


def test_results_are_serializable_field_by_field() -> None:
    results = evaluate_rules([rule(seed_key="k")], text="free", limits=FAST)
    data = dataclasses.asdict(results)
    assert data["complete"] is True
    assert data["results"][0]["status"] == "matched"
    assert data["results"][0]["seed_key"] == "k"


def test_seeded_disabled_rule_is_not_special_cased() -> None:
    seeded = regex(
        1,
        pattern=r"\A\s*(?:re|fwd)\s*:",
        flags=int(re.IGNORECASE),
        enabled=False,
        seed_key="subject_fake_reply_forward_prefix",
    )
    assert evaluate_rules([seeded], subject="Re: hi", limits=FAST).results == ()
    enabled = replace(seeded, enabled=True)
    result = evaluate_rules([enabled], text="Re: a body", limits=FAST).results[0]
    assert result.status is RuleStatus.MATCHED  # no target scoping in this ticket


# --- tenant merge --------------------------------------------------------------------------------

GLOBAL_A = rule(1, seed_key="a", pattern="alpha", weight=10)
GLOBAL_B = rule(2, seed_key="b", pattern="beta", weight=10)
GLOBAL_PLAIN = rule(3, pattern="gamma", weight=10, title="t")
TENANT_1_OFF = rule(
    11, scope="tenant", tenant_id=1, seed_key="a", pattern="alpha", enabled=False, weight=10
)
TENANT_1_OWN = rule(12, scope="tenant", tenant_id=1, pattern="delta", weight=10)
TENANT_2_REWEIGHT = rule(21, scope="tenant", tenant_id=2, seed_key="b", pattern="beta", weight=50)
TENANT_2_DANGLING = rule(22, scope="tenant", tenant_id=2, seed_key="gone", pattern="eps", weight=1)
ALL_ROWS = [
    GLOBAL_A,
    GLOBAL_B,
    GLOBAL_PLAIN,
    TENANT_1_OFF,
    TENANT_1_OWN,
    TENANT_2_REWEIGHT,
    TENANT_2_DANGLING,
]
BODY = "alpha beta gamma delta eps"


@pytest.mark.parametrize(
    ("tenant_id", "merged_ids", "matched", "score"),
    [
        (1, [2, 3, 11, 12], {2, 3, 12}, 30),
        (2, [1, 3, 21, 22], {1, 3, 21, 22}, 71),
        (3, [1, 2, 3], {1, 2, 3}, 30),
    ],
)
def test_tenant_merge(tenant_id: int, merged_ids: list[int], matched: set[int], score: int) -> None:
    merged = merge_tenant_rules(ALL_ROWS, tenant_id=tenant_id)
    assert sorted(r.id for r in merged) == merged_ids
    results = evaluate_rules(merged, text=BODY, limits=FAST)
    assert {r.rule_id for r in results.results if r.status is RuleStatus.MATCHED} == matched
    assert results.score == score


def test_tenant_disabling_a_global_does_not_affect_another_tenant() -> None:
    first = evaluate_rules(merge_tenant_rules(ALL_ROWS, tenant_id=1), text="alpha", limits=FAST)
    second = evaluate_rules(merge_tenant_rules(ALL_ROWS, tenant_id=2), text="alpha", limits=FAST)
    assert first.score == 0
    assert second.score == 10


def test_override_is_by_seed_key_not_by_name() -> None:
    same_name = rule(
        31, scope="tenant", tenant_id=1, name=GLOBAL_PLAIN.name, enabled=False, title="t"
    )
    merged = merge_tenant_rules([GLOBAL_PLAIN, same_name], tenant_id=1)
    assert {r.id for r in merged} == {GLOBAL_PLAIN.id, 31}


def test_rows_with_inconsistent_scope_are_dropped() -> None:
    bad_global = rule(41, scope="global", tenant_id=2)
    bad_tenant = rule(42, scope="tenant", tenant_id=None)
    assert merge_tenant_rules([bad_global, bad_tenant], tenant_id=2) == []


@pytest.mark.parametrize("tenant_id", [None, "1", True, 1.0])
def test_merge_rejects_malformed_tenant_id(tenant_id: Any) -> None:
    with pytest.raises(TypeError):
        merge_tenant_rules(ALL_ROWS, tenant_id=tenant_id)


# --- async entry point ---------------------------------------------------------------------------


async def test_async_entry_point_matches_sync_result() -> None:
    rules = [rule(1), regex(2)]
    assert await evaluate_rules_async(rules, text="free", limits=FAST) == evaluate_rules(
        rules, text="free", limits=FAST
    )


async def test_async_entry_point_runs_off_the_event_loop_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    threads: list[int] = []

    def spy(rules: Any, text: str, **kwargs: Any) -> list[MatchResult]:
        threads.append(threading.get_ident())
        return safe_regex.search_many(rules, text, **kwargs)

    monkeypatch.setattr(engine, "search_many", spy)
    results = await evaluate_rules_async([regex()], text="free", limits=FAST)
    assert results.results[0].status is RuleStatus.MATCHED
    assert threads
    assert threading.get_ident() not in threads
