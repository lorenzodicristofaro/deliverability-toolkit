"""Tests for app.services.content_findings (M5-14). Pure and offline."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.checks.models import CODE_RE, Finding
from app.core import i18n
from app.core.i18n import t
from app.parsers.content_html import parse_content
from app.parsers.content_links import analyze_links
from app.parsers.content_subject import analyze_subject
from app.parsers.list_unsubscribe import MAX_FIELDS, MAX_URIS, analyze_list_unsubscribe
from app.parsers.message import parse_header_block
from app.parsers.url_shorteners import Shortener
from app.services import content_findings as cf
from app.services.content_findings import SectionFindings
from app.services.content_rules_engine import (
    ContentPart,
    RuleIssue,
    RuleResult,
    RuleResults,
    RuleStatus,
)

LOCALES = Path(__file__).resolve().parents[2] / "locales"
EN = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
IT = json.loads((LOCALES / "it.json").read_text(encoding="utf-8"))
SHORTENERS = (Shortener("bit.ly", None, "n", "verified", ()),)
WORDS = "word " * 40
SENDER = ["example.com"]


@pytest.fixture(autouse=True)
def _strict_i18n() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)


def codes(found: SectionFindings) -> set[str]:
    return {f.code for f in found.findings}


def rendered(found: SectionFindings) -> None:
    """Every key exists and every placeholder is supplied, in both languages."""
    for item in found.findings:
        assert item.code in cf.CODES
        for lang in ("en", "it"):
            for key in (item.title_key, item.detail_key, item.remediation_key):
                assert key is not None
                assert t(key, lang, **item.params)


# --- catalogue -------------------------------------------------------------------------------


def test_codes_are_unique_and_well_formed() -> None:
    assert len(set(cf.CODES)) == len(cf.CODES)
    assert all(CODE_RE.fullmatch(c) and c.startswith("CONTENT_") for c in cf.CODES)


@pytest.mark.parametrize("catalogue", [EN, IT], ids=["en", "it"])
@pytest.mark.parametrize("code", cf.CODES)
@pytest.mark.parametrize("part", ["title", "detail", "remediation"])
def test_every_code_has_its_texts(catalogue: dict[str, str], code: str, part: str) -> None:
    assert catalogue[f"finding.{code}.{part}"].strip()


@pytest.mark.parametrize("variant", cf.ONE_CLICK_VARIANTS)
@pytest.mark.parametrize("catalogue", [EN, IT], ids=["en", "it"])
def test_one_click_variants_exist(catalogue: dict[str, str], variant: str) -> None:
    assert catalogue[f"finding.CONTENT_NO_ONE_CLICK.detail_{variant}"].strip()


def test_every_content_key_belongs_to_a_known_code() -> None:
    allowed = {f"finding.{c}.{p}" for c in cf.CODES for p in ("title", "detail", "remediation")}
    allowed |= {f"finding.CONTENT_NO_ONE_CLICK.detail_{v}" for v in cf.ONE_CLICK_VARIANTS}
    allowed.add(f"finding.CONTENT_RULE_MATCH.{cf.RULE_MATCH_CUSTOM_ADVICE}")
    for catalogue in (EN, IT):
        assert {k for k in catalogue if k.startswith("finding.CONTENT_")} == allowed


@pytest.mark.parametrize("code", cf.ADVISORY_CODES)
def test_heuristic_texts_say_advisory(code: str) -> None:
    assert "advisory" in EN[f"finding.{code}.detail"]
    assert "indicativ" in IT[f"finding.{code}.detail"]
    assert "no official source" in EN[f"finding.{code}.detail"]


@pytest.mark.parametrize("code", cf.CODES)
def test_texts_differ_between_languages(code: str) -> None:
    assert EN[f"finding.{code}.detail"] != IT[f"finding.{code}.detail"]


# --- body ------------------------------------------------------------------------------------

CSS = "a{color:red}" * 1000


@pytest.mark.parametrize(
    ("html", "text", "expected"),
    [
        (f"<p>{WORDS}</p>", "hello", set()),
        ("", "only text", set()),
        (f"<p>{WORDS}</p>", None, {"CONTENT_MISSING_PLAIN_TEXT"}),
        (f"<p>{WORDS}</p>", "   ", {"CONTENT_MISSING_PLAIN_TEXT"}),
        ('<img alt="x"><p>short</p>', "hi", {"CONTENT_LOW_TEXT_IMAGE_RATIO"}),
        (f'<img alt="x"><p>{WORDS}</p>', "hi", set()),
        (
            "<img><p>short</p>",
            "hi",
            {"CONTENT_LOW_TEXT_IMAGE_RATIO", "CONTENT_IMAGES_MISSING_ALT"},
        ),
        (f'<img alt=""><p>{WORDS}</p>', "hi", set()),  # empty alt is decorative
        (f"<div><p>{WORDS}</span>", "hi", {"CONTENT_MALFORMED_HTML"}),
        (f"<p>{WORDS}</p>\x00", "hi", {"CONTENT_MALFORMED_HTML"}),
        (f'<p style="display:none">x</p><p>{WORDS}</p>', "hi", {"CONTENT_HIDDEN_TEXT"}),
        ("<p>" + "a" * 102_500 + "</p>", "hi", {"CONTENT_GMAIL_CLIP_RISK"}),
        (f"<style>{CSS}</style><p>{WORDS}</p>", "hi", {"CONTENT_EXCESS_CSS"}),
        (f"<style>{CSS[:600]}</style><p>{WORDS}</p>", "hi", set()),  # under the minimum size
    ],
)
def test_body_findings(html: str, text: str | None, expected: set[str]) -> None:
    found = cf.body_findings(parse_content(html, text))
    assert codes(found) == expected
    assert found.unevaluated == ()
    rendered(found)


@pytest.mark.parametrize(
    ("html", "reason"),
    [
        ("<br>" * 20_001, "body_element_count"),
        ("<div>" * 101, "body_nesting_depth"),
        ("<p " + " ".join(f"a{i}" for i in range(101)) + ">", "body_attribute_count"),
        ("x" * 2_000_001, "body_input_size"),
    ],
)
def test_body_cap_is_error_class(html: str, reason: str) -> None:
    found = cf.body_findings(parse_content(html, "hi"))
    assert reason in found.unevaluated
    assert "CONTENT_INPUT_CAPPED" in codes(found)
    assert "CONTENT_LOW_TEXT_IMAGE_RATIO" not in codes(found)
    rendered(found)


def test_body_parser_error_is_error_class(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_self: Any, _data: str) -> None:
        raise RuntimeError

    monkeypatch.setattr("app.parsers.content_html._Collector.feed", boom)
    found = cf.body_findings(parse_content("<p>x</p>", "hi"))
    assert found.unevaluated == ("body_parser_error",)


# --- links -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("anchors", "senders", "expected"),
    [
        ([("Read", "https://example.com/a")], SENDER, set()),
        ([("Read", "/relative")], SENDER, set()),
        ([("Mail", "mailto:a@other.example")], SENDER, set()),
        ([("Read", "https://example.com/a")], [], set()),  # no sender: nothing to compare
        ([("example.com", "https://evil.example/")], [], {"CONTENT_MASKED_LINK"}),
        ([("Go", "https://bit.ly/x")], [], {"CONTENT_URL_SHORTENER"}),
        ([("Go", "http://example.com/")], SENDER, {"CONTENT_NON_HTTPS_LINK"}),
        ([("Go", "https://203.0.113.9/")], [], {"CONTENT_IP_LITERAL_LINK"}),
        ([("Go", "https://other.example/")], SENDER, {"CONTENT_UNALIGNED_LINK_DOMAIN"}),
        (
            [("Go", f"https://d{i}.example/") for i in range(6)],
            [],
            {"CONTENT_MANY_LINK_DOMAINS"},
        ),
        ([("Go", f"https://d{i}.example/") for i in range(5)], [], set()),
    ],
)
def test_link_findings(
    anchors: list[tuple[str, str | None]], senders: list[str], expected: set[str]
) -> None:
    found = cf.link_findings(analyze_links(anchors, sender_domains=senders, shorteners=SHORTENERS))
    assert codes(found) == expected
    assert found.unevaluated == ()
    rendered(found)


def test_unaligned_is_reported_even_when_another_link_is_unevaluated() -> None:
    # all_aligned is None here, so a verdict based on it would hide the unaligned link.
    facts = analyze_links(
        [("a", "https://other.example/"), ("b", "https://[bad/")],
        sender_domains=SENDER,
        shorteners=(),
    )
    assert facts.all_aligned is None
    found = cf.link_findings(facts)
    assert codes(found) == {"CONTENT_UNALIGNED_LINK_DOMAIN", "CONTENT_LINK_UNEVALUATED"}
    assert found.unevaluated == ()
    assert found.partial == ("links_malformed",)
    unevaluated = next(f for f in found.findings if f.code == "CONTENT_LINK_UNEVALUATED")
    assert unevaluated.params["count"] == 1
    rendered(found)


@pytest.mark.parametrize(
    ("anchors", "reason"),
    [
        ([("a", "https://example.com/")] * 501, "links_link_count"),
        ([("a", "https://example.com/" + "x" * 5000)], "links_url_length"),
    ],
)
def test_link_caps_are_error_class(anchors: list[tuple[str, str]], reason: str) -> None:
    found = cf.link_findings(analyze_links(anchors, sender_domains=SENDER, shorteners=()))
    assert reason in found.unevaluated
    assert "CONTENT_INPUT_CAPPED" in codes(found)


def test_link_evidence_never_holds_the_path_or_query() -> None:
    facts = analyze_links(
        [("Go", "http://other.example/track?email=person@example.net")],
        sender_domains=SENDER,
        shorteners=(),
    )
    found = cf.link_findings(facts)
    assert all("person" not in e and "track" not in e for f in found.findings for e in f.evidence)


# --- subject ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("subject", "in_reply_to", "expected"),
    [
        ("Hello there", None, set()),
        (None, None, {"CONTENT_SUBJECT_EMPTY"}),
        ("   ", None, {"CONTENT_SUBJECT_EMPTY"}),
        ("​", None, {"CONTENT_SUBJECT_EMPTY"}),
        ("BUY THIS AMAZING THING", None, {"CONTENT_SUBJECT_ALL_CAPS"}),
        ("Hello!!", None, {"CONTENT_SUBJECT_PUNCTUATION"}),
        ("Hello!", None, set()),
        ("ab " * 60, None, {"CONTENT_SUBJECT_LONG"}),
        ("Re: hi", False, {"CONTENT_SUBJECT_REPLY_PREFIX"}),
        ("Re: hi", True, set()),
        ("Re: hi", None, set()),  # unknown headers: no verdict
        ("Fwd: hi", False, set()),  # a real forward has no In-Reply-To
        ("a\x01b", None, {"CONTENT_SUBJECT_CONTROL_CHARS"}),
        ("a‮b", None, {"CONTENT_SUBJECT_BIDI_OVERRIDE"}),
        ("pаypal", None, {"CONTENT_SUBJECT_MIXED_SCRIPT"}),
    ],
)
def test_subject_findings(
    subject: str | None, in_reply_to: bool | None, expected: set[str]
) -> None:
    found = cf.subject_findings(analyze_subject(subject, has_in_reply_to=in_reply_to))
    assert codes(found) == expected
    assert found.unevaluated == ()
    rendered(found)


def test_subject_cap_is_error_class() -> None:
    found = cf.subject_findings(analyze_subject("x" * 10_001))
    assert found.unevaluated == ("subject_too_long",)
    assert "CONTENT_INPUT_CAPPED" in codes(found)


# --- unsubscribe -----------------------------------------------------------------------------

HTTPS = "<https://u.example/x>"
POST = "List-Unsubscribe=One-Click"
SIGNED = [["from", "list-unsubscribe", "list-unsubscribe-post"]]


def block(*headers: tuple[str, str]) -> Any:
    lines = [f"{n}: {v}" for n, v in (("From", "a@x.example"), *headers)]
    return parse_header_block(("\r\n".join(lines) + "\r\n\r\n").encode())


def lu(value: str) -> tuple[str, str]:
    return ("List-Unsubscribe", value)


def lup(value: str = POST) -> tuple[str, str]:
    return ("List-Unsubscribe-Post", value)


@pytest.mark.parametrize(
    ("headers", "dkim", "expected", "detail"),
    [
        ((), SIGNED, {"CONTENT_NO_LIST_UNSUBSCRIBE"}, None),
        ((lu(HTTPS), lup()), SIGNED, set(), None),
        ((lu(HTTPS),), SIGNED, {"CONTENT_NO_ONE_CLICK"}, "detail"),
        ((lu(HTTPS), lu(HTTPS), lup()), SIGNED, {"CONTENT_NO_ONE_CLICK"}, "detail_duplicated"),
        ((lu(HTTPS), lup(), lup()), SIGNED, {"CONTENT_NO_ONE_CLICK"}, "detail_duplicated"),
        (
            (lu(HTTPS), lup("list-unsubscribe=one-click")),
            SIGNED,
            {"CONTENT_NO_ONE_CLICK"},
            "detail_post_value",
        ),
        ((lu(HTTPS), lup("yes")), SIGNED, {"CONTENT_NO_ONE_CLICK"}, "detail_post_value"),
        (
            (lu("<https:u.example/x>"), lup()),
            SIGNED,
            {"CONTENT_NO_ONE_CLICK"},
            "detail_nonstandard_authority",
        ),
        (
            (lu("<mailto:u@x.example>"), lup()),
            SIGNED,
            {"CONTENT_NO_ONE_CLICK"},
            "detail_no_https_uri",
        ),
        (
            (lu("<http://u.example/x>"), lup()),
            SIGNED,
            {"CONTENT_NO_ONE_CLICK", "CONTENT_HTTP_ONLY_UNSUBSCRIBE"},
            "detail_no_https_uri",
        ),
        ((lu(HTTPS), lup()), [], {"CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER"}, None),
        ((lu(HTTPS), lup()), [["from"]], {"CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER"}, None),
        ((lu("<mailto:u@x.example>"),), [], {"CONTENT_NO_ONE_CLICK"}, "detail"),  # no Post
    ],
)
def test_unsubscribe_findings(
    headers: tuple[tuple[str, str], ...],
    dkim: list[list[str]] | None,
    expected: set[str],
    detail: str | None,
) -> None:
    facts = analyze_list_unsubscribe(block(*headers), dkim_signed_headers=dkim)
    found = cf.unsubscribe_findings(facts)
    assert codes(found) == expected
    assert found.unevaluated == ()
    if detail is not None:
        one_click = next(f for f in found.findings if f.code == "CONTENT_NO_ONE_CLICK")
        assert one_click.detail_key == f"finding.CONTENT_NO_ONE_CLICK.{detail}"
    rendered(found)


def test_unknown_dkim_coverage_is_error_class_when_one_click_is_attempted() -> None:
    facts = analyze_list_unsubscribe(block(lu(HTTPS), lup()), dkim_signed_headers=None)
    found = cf.unsubscribe_findings(facts)
    assert found.unevaluated == ("dkim_signed_headers_unknown",)
    assert codes(found) == {"CONTENT_INPUT_CAPPED"}
    rendered(found)


def test_unknown_dkim_coverage_does_not_matter_without_one_click() -> None:
    facts = analyze_list_unsubscribe(block(lu(HTTPS)), dkim_signed_headers=None)
    found = cf.unsubscribe_findings(facts)
    assert found.unevaluated == ()
    assert codes(found) == {"CONTENT_NO_ONE_CLICK"}


@pytest.mark.parametrize(
    "headers",
    [
        # Value over the cap; folded, because a physical header line has its own cap.
        (lu("<https://u.example/" + "x" * 4000 + "\r\n " + "x" * 4300 + ">"), lup()),
        (lu(",".join([HTTPS] * (MAX_URIS + 1))), lup()),  # first URI is https: fact is True
        tuple(lu(HTTPS) for _ in range(MAX_FIELDS + 1)),
        (lu("<https://u.example/" + "x" * 2100 + ">"), lup()),  # URI over the cap
    ],
    ids=["value", "uris", "fields", "uri"],
)
def test_unsubscribe_caps_are_error_class(headers: tuple[tuple[str, str], ...]) -> None:
    facts = analyze_list_unsubscribe(block(*headers), dkim_signed_headers=SIGNED)
    found = cf.unsubscribe_findings(facts)
    assert found.unevaluated == ("list_unsubscribe_unevaluated",)
    assert "CONTENT_INPUT_CAPPED" in codes(found)


# --- rules -----------------------------------------------------------------------------------


def result(
    status: RuleStatus,
    issue: RuleIssue | None = None,
    *,
    seed_key: str | None = None,
    evidence: str | None = "snippet",
    rule_id: int = 1,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        seed_key=seed_key,
        name="rule-name",
        category="spam",
        severity="medium",
        weight=10,
        status=status,
        issue=issue,
        part=ContentPart.TEXT if status is RuleStatus.MATCHED else None,
        evidence=evidence if status is RuleStatus.MATCHED else None,
    )


def results(*rows: RuleResult, capped: tuple[ContentPart, ...] = ()) -> RuleResults:
    errors = sum(r.status is RuleStatus.ERROR for r in rows)
    skipped = sum(r.status is RuleStatus.NOT_EVALUATED for r in rows)
    return RuleResults(rows, 0, (), capped, errors, skipped, not (errors or skipped or capped))


def record(title: str | None = None, advice: str | None = None) -> Any:
    return SimpleNamespace(title=title, advice=advice)


@pytest.mark.parametrize(
    ("row", "expected", "reason"),
    [
        (result(RuleStatus.OK), set(), None),
        (result(RuleStatus.MATCHED), {"CONTENT_RULE_MATCH"}, None),
        (result(RuleStatus.MATCHED, evidence=None), {"CONTENT_RULE_MATCH"}, None),
        (result(RuleStatus.ERROR, RuleIssue.TIMEOUT), {"CONTENT_RULE_ERROR"}, "rules_failed"),
        (
            result(RuleStatus.ERROR, RuleIssue.INVALID_PATTERN),
            {"CONTENT_RULE_ERROR"},
            "rules_failed",
        ),
        (result(RuleStatus.NOT_EVALUATED, RuleIssue.BUSY), {"CONTENT_RULE_ERROR"}, "rules_failed"),
        (
            result(RuleStatus.NOT_EVALUATED, RuleIssue.BUDGET_EXCEEDED),
            {"CONTENT_RULE_ERROR"},
            "rules_failed",
        ),
        (
            result(RuleStatus.NOT_EVALUATED, RuleIssue.TOO_MANY_RULES),
            {"CONTENT_RULE_ERROR"},
            "rules_failed",
        ),
        (
            result(RuleStatus.NOT_EVALUATED, RuleIssue.INPUT_CAPPED),
            {"CONTENT_INPUT_CAPPED"},
            "rules_input_capped",
        ),
        (result(RuleStatus.NOT_EVALUATED, RuleIssue.NO_INPUT), set(), None),
    ],
)
def test_rule_findings(row: RuleResult, expected: set[str], reason: str | None) -> None:
    found = cf.rule_findings(results(row), {1: record("A title")})
    assert codes(found) == expected
    assert found.unevaluated == (() if reason is None else (reason,))
    rendered(found)


def test_capped_part_is_error_class_even_when_a_rule_matched() -> None:
    found = cf.rule_findings(
        results(result(RuleStatus.MATCHED), capped=(ContentPart.TEXT,)), {1: record("A")}
    )
    assert codes(found) == {"CONTENT_RULE_MATCH", "CONTENT_INPUT_CAPPED"}
    assert found.unevaluated == ("rules_input_capped",)


def match(found: SectionFindings) -> Finding:
    return next(f for f in found.findings if f.code == "CONTENT_RULE_MATCH")


def test_seeded_rule_takes_its_text_from_the_catalogue() -> None:
    found = cf.rule_findings(
        results(result(RuleStatus.MATCHED, seed_key="all_caps_run")), {1: record()}
    )
    item = match(found)
    assert item.title_key == "CONTENT_RULE.all_caps_run.title"
    assert item.remediation_key == "CONTENT_RULE.all_caps_run.advice"
    assert item.params["rule"] == "rule-name"
    rendered_item = t(item.title_key, "it")
    assert rendered_item == IT["CONTENT_RULE.all_caps_run.title"]


@pytest.mark.parametrize("records", [{1: record()}, {}], ids=["null-title", "unknown-id"])
def test_rule_without_any_text_does_not_crash(records: dict[int, Any]) -> None:
    found = cf.rule_findings(
        results(result(RuleStatus.MATCHED, seed_key="removed_from_catalogue")), records
    )
    item = match(found)
    assert item.title_key == "finding.CONTENT_RULE_MATCH.title"
    assert item.remediation_key == "finding.CONTENT_RULE_MATCH.remediation"
    assert item.params["rule"] == "rule-name"
    rendered(found)


def test_tenant_rule_uses_its_own_title_and_advice() -> None:
    found = cf.rule_findings(
        results(result(RuleStatus.MATCHED, seed_key="all_caps_run")),
        {1: record("My title", "My advice")},
    )
    item = match(found)
    assert item.title_key == "finding.CONTENT_RULE_MATCH.title"
    assert item.remediation_key == "finding.CONTENT_RULE_MATCH.remediation_custom"
    assert t(item.remediation_key, "en", **item.params) == "My advice"
    assert item.params["rule"] == "My title"
    assert item.params["advice"] == "My advice"


def test_rule_evidence_absent_on_match_gives_empty_evidence() -> None:
    found = cf.rule_findings(results(result(RuleStatus.MATCHED, evidence=None)), {1: record("A")})
    assert match(found).evidence == ()


def test_rule_severity_is_the_rule_severity() -> None:
    found = cf.rule_findings(results(result(RuleStatus.MATCHED)), {1: record("A")})
    assert match(found).severity == "medium"


def test_rules_unavailable_is_error_class() -> None:
    found = cf.rules_unavailable("rules_unavailable")
    assert codes(found) == {"CONTENT_RULE_ERROR"}
    assert found.unevaluated == ("rules_unavailable",)
    rendered(found)
