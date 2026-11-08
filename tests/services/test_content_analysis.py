"""Tests for app.services.content_analysis (M5-14). No DNS or sockets; nothing is stored."""

from __future__ import annotations

import base64
import json
import logging
import socket
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Base
from app.models.content_rule import ContentRule
from app.models.tenant import Tenant
from app.parsers.message import MAX_RAW_BYTES
from app.parsers.mime import MAX_MIME_DEPTH, MAX_MIME_PARTS
from app.repositories import GlobalContentRuleRepository, repo_for
from app.repositories.content_rules import ContentRuleRepository
from app.services import content_analysis as ca
from app.services.content_analysis import ContentAnalysis, ContentInput, analyze_content
from app.services.content_rules_engine import (
    ContentPart,
    RuleIssue,
    RuleResult,
    RuleResults,
    RuleStatus,
)
from tests.support.socket_guard import db_endpoint, install

WORDS = "word " * 40
HTML = f"<p>{WORDS}</p>"
HEADERS = (
    "From: A <a@example.com>\r\n"
    "Subject: Hello there\r\n"
    "List-Unsubscribe: <https://example.com/u>\r\n"
    "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    "DKIM-Signature: v=1; d=example.com; s=x;"
    " h=from:list-unsubscribe:list-unsubscribe-post; b=x\r\n"
)
MARKER = "zqxjsecretmarker"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "content analysis", db_endpoint())


@dataclass
class World:
    session: Session
    ctx: TenantContext
    other: TenantContext

    def analyze(self, **fields: Any) -> ContentAnalysis:
        return analyze_content(self.ctx, self.session, ContentInput(**fields))

    @property
    def tenant_rules(self) -> ContentRuleRepository:
        return repo_for(self.ctx, self.session).content_rules

    @property
    def global_rules(self) -> GlobalContentRuleRepository:
        return GlobalContentRuleRepository(self.session)


@pytest.fixture
def engine(db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(db_url)
    Base.metadata.create_all(eng)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        tenants = [Tenant(name=n, slug=n) for n in ("a", "b")]
        session.add_all(tenants)
        session.commit()
        yield World(session, TenantContext(tenants[0].id, None), TenantContext(tenants[1].id, None))
    finally:
        session.close()


def rule(name: str, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "name": name,
        "kind": "keyword",
        "pattern": "winner",
        "weight": 10,
        "category": "spam",
        "severity": "medium",
        "enabled": True,
        "title": f"Title {name}",
    }
    values.update(overrides)
    return values


def eml(body: str, content_type: str = "text/plain", extra: str = "", head: str = HEADERS) -> bytes:
    return f"{head}Content-Type: {content_type}\r\n{extra}\r\n{body}".encode("latin-1")


def multipart(*parts: tuple[str, str, str], subtype: str = "alternative") -> bytes:
    """`parts`: (content type, extra headers, body)."""
    chunks = [f"--b\r\nContent-Type: {ct}\r\n{extra}\r\n{body}\r\n" for ct, extra, body in parts]
    body = "".join(chunks) + "--b--\r\n"
    return eml(body, f'multipart/{subtype}; boundary="b"')


def codes(result: ContentAnalysis) -> set[str]:
    return {f.code for f in result.findings}


def reasons(result: ContentAnalysis) -> set[str]:
    return {str(f.params["reason"]) for f in result.findings if f.code == "CONTENT_INPUT_CAPPED"}


# --- status mapping --------------------------------------------------------------------------


def test_no_input_at_all_is_not_evaluated(world: World) -> None:
    result = world.analyze()
    assert result.status == "not_evaluated"
    assert result.complete is False
    assert set(result.not_evaluated_sections) == {
        "body",
        "links",
        "subject",
        "unsubscribe",
        "rules",
    }
    assert result.message is None
    assert result.findings == ()


def test_clean_html_without_headers_shows_what_was_not_evaluated(world: World) -> None:
    result = world.analyze(html=HTML, text="hello")
    assert result.status == "ok"
    assert result.complete is False
    assert result.body.status == "ok"
    assert result.links.status == "ok"
    assert result.unsubscribe.status == "not_evaluated"
    assert result.unsubscribe.reasons == ("no_headers",)
    assert result.unsubscribe.facts is None
    assert result.subject.status == "not_evaluated"
    assert "unsubscribe" in result.not_evaluated_sections


def test_section_status_follows_its_own_findings(world: World) -> None:
    result = world.analyze(html='<a href="https://203.0.113.9/">x</a>' + HTML, text="hello")
    assert result.status == "fail"
    assert result.links.status == "fail"
    assert result.body.status == "ok"


def test_text_only_has_no_link_section(world: World) -> None:
    result = world.analyze(text="hello")
    assert result.body.status == "ok"
    assert result.links.status == "not_evaluated"
    assert result.links.reasons == ("no_html",)


@pytest.mark.parametrize("field", ["html", "text", "subject", "language_hint"])
@pytest.mark.parametrize("value", [123, b"bytes", ["x"]], ids=["int", "bytes", "list"])
def test_malformed_field_types_are_error_class(world: World, field: str, value: object) -> None:
    result = world.analyze(**{field: value})
    assert result.status == "error"
    assert f"invalid_{field}" in reasons(result)


def test_wrong_context_is_a_programming_error(world: World) -> None:
    with pytest.raises(TypeError):
        analyze_content(1, world.session, ContentInput())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        analyze_content(world.ctx, world.session, "html")  # type: ignore[arg-type]


# --- caps ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"html": "<br>" * 20_001}, "body_element_count"),
        ({"html": "<div>" * 101}, "body_nesting_depth"),
        ({"html": "<p " + " ".join(f"a{i}" for i in range(101)) + ">"}, "body_attribute_count"),
        ({"html": "x" * 2_000_001}, "body_input_size"),
        ({"text": "x" * 2_000_001}, "body_input_size"),
    ],
)
def test_body_caps_make_body_rules_and_overall_error(
    world: World, fields: dict[str, str], reason: str
) -> None:
    result = world.analyze(**fields)
    assert result.status == "error"
    assert result.complete is False
    assert result.body.status == "error"
    assert result.rules.status == "error"  # even though no rule is enabled
    assert reason in reasons(result)


@pytest.mark.parametrize(
    ("html", "reason"),
    [
        ('<a href="https://example.com/">x</a>' * 501, "links_link_count"),
        ('<a href="https://example.com/' + "x" * 5000 + '">x</a>', "links_url_length"),
    ],
)
def test_link_caps_are_error(world: World, html: str, reason: str) -> None:
    result = world.analyze(html=html, text="hello")
    assert result.status == "error"
    assert result.links.status == "error"
    assert reason in reasons(result)


def test_subject_cap_is_error(world: World) -> None:
    result = world.analyze(subject="x" * 10_001)
    assert result.status == "error"
    assert result.subject.status == "error"
    assert "subject_too_long" in reasons(result)


def test_rule_text_cap_is_error(world: World) -> None:
    world.tenant_rules.create(rule("r1", pattern="absent"))
    result = world.analyze(text="a " * 150_000)
    assert result.status == "error"
    assert result.rules.status == "error"
    assert "rules_input_capped" in reasons(result)
    assert result.rules.facts is not None
    assert result.rules.facts.complete is False
    assert [r.status for r in result.rules.facts.results] == ["not_evaluated"]
    assert result.rules.facts.results[0].issue == "input_capped"


# --- .eml ------------------------------------------------------------------------------------


def test_eml_extracts_parts_headers_and_domains(world: World) -> None:
    raw = multipart(("text/plain", "", "plain"), ("text/html", "", HTML))
    result = world.analyze(eml=raw)
    assert result.status == "ok"
    assert result.complete is False  # rules: none enabled
    assert result.message is not None
    assert result.message.facts is not None
    assert result.message.facts.from_domains == ("example.com",)
    assert result.message.facts.dkim_domains == ("example.com",)
    assert result.message.facts.body_parts == 2
    assert result.unsubscribe.status == "ok"
    assert result.unsubscribe.facts is not None
    assert result.unsubscribe.facts.one_click_signed is True
    assert result.unsubscribe.facts.signature_verified is False
    assert result.subject.status == "ok"
    assert result.body.facts is not None
    assert result.body.facts.has_plain_text is True
    assert result.links.status == "ok"


@pytest.mark.parametrize(
    ("body", "ctype", "extra", "needle"),
    [
        (base64.b64encode(b"winner body").decode(), "text/plain", "CTE: base64", "winner"),
        ("winner=20body=", "text/plain", "CTE: quoted-printable", "winner"),
        ("winn\xe9r winner", "text/plain; charset=iso-8859-1", "", "winner"),
        ("<p>winner</p>", "text/html", "", "winner"),
    ],
    ids=["base64", "qp", "latin1", "html"],
)
def test_eml_body_is_decoded_for_the_rules(
    world: World, body: str, ctype: str, extra: str, needle: str
) -> None:
    world.tenant_rules.create(rule("r1", pattern=needle))
    header = extra.replace("CTE", "Content-Transfer-Encoding") + "\r\n" if extra else ""
    result = world.analyze(eml=eml(body, ctype, header))
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 1
    assert "CONTENT_RULE_MATCH" in codes(result)


def test_attached_message_is_not_the_body(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    inner = "Subject: inner\r\nContent-Type: text/plain\r\n\r\nwinner"
    raw = multipart(("text/plain", "", "hello"), ("message/rfc822", "", inner), subtype="mixed")
    result = world.analyze(eml=raw)
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 0
    assert result.rules.status == "ok"


def test_attachment_is_not_the_body(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    raw = multipart(
        ("text/plain", "", "hello"),
        ("text/plain", 'Content-Disposition: attachment; filename="a.txt"\r\n', "winner"),
        subtype="mixed",
    )
    result = world.analyze(eml=raw)
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 0


def test_all_body_parts_are_used(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    raw = multipart(("text/plain", "", "hello"), ("text/plain", "", "winner"), subtype="mixed")
    result = world.analyze(eml=raw)
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 1


def test_explicit_field_wins_over_the_eml(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    result = world.analyze(eml=eml("winner"), text="hello", subject="Other subject")
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 0
    assert result.unsubscribe.status == "ok"  # headers still come from the .eml


def nested(depth: int) -> bytes:
    opening = "".join(
        f'--b{i}\r\nContent-Type: multipart/mixed; boundary="b{i + 1}"\r\n\r\n'
        for i in range(depth)
    )
    head = HEADERS + 'Content-Type: multipart/mixed; boundary="b0"\r\n\r\n'
    return (head + opening + f"--b{depth}\r\nContent-Type: text/plain\r\n\r\nx\r\n").encode()


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"", "empty_input"),
        ("text", "invalid_input"),
        (b"no colon here and no block", "no_header_block"),
        (b"From: a\x00b@example.com\r\n\r\nbody", "nul_byte"),
        (b"x" * (MAX_RAW_BYTES + 1), "message_too_large"),
        (nested(MAX_MIME_DEPTH + 2), "mime_truncated"),
        (
            multipart(*[("text/plain", "", "x")] * (MAX_MIME_PARTS + 1), subtype="mixed"),
            "mime_truncated",
        ),
        (eml("!!!not base64", extra="Content-Transfer-Encoding: base64\r\n"), "undecodable_part"),
        (eml("x", extra="Content-Transfer-Encoding: bogus\r\n"), "unknown_transfer_encoding"),
        (eml("x", "text/plain; charset=no-such-charset"), "unknown_charset"),
        (eml("caf\xe9", "text/plain; charset=utf-8"), "undecodable_part"),
        (eml("x", 'multipart/mixed; boundary=""'), "mime_missing_boundary"),
    ],
    ids=[
        "empty",
        "not-bytes",
        "no-headers",
        "nul",
        "too-large",
        "depth",
        "parts",
        "bad-base64",
        "bad-cte",
        "bad-charset",
        "bad-utf8",
        "no-boundary",
    ],
)
def test_eml_problems_are_error_class(world: World, raw: Any, reason: str) -> None:
    result = world.analyze(eml=raw)
    assert result.status == "error"
    assert result.complete is False
    assert result.message is not None
    assert result.message.status == "error"
    assert reason in reasons(result)
    assert result.body.status == "error"
    assert result.rules.status == "error"


def test_rejected_eml_leaves_unsubscribe_in_error_not_ok(world: World) -> None:
    result = world.analyze(eml=b"")
    assert result.unsubscribe.status == "error"
    assert result.unsubscribe.facts is None


def test_headers_only_eml_has_no_body_section(world: World) -> None:
    result = world.analyze(eml=HEADERS.encode() + b"\r\n")
    assert result.body.status == "not_evaluated"
    assert result.body.reasons == ("no_input",)
    assert result.unsubscribe.status == "ok"
    assert "CONTENT_MISSING_PLAIN_TEXT" not in codes(result)


def test_eml_without_subject_is_a_finding(world: World) -> None:
    head = "From: a@example.com\r\n"
    result = world.analyze(eml=eml("hello", head=head))
    assert "CONTENT_SUBJECT_EMPTY" in codes(result)
    assert "CONTENT_NO_LIST_UNSUBSCRIBE" in codes(result)


def test_reply_prefix_uses_the_message_headers(world: World) -> None:
    head = "From: a@example.com\r\nSubject: Re: hello\r\n"
    assert "CONTENT_SUBJECT_REPLY_PREFIX" in codes(world.analyze(eml=eml("x", head=head)))
    for header in ("In-Reply-To", "References"):
        replied = head + f"{header}: <1@example.com>\r\n"
        assert "CONTENT_SUBJECT_REPLY_PREFIX" not in codes(
            world.analyze(eml=eml("x", head=replied))
        )
    forward = "From: a@example.com\r\nSubject: Fwd: hello\r\n"
    assert "CONTENT_SUBJECT_REPLY_PREFIX" not in codes(world.analyze(eml=eml("x", head=forward)))


@pytest.mark.parametrize(
    ("signature", "signed", "code", "status"),
    [
        (None, False, True, "warn"),  # no signature at all
        ("v=1; d=example.com; h=from; b=x", False, True, "warn"),
        (
            "v=1; d=example.com; h=from:list-unsubscribe:list-unsubscribe-post; b=x",
            True,
            False,
            "ok",
        ),
        ("v=1; d=example.com; b=x", None, False, "error"),  # h= unreadable: unknown, never ok
    ],
)
def test_unsigned_header_comes_from_h_lists(
    world: World, signature: str | None, signed: bool | None, code: bool, status: str
) -> None:
    head = (
        "From: a@example.com\r\nSubject: Hello there\r\n"
        "List-Unsubscribe: <https://example.com/u>\r\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    )
    if signature is not None:
        head += f"DKIM-Signature: {signature}\r\n"
    result = world.analyze(eml=eml("hello", head=head))
    assert result.unsubscribe.facts is not None
    assert result.unsubscribe.facts.one_click_signed is signed
    assert ("CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER" in codes(result)) is code
    assert result.unsubscribe.status == status
    if status == "error":
        assert result.status == "error"
        assert result.unsubscribe.reasons == ("dkim_signed_headers_unknown",)


def test_mailto_only_unsubscribe_is_not_held_to_rfc_8058(world: World) -> None:
    head = "From: a@example.com\r\nSubject: Hello there\r\n"
    head += "List-Unsubscribe: <mailto:u@example.com>\r\n"
    for signature in ("", "DKIM-Signature: v=1; d=example.com; b=x\r\n"):
        result = world.analyze(eml=eml("hello", head=head + signature))
        assert "CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER" not in codes(result)
        assert result.unsubscribe.status == "warn"  # CONTENT_NO_ONE_CLICK only


def test_truncated_dkim_signatures_only_affect_alignment(world: World) -> None:
    head = "From: a@example.com\r\nSubject: Hello there\r\n" + "".join(
        f"DKIM-Signature: v=1; d=d{i}.example; h=from; b=x\r\n" for i in range(51)
    )
    html = '<a href="https://example.com/">x</a>' + HTML
    result = world.analyze(eml=eml(html, "text/html", head=head))
    assert result.status == "error"
    assert result.message is not None
    assert result.message.status == "error"
    assert result.message.reasons == ("dkim_signatures_truncated",)
    assert {result.body.status, result.links.status} <= {"ok", "info", "warn", "fail"}
    assert result.rules.status == "not_evaluated"  # no rule is enabled; not an error
    assert result.links.facts is not None
    assert result.links.facts.alignment_evaluated is False


def test_link_alignment_uses_from_and_dkim_domains(world: World) -> None:
    html = '<a href="https://other.example/">x</a>' + HTML
    raw = multipart(("text/plain", "", "hello"), ("text/html", "", html))
    result = world.analyze(eml=raw)
    assert "CONTENT_UNALIGNED_LINK_DOMAIN" in codes(result)
    assert result.links.facts is not None
    assert result.links.facts.unaligned_count == 1
    assert result.links.facts.alignment_evaluated is True


def test_alignment_not_evaluated_without_a_sender(world: World) -> None:
    result = world.analyze(html='<a href="https://other.example/">x</a>' + HTML, text="hi")
    assert result.links.facts is not None
    assert result.links.facts.unaligned_count is None
    assert result.links.facts.alignment_evaluated is False
    assert "CONTENT_UNALIGNED_LINK_DOMAIN" not in codes(result)


@pytest.mark.parametrize("href", ["https://[bad/", "https://{{domain}}/x"])
def test_unreadable_link_is_a_warning_and_alignment_stays_incomplete(
    world: World, href: str
) -> None:
    html = f'<a href="https://example.com/">x</a><a href="{href}">y</a>' + HTML
    raw = multipart(("text/plain", "", "hello"), ("text/html", "", html))
    world.tenant_rules.create(rule("r1", pattern="absent"))
    result = world.analyze(eml=raw)
    assert result.status == "warn"
    assert result.complete is False
    assert result.links.status == "warn"
    assert result.links.reasons == ("links_malformed",)
    assert result.links.facts is not None
    assert result.links.facts.unaligned_count == 0
    assert result.links.facts.alignment_evaluated is False
    assert "CONTENT_LINK_UNEVALUATED" in codes(result)


# --- rules -----------------------------------------------------------------------------------


def test_zero_enabled_rules_differs_from_rules_that_ran(world: World) -> None:
    idle = world.analyze(text="hello")
    assert idle.rules.status == "not_evaluated"
    assert idle.rules.reasons == ("no_enabled_rules",)
    assert idle.rules.facts is not None
    assert idle.rules.facts.enabled_rules == 0
    assert idle.rules.facts.evaluated_rules == 0

    world.tenant_rules.create(rule("r1", pattern="absent"))
    ran = world.analyze(text="hello")
    assert ran.rules.status == "ok"
    assert ran.rules.reasons == ()
    assert ran.rules.facts is not None
    assert ran.rules.facts.enabled_rules == 1
    assert ran.rules.facts.evaluated_rules == 1
    assert ran.rules.facts.matched_rules == 0


def test_only_disabled_rules_is_not_evaluated(world: World) -> None:
    world.tenant_rules.create(rule("r1", enabled=False))
    result = world.analyze(text="winner")
    assert result.rules.status == "not_evaluated"
    assert result.rules.reasons == ("no_enabled_rules",)


def test_rules_without_content_are_not_evaluated(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    result = world.analyze()
    assert result.rules.status == "not_evaluated"
    assert result.rules.reasons == ("no_input",)
    assert result.rules.facts is not None
    assert result.rules.facts.not_evaluated_rules == 1
    assert result.rules.facts.results[0].status == "not_evaluated"
    assert result.rules.facts.results[0].issue == "no_input"


def test_language_rules_need_the_hint(world: World) -> None:
    world.tenant_rules.create(rule("r1", language="it"))
    skipped = world.analyze(text="winner")
    assert skipped.rules.status == "not_evaluated"
    assert skipped.rules.reasons == ("no_applicable_rules",)
    assert skipped.rules.facts is not None
    assert skipped.rules.facts.enabled_rules == 1
    assert skipped.rules.facts.skipped_by_language == 1
    used = world.analyze(text="winner", language_hint="it")
    assert used.rules.facts is not None
    assert used.rules.facts.matched_rules == 1


def full_clean_message() -> bytes:
    return multipart(("text/plain", "", "hello"), ("text/html", "", HTML))


@pytest.mark.parametrize(
    ("hint", "status", "reasons_expected", "complete", "skipped", "evaluated"),
    [
        (None, "ok", ("language_rules_skipped",), False, 1, 1),
        ("  ", "ok", ("language_rules_skipped",), False, 1, 1),
        ("it", "ok", (), True, 0, 2),
        ("en", "ok", (), True, 1, 1),  # the hint chose: other languages are out of scope
    ],
    ids=["no-hint", "blank-hint", "matching-hint", "other-hint"],
)
def test_rules_left_out_for_lack_of_a_hint_are_not_complete(
    world: World,
    hint: str | None,
    status: str,
    reasons_expected: tuple[str, ...],
    complete: bool,
    skipped: int,
    evaluated: int,
) -> None:
    world.tenant_rules.create(rule("null-language", pattern="absent"))
    world.tenant_rules.create(rule("italian", pattern="absent", language="it"))
    result = world.analyze(eml=full_clean_message(), language_hint=hint)
    assert result.status == "ok"
    assert result.rules.status == status
    assert result.rules.reasons == reasons_expected
    assert result.complete is complete
    assert result.rules.facts is not None
    assert result.rules.facts.skipped_by_language == skipped
    assert result.rules.facts.evaluated_rules == evaluated


@pytest.mark.parametrize(
    ("kind", "pattern"),
    [("keyword", "winner"), ("regex", "win+er")],
)
def test_rules_search_the_visible_html_text(world: World, kind: str, pattern: str) -> None:
    world.tenant_rules.create(rule("r1", kind=kind, pattern=pattern))
    result = world.analyze(html=f"<p>{WORDS} winner</p>", text=None)
    assert result.rules.facts is not None
    view = result.rules.facts.results[0]
    assert (view.status, view.part) == ("matched", "html_visible_text")
    assert view.evidence is not None and "winner" in view.evidence
    match = next(f for f in result.findings if f.code == "CONTENT_RULE_MATCH")
    assert match.evidence and "winner" in match.evidence[0]


@pytest.mark.parametrize(
    "html",
    [
        "<style>winner{}</style><p>x</p>",
        "<script>winner</script><p>x</p>",
        "<!-- winner --><p>x</p>",
    ],
    ids=["style", "script", "comment"],
)
def test_rules_do_not_search_invisible_markup(world: World, html: str) -> None:
    world.tenant_rules.create(rule("r1"))
    result = world.analyze(html=html, text="hello")
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 0


def test_adjacent_blocks_do_not_merge_into_a_word(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    result = world.analyze(html="<td>win</td><td>ner</td>", text="hello")
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 0


def engine_result(status: RuleStatus, issue: RuleIssue | None) -> RuleResults:
    row = RuleResult(1, None, "n", "spam", "low", 1, status, issue=issue)
    errors = int(status is RuleStatus.ERROR)
    skipped = int(status is RuleStatus.NOT_EVALUATED)
    return RuleResults((row,), 0, (), (), errors, skipped, False)


@pytest.mark.parametrize(
    ("status", "issue", "code"),
    [
        (RuleStatus.ERROR, RuleIssue.INVALID_PATTERN, "CONTENT_RULE_ERROR"),
        (RuleStatus.ERROR, RuleIssue.TIMEOUT, "CONTENT_RULE_ERROR"),
        (RuleStatus.ERROR, RuleIssue.WORKER_FAILED, "CONTENT_RULE_ERROR"),
        (RuleStatus.NOT_EVALUATED, RuleIssue.BUSY, "CONTENT_RULE_ERROR"),
        (RuleStatus.NOT_EVALUATED, RuleIssue.BUDGET_EXCEEDED, "CONTENT_RULE_ERROR"),
        (RuleStatus.NOT_EVALUATED, RuleIssue.TOO_MANY_RULES, "CONTENT_RULE_ERROR"),
        (RuleStatus.NOT_EVALUATED, RuleIssue.INPUT_CAPPED, "CONTENT_INPUT_CAPPED"),
    ],
)
def test_incomplete_rules_are_never_ok(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    status: RuleStatus,
    issue: RuleIssue,
    code: str,
) -> None:
    world.tenant_rules.create(rule("r1"))
    monkeypatch.setattr(ca, "evaluate_rules", lambda *_a, **_k: engine_result(status, issue))
    result = world.analyze(text="hello")
    assert result.status == "error"
    assert result.rules.status == "error"
    assert code in codes(result)
    assert result.rules.facts is not None
    assert result.rules.facts.results[0].status == status.value  # per-rule value is kept
    assert result.rules.facts.evaluated_rules == 0


def test_capped_part_reported_in_facts(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    world.tenant_rules.create(rule("r1"))
    capped = RuleResults((), 0, (), (ContentPart.TEXT,), 0, 0, False)
    monkeypatch.setattr(ca, "evaluate_rules", lambda *_a, **_k: capped)
    result = world.analyze(text="hello")
    assert result.status == "error"
    assert result.rules.facts is not None
    assert result.rules.facts.capped_parts == ("text",)


def test_engine_failure_is_error(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> RuleResults:
        raise RuntimeError(MARKER)

    monkeypatch.setattr(ca, "evaluate_rules", boom)
    result = world.analyze(text="hello")
    assert result.status == "error"
    assert result.rules.reasons == ("rules_engine_failed",)
    assert "CONTENT_RULE_ERROR" in codes(result)
    assert MARKER not in result.model_dump_json()


def test_repository_failure_is_error(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> list[Any]:
        raise OperationalError("select", {}, Exception("down"))

    monkeypatch.setattr(ca, "load_tenant_rules", boom)
    result = world.analyze(html=HTML, text="hello")
    assert result.status == "error"
    assert result.rules.status == "error"
    assert result.rules.reasons == ("rules_unavailable",)
    assert result.body.status == "ok"  # the other sections are still produced


@pytest.mark.parametrize(
    ("target", "fails"),
    [
        ("analyze_subject", "subject"),
        ("analyze_list_unsubscribe", "unsubscribe"),
        ("analyze_links", "links"),
        ("parse_content", "body"),
    ],
)
def test_a_parser_failure_stays_in_its_section(
    world: World, monkeypatch: pytest.MonkeyPatch, target: str, fails: str
) -> None:
    def boom(*_a: object, **_k: object) -> Any:
        raise RuntimeError(MARKER)

    monkeypatch.setattr(ca, target, boom)
    raw = multipart(("text/plain", "", "hello"), ("text/html", "", HTML))
    result = world.analyze(eml=raw)
    assert result.status == "error"
    assert getattr(result, fails).status == "error"
    assert MARKER not in result.model_dump_json()


# --- tenant rules ----------------------------------------------------------------------------


def test_global_and_own_rules_apply_but_not_another_tenants(world: World) -> None:
    world.global_rules.create(rule("global", pattern="alpha"), actor=None)
    world.tenant_rules.create(rule("own", pattern="beta"))
    repo_for(world.other, world.session).content_rules.create(rule("foreign", pattern="gamma"))
    result = world.analyze(text="alpha beta gamma")
    assert result.rules.facts is not None
    assert {r.name for r in result.rules.facts.results} == {"global", "own"}
    assert result.rules.facts.enabled_rules == 2


@pytest.mark.parametrize("page_size", [50, 7])
def test_disabled_override_past_the_first_page_suppresses_the_global_rule(
    world: World, monkeypatch: pytest.MonkeyPatch, page_size: int
) -> None:
    monkeypatch.setattr(ca, "RULE_PAGE_SIZE", page_size)
    for index in range(120):
        world.global_rules.create(
            rule(f"filler{index}", seed_key=f"filler{index}", enabled=False), actor=None
        )
    world.global_rules.create(rule("target", seed_key="target"), actor=None)
    # Created last, so its id is past page 1 of both this loader and the default list().
    override = world.tenant_rules.create(rule("override", seed_key="target", enabled=False))
    assert override.id not in {r.id for r in world.tenant_rules.list()}

    result = world.analyze(text="winner")
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 0
    assert result.rules.facts.enabled_rules == 0
    assert result.rules.reasons == ("no_enabled_rules",)


def test_without_the_override_the_global_rule_runs(world: World) -> None:
    world.global_rules.create(rule("target", seed_key="target"), actor=None)
    result = world.analyze(text="winner")
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 1


def test_enabled_override_replaces_the_global_rule(world: World) -> None:
    world.global_rules.create(rule("target", seed_key="target"), actor=None)
    world.tenant_rules.create(rule("own", seed_key="target", pattern="other"))
    result = world.analyze(text="winner other")
    assert result.rules.facts is not None
    assert [(r.name, r.status) for r in result.rules.facts.results] == [("own", "matched")]


@pytest.mark.parametrize(
    ("rows", "offsets"),
    [(0, [0]), (1, [0]), (2, [0, 2]), (3, [0, 2]), (4, [0, 2, 4])],
)
def test_loader_pages_until_a_short_page_and_never_filters(
    world: World, monkeypatch: pytest.MonkeyPatch, rows: int, offsets: list[int]
) -> None:
    monkeypatch.setattr(ca, "RULE_PAGE_SIZE", 2)
    for index in range(rows):
        world.tenant_rules.create(rule(f"r{index}", enabled=bool(index % 2)))
    calls: list[dict[str, Any]] = []
    real = ContentRuleRepository.list

    def spy(self: ContentRuleRepository, **kwargs: Any) -> Any:
        calls.append(kwargs)
        return real(self, **kwargs)

    monkeypatch.setattr(ContentRuleRepository, "list", spy)
    loaded = ca.load_tenant_rules(world.ctx, world.session)
    assert len(loaded) == rows
    assert [c["offset"] for c in calls] == offsets
    assert all("enabled_only" not in c for c in calls)


def test_seeded_rule_without_title_uses_the_catalogue(world: World) -> None:
    world.global_rules.create(rule("seed", seed_key="all_caps_run", title=None), actor=None)
    result = world.analyze(text="winner")
    match = next(f for f in result.findings if f.code == "CONTENT_RULE_MATCH")
    assert match.title_key == "CONTENT_RULE.all_caps_run.title"


def test_tenant_rule_whose_global_row_was_removed_does_not_crash(world: World) -> None:
    created = world.global_rules.create(
        rule("seed", seed_key="gone", title=None, enabled=False), actor=None
    )
    world.tenant_rules.create(rule("own", seed_key="gone", title=None))
    assert world.global_rules.delete(created.id)
    result = world.analyze(text="winner")
    assert result.status != "error"
    match = next(f for f in result.findings if f.code == "CONTENT_RULE_MATCH")
    assert match.title_key == "finding.CONTENT_RULE_MATCH.title"
    assert match.params["rule"] == "own"


# --- output, storage, logging, network -------------------------------------------------------


def full_message() -> bytes:
    html = f'<a href="http://other.example/{MARKER}">{MARKER}</a><p>{WORDS} winner {MARKER}</p>'
    return multipart(("text/html", "", html))


def test_output_is_json_and_stable(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    first = world.analyze(eml=full_message()).model_dump_json()
    second = world.analyze(eml=full_message()).model_dump_json()
    assert first == second
    parsed = json.loads(first)
    assert list(parsed) == [
        "status",
        "complete",
        "not_evaluated_sections",
        "message",
        "body",
        "links",
        "subject",
        "unsubscribe",
        "rules",
        "findings",
    ]


@pytest.mark.parametrize(
    "fields",
    [
        {"html": "<p>\ud800 winner</p>", "text": "\udfff"},
        {"subject": "\ud800 winner"},
        {"html": '<meta charset="\x01\ud800"><p>x</p>'},
        {"text": "winner\x00"},
    ],
    ids=["html", "subject", "charset", "nul"],
)
def test_hostile_text_stays_serialisable(world: World, fields: dict[str, str]) -> None:
    world.tenant_rules.create(rule("r1"))
    json.loads(world.analyze(**fields).model_dump_json())


def test_nothing_is_stored(world: World) -> None:
    world.tenant_rules.create(rule("r1"))
    world.session.commit()
    count = select(func.count()).select_from(ContentRule)
    before = world.session.scalar(count)
    world.analyze(eml=full_message())
    assert not world.session.new and not world.session.dirty and not world.session.deleted
    assert world.session.scalar(count) == before


def test_no_request_content_in_logs(
    world: World, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    world.tenant_rules.create(rule("r1"))
    with caplog.at_level(logging.DEBUG):
        world.analyze(eml=full_message(), subject=f"Subject {MARKER}", text=f"text {MARKER}")
        world.analyze(eml=b"Subject: " + MARKER.encode() + b"\x00\r\n\r\nx")

        def boom(*_a: object, **_k: object) -> RuleResults:
            raise RuntimeError(MARKER)

        monkeypatch.setattr(ca, "evaluate_rules", boom)
        world.analyze(text=f"text {MARKER}")
    logged = "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert MARKER not in logged


def test_no_dns_or_sockets_are_used(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """Links are never resolved or fetched: any attempt fails the test."""

    def refuse(*_a: object, **_k: object) -> Any:
        raise AssertionError("network access")

    world.tenant_rules.create(rule("r1", kind="regex", pattern="win+er"))
    rows = ca.load_tenant_rules(world.ctx, world.session)  # the only step that may use the DB
    monkeypatch.setattr(ca, "load_tenant_rules", lambda *_a, **_k: rows)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    result = world.analyze(eml=full_message())
    assert result.status != "error"
    assert result.rules.facts is not None
    assert result.rules.facts.matched_rules == 1
