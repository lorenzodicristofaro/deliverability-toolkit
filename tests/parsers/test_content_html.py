"""Table-driven tests for the offline HTML/text structure parser (M5-08)."""

from __future__ import annotations

import pytest

from app.parsers.content_html import (
    GMAIL_CLIP_THRESHOLD_BYTES,
    ContentLimits,
    parse_content,
)


def reasons(html: str) -> set[str]:
    return {h.reason for h in parse_content(html, None).hidden_candidates}


@pytest.mark.parametrize(
    ("style", "expected"),
    [
        ("display:none", "display_none"),
        ("DISPLAY : NONE !important", "display_none"),
        ("visibility:hidden", "visibility_hidden"),
        ("font-size:0", "font_size_zero"),
        ("font-size:0px", "font_size_zero"),
        ("color:#fff;background-color:#fff", "color_matches_background"),
        ("position:absolute;left:-9999px", "offscreen"),
        ("text-indent:-5000px", "offscreen"),
    ],
)
def test_hidden_candidates(style: str, expected: str) -> None:
    assert expected in reasons(f'<p style="{style}">x</p>')


@pytest.mark.parametrize(
    "style",
    [
        "font-size:12px",
        "color:#fff;background-color:#000",
        "left:-9999px",
        "display:block",
        "",
        "bogus",
    ],
)
def test_not_hidden(style: str) -> None:
    assert reasons(f'<p style="{style}">x</p>') == set()


def test_basic_facts() -> None:
    html = (
        '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>p{color:red}</style>'
        '<script>var a=1;</script></head><body><p style="color:red">Hello &amp; bye</p>'
        '<img src="a.png"><img src="b.png" alt=""><img src="c.png" alt="c">'
        '<a href="http://x.example/">  Click\n here </a><a>none</a></body></html>'
    )
    r = parse_content(html, "plain")
    assert not r.capped
    assert r.malformed == ()
    assert r.has_doctype
    assert r.charset == "utf-8"
    assert r.visible_text_length == len("Hello&bye") + len("Clickhere") + len("none")
    assert (r.image_count, r.images_missing_alt, r.images_empty_alt) == (3, 1, 1)
    assert r.anchors == (("Click here", "http://x.example/"), ("none", None))
    assert r.style_tag_bytes == len("p{color:red}")
    assert r.inline_style_bytes == len("color:red")
    assert r.has_plain_text_part
    assert r.text_length == 5
    assert r.text_bytes == 5
    assert r.html_bytes == len(html.encode())


def test_http_equiv_charset() -> None:
    html = '<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">x'
    r = parse_content(html, None)
    assert r.charset == "iso-8859-1"
    assert not r.has_doctype


@pytest.mark.parametrize(
    ("html", "text", "has_html", "has_text"),
    [
        (None, None, False, False),
        ("", "", False, False),
        ("   ", "  \n", False, False),
        ("<p>a</p>", None, True, False),
        (None, "hello", False, True),
    ],
)
def test_empty_html_only_text_only(
    html: str | None, text: str | None, has_html: bool, has_text: bool
) -> None:
    r = parse_content(html, text)
    assert (r.has_html_part, r.has_plain_text_part) == (has_html, has_text)
    assert not r.capped


@pytest.mark.parametrize(
    ("html", "flag"),
    [
        ("<div><span>x</div>", "unbalanced_end_tags"),
        ("<div><b>x", "unclosed_tags"),
        ("<p>x</b>", "unbalanced_end_tags"),
        ("<p>x <!-- never closed", "unterminated_comment"),
        ("<p>x</p><a href='y", "truncated_tag"),
        ("<p>x</p><div clas", "truncated_tag"),
    ],
)
def test_malformed_flags(html: str, flag: str) -> None:
    assert flag in parse_content(html, None).malformed


@pytest.mark.parametrize("html", ["<p>a<p>b", "<ul><li>a<li>b</ul>", "<br><img src=x><hr/>"])
def test_well_formed_enough(html: str) -> None:
    assert parse_content(html, None).malformed == ()


@pytest.mark.parametrize(
    "html",
    [
        "<p>&bogus; &#xZZ; &#99999999999; &amp</p>",
        "<p>a\x00b</p><a href='\x00'>q</a>",
        "<p>café \udcff mojibake Ã©</p>",
        "<<<>>><!><!-- -- --><?php ?><![CDATA[x]]>",
        '<a href="' + "A" * 500_000 + '">t</a>',
        '<p title="unterminated>text',
    ],
)
def test_hostile_input_never_raises(html: str) -> None:
    r = parse_content(html, None)
    assert isinstance(r.visible_text_length, int)


def test_nul_flagged() -> None:
    assert parse_content("<p>a\x00b</p>", None).has_nul


def test_huge_attribute_value_measured() -> None:
    r = parse_content('<p style="' + "a:b;" * 10_000 + '">x</p>', None)
    assert r.inline_style_bytes == 40_000
    assert not r.capped


@pytest.mark.parametrize(
    ("html", "limits", "reason"),
    [
        ("<p>" * 5 + "x", ContentLimits(max_depth=3), "nesting_depth"),
        ("<div>" * 10_000, ContentLimits(), "nesting_depth"),
        ("<br>" * 11, ContentLimits(max_elements=10), "element_count"),
        ("<p a=1 b=2 c=3>x</p>", ContentLimits(max_attributes=2), "attribute_count"),
        ("<p>" + "x" * 100 + "</p>", ContentLimits(max_input_bytes=50), "input_size"),
    ],
)
def test_limits_cap(html: str, limits: ContentLimits, reason: str) -> None:
    r = parse_content(html, None, limits=limits)
    assert r.capped
    assert r.cap_reason == reason


def test_text_over_limit_caps() -> None:
    r = parse_content(None, "x" * 100, limits=ContentLimits(max_input_bytes=10))
    assert r.capped
    assert r.cap_reason == "input_size"


def test_gmail_threshold_is_heuristic_constant() -> None:
    assert GMAIL_CLIP_THRESHOLD_BYTES == 102_400
    below = parse_content("<p>" + "x" * 1000 + "</p>", None)
    assert not below.exceeds_gmail_clip_threshold
    big = parse_content("<p>" + "x" * 102_400 + "</p>", None)
    assert big.exceeds_gmail_clip_threshold
    assert big.gmail_clip_threshold_bytes == 102_400


def test_script_and_style_not_visible() -> None:
    r = parse_content("<script>alert(1)</script><style>p{}</style><title>T</title>", None)
    assert r.visible_text_length == 0
