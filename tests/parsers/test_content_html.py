"""Table-driven tests for the offline HTML/text structure parser (M5-08)."""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from app.parsers.content_html import (
    GMAIL_CLIP_THRESHOLD_BYTES,
    ContentLimits,
    _hidden_reasons,
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


@pytest.mark.parametrize(
    ("html", "limits", "anchors"),
    [
        ("<p>see <a href='http://x'>link", None, [("link", "http://x")]),
        ("<a href=a>one<a href=b>two</a>", None, [("one", "a"), ("two", "b")]),
        ("<a href=a>one</a><a>two", None, [("one", "a"), ("two", None)]),
        ("<a href=a>one<b><b><b><b>", ContentLimits(max_depth=3), [("one", "a")]),
        ("<a href=a>one<br><br><br>", ContentLimits(max_elements=3), [("one", "a")]),
    ],
)
def test_no_anchor_lost(html: str, limits: ContentLimits | None, anchors: list) -> None:  # type: ignore[type-arg]
    r = parse_content(html, None, limits=limits)
    assert list(r.anchors) == anchors


def test_unexpected_parser_exception_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.parsers import content_html

    def boom(self: object, data: str) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(content_html._Collector, "handle_data", boom)
    r = parse_content("<p>x</p>", None)
    assert r.capped
    assert r.cap_reason == "parser_error"
    assert "parser_error" in r.malformed


def test_oversize_string_capped_without_byte_counts() -> None:
    r = parse_content("x" * 100, None, limits=ContentLimits(max_input_bytes=10))
    assert r.capped
    assert r.cap_reason == "input_size"


def test_capped_input_never_reports_zero_bytes() -> None:
    r = parse_content("x" * 100, "y" * 5, limits=ContentLimits(max_input_bytes=10))
    assert r.capped
    assert r.html_bytes is None
    assert r.text_bytes == 5
    assert r.html_bytes_at_least == 100
    assert r.text_bytes_at_least is None
    ok = parse_content("<p>x</p>", None)
    assert ok.html_bytes == 8
    assert ok.html_bytes_at_least is None


def test_gmail_flag_with_capped_inputs() -> None:
    lim = ContentLimits(max_input_bytes=3_000_000)
    huge = parse_content("x" * 3_000_001, None, limits=lim)
    assert huge.capped
    assert huge.exceeds_gmail_clip_threshold
    mid = parse_content("<p>" + "x" * 200_000 + "</p>", "y" * 3_000_001, limits=lim)
    assert mid.capped
    assert mid.html_bytes == 200_007
    assert mid.text_bytes is None
    assert mid.exceeds_gmail_clip_threshold
    small = parse_content("<p>x</p>", "y" * 3_000_001, limits=lim)
    assert small.capped
    assert small.html_bytes == 8
    assert not small.exceeds_gmail_clip_threshold


# --- R1-01: inline style values are analysed in linear time -----------------------------------
#
# No wall-clock thresholds: each adversarial row compares the time at n and 4n (best of several
# calibrated batches). Linear code grows about 4x, the quadratic regexes this replaced grew 16x.
_GROWTH_LIMIT = 10.0


def _best_batch(fn: Callable[[], object], repeats: int) -> float:
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(repeats):
            fn()
        best = min(best, time.perf_counter() - start)
    return best


def growth(make: Callable[[int], Callable[[], object]], n: int) -> float:
    """Time ratio of make(4n) over make(n); batches are calibrated on the small size."""
    small, large = make(n), make(4 * n)
    repeats = 1
    while repeats < 100_000 and _best_batch(small, repeats) < 0.02:
        repeats *= 4
    return _best_batch(large, repeats) / _best_batch(small, repeats)


@pytest.mark.parametrize(
    ("style", "expected"),
    [
        ("font-size:0", True),
        ("font-size:0.0px", True),
        ("font-size:+0em", True),
        ("font-size:-0", True),
        ("font-size:.0", True),
        ("font-size:0%", True),
        ("font-size:00.00rem", True),
        ("font-size:0pt !important", True),
        ("font-size:0px\t!IMPORTANT ", True),
        ("font-size:0.", False),
        ("font-size:.", False),
        ("font-size:+", False),
        ("font-size:px", False),
        ("font-size:", False),
        ("font-size:0.0.0", False),
        ("font-size:0x", False),
        ("font-size:0 px", False),
        ("font-size:01", False),
        ("font-size:0pxpx", False),
        ("font-size:+-0", False),
        ("font-size:0!important!important", False),
        ("font-size:1px", False),
    ],
)
def test_font_size_zero_table(style: str, expected: bool) -> None:
    assert ("font_size_zero" in _hidden_reasons(style)) is expected


@pytest.mark.parametrize(
    ("style", "expected"),
    [
        ("display:none !important", ["display_none"]),
        ("display:none!important", ["display_none"]),
        ("display:none   !important   ", ["display_none"]),
        ("display:none !important;font-size:0 !important", ["display_none", "font_size_zero"]),
        ("display:none ! important", []),  # not the !important token: unchanged behaviour
        ("display:!important", []),
        ("position:fixed;top:-  600px", ["offscreen"]),
        ("position:absolute;left:-499.9px", []),
        ("position:absolute;left:-500", ["offscreen"]),
        ("text-indent:-1e4px", []),
    ],
)
def test_important_and_offscreen_table(style: str, expected: list[str]) -> None:
    assert _hidden_reasons(style) == expected


_ADVERSARIAL_STYLES: list[tuple[str, Callable[[int], str]]] = [
    ("zero_run", lambda n: "font-size:" + "0" * n + "x"),
    ("zero_run_dot", lambda n: "font-size:" + "0" * n + ".x"),
    ("space_run_no_important", lambda n: "color:a" + " " * n + "b"),
    ("space_run_before_important", lambda n: "display:none" + " " * n + "!important"),
    ("space_run_after_important", lambda n: "display:none !important" + " " * n + "x"),
    ("space_run_both_sides", lambda n: "color:a" + " " * n + "!important" + " " * n + "b"),
    ("digit_run_left", lambda n: "position:absolute;left:-" + "9" * n + "x"),
    ("digit_run_top_dot", lambda n: "position:fixed;top:-" + "1" * n + "." + "1" * n + "!"),
    ("neg_space_run", lambda n: "text-indent:-" + " " * n + "x"),
]


@pytest.mark.parametrize(
    "make", [m for _, m in _ADVERSARIAL_STYLES], ids=[i for i, _ in _ADVERSARIAL_STYLES]
)
def test_hidden_reasons_linear_on_adversarial_values(make: Callable[[int], str]) -> None:
    def call(n: int) -> Callable[[], object]:
        style = make(n)
        return lambda: _hidden_reasons(style)

    assert growth(call, 2_500) < _GROWTH_LIMIT


@pytest.mark.parametrize(
    "make", [m for _, m in _ADVERSARIAL_STYLES], ids=[i for i, _ in _ADVERSARIAL_STYLES]
)
def test_parse_content_linear_on_adversarial_styles(make: Callable[[int], str]) -> None:
    cap = ContentLimits().max_style_chars

    def call(n: int) -> Callable[[], object]:
        style = make(n)
        # Every size, 4n included, stays under the per-attribute cap so the hidden-text test runs.
        assert len(style) <= cap
        html = f'<p style="{style}">x</p>'
        return lambda: parse_content(html, None)

    # n = 1,000 and 4,000: rows with two runs reach about 8,000 chars at 4n, still under the cap.
    assert growth(call, 1_000) < _GROWTH_LIMIT


@pytest.mark.parametrize(
    ("label", "style"),
    [
        ("zero_run", "font-size:" + "0" * 1_999_000 + "x"),
        ("space_run", "color:a" + " " * 1_999_000 + "b"),
        ("hidden_but_long", "display:none;" + " " * 1_999_000),
    ],
)
def test_two_megabyte_style_is_not_evaluated(label: str, style: str) -> None:
    s = parse_content(f'<p style="{style}">x</p><p style="display:none">y</p>', None)
    assert not s.capped  # the rest of the body is still parsed
    assert s.hidden_unevaluated == 1
    # Only the short attribute was tested; the long one is never reported as "no hidden text".
    assert [h.reason for h in s.hidden_candidates] == ["display_none"]


@pytest.mark.parametrize(("over", "unevaluated"), [(-1, 0), (0, 0), (1, 1), (2, 1)])
def test_style_cap_boundary(over: int, unevaluated: int) -> None:
    length = ContentLimits().max_style_chars + over
    style = "display:none;" + "x" * (length - len("display:none;"))
    s = parse_content(f'<p style="{style}">x</p>', None)
    assert s.hidden_unevaluated == unevaluated
    assert bool(s.hidden_candidates) is (unevaluated == 0)


def test_style_cap_uses_limits() -> None:
    s = parse_content(
        '<p style="display:none">x</p>', None, limits=ContentLimits(max_style_chars=5)
    )
    assert s.hidden_unevaluated == 1
    assert s.hidden_candidates == ()
    assert s.inline_style_bytes == len("display:none")  # still measured


# _NEG and the charset search measured linear (R1-01 review): kept as is, guarded here.
def test_charset_search_linear_on_whitespace_runs() -> None:
    def call(n: int) -> Callable[[], object]:
        content = "text/html; charset" + " " * n + "=" + " " * n + ";"
        html = f'<meta http-equiv="Content-Type" content="{content}"><p>x</p>'
        return lambda: parse_content(html, None)

    assert growth(call, 5_000) < _GROWTH_LIMIT


@pytest.mark.parametrize(
    ("content", "charset"),
    [
        ("text/html; charset = UTF-8", "utf-8"),
        ("text/html;charset=iso-8859-1;x", "iso-8859-1"),
        ("text/html; charset=", None),
        ("text/html; charset" + " " * 10_000 + "=", None),
    ],
)
def test_http_equiv_charset_table(content: str, charset: str | None) -> None:
    html = f'<meta http-equiv="Content-Type" content="{content}">'
    assert parse_content(html, None).charset == charset
