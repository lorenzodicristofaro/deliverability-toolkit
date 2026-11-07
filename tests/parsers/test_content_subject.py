"""Table-driven tests for app.parsers.content_subject (M5-11). No network."""

from __future__ import annotations

import pytest

from app.parsers.content_subject import SubjectLimits, analyze_subject


def test_none_is_not_evaluated() -> None:
    f = analyze_subject(None)
    assert f.present is False
    assert f.empty is None and f.all_caps is None and f.has_punct_run is None
    assert f.length_codepoints is None and f.scripts is None


@pytest.mark.parametrize("text", ["", "   ", "\t  "])
def test_empty_or_whitespace(text: str) -> None:
    f = analyze_subject(text)
    assert f.present is True and f.empty is True


@pytest.mark.parametrize(
    ("text", "empty"),
    [
        ("​‍", True),  # zero-width only: nothing visible
        ("‮ ⁦", True),  # bidi format chars only
        ("﻿", True),
        ("​x", False),
        ("\x00", False),  # control char is Cc, not Cf: not empty
    ],
)
def test_format_chars_only_is_empty(text: str, empty: bool) -> None:
    assert analyze_subject(text).empty is empty


@pytest.mark.parametrize(
    ("text", "cp", "by", "gr"),
    [
        ("abc", 3, 3, 3),
        ("café", 4, 5, 4),
        ("café", 5, 6, 4),  # combining acute: not its own grapheme
        ("\U0001f600", 1, 4, 1),
        ("\U0001f468‍\U0001f469‍\U0001f467", 5, 18, 1),  # ZWJ family
        ("\U0001f1ee\U0001f1f9", 2, 8, 1),  # flag
        ("\U0001f44d\U0001f3fd", 2, 8, 1),  # skin tone
        ("\ud800", 1, 3, 1),  # lone surrogate must not raise
    ],
)
def test_lengths(text: str, cp: int, by: int, gr: int) -> None:
    f = analyze_subject(text)
    assert (f.length_codepoints, f.length_bytes, f.length_graphemes) == (cp, by, gr)


def test_long_heuristic_uses_limits() -> None:
    assert analyze_subject("a" * 101).is_long is True
    assert analyze_subject("a" * 100).is_long is False
    assert analyze_subject("a" * 11, limits=SubjectLimits(long_graphemes=10)).is_long is True


@pytest.mark.parametrize(
    ("text", "emoji"),
    [
        ("hello", 0),
        ("sale \U0001f525\U0001f525", 2),
        ("\U0001f468‍\U0001f469‍\U0001f467 family", 1),
        ("\U0001f1ee\U0001f1f9 \U0001f1fa\U0001f1f8", 2),
        ("1️⃣ first", 1),
        ("© ™ plain 1", 0),
        ("❤️", 1),
    ],
)
def test_emoji(text: str, emoji: int) -> None:
    assert analyze_subject(text).emoji_count == emoji


@pytest.mark.parametrize(
    ("text", "all_caps", "cased", "caseless"),
    [
        ("BUY NOW LIMITED OFFER", True, 18, 0),
        ("Buy now limited offer", False, 18, 0),
        ("HELLO", None, 5, 0),  # too few cased letters: not evaluated
        ("12345 !!!", None, 0, 0),
        ("你好世界你好世界你好", None, 0, 10),
        ("مرحبا שלום", None, 0, 9),
        ("ΣΑΒΓΔΕΖΗΘ", True, 9, 0),
        ("ǅǅǅǅǅǅǅǅ", True, 8, 0),  # Lt counts as upper
        ("ǅabcdefg", False, 8, 0),
    ],
)
def test_caps(text: str, all_caps: bool | None, cased: int, caseless: int) -> None:
    f = analyze_subject(text)
    assert f.all_caps is all_caps
    assert (f.cased_letters, f.caseless_letters) == (cased, caseless)
    if cased == 0:
        assert f.caps_ratio is None


@pytest.mark.parametrize(
    ("text", "run", "flag"),
    [
        ("Hi", 0, False),
        ("Hi!", 1, False),
        ("Hi!!", 2, True),
        ("What??", 2, True),
        ("What?!?!", 4, True),
        ("a!b!c!", 1, False),
        ("！！", 2, True),
    ],
)
def test_punct_runs(text: str, run: int, flag: bool) -> None:
    f = analyze_subject(text)
    assert (f.max_punct_run, f.has_punct_run) == (run, flag)


@pytest.mark.parametrize(
    ("text", "irt", "prefix", "flag"),
    [
        ("Re: hello", False, "re", True),
        ("Re: hello", True, "re", False),
        ("RE: hello", None, "re", None),
        ("Fwd: x", False, "fwd", True),
        ("FW: x", False, "fwd", True),
        ("  re[2]: x", False, "re", True),
        ("Reply soon", False, None, False),
        ("Re hello", False, None, False),
        ("hello Re: x", False, None, False),
    ],
)
def test_reply_prefix(text: str, irt: bool | None, prefix: str | None, flag: bool | None) -> None:
    f = analyze_subject(text, has_in_reply_to=irt)
    assert f.reply_prefix == prefix
    assert f.reply_prefix_without_in_reply_to is flag


@pytest.mark.parametrize(
    ("text", "controls", "nul", "bidi", "override"),
    [
        ("plain", 0, False, 0, False),
        ("a\x00b", 1, True, 0, False),
        ("a\x07\x1bb\x7f", 3, False, 0, False),
        ("tab\there", 0, False, 0, False),
        ("evil‮gnp.exe", 0, False, 1, True),
        ("⁧x⁩", 0, False, 2, True),
        ("a‏b", 0, False, 1, False),  # RLM: bidi control, not override
    ],
)
def test_control_and_bidi(text: str, controls: int, nul: bool, bidi: int, override: bool) -> None:
    f = analyze_subject(text)
    assert (f.control_chars, f.has_nul, f.bidi_controls, f.has_bidi_override) == (
        controls,
        nul,
        bidi,
        override,
    )


@pytest.mark.parametrize(
    ("text", "scripts", "mixed", "word"),
    [
        ("hello", ("LATIN",), False, False),
        ("hello мир", ("CYRILLIC", "LATIN"), True, False),
        ("pаypal", ("CYRILLIC", "LATIN"), True, True),  # Cyrillic a inside Latin word
        ("こんにちは世界カタ", ("CJK",), False, False),
        ("مرحبا hello", ("ARABIC", "LATIN"), True, False),
        ("שלום", ("HEBREW",), False, False),
        ("1234 !!!", (), False, False),
        ("コーヒー", ("CJK",), False, False),  # U+30FC is Lm: no script of its own
        ("人々", ("CJK",), False, False),  # U+3005 is Lm
        ("〆切 ゝ ヽ", ("CJK",), False, False),
        ("ｺｰﾋｰ ＡＢ", ("CJK", "LATIN"), True, False),  # half/full
        ("5µm", ("LATIN",), False, False),  # U+00B5 MICRO SIGN is not Greek
        ("1ª 2º", (), False, False),
        ("Kelvin 5K", ("LATIN",), False, False),  # Letterlike Symbols skipped
        ("Аpple", ("CYRILLIC", "LATIN"), True, True),  # Cyrillic A lookalike
        ("gοogle", ("GREEK", "LATIN"), True, True),  # Greek omicron lookalike
        ("\U0001f600", (), False, False),
    ],
)
def test_scripts(text: str, scripts: tuple[str, ...], mixed: bool, word: bool) -> None:
    f = analyze_subject(text)
    assert (f.scripts, f.mixed_scripts, f.mixed_script_word) == (scripts, mixed, word)


def test_huge_input_is_capped_but_sized() -> None:
    f = analyze_subject("A" * 1_000_000)
    assert f.capped is True
    assert f.length_codepoints == 1_000_000
    assert f.length_graphemes == 10_000
    assert f.empty is False
    assert analyze_subject("A" * 10_000).capped is False


def test_cap_boundary_with_custom_limit() -> None:
    f = analyze_subject("ab" * 10, limits=SubjectLimits(max_chars=5))
    assert f.capped is True and f.length_graphemes == 5


@pytest.mark.parametrize(
    ("raw", "decoded"),
    [
        ("=?UTF-8?B?Y2Fmw6k=?=", "café"),
        ("=?UTF-8?Q?caf=C3=A9?= au lait", "café au lait"),
        ("=?UTF-8?Q?a?=\r\n =?UTF-8?Q?b?=", "ab"),  # folding + adjacent words
        ("Re:\r\n  hello", "Re:  hello"),
    ],
)
def test_encoded_input_uses_m4_decoder(raw: str, decoded: str) -> None:
    f = analyze_subject(raw, encoded=True)
    assert f.length_codepoints == len(decoded)


@pytest.mark.parametrize(
    "raw", ["=?UTF-8?B?!!!?=", "=?bogus-charset?Q?x?=", "=?UTF-8?X?x?=", "=?", "=?UTF-8?Q?=FF?="]
)
def test_malformed_encoded_words_do_not_raise(raw: str) -> None:
    f = analyze_subject(raw, encoded=True)
    assert f.present is True and f.length_codepoints is not None


@pytest.mark.parametrize(
    ("raw", "encoded", "controls", "length"),
    [
        ("Re: x\r\nBcc: y", True, 2, 13),  # bare CRLF is not folding: kept and counted
        ("Re: x\nBcc: y", True, 1, 12),
        ("a\rb", True, 1, 3),
        ("a\r\n b", True, 0, 3),  # folding removed, the whitespace stays
        ("a\n\tb", True, 0, 3),
        ("a\r\n b", False, 2, 5),  # decoded input: no unfolding
    ],
)
def test_unfold_only_folding(raw: str, encoded: bool, controls: int, length: int) -> None:
    f = analyze_subject(raw, encoded=encoded)
    assert (f.control_chars, f.length_codepoints) == (controls, length)


@pytest.mark.parametrize(
    ("raw", "encoded", "warnings"),
    [
        ("plain", False, None),
        ("=?UTF-8?B?!!!?=", False, None),
        ("plain", True, ()),
        ("=?UTF-8?Q?caf=C3=A9?=", True, ()),
        ("=?bogus-charset?Q?x?=", True, ("encoded_word_unknown_charset",)),
        ("=?UTF-8?B?!!!?=", True, ("encoded_word_invalid",)),
    ],
)
def test_decode_warnings(raw: str, encoded: bool, warnings: tuple[str, ...] | None) -> None:
    assert analyze_subject(raw, encoded=encoded).decode_warnings == warnings


def test_encoded_nul_is_flagged() -> None:
    assert analyze_subject("=?UTF-8?Q?a=00b?=", encoded=True).has_nul is True


def test_decoded_text_not_decoded_again() -> None:
    assert analyze_subject("=?UTF-8?Q?x?=").length_codepoints == 13
