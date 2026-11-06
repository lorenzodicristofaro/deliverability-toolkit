"""Table-driven tests for the raw message limits and header block parser. No network."""

from __future__ import annotations

import dataclasses
import time

import pytest

from app.parsers import message as m
from app.parsers.message import (
    MAX_HEADER_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_LINE,
    MAX_RAW_BYTES,
    RFC5322_LINE_LIMIT,
    HeaderBlock,
    InvalidMessage,
    MessageParseError,
    MessageTooLarge,
    TooManyHeaders,
    parse_header_block,
)


def codes(block: HeaderBlock) -> list[str]:
    return [w.code for w in block.warnings]


def names(block: HeaderBlock) -> list[str]:
    return [f.name for f in block.fields]


# --- caps -------------------------------------------------------------------------------


def _raw_of_size(size: int) -> bytes:
    head = b"Subject: x\r\n\r\n"
    return head + b"a" * (size - len(head))


def _header_block_of_size(size: int) -> bytes:
    """Header block of exactly ``size`` bytes (all lines <= MAX_HEADER_LINE)."""
    lines: list[bytes] = []
    remaining = size
    while remaining:
        chunk = min(remaining, 8000)
        if remaining - chunk and remaining - chunk < 10:
            chunk -= 10
        lines.append(b"X-P: " + b"a" * (chunk - 7) + b"\r\n")
        remaining -= chunk
    block = b"".join(lines)
    assert len(block) == size
    return block


def _logical_line(length: int, folded: bool) -> bytes:
    prefix = b"X-Long:"
    if not folded:
        return prefix + b"a" * (length - len(prefix)) + b"\r\n\r\n"
    # Continuation lines " aaaa..." of 100 bytes each; line endings are not counted.
    body = b""
    remaining = length - len(prefix)
    while remaining:
        n = min(remaining, 100)
        body += b"\r\n " + b"a" * (n - 1)
        remaining -= n
    return prefix + body + b"\r\n\r\n"


@pytest.mark.parametrize(
    ("raw", "exc", "code"),
    [
        (_raw_of_size(MAX_RAW_BYTES), None, None),
        (_raw_of_size(MAX_RAW_BYTES + 1), MessageTooLarge, "message_too_large"),
        (_header_block_of_size(MAX_HEADER_BYTES) + b"\r\nbody", None, None),
        (_header_block_of_size(MAX_HEADER_BYTES), None, None),
        (
            _header_block_of_size(MAX_HEADER_BYTES + 1) + b"\r\nbody",
            MessageTooLarge,
            "header_block_too_large",
        ),
        (_header_block_of_size(MAX_HEADER_BYTES + 1), MessageTooLarge, "header_block_too_large"),
        (b"X: y\n" * MAX_HEADER_COUNT + b"\n", None, None),
        (b"X: y\n" * (MAX_HEADER_COUNT + 1) + b"\n", TooManyHeaders, "too_many_headers"),
        (b"no colon\n" * (MAX_HEADER_COUNT + 1), TooManyHeaders, "too_many_headers"),
        (_logical_line(MAX_HEADER_LINE, folded=False), None, None),
        (_logical_line(MAX_HEADER_LINE + 1, folded=False), MessageTooLarge, "header_line_too_long"),
        (_logical_line(MAX_HEADER_LINE, folded=True), None, None),
        (_logical_line(MAX_HEADER_LINE + 1, folded=True), MessageTooLarge, "header_line_too_long"),
        (b"a" * MAX_HEADER_LINE, None, None),
        (b"a" * (MAX_HEADER_LINE + 1), MessageTooLarge, "header_line_too_long"),
    ],
    ids=[
        "raw-at-cap",
        "raw-over-cap",
        "header-block-at-cap",
        "header-block-at-cap-headers-only",
        "header-block-over-cap",
        "header-block-over-cap-headers-only",
        "count-at-cap",
        "count-over-cap",
        "count-over-cap-malformed-lines",
        "line-at-cap",
        "line-over-cap",
        "folded-line-at-cap",
        "folded-line-over-cap",
        "no-colon-line-at-cap",
        "no-colon-line-over-cap",
    ],
)
def test_caps(raw: bytes, exc: type[MessageParseError] | None, code: str | None) -> None:
    if exc is None:
        parse_header_block(raw)
        return
    with pytest.raises(exc) as info:
        parse_header_block(raw)
    assert info.value.code == code
    # Stable code, no echo of the input.
    assert str(info.value) == code


def test_cap_constants() -> None:
    assert MAX_RAW_BYTES == 2 * 1024 * 1024
    assert MAX_HEADER_BYTES == 128 * 1024
    assert MAX_HEADER_COUNT == 500
    assert MAX_HEADER_LINE == 8 * 1024
    assert RFC5322_LINE_LIMIT == 998


@pytest.mark.parametrize(
    ("length", "warned"),
    [(RFC5322_LINE_LIMIT, False), (RFC5322_LINE_LIMIT + 1, True)],
)
def test_rfc5322_line_limit_is_warning(length: int, warned: bool) -> None:
    raw = b"X:" + b"a" * (length - 2) + b"\r\n\r\n"
    block = parse_header_block(raw)
    assert ("line_over_rfc_limit" in codes(block)) is warned
    assert len(block.fields) == 1


def test_fold_bomb_is_capped_quickly() -> None:
    raw = b"Subject: x" + b"\r\n a" * 10_000 + b"\r\n\r\n"
    start = time.monotonic()
    with pytest.raises(MessageTooLarge) as info:
        parse_header_block(raw)
    assert info.value.code == "header_line_too_long"
    assert time.monotonic() - start < 1.0


def test_fold_bomb_over_block_cap() -> None:
    raw = b"Subject: x" + b"\r\n aaaaaaaaaa" * 12_000 + b"\r\n\r\n"
    with pytest.raises(MessageTooLarge) as info:
        parse_header_block(raw)
    assert info.value.code == "header_block_too_large"


def test_huge_line_without_newline_raises_block_cap() -> None:
    with pytest.raises(MessageTooLarge) as info:
        parse_header_block(b"S" * (MAX_RAW_BYTES - 1))
    assert info.value.code == "header_block_too_large"


def test_warnings_are_capped() -> None:
    raw = b"no colon\n" * MAX_HEADER_COUNT + b"\n"
    block = parse_header_block(raw)
    assert len(block.warnings) == m.MAX_WARNINGS + 1
    assert block.warnings[-1].code == "too_many_warnings"


# --- NUL and input type -------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        b"Subject: a\x00b\r\n\r\nbody",
        b"\x00Subject: x\r\n\r\n",
        b"From a@b Mon\x00\nSubject: x\n\n",
        b"Subject: x\r\n \x00folded\r\n\r\n",
        b"Subj\x00ect: x",
        b"no colon \x00\n\n",
    ],
    ids=["value", "first-byte", "mbox-line", "continuation", "name-headers-only", "no-colon"],
)
def test_nul_in_header_block(raw: bytes) -> None:
    with pytest.raises(InvalidMessage) as info:
        parse_header_block(raw)
    assert info.value.code == "nul_byte"
    assert str(info.value) == "nul_byte"


def test_nul_in_body_is_not_a_header_concern() -> None:
    block = parse_header_block(b"Subject: x\r\n\r\nbo\x00dy")
    assert names(block) == ["Subject"]


@pytest.mark.parametrize("raw", ["Subject: x", None, 42])
def test_non_bytes_input(raw: object) -> None:
    with pytest.raises(TypeError):
        parse_header_block(raw)  # type: ignore[arg-type]


def test_bytearray_accepted() -> None:
    assert names(parse_header_block(bytearray(b"A: b\n\n"))) == ["A"]


# --- structure ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "fields", "body_offset", "warnings"),
    [
        (
            b"Subject: hi\r\nTo: a@b\r\n\r\nbody",
            [("Subject", "hi"), ("To", "a@b")],
            24,
            [],
        ),
        (b"Subject: hi\nTo: a@b\n\nbody", [("Subject", "hi"), ("To", "a@b")], 21, []),
        (
            b"Subject: hi\r\nTo: a@b\n\r\nbody",
            [("Subject", "hi"), ("To", "a@b")],
            23,
            ["mixed_line_endings"],
        ),
        (b"Subject: hi\r\nTo: a@b", [("Subject", "hi"), ("To", "a@b")], 20, []),
        (b"Subject: hi\r\nTo: a@b\r\n", [("Subject", "hi"), ("To", "a@b")], 22, []),
        (
            b"From someone@example.com Mon Jan  1 00:00:00 2024\nSubject: hi\n\nb",
            [("Subject", "hi")],
            63,
            ["mbox_from_line"],
        ),
        (b"From: a@b\n\n", [("From", "a@b")], 11, []),
        (
            b"From : a@b\n\n",
            [("From", "a@b")],
            12,
            ["space_before_colon"],
        ),
        (
            b"Subject: a\r\n b\r\n\tc\r\n\r\n",
            [("Subject", "a b\tc")],
            22,
            [],
        ),
        (
            b"Subject:\r\n folded-only\r\n\r\n",
            [("Subject", "folded-only")],
            26,
            [],
        ),
        (b"", [], 0, ["no_headers"]),
        (b"\r\nbody only", [], 2, ["no_headers"]),
        (b"\nbody only", [], 1, ["no_headers"]),
        (b"Subject: a\rb\r\n\r\n", [("Subject", "a\rb")], 16, ["lone_cr"]),
        (b"Subject: a\r", [("Subject", "a\r")], 11, ["lone_cr"]),
        (b"Subject: a\x07b\n\n", [("Subject", "a\x07b")], 14, ["control_character"]),
        (b"no colon here\nTo: a\n\n", [("", "no colon here"), ("To", "a")], 21, ["missing_colon"]),
        (b": value\n\n", [("", "value")], 9, ["empty_header_name"]),
        (b"Subject : x\n\n", [("Subject", "x")], 13, ["space_before_colon"]),
        (b"Sub ject: x\n\n", [("Sub ject", "x")], 13, ["invalid_header_name"]),
        (
            b" orphan\nTo: a\n\n",
            [("", "orphan"), ("To", "a")],
            15,
            ["orphan_continuation"],
        ),
        (
            b"Subject: caf\xc3\xa9\n\n",
            [("Subject", "café")],
            16,
            ["non_ascii_header"],
        ),
        (
            b"Subject: caf\xe9\n\n",
            [("Subject", "caf�")],
            15,
            ["invalid_utf8"],
        ),
        (
            b"X-Caf\xc3\xa9: a\n\n",
            [("X-Café", "a")],
            12,
            ["non_ascii_header", "invalid_header_name"],
        ),
        (
            b"Subject: a\nSubject: b\n\n",
            [("Subject", "a"), ("Subject", "b")],
            23,
            ["duplicate_header"],
        ),
        (
            b"Received: a\nreceived: b\nX-A: 1\nX-A: 2\n\n",
            [("Received", "a"), ("received", "b"), ("X-A", "1"), ("X-A", "2")],
            39,
            [],
        ),
        (
            b"Subject: x\n   \nTo: a\n\n",
            [("Subject", "x"), ("To", "a")],
            22,
            [],
        ),
    ],
    ids=[
        "crlf",
        "lf",
        "mixed",
        "headers-only-no-newline",
        "headers-only-trailing-newline",
        "mbox-from-line",
        "from-header-not-mbox",
        "from-space-colon-not-mbox",
        "unfold-space-and-tab",
        "empty-first-line-then-fold",
        "empty-input",
        "body-only-crlf",
        "body-only-lf",
        "lone-cr-in-value",
        "lone-cr-at-eof",
        "control-character",
        "missing-colon",
        "empty-name",
        "space-before-colon",
        "space-in-name",
        "orphan-continuation",
        "utf8-value",
        "non-utf8-value",
        "utf8-name",
        "duplicate-single-instance",
        "duplicate-multi-instance-no-warning",
        "whitespace-only-line-is-continuation",
    ],
)
def test_structure(
    raw: bytes,
    fields: list[tuple[str, str]],
    body_offset: int,
    warnings: list[str],
) -> None:
    block = parse_header_block(raw)
    assert [(f.name, f.raw_value) for f in block.fields] == fields
    assert block.body_offset == body_offset
    assert codes(block) == warnings


def test_positions_are_byte_offsets() -> None:
    raw = b"From x Mon\nA: 1\r\nB: caf\xc3\xa9\r\n more\r\nC: 3\r\n\r\n"
    block = parse_header_block(raw)
    assert [f.position for f in block.fields] == [11, 17, 34]
    for f in block.fields:
        assert raw[f.position :].startswith(f.name.encode())


def test_get_all_case_insensitive_keeps_order() -> None:
    raw = (
        b"Received: from c by d\r\n"
        b"Subject: s\r\n"
        b"RECEIVED: from b by c\r\n"
        b"received: from a\r\n by b\r\n"
        b"\r\n"
    )
    block = parse_header_block(raw)
    got = block.get_all("Received")
    assert [f.raw_value for f in got] == ["from c by d", "from b by c", "from a by b"]
    assert block.get_all("rEcEiVeD") == got
    assert block.get_all("missing") == ()
    assert block.get_all("") == ()


def test_result_is_frozen() -> None:
    block = parse_header_block(b"A: b\n\n")
    with pytest.raises(dataclasses.FrozenInstanceError):
        block.body_offset = 1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        block.fields[0].name = "x"  # type: ignore[misc]
    assert isinstance(block.fields, tuple)
    assert isinstance(block.warnings, tuple)


# --- RFC 2047 ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "decoded", "warnings"),
    [
        ("plain text", "plain text", []),
        ("=?utf-8?b?Y2Fmw6k=?=", "café", []),
        ("=?UTF-8?B?Y2Fmw6k=?=", "café", []),
        ("=?utf-8?q?caf=C3=A9_au_lait?=", "café au lait", []),
        ("=?iso-8859-1?q?caf=E9?=", "café", []),
        ("=?ISO-8859-1?B?Y2Fm6Q==?=", "café", []),
        ("=?utf-8*en?q?hello?=", "hello", []),
        ("Re: =?utf-8?q?caf=C3=A9?= ok", "Re: café ok", []),
        ("=?utf-8?q?a?= =?utf-8?q?b?=", "ab", []),
        ("=?utf-8?q?a?=\t  =?iso-8859-1?q?b?=", "ab", []),
        ("=?utf-8?q?a?= x =?utf-8?q?b?=", "a x b", []),
        # Multi-byte character split across two adjacent words.
        ("=?utf-8?b?w6k=?= =?utf-8?b?w6k=?=", "éé", []),
        ("=?utf-8?q?=C3?= =?utf-8?q?=A9?=", "é", []),
        ("=?utf-8?b?Y2Fmw6k?=", "café", []),
        ("=?x-unknown?q?abc?=", "=?x-unknown?q?abc?=", ["encoded_word_unknown_charset"]),
        (
            "=?zlib?b?eJwrSS0uAQAEXQHB?=",
            "=?zlib?b?eJwrSS0uAQAEXQHB?=",
            ["encoded_word_unknown_charset"],
        ),
        ("=?rot13?q?nop?=", "=?rot13?q?nop?=", ["encoded_word_unknown_charset"]),
        ("=?punycode?q?abc?=", "=?punycode?q?abc?=", ["encoded_word_unknown_charset"]),
        (
            "=?" + "u" * 5000 + "?q?a?=",
            "=?" + "u" * 5000 + "?q?a?=",
            ["line_over_rfc_limit", "encoded_word_unknown_charset"],
        ),
        ("=?utf-8?b?", "=?utf-8?b?", ["encoded_word_malformed"]),
        ("=?utf-8?b?Y2Fm", "=?utf-8?b?Y2Fm", ["encoded_word_malformed"]),
        ("=?utf-8?b?!!!!?=", "=?utf-8?b?!!!!?=", ["encoded_word_invalid"]),
        ("=?utf-8?b?Y?=", "=?utf-8?b?Y?=", ["encoded_word_invalid"]),
        ("=?utf-8?q?bad=ZZ?=", "=?utf-8?q?bad=ZZ?=", ["encoded_word_invalid"]),
        ("=?utf-8?q?trunc=4?=", "=?utf-8?q?trunc=4?=", ["encoded_word_invalid"]),
        ("=?utf-8?x?abc?=", "=?utf-8?x?abc?=", ["encoded_word_invalid"]),
        ("=?utf-8?b?/w==?=", "=?utf-8?b?/w==?=", ["encoded_word_invalid"]),
        (
            "=?utf-8?b?/w==?= =?utf-8?q?ok?=",
            "=?utf-8?b?/w==?= ok",
            ["encoded_word_invalid"],
        ),
        (
            "=?bogus?q?a?= =?utf-8?q?b?=",
            "=?bogus?q?a?= b",
            ["encoded_word_unknown_charset"],
        ),
        ("a ?= b =? c", "a ?= b =? c", ["encoded_word_malformed"]),
    ],
    ids=[
        "plain",
        "b-utf8",
        "b-utf8-upper",
        "q-utf8-underscore",
        "q-latin1",
        "b-latin1",
        "rfc2231-language",
        "mixed-with-plain",
        "adjacent-words-join",
        "adjacent-words-different-charset",
        "words-separated-by-text",
        "b-split-multibyte",
        "q-split-multibyte",
        "b-missing-padding",
        "unknown-charset",
        "bytes-codec-rejected",
        "str-codec-rejected",
        "punycode-rejected",
        "charset-bomb",
        "truncated-empty",
        "truncated-text",
        "invalid-base64-chars",
        "invalid-base64-length",
        "q-bad-hex",
        "q-truncated-hex",
        "unknown-encoding",
        "undecodable-bytes",
        "invalid-then-valid",
        "unknown-charset-then-valid",
        "stray-markers",
    ],
)
def test_rfc2047(value: str, decoded: str, warnings: list[str]) -> None:
    block = parse_header_block(b"Subject: " + value.encode() + b"\r\n\r\n")
    (field,) = block.fields
    assert field.raw_value == value
    assert field.decoded_value == decoded
    assert codes(block) == warnings


def test_rfc2047_folded_words() -> None:
    raw = b"Subject: =?utf-8?q?caf=C3=A9?=\r\n =?utf-8?q?_au_lait?=\r\n\r\n"
    (field,) = parse_header_block(raw).fields
    assert field.raw_value == "=?utf-8?q?caf=C3=A9?= =?utf-8?q?_au_lait?="
    assert field.decoded_value == "café au lait"


def test_no_colon_line_is_not_decoded() -> None:
    (field,) = parse_header_block(b"=?utf-8?q?a?=\n\n").fields
    assert field.name == ""
    assert field.decoded_value == field.raw_value == "=?utf-8?q?a?="
