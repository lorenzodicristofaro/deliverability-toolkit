"""Table-driven tests for the MIME structure and size breakdown parser. No network."""

from __future__ import annotations

import base64
import binascii
import dataclasses
import random
import threading
import time

import pytest

from app.parsers import mime as mm
from app.parsers.message import MAX_RAW_BYTES, MessageParseError, MessageTooLarge
from app.parsers.mime import (
    MAX_BOUNDARY_LEN,
    MAX_MIME_DEPTH,
    MAX_MIME_PARTS,
    MimeSummary,
    parse_mime,
)


def codes(summary: MimeSummary) -> list[str]:
    return [w.code for w in summary.warnings]


def types(summary: MimeSummary) -> list[str]:
    return [p.content_type for p in summary.parts]


def multipart(subtype: str, boundary: str, parts: list[bytes], close: bool = True) -> bytes:
    body = b"".join(b"--" + boundary.encode() + b"\r\n" + p + b"\r\n" for p in parts)
    if close:
        body += b"--" + boundary.encode() + b"--\r\n"
    return f'Content-Type: multipart/{subtype}; boundary="{boundary}"\r\n\r\n'.encode() + body


def message(headers: str, body: bytes) -> bytes:
    return b"From: a@example.com\r\nSubject: s\r\n" + headers.encode() + b"\r\n" + body


TEXT = b"Content-Type: text/plain; charset=utf-8\r\n\r\nhello"
HTML = b"Content-Type: text/html; charset=utf-8\r\n\r\n<p>hello</p>"
ALT = multipart("alternative", "alt", [TEXT, HTML])
B64_BODY = base64.encodebytes(b"x" * 1000)
ATTACHMENT = (
    b'Content-Type: application/pdf; name="r.pdf"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b'Content-Disposition: attachment; filename="r.pdf"\r\n\r\n' + B64_BODY
)
IMAGE = b"Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0K"


# --- well-formed structures ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected_types", "expected_codes"),
    [
        (b"Subject: x\r\n\r\nhello", ["text/plain"], []),
        (message("Content-Type: text/html\r\n", b"<b>x</b>"), ["text/html"], []),
        (ALT, ["multipart/alternative", "text/plain", "text/html"], []),
        (
            multipart("mixed", "mix", [ALT, ATTACHMENT, IMAGE]),
            [
                "multipart/mixed",
                "multipart/alternative",
                "text/plain",
                "text/html",
                "application/pdf",
                "image/png",
            ],
            [],
        ),
        (
            multipart("mixed", "m", [b"Content-Type: message/rfc822\r\n\r\n" + ALT]),
            [
                "multipart/mixed",
                "message/rfc822",
                "multipart/alternative",
                "text/plain",
                "text/html",
            ],
            [],
        ),
        (
            multipart("digest", "d", [b"\r\nSubject: inner\r\n\r\nbody"]),
            ["multipart/digest", "message/rfc822", "text/plain"],
            [],
        ),
        (b"Subject: x\r\n\r\n", ["text/plain"], []),
        (b"Subject: x\r\n", ["text/plain"], []),
    ],
    ids=[
        "plain",
        "html",
        "alternative",
        "mixed",
        "nested_rfc822",
        "digest_default",
        "empty",
        "no_body",
    ],
)
def test_structures(raw: bytes, expected_types: list[str], expected_codes: list[str]) -> None:
    summary = parse_mime(raw)
    assert types(summary) == expected_types
    assert codes(summary) == expected_codes
    assert summary.truncated is False


def test_tree_links_depth_and_offsets() -> None:
    raw = multipart("mixed", "mix", [ALT, ATTACHMENT])
    summary = parse_mime(raw)
    parts = summary.parts
    assert [p.depth for p in parts] == [0, 1, 2, 2, 1]
    assert [p.parent for p in parts] == [None, 0, 1, 1, 0]
    assert parts[0].children == (1, 4)
    assert parts[1].children == (2, 3)
    assert summary.max_depth == 2
    text = parts[2]
    assert raw[text.offset + text.header_bytes :][: text.encoded_size] == b"hello"
    html = parts[3]
    assert raw[html.offset + html.header_bytes :][: html.encoded_size] == b"<p>hello</p>"
    pdf = parts[4]
    assert raw[pdf.offset + pdf.header_bytes :][: pdf.encoded_size] == B64_BODY


def test_part_fields_and_totals() -> None:
    raw = multipart("mixed", "mix", [ALT, ATTACHMENT, IMAGE])
    summary = parse_mime(raw)
    text, html, pdf, png = summary.parts[2], summary.parts[3], summary.parts[4], summary.parts[5]
    assert (text.charset, text.category, text.transfer_encoding) == ("utf-8", "text", "7bit")
    assert html.category == "html"
    assert (pdf.disposition, pdf.has_filename, pdf.category) == ("attachment", True, "attachment")
    assert pdf.transfer_encoding == "base64"
    assert pdf.estimated_decoded_size == 1000 and pdf.decoded_size_estimated
    assert png.category == "inline_image"
    assert text.decoded_size_estimated is False and text.estimated_decoded_size == 5
    totals = summary.totals
    assert totals.total_bytes == len(raw)
    assert totals.header_bytes + totals.body_bytes == len(raw)
    assert totals.text_bytes == 5 and totals.html_bytes == 12
    assert totals.attachment_bytes == len(B64_BODY)
    assert totals.inline_image_bytes == 8
    assert totals.other_bytes == 0
    assert summary.has_text_plain and summary.has_text_html and summary.has_alternative
    assert dataclasses.is_dataclass(summary)
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.truncated = True  # type: ignore[misc]


@pytest.mark.parametrize(
    ("raw", "plain", "html", "alternative"),
    [
        (b"Subject: x\r\n\r\nhi", True, False, False),
        (message("Content-Type: text/html\r\n", b"x"), False, True, False),
        (ALT, True, True, True),
        (multipart("mixed", "m", [TEXT, HTML]), True, True, False),
        (multipart("alternative", "a", [TEXT]), True, False, False),
        (message("Content-Type: application/pdf\r\n", b"x"), False, False, False),
    ],
    ids=["plain_only", "html_only", "alternative", "mixed_not_alt", "alt_one_part", "neither"],
)
def test_text_html_presence(raw: bytes, plain: bool, html: bool, alternative: bool) -> None:
    summary = parse_mime(raw)
    assert (summary.has_text_plain, summary.has_text_html, summary.has_alternative) == (
        plain,
        html,
        alternative,
    )


@pytest.mark.parametrize(
    ("headers", "category"),
    [
        ("Content-Type: text/plain\r\n", "text"),
        ("Content-Type: text/plain\r\nContent-Disposition: attachment\r\n", "attachment"),
        ('Content-Type: text/plain; name="a.txt"\r\n', "attachment"),
        (
            'Content-Type: text/html\r\nContent-Disposition: inline; filename="a.htm"\r\n',
            "attachment",
        ),
        ("Content-Type: image/gif\r\nContent-Disposition: inline\r\n", "inline_image"),
        ("Content-Type: image/gif\r\nContent-Disposition: attachment\r\n", "attachment"),
        ("Content-Type: application/json\r\n", "other"),
        ("Content-Type: TEXT/HTML\r\n", "html"),
    ],
)
def test_leaf_categories(headers: str, category: str) -> None:
    assert parse_mime(message(headers, b"data")).parts[0].category == category


# --- decoded size estimates (never decoded) ------------------------------------------------


@pytest.mark.parametrize(
    ("cte", "body", "decoded", "estimated"),
    [
        ("base64", b"QQ==", 1, True),
        ("base64", b"QUI=\r\n", 2, True),
        ("base64", b"QUJD\r\nREVG\r\n", 6, True),
        ("base64", b"QUJD \t\r\n", 3, True),
        ("base64", b"", 0, True),
        ("base64", b"=", 0, True),
        ("quoted-printable", b"caf=C3=A9", 9, True),
        ("7bit", b"abc", 3, False),
        ("8bit", b"\xc3\xa9", 2, False),
        ("binary", b"\x00\x01", 2, False),
        ("x-uuencode", b"abc", 3, False),
    ],
)
def test_decoded_size_estimates(cte: str, body: bytes, decoded: int, estimated: bool) -> None:
    raw = message(
        f"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: {cte}\r\n", body
    )
    part = parse_mime(raw).parts[0]
    assert part.encoded_size == len(body)
    assert part.estimated_decoded_size == decoded
    assert part.decoded_size_estimated is estimated


def test_large_base64_part_is_never_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = base64.encodebytes(b"\xab" * (768 * 1024))  # ~1 MiB encoded
    assert len(payload) >= 1024 * 1024

    def refuse(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("attachment must not be decoded")

    for name in ("b64decode", "decodebytes", "standard_b64decode"):
        monkeypatch.setattr(base64, name, refuse)
    monkeypatch.setattr(binascii, "a2b_base64", refuse)
    attachment = (
        b"Content-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\n"
        b'Content-Disposition: attachment; filename="bomb.zip"\r\n\r\n' + payload
    )
    summary = parse_mime(multipart("mixed", "z", [TEXT, attachment]))
    zip_part = summary.parts[2]
    assert zip_part.estimated_decoded_size == 768 * 1024
    assert zip_part.decoded_size_estimated is True
    assert summary.totals.attachment_bytes == len(payload)


# --- malformed input -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected_codes", "expected_types"),
    [
        (
            message("Content-Type: multipart/mixed\r\n", b"--x\r\n\r\na\r\n--x--\r\n"),
            ["missing_boundary"],
            ["multipart/mixed"],
        ),
        (
            message('Content-Type: multipart/mixed; boundary=""\r\n', b"x"),
            ["missing_boundary"],
            ["multipart/mixed"],
        ),
        (
            message(
                "Content-Type: multipart/mixed; boundary=a; boundary=b\r\n",
                b"--a\r\n\r\none\r\n--a--\r\n",
            ),
            ["duplicate_boundary"],
            ["multipart/mixed", "text/plain"],
        ),
        (
            multipart("mixed", "same", [multipart("alternative", "same", [TEXT, HTML])]),
            ["nested_boundary_reused", "multipart_no_parts"],
            ["multipart/mixed", "multipart/alternative", "text/plain", "text/html"],
        ),
        (
            multipart("mixed", "m", [TEXT, HTML], close=False),
            ["missing_closing_boundary"],
            ["multipart/mixed", "text/plain", "text/html"],
        ),
        (
            message(
                'Content-Type: multipart/mixed; boundary="b"\r\n',
                b"preamble junk\r\n--b\r\n\r\none\r\n--b--\r\nepilogue \x00junk\r\n--b\r\n",
            ),
            [],
            ["multipart/mixed", "text/plain"],
        ),
        (
            message('Content-Type: multipart/mixed; boundary="b"\r\n', b"no delimiters here"),
            ["multipart_no_parts"],
            ["multipart/mixed"],
        ),
        (
            message('Content-Type: multipart/mixed; boundary="b"\r\n', b"--b--\r\n"),
            ["multipart_no_parts"],
            ["multipart/mixed"],
        ),
        (
            message("Content-Type: text/plain; charset=x-bogus-123\r\n", b"x"),
            ["unknown_charset"],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/plain; charset=zlib_codec\r\n", b"x"),
            ["unknown_charset"],
            ["text/plain"],
        ),
        (
            message('Content-Type: text/plain; charset="utf-8\r\n', b"x"),
            ["unterminated_quote"],
            ["text/plain"],
        ),
        (
            message('Content-Type: multipart/mixed; boundary="b\r\n', b"--b\r\n\r\nx\r\n--b--"),
            ["unterminated_quote"],
            ["multipart/mixed", "text/plain"],
        ),
        (
            message("Content-Type: text/plain\r\nContent-Transfer-Encoding: base65\r\n", b"x"),
            ["invalid_transfer_encoding"],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/plain\r\n", b"caf\xc3\xa9"),
            ["eight_bit_in_7bit"],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n", b"\xc3\xa9"),
            [],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/plain\r\n", b"a\x00b\x00"),
            ["nul_in_body"],
            ["text/plain"],
        ),
        (
            message("Content-Type: nonsense\r\n", b"x"),
            ["invalid_content_type"],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/\r\n", b"x"),
            ["invalid_content_type"],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/plain\r\nContent-Type: text/html\r\n", b"x"),
            ["duplicate_mime_header"],
            ["text/plain"],
        ),
        (
            message("Content-Type: text/plain; charset=utf-8; charset=latin1\r\n", b"x"),
            ["duplicate_parameter"],
            ["text/plain"],
        ),
        (
            message(
                'Content-Type: multipart/mixed; boundary="b"\r\n'
                "Content-Transfer-Encoding: base64\r\n",
                b"--b\r\n\r\nx\r\n--b--\r\n",
            ),
            ["encoded_composite"],
            ["multipart/mixed"],
        ),
        (
            multipart("mixed", "b", [b"no headers and no blank line"]),
            ["part_missing_headers"],
            ["multipart/mixed", "text/plain"],
        ),
        (
            multipart("mixed", "b", [b"Content-Type: text/plain\r\nX: \x00\r\n\r\nbody"]),
            ["part_headers_unparseable", "nul_in_body"],
            ["multipart/mixed", "text/plain"],
        ),
        (
            message('Content-Type: multipart/mixed; boundary="b"\r\n', b"--bx\r\n--b junk\r\n"),
            ["multipart_no_parts"],
            ["multipart/mixed"],
        ),
        (
            message('Content-Type: multipart/mixed; boundary="b\xc3\xa9"\r\n', b"x"),
            ["invalid_boundary"],
            ["multipart/mixed"],
        ),
    ],
    ids=[
        "missing_boundary_param",
        "empty_boundary",
        "duplicate_boundary_param",
        "boundary_reused_in_nested_part",
        "missing_closing_boundary",
        "preamble_epilogue_junk",
        "no_delimiters",
        "zero_parts_only_close",
        "bogus_charset",
        "bytes_codec_charset",
        "unterminated_quote_charset",
        "unterminated_quote_boundary",
        "invalid_cte",
        "8bit_in_7bit",
        "8bit_declared",
        "nul_in_body",
        "content_type_no_slash",
        "content_type_empty_subtype",
        "duplicate_content_type",
        "duplicate_parameter",
        "encoded_multipart",
        "part_without_headers",
        "part_headers_with_nul",
        "boundary_lookalikes",
        "non_ascii_boundary",
    ],
)
def test_malformed(raw: bytes, expected_codes: list[str], expected_types: list[str]) -> None:
    summary = parse_mime(raw)
    assert codes(summary) == expected_codes
    assert types(summary) == expected_types


def test_reused_boundary_splits_at_inner_delimiters() -> None:
    # The outer scan sees the inner delimiters first; the inner multipart is cut short and
    # then has no delimiters of its own left; its parts surface as siblings. No loop.
    raw = multipart("mixed", "same", [multipart("alternative", "same", [TEXT, HTML])])
    summary = parse_mime(raw)
    assert [(p.depth, p.category) for p in summary.parts] == [
        (0, "multipart"),
        (1, "multipart"),
        (1, "text"),
        (1, "html"),
    ]
    assert summary.parts[1].children == ()


def test_nul_bytes_counted() -> None:
    raw = multipart("mixed", "b", [b"\r\na\x00\x00", b"\r\nb\x00"])
    summary = parse_mime(raw)
    assert [p.nul_bytes for p in summary.parts] == [0, 2, 1]
    assert summary.totals.nul_bytes == 3


def test_8bit_in_base64_part_warns() -> None:
    raw = message("Content-Transfer-Encoding: base64\r\n", b"QQ\xff=")
    assert codes(parse_mime(raw)) == ["eight_bit_in_7bit"]


@pytest.mark.parametrize(
    ("headers", "has_filename"),
    [
        ('Content-Disposition: attachment; filename*0="a"; filename*1="b.pdf"\r\n', True),
        ("Content-Disposition: attachment; filename*=utf-8''r%C3%A9.pdf\r\n", True),
        ("Content-Disposition: attachment; filename*0*=utf-8''r%C3%A9; filename*1=.pdf\r\n", True),
        ("Content-Type: application/pdf; name*0=a; name*1=b\r\n", True),
        ("Content-Disposition: attachment\r\n", False),
        ("Content-Disposition: attachment; filename\r\n", False),
        ("Content-Disposition: attachment; size=10\r\n", False),
    ],
    ids=["continued", "extended", "extended_continued", "ct_name", "none", "no_value", "other"],
)
def test_rfc2231_filename_presence(headers: str, has_filename: bool) -> None:
    part = parse_mime(message(headers, b"x")).parts[0]
    assert part.has_filename is has_filename


def test_rfc2231_continued_boundary() -> None:
    raw = message(
        "Content-Type: multipart/mixed; boundary*0=ab; boundary*1=cd\r\n",
        b"--abcd\r\n\r\nx\r\n--abcd--\r\n",
    )
    assert types(parse_mime(raw)) == ["multipart/mixed", "text/plain"]


@pytest.mark.parametrize(
    ("value", "head", "params"),
    [
        ("text/plain", "text/plain", {}),
        ("Text/Plain; Charset=UTF-8", "text/plain", {"charset": "UTF-8"}),
        ('a/b; x="q\\"uo;te"; y=2', "a/b", {"x": 'q"uo;te', "y": "2"}),
        ("a/b (comment); x=1", "a/b", {"x": "1"}),
        ("a/b;;; ;", "a/b", {}),
        ("a/b; =v; x=1", "a/b", {"x": "1"}),
        ("a/b; x = 1 ; y= 2", "a/b", {"x": "1", "y": "2"}),
        ('a/b; x="unterminated', "a/b", {"x": "unterminated"}),
        ("a/b; x=)); y=(", "a/b", {"x": "))", "y": "("}),
        ("", "", {}),
    ],
)
def test_parse_params(value: str, head: str, params: dict[str, str]) -> None:
    from app.parsers.message import _Warnings

    parsed = mm._parse_params(value, 0, _Warnings())
    assert parsed.value == head
    assert parsed.params == params


def test_too_many_parameters() -> None:
    value = "a/b" + "; p=1" * (mm.MAX_PARAMETERS + 5)
    from app.parsers.message import _Warnings

    warnings = _Warnings()
    parsed = mm._parse_params(value, 0, warnings)
    assert len(parsed.params) == 1
    assert [w.code for w in warnings.items] == ["duplicate_parameter"] * (mm.MAX_PARAMETERS - 1) + [
        "too_many_parameters"
    ]


# --- caps and boundaries -------------------------------------------------------------------


def nested(depth: int) -> bytes:
    """A message whose deepest part is at ``depth`` (root is depth 0)."""
    inner = TEXT
    for level in range(depth, 0, -1):
        inner = multipart("mixed", f"b{level}", [inner])
    return inner


@pytest.mark.parametrize(
    ("depth", "truncated", "max_depth"),
    [
        (MAX_MIME_DEPTH - 1, False, MAX_MIME_DEPTH - 1),
        (MAX_MIME_DEPTH, False, MAX_MIME_DEPTH),
        (MAX_MIME_DEPTH + 1, True, MAX_MIME_DEPTH),
        (60, True, MAX_MIME_DEPTH),
    ],
    ids=["below", "at_cap", "one_over", "far_over"],
)
def test_depth_cap(depth: int, truncated: bool, max_depth: int) -> None:
    summary = parse_mime(nested(depth))
    assert summary.truncated is truncated
    assert summary.max_depth == max_depth
    assert ("mime_depth_exceeded" in codes(summary)) is truncated
    assert all(p.depth <= MAX_MIME_DEPTH for p in summary.parts)


def test_depth_counts_message_rfc822() -> None:
    inner = TEXT
    for _ in range(MAX_MIME_DEPTH + 1):
        inner = b"Content-Type: message/rfc822\r\n\r\n" + inner
    summary = parse_mime(inner)
    assert summary.truncated
    assert summary.max_depth == MAX_MIME_DEPTH
    assert summary.parts[-1].content_type == "message/rfc822"
    assert summary.parts[-1].category == "other"


@pytest.mark.parametrize(
    ("count", "truncated"),
    [
        (MAX_MIME_PARTS - 1, False),  # root + 199 = 200 parts
        (MAX_MIME_PARTS, True),
        (MAX_MIME_PARTS + 1, True),
        (5000, True),
    ],
    ids=["at_cap", "one_over", "two_over", "far_over"],
)
def test_part_count_cap(count: int, truncated: bool) -> None:
    summary = parse_mime(multipart("mixed", "p", [b"\r\nx"] * count))
    assert summary.truncated is truncated
    assert len(summary.parts) == min(count + 1, MAX_MIME_PARTS)
    assert ("too_many_parts" in codes(summary)) is truncated


def test_part_count_cap_across_levels() -> None:
    inner = multipart("alternative", "i", [b"\r\nx"] * 150)
    summary = parse_mime(multipart("mixed", "o", [inner, inner]))
    assert len(summary.parts) == MAX_MIME_PARTS
    assert summary.truncated and codes(summary) == ["too_many_parts"]


@pytest.mark.parametrize(
    ("length", "truncated"),
    [(1, False), (MAX_BOUNDARY_LEN, False), (MAX_BOUNDARY_LEN + 1, True), (1000, True)],
    ids=["one", "at_cap", "one_over", "far_over"],
)
def test_boundary_length_cap(length: int, truncated: bool) -> None:
    summary = parse_mime(multipart("mixed", "b" * length, [TEXT]))
    assert summary.truncated is truncated
    assert ("boundary_too_long" in codes(summary)) is truncated
    assert len(summary.parts) == (1 if truncated else 2)


def test_raw_size_cap() -> None:
    with pytest.raises(MessageTooLarge) as exc:
        parse_mime(b"Subject: x\r\n\r\n" + b"a" * MAX_RAW_BYTES)
    assert exc.value.code == "message_too_large"


def test_top_level_header_errors_propagate() -> None:
    with pytest.raises(MessageParseError) as exc:
        parse_mime(b"Subject: \x00\r\n\r\nbody")
    assert exc.value.code == "nul_byte"


def test_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        parse_mime("Subject: x\r\n\r\n")  # type: ignore[arg-type]


def test_bytearray_accepted() -> None:
    assert types(parse_mime(bytearray(ALT))) == types(parse_mime(ALT))


# --- hostile input: linear time, always returns --------------------------------------------

HOSTILE_HEADER = b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
HOSTILE_ROOM = MAX_RAW_BYTES - len(HOSTILE_HEADER)
HOSTILE_SECONDS = 5.0


@pytest.mark.parametrize(
    "body",
    [
        b"--b\r\n" * (HOSTILE_ROOM // 5),
        b"--b" * (HOSTILE_ROOM // 3),
        b"\n--bx" * (HOSTILE_ROOM // 5),
        b"\n--b" + b" " * (HOSTILE_ROOM - 10) + b"x",
        b"-" * HOSTILE_ROOM,
        b"\n" * HOSTILE_ROOM,
        b"\x00" * HOSTILE_ROOM,
        b"\xff" * HOSTILE_ROOM,
        b")" * HOSTILE_ROOM,
        b'--b\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n' * 30000,
    ],
    ids=[
        "many_delimiters",
        "delimiters_not_at_line_start",
        "lookalike_lines",
        "long_padding",
        "dashes",
        "newlines",
        "nuls",
        "high_bytes",
        "parens",
        "reused_boundary_chain",
    ],
)
def test_hostile_bodies_bounded(body: bytes) -> None:
    raw = (HOSTILE_HEADER + body)[:MAX_RAW_BYTES]
    started = time.perf_counter()
    summary = parse_mime(raw)
    assert time.perf_counter() - started < HOSTILE_SECONDS
    assert len(summary.parts) <= MAX_MIME_PARTS
    assert summary.max_depth <= MAX_MIME_DEPTH


def test_hostile_deep_nesting_with_filler_bounded() -> None:
    # Every level rescans the filler: work is bounded by MAX_MIME_DEPTH passes.
    filler = b"\n--b1x" * ((MAX_RAW_BYTES - 4096) // 6)
    raw = nested(MAX_MIME_DEPTH + 5).replace(b"hello", filler)[:MAX_RAW_BYTES]
    started = time.perf_counter()
    summary = parse_mime(raw)
    assert time.perf_counter() - started < HOSTILE_SECONDS
    assert summary.truncated and summary.max_depth == MAX_MIME_DEPTH


def test_hostile_content_type_parameters_bounded() -> None:
    value = b"multipart/mixed" + b';x="' + b"\\" * 8000
    raw = b"Content-Type: " + value + b"\r\n" + (b"X: " + b";" * 8000 + b"\r\n") * 10 + b"\r\n"
    started = time.perf_counter()
    parse_mime(raw)
    assert time.perf_counter() - started < HOSTILE_SECONDS


FUZZ_SEED = 4202
FUZZ_CASES = 2_000
FUZZ_CASE_SECONDS = 2.0
FUZZ_TOKENS = [
    b"--b",
    b"--b--",
    b"--c",
    b"\r\n",
    b"\n",
    b"\r",
    b'"',
    b")",
    b"(",
    b";",
    b"=",
    b"*",
    b"'",
    b"\\",
    b" ",
    b"\x00",
    b"\xff",
    b"Content-Type: multipart/mixed; boundary=b\r\n",
    b'Content-Type: multipart/alternative; boundary="c"\r\n',
    b"Content-Type: message/rfc822\r\n",
    b"Content-Transfer-Encoding: base64\r\n",
    b"Content-Disposition: attachment; filename*0*=utf-8''a; filename*1=b\r\n",
    b"boundary=",
    b"charset=",
]
FUZZ_SEEDS = [
    ALT,
    multipart("mixed", "b", [ALT, ATTACHMENT, IMAGE]),
    nested(4),
    multipart("digest", "b", [b"\r\nSubject: x\r\n\r\ny"]),
]


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    data = bytearray(seed)
    for _ in range(rng.randint(1, 12)):
        op = rng.randrange(4)
        at = rng.randint(0, len(data))
        if op == 0:
            data[at:at] = rng.choice(FUZZ_TOKENS)
        elif op == 1 and data:
            del data[at : at + rng.randint(1, 16)]
        elif op == 2 and data:
            data[min(at, len(data) - 1)] = rng.randrange(256)
        else:
            data[at:at] = rng.choice(FUZZ_TOKENS) * rng.randint(1, 50)
    return bytes(data)


def test_fuzz_always_returns_within_time() -> None:
    rng = random.Random(FUZZ_SEED)
    for _ in range(FUZZ_CASES):
        raw = _mutate(rng, rng.choice(FUZZ_SEEDS))
        outcome: list[MimeSummary | BaseException] = []

        def run(data: bytes = raw, out: list[MimeSummary | BaseException] = outcome) -> None:
            try:
                out.append(parse_mime(data))
            except BaseException as exc:  # reported below with the failing input
                out.append(exc)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(FUZZ_CASE_SECONDS)
        assert not worker.is_alive(), f"parser did not finish in {FUZZ_CASE_SECONDS}s: {raw!r}"
        (result,) = outcome
        if isinstance(result, MessageParseError):
            continue  # top-level header block rejected by M4-01 (documented)
        assert isinstance(result, MimeSummary), f"{raw!r} raised {result!r}"
        assert 1 <= len(result.parts) <= MAX_MIME_PARTS
        assert result.max_depth <= MAX_MIME_DEPTH
        leaves = [
            p for p in result.parts if not p.children and p.category not in ("multipart", "message")
        ]
        assert sum(p.encoded_size for p in leaves) <= result.totals.body_bytes or (
            result.totals.body_bytes == 0
        )
        for part in result.parts:
            assert 0 <= part.offset <= len(raw)
            assert part.offset + part.header_bytes + part.encoded_size <= len(raw)
            assert part.estimated_decoded_size >= 0
        for issue in result.warnings:
            assert 0 <= issue.position <= len(raw)
