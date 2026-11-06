"""Raw message limits and header block parser (RFC 5322 sections 2.1-2.2, 3.6; RFC 2047).

Pure and offline: no DNS, no network, no filesystem, no database. Nothing is stored; the
result lives only for the request that asked for it.

``parse_header_block`` takes the raw message as ``bytes`` and returns a frozen
:class:`HeaderBlock`: the header fields in input order (duplicates kept), the byte offset
where the body starts and a tuple of warnings (:class:`~app.parsers.spf.ParseIssue` with
``severity="warning"`` and a stable lowercase ``code``).

It raises only in these cases, each with a stable ``code`` and a message that never echoes
the input:

- :class:`MessageTooLarge`: input over :data:`MAX_RAW_BYTES` (``message_too_large``),
  header block over :data:`MAX_HEADER_BYTES` (``header_block_too_large``) or a logical
  (unfolded) header line over :data:`MAX_HEADER_LINE` (``header_line_too_long``). Nothing
  is ever truncated silently.
- :class:`TooManyHeaders`: more than :data:`MAX_HEADER_COUNT` fields (``too_many_headers``).
- :class:`InvalidMessage`: a NUL byte in the header block (``nul_byte``).

Everything else malformed (lone CR, 8-bit bytes, missing colon, empty name, space before the
colon, duplicates, broken encoded-words, ...) is kept in order and reported as a warning.

Parsing rules:

- Lines end at LF; a CR directly before the LF is part of the line ending (CRLF, bare LF and
  mixed endings are all accepted). Any other CR is a lone CR and stays in the value.
- The header block ends at the first empty line; ``body_offset`` is the byte offset just
  after that line. Input with no empty line is headers-only and ``body_offset`` is its
  length.
- A first line starting with ``From `` (mbox separator) is skipped with a warning.
- Unfolding (RFC 5322 section 2.2.3) removes the line ending before a line that starts with
  SP or HTAB; the whitespace itself is kept. ``raw_value`` is the unfolded text after the
  first colon with surrounding whitespace stripped. Lines that cannot be a field (no colon,
  continuation with nothing to continue) are kept as fields with ``name=""``.
- :data:`MAX_HEADER_LINE` applies to each logical line after unfolding (name, colon and
  value, without line endings), so a fold bomb of many short continuation lines is capped
  by the same limit as one long physical line. The RFC 5322 section 2.1.1 limit of 998
  characters per physical line is a warning only.
- 8-bit bytes are decoded as UTF-8 (RFC 6532); invalid UTF-8 is decoded with U+FFFD
  replacement characters and a warning. The exact bytes are at ``raw[position:]``.
- ``decoded_value`` is ``raw_value`` with RFC 2047 encoded-words (``B`` and ``Q``) decoded.
  Adjacent encoded-words separated only by whitespace are joined without the whitespace
  (section 6.2). An encoded-word that cannot be decoded is left as raw text with a warning.
  Only text encodings found by :func:`codecs.lookup` are used, never bytes-to-bytes codecs
  such as ``zlib_codec``; charset names are capped at :data:`MAX_CHARSET_LENGTH`.
- ``duplicate_header`` is reported for the fields RFC 5322 section 3.6 allows at most once.

Warnings are capped at :data:`MAX_WARNINGS`; past the cap a single ``too_many_warnings`` is
added. All scans are linear in the input size.
"""

from __future__ import annotations

import binascii
import codecs
import re
from dataclasses import dataclass

from app.parsers.spf import ParseIssue

MAX_RAW_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 128 * 1024
MAX_HEADER_COUNT = 500
MAX_HEADER_LINE = 8 * 1024
RFC5322_LINE_LIMIT = 998
MAX_CHARSET_LENGTH = 64
MAX_WARNINGS = 200

# Error codes (stable, lowercase).
MESSAGE_TOO_LARGE = "message_too_large"
HEADER_BLOCK_TOO_LARGE = "header_block_too_large"
HEADER_LINE_TOO_LONG = "header_line_too_long"
TOO_MANY_HEADERS = "too_many_headers"
NUL_BYTE = "nul_byte"

# Warning codes (stable, lowercase).
MBOX_FROM_LINE = "mbox_from_line"
MIXED_LINE_ENDINGS = "mixed_line_endings"
LONE_CR = "lone_cr"
LINE_OVER_RFC_LIMIT = "line_over_rfc_limit"
CONTROL_CHARACTER = "control_character"
NON_ASCII_HEADER = "non_ascii_header"
INVALID_UTF8 = "invalid_utf8"
MISSING_COLON = "missing_colon"
EMPTY_NAME = "empty_header_name"
SPACE_BEFORE_COLON = "space_before_colon"
INVALID_NAME = "invalid_header_name"
ORPHAN_CONTINUATION = "orphan_continuation"
DUPLICATE_HEADER = "duplicate_header"
NO_HEADERS = "no_headers"
ENCODED_WORD_UNKNOWN_CHARSET = "encoded_word_unknown_charset"
ENCODED_WORD_INVALID = "encoded_word_invalid"
ENCODED_WORD_MALFORMED = "encoded_word_malformed"
TOO_MANY_WARNINGS = "too_many_warnings"

# RFC 5322 section 3.6: fields with a maximum of one occurrence.
SINGLE_INSTANCE_FIELDS: frozenset[str] = frozenset(
    {
        "date",
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "message-id",
        "in-reply-to",
        "references",
        "subject",
    }
)

_WSP = b" \t"
# RFC 5322 section 3.6.8: ftext = %d33-57 / %d59-126.
_FTEXT = frozenset(range(33, 127)) - {58}
_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([^?\s]*)\?([^?\s]*)\?=")
_B_TEXT = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_HEX = frozenset("0123456789abcdefABCDEF")
_CHARSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]*")
# Text codecs that are not character sets and must never be selected by message content.
_REJECTED_CODECS: frozenset[str] = frozenset(
    {"idna", "punycode", "undefined", "unicode-escape", "raw-unicode-escape"}
)


class MessageParseError(ValueError):
    """Base class: the message could not be parsed. ``code`` is stable; no input is echoed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MessageTooLarge(MessageParseError):
    """Input, header block or a header line is over its cap."""


class TooManyHeaders(MessageParseError):
    """More than :data:`MAX_HEADER_COUNT` header fields."""


class InvalidMessage(MessageParseError):
    """The header block cannot be processed at all (e.g. it contains a NUL byte)."""


@dataclass(frozen=True, slots=True)
class HeaderField:
    """One header field. ``position`` is the byte offset of its first line in the input."""

    name: str
    raw_value: str
    decoded_value: str
    position: int


@dataclass(frozen=True, slots=True)
class HeaderBlock:
    """Parsed header block: fields in input order, body start offset and warnings."""

    fields: tuple[HeaderField, ...]
    body_offset: int
    warnings: tuple[ParseIssue, ...]

    def get_all(self, name: str) -> tuple[HeaderField, ...]:
        """All fields named ``name`` (ASCII case-insensitive), in input order."""
        wanted = name.lower()
        return tuple(f for f in self.fields if f.name and f.name.lower() == wanted)


class _Warnings:
    def __init__(self) -> None:
        self.items: list[ParseIssue] = []
        self._full = False

    def add(self, code: str, position: int, term: str = "") -> None:
        if self._full:
            return
        if len(self.items) >= MAX_WARNINGS:
            self.items.append(ParseIssue(TOO_MANY_WARNINGS, "", position, "warning"))
            self._full = True
            return
        self.items.append(ParseIssue(code, term[:78], position, "warning"))


@dataclass(slots=True)
class _Line:
    content: bytes  # without the line ending
    position: int
    ending: bytes  # b"\r\n", b"\n" or b"" at end of input


def _split_header_lines(raw: bytes) -> tuple[list[_Line], int]:
    """Split the header block into lines; return them and the body offset.

    Stops at the first empty line. Raises when the header block exceeds its cap, before
    scanning further.
    """
    lines: list[_Line] = []
    pos = 0
    size = len(raw)
    while pos < size:
        nl = raw.find(b"\n", pos, pos + MAX_HEADER_BYTES + 2)
        if nl == -1:
            end, next_pos = size, size
        else:
            end, next_pos = nl, nl + 1
        if nl != -1 and end > pos and raw[end - 1] == 0x0D:
            content, ending = raw[pos : end - 1], b"\r\n"
        else:
            content, ending = raw[pos:end], (b"\n" if nl != -1 else b"")
        if not content and ending:
            return lines, next_pos
        if next_pos > MAX_HEADER_BYTES:
            raise MessageTooLarge(HEADER_BLOCK_TOO_LARGE)
        lines.append(_Line(content, pos, ending))
        pos = next_pos
    return lines, size


def _to_text(data: bytes, position: int, warnings: _Warnings) -> str:
    if data.isascii():
        return data.decode("ascii")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        warnings.add(INVALID_UTF8, position)
        return data.decode("utf-8", errors="replace")
    warnings.add(NON_ASCII_HEADER, position)
    return text


def _lookup_charset(charset: str) -> str | None:
    """Return the codec name for a MIME charset, or None if unknown or not a charset."""
    if len(charset) > MAX_CHARSET_LENGTH or not _CHARSET_NAME.fullmatch(charset):
        return None
    try:
        info = codecs.lookup(charset)
    except LookupError:
        return None
    # Reject bytes-to-bytes and str-to-str codecs (zlib_codec, base64_codec, rot13, ...).
    if getattr(info, "_is_text_encoding", True) is False or info.name in _REJECTED_CODECS:
        return None
    return info.name


def _decode_q(text: str) -> bytes | None:
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "_":
            out.append(0x20)
            i += 1
        elif ch == "=":
            pair = text[i + 1 : i + 3]
            if len(pair) != 2 or not set(pair) <= _HEX:
                return None
            out.append(int(pair, 16))
            i += 3
        elif " " < ch <= "~":
            out.append(ord(ch))
            i += 1
        else:
            return None
    return bytes(out)


def _decode_b(text: str) -> bytes | None:
    if not _B_TEXT.fullmatch(text):
        return None
    stripped = text.rstrip("=")
    if len(stripped) % 4 == 1:
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return binascii.a2b_base64(padded, strict_mode=True)
    except binascii.Error:
        return None


@dataclass(slots=True)
class _Word:
    start: int
    end: int
    charset: str
    data: bytes


def decode_rfc2047(value: str, position: int, warnings: _Warnings) -> str:
    """Decode RFC 2047 encoded-words in ``value``; failures stay raw with a warning."""
    if "=?" not in value:
        return value
    words: list[_Word] = []
    for match in _ENCODED_WORD.finditer(value):
        charset_spec, encoding, etext = match.group(1), match.group(2), match.group(3)
        charset = _lookup_charset(charset_spec.split("*", 1)[0])  # RFC 2231 language suffix
        if charset is None:
            warnings.add(ENCODED_WORD_UNKNOWN_CHARSET, position)
            continue
        enc = encoding.upper()
        if enc == "B":
            data = _decode_b(etext)
        elif enc == "Q":
            data = _decode_q(etext)
        else:
            data = None
        if data is None:
            warnings.add(ENCODED_WORD_INVALID, position)
            continue
        words.append(_Word(match.start(), match.end(), charset, data))

    # Group adjacent words (only whitespace between them) with the same charset so that
    # multi-byte characters split across words decode correctly.
    groups: list[list[_Word]] = []
    for word in words:
        if groups:
            prev = groups[-1][-1]
            gap = value[prev.end : word.start]
            if prev.charset == word.charset and gap.strip(" \t") == "":
                groups[-1].append(word)
                continue
        groups.append([word])

    # Decode each group; if the joined bytes fail, fall back to word by word so one bad
    # word does not leave its valid neighbours undecoded.
    spans: list[tuple[int, int, str | None]] = []
    for group in groups:
        try:
            joined = b"".join(w.data for w in group).decode(group[0].charset)
        except UnicodeDecodeError:
            if len(group) == 1:
                warnings.add(ENCODED_WORD_INVALID, position)
                spans.append((group[0].start, group[0].end, None))
                continue
            for word in group:
                try:
                    spans.append((word.start, word.end, word.data.decode(word.charset)))
                except UnicodeDecodeError:
                    warnings.add(ENCODED_WORD_INVALID, position)
                    spans.append((word.start, word.end, None))
        else:
            spans.append((group[0].start, group[-1].end, joined))

    out: list[str] = []
    cursor = 0
    prev_decoded_end: int | None = None
    for start, end, text in spans:
        gap = value[cursor:start]
        # RFC 2047 section 6.2: whitespace between two decoded encoded-words is dropped.
        if not (text is not None and prev_decoded_end == cursor and gap.strip(" \t") == ""):
            out.append(gap)
        out.append(value[start:end] if text is None else text)
        prev_decoded_end = end if text is not None else None
        cursor = end
    out.append(value[cursor:])
    decoded = "".join(out)

    remaining = _ENCODED_WORD.sub("", value)
    if "=?" in remaining:
        warnings.add(ENCODED_WORD_MALFORMED, position)
    return decoded


def _check_line(line: _Line, warnings: _Warnings) -> None:
    content = line.content
    if b"\r" in content:
        warnings.add(LONE_CR, line.position)
    if len(content) > RFC5322_LINE_LIMIT:
        warnings.add(LINE_OVER_RFC_LIMIT, line.position)
    if any((b < 0x20 and b not in (0x09, 0x0D)) or b == 0x7F for b in content):
        warnings.add(CONTROL_CHARACTER, line.position)


def _build_field(parts: list[_Line], warnings: _Warnings, orphan: bool) -> HeaderField:
    first = parts[0]
    position = first.position
    logical = b"".join(p.content for p in parts)
    if len(logical) > MAX_HEADER_LINE:
        raise MessageTooLarge(HEADER_LINE_TOO_LONG)
    text = _to_text(logical, position, warnings)

    if orphan:
        warnings.add(ORPHAN_CONTINUATION, position)
        raw_value = text.strip(" \t")
        return HeaderField("", raw_value, decode_rfc2047(raw_value, position, warnings), position)

    colon = text.find(":")
    if colon == -1:
        warnings.add(MISSING_COLON, position)
        raw_value = text.strip(" \t")
        return HeaderField("", raw_value, raw_value, position)

    name_part = text[:colon]
    name = name_part.rstrip(" \t")
    if name != name_part:
        warnings.add(SPACE_BEFORE_COLON, position, name)
    if not name:
        warnings.add(EMPTY_NAME, position)
    elif not all(ord(c) in _FTEXT for c in name):
        warnings.add(INVALID_NAME, position)
    raw_value = text[colon + 1 :].strip(" \t")
    return HeaderField(name, raw_value, decode_rfc2047(raw_value, position, warnings), position)


def _is_mbox_from_line(content: bytes) -> bool:
    # "From " separator, but not a "From : x" header with space before the colon.
    return content.startswith(b"From ") and not content[5:].lstrip(_WSP).startswith(b":")


def parse_header_block(raw: bytes) -> HeaderBlock:
    """Parse the header block of a raw RFC 5322 message. See the module docstring."""
    if not isinstance(raw, bytes | bytearray):
        raise TypeError("raw message must be bytes")
    raw = bytes(raw)
    if len(raw) > MAX_RAW_BYTES:
        raise MessageTooLarge(MESSAGE_TOO_LARGE)

    lines, body_offset = _split_header_lines(raw)
    if b"\x00" in raw[:body_offset]:
        raise InvalidMessage(NUL_BYTE)

    warnings = _Warnings()
    endings = {line.ending for line in lines if line.ending}
    if len(endings) > 1:
        warnings.add(MIXED_LINE_ENDINGS, 0)

    if lines and _is_mbox_from_line(lines[0].content):
        warnings.add(MBOX_FROM_LINE, 0)
        lines = lines[1:]

    groups: list[tuple[list[_Line], bool]] = []
    for line in lines:
        _check_line(line, warnings)
        if line.content[:1] in (b" ", b"\t"):
            if groups:
                groups[-1][0].append(line)
            else:
                groups.append(([line], True))
        else:
            groups.append(([line], False))
        if len(groups) > MAX_HEADER_COUNT:
            raise TooManyHeaders(TOO_MANY_HEADERS)

    fields = [_build_field(parts, warnings, orphan) for parts, orphan in groups]
    if not fields:
        warnings.add(NO_HEADERS, 0)

    seen: set[str] = set()
    for field in fields:
        key = field.name.lower()
        if key in SINGLE_INSTANCE_FIELDS:
            if key in seen:
                warnings.add(DUPLICATE_HEADER, field.position, field.name)
            seen.add(key)

    return HeaderBlock(tuple(fields), body_offset, tuple(warnings.items))
