"""MIME structure and size breakdown parser (RFC 2045, RFC 2046, RFC 2231).

Pure and offline: no DNS, no network, no filesystem, no database. Nothing is stored.

``parse_mime`` takes the raw message as ``bytes`` and returns a frozen :class:`MimeSummary`:
the tree of parts in document order (pre-order; each :class:`MimePart` names its ``parent``
and ``children`` by index), size totals, the presence of text/plain and text/html bodies
(informational) and MIME warnings (:class:`~app.parsers.spf.ParseIssue`, ``severity=
"warning"``).

Header block splitting is delegated to :func:`app.parsers.message.parse_header_block`
(M4-01). For the top-level header block its errors propagate unchanged (input over
:data:`~app.parsers.message.MAX_RAW_BYTES`, header caps, NUL in the header block). Inside
the body nothing raises: a nested part whose header block M4-01 rejects is reported with
``part_headers_unparseable`` and treated as a part without headers. Header-block warnings
(M4-01's own codes) are not repeated here; only MIME warnings are returned.

Caps: at most :data:`MAX_MIME_PARTS` parts (the root included), nesting depth at most
:data:`MAX_MIME_DEPTH` (root is depth 0; a container at that depth is kept but not
descended) and boundaries of at most :data:`MAX_BOUNDARY_LEN` characters (RFC 2046 section
5.1.1). Over a cap the parser stops descending, sets ``truncated=True`` and adds a warning.
The tree is walked with an explicit stack, never recursion.

No decoding: bodies are never decoded, decompressed or unpacked. The decoded size is
computed arithmetically from the encoded bytes and flagged with ``decoded_size_estimated``:
base64 is ``data_chars * 3 // 4 - padding`` (whitespace excluded); quoted-printable is an
upper bound (the encoded size); 7bit, 8bit and binary are exact (the encoded size).

Linear time: each multipart body is scanned once for its delimiters with ``bytes.find``
(every loop iteration moves the cursor forward), so total work is bounded by
``MAX_MIME_DEPTH`` passes over the input. Parameter parsing is a single forward scan with no
regular expressions; the only regex is a byte class search for 8-bit data.

Size totals count leaves only (parts that were not descended), so their encoded sizes never
overlap. Categories: ``attachment`` (Content-Disposition attachment, or a non-image part with
a filename), ``inline_image`` (image/* not marked as attachment), ``text`` (text/plain),
``html`` (text/html), ``other``; containers are ``multipart`` or ``message``. Parts of an
attached message/rfc822 are categorised by their own headers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from app.parsers.message import (
    MAX_CHARSET_LENGTH,
    MAX_HEADER_BYTES,
    MAX_RAW_BYTES,
    MESSAGE_TOO_LARGE,
    HeaderBlock,
    MessageParseError,
    MessageTooLarge,
    _lookup_charset,
    _Warnings,
    parse_header_block,
)
from app.parsers.spf import ParseIssue

MAX_MIME_DEPTH = 10
MAX_MIME_PARTS = 200
MAX_BOUNDARY_LEN = 70
MAX_PARAMETERS = 64
MAX_SECTION_DIGITS = 3  # RFC 2231 continuation index digits accepted

# Warning codes (stable, lowercase).
MISSING_BOUNDARY = "missing_boundary"
INVALID_BOUNDARY = "invalid_boundary"
INVALID_PARAMETER = "invalid_parameter"
BOUNDARY_TOO_LONG = "boundary_too_long"
DUPLICATE_BOUNDARY = "duplicate_boundary"
NESTED_BOUNDARY_REUSED = "nested_boundary_reused"
MISSING_CLOSING_BOUNDARY = "missing_closing_boundary"
MULTIPART_NO_PARTS = "multipart_no_parts"
MIME_DEPTH_EXCEEDED = "mime_depth_exceeded"
TOO_MANY_PARTS = "too_many_parts"
INVALID_CONTENT_TYPE = "invalid_content_type"
UNTERMINATED_QUOTE = "unterminated_quote"
DUPLICATE_PARAMETER = "duplicate_parameter"
TOO_MANY_PARAMETERS = "too_many_parameters"
UNKNOWN_CHARSET = "unknown_charset"
INVALID_TRANSFER_ENCODING = "invalid_transfer_encoding"
ENCODED_COMPOSITE = "encoded_composite"
EIGHT_BIT_IN_7BIT = "eight_bit_in_7bit"
NUL_IN_BODY = "nul_in_body"
DUPLICATE_MIME_HEADER = "duplicate_mime_header"
PART_HEADERS_UNPARSEABLE = "part_headers_unparseable"
PART_MISSING_HEADERS = "part_missing_headers"

# Part categories.
CATEGORY_TEXT = "text"
CATEGORY_HTML = "html"
CATEGORY_ATTACHMENT = "attachment"
CATEGORY_INLINE_IMAGE = "inline_image"
CATEGORY_OTHER = "other"
CATEGORY_MULTIPART = "multipart"
CATEGORY_MESSAGE = "message"

VALID_TRANSFER_ENCODINGS: frozenset[str] = frozenset(
    {"7bit", "8bit", "binary", "quoted-printable", "base64"}
)
# RFC 2045 section 6.4: composite types allow only identity encodings.
_IDENTITY_ENCODINGS: frozenset[str] = frozenset({"7bit", "8bit", "binary"})
# Encodings whose encoded form must be 7-bit data.
_SEVEN_BIT_ENCODINGS: frozenset[str] = frozenset({"7bit", "quoted-printable", "base64"})
_MIME_HEADERS = ("content-type", "content-transfer-encoding", "content-disposition")
_TOKEN_STOP = frozenset(' \t"(),/:;<=>?@[\\]')
# RFC 2046 section 5.1.1: bchars := bcharsnospace / " ".
_BCHARS = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'()+_,-./:=? ")
_WS = b" \t\r\n"
_EIGHT_BIT = re.compile(rb"[\x80-\xff]")


@dataclass(frozen=True, slots=True)
class MimePart:
    """One MIME part. Offsets and sizes are in bytes of the raw input."""

    index: int
    parent: int | None
    children: tuple[int, ...]
    depth: int
    content_type: str  # lowercased "type/subtype" (RFC 2045 default when absent/invalid)
    content_type_declared: bool
    charset: str | None
    disposition: str | None  # lowercased disposition type, if any
    has_filename: bool  # presence only; the name itself is never reported
    transfer_encoding: str  # lowercased; "7bit" when absent
    category: str
    offset: int
    header_bytes: int
    encoded_size: int  # body bytes, as transmitted
    estimated_decoded_size: int
    decoded_size_estimated: bool
    nul_bytes: int


@dataclass(frozen=True, slots=True)
class MimeTotals:
    """Byte totals. Category totals are encoded sizes of leaf parts."""

    total_bytes: int
    header_bytes: int
    body_bytes: int
    text_bytes: int
    html_bytes: int
    attachment_bytes: int
    inline_image_bytes: int
    other_bytes: int
    nul_bytes: int


@dataclass(frozen=True, slots=True)
class MimeSummary:
    """MIME tree, totals and warnings for one raw message."""

    parts: tuple[MimePart, ...]
    totals: MimeTotals
    has_text_plain: bool
    has_text_html: bool
    has_alternative: bool  # a multipart/alternative with text/plain and text/html children
    max_depth: int
    truncated: bool
    warnings: tuple[ParseIssue, ...]


@dataclass(slots=True)
class _Task:
    start: int
    end: int
    depth: int
    parent: int | None
    in_digest: bool
    ancestors: tuple[bytes, ...]


@dataclass(slots=True)
class _Params:
    value: str
    params: dict[str, str]


def _parse_params(text: str, position: int, warnings: _Warnings) -> _Params:
    """Split ``value; name=val; ...`` (RFC 2045 section 5.1, RFC 2231 section 3).

    Single forward scan: every iteration moves ``i`` strictly forward. Parameter names are
    lowercased; RFC 2231 continuations are joined in index order (not percent-decoded).
    """
    n = len(text)
    semi = text.find(";")
    head = text if semi == -1 else text[:semi]
    plain: dict[str, str] = {}
    continued: dict[str, list[tuple[int, str]]] = {}
    i = n if semi == -1 else semi + 1
    count = 0
    while i < n:
        while i < n and text[i] in " \t;":
            i += 1
        if i >= n:
            break
        count += 1
        if count > MAX_PARAMETERS:
            warnings.add(TOO_MANY_PARAMETERS, position)
            break
        sc = text.find(";", i)
        seg_end = n if sc == -1 else sc
        eq = text.find("=", i, seg_end)
        if eq == -1:  # attribute without a value: ignored
            i = seg_end + 1
            continue
        name = text[i:eq].strip(" \t").lower()
        j = eq + 1
        while j < n and text[j] in " \t":
            j += 1
        if j < n and text[j] == '"':
            buf: list[str] = []
            k = j + 1
            closed = False
            while k < n:
                ch = text[k]
                if ch == "\\" and k + 1 < n:
                    buf.append(text[k + 1])
                    k += 2
                elif ch == '"':
                    closed = True
                    k += 1
                    break
                else:
                    buf.append(ch)
                    k += 1
            if not closed:
                warnings.add(UNTERMINATED_QUOTE, position)
            value = "".join(buf)
            sc = text.find(";", k)
            i = n if sc == -1 else sc + 1
        else:
            value = text[j:seg_end].strip(" \t")
            i = seg_end + 1
        if not name:
            continue
        base, star, rest = name.partition("*")
        if star:
            # RFC 2231: name*, name*N or name*N*. The index is at most MAX_SECTION_DIGITS
            # ASCII digits, so int() never sees unbounded input.
            extended = rest.endswith("*") or not rest
            index_text = rest[:-1] if rest.endswith("*") else rest
            if not rest:
                index = 0
            elif (
                0 < len(index_text) <= MAX_SECTION_DIGITS
                and index_text.isascii()
                and index_text.isdigit()
            ):
                index = int(index_text)
            else:
                warnings.add(INVALID_PARAMETER, position, base)
                continue
            # Extended value (charset'language'text): keep the text part.
            if extended and index == 0 and value.count("'") >= 2:
                value = value.split("'", 2)[2]
            continued.setdefault(base, []).append((index, value))
        elif base in plain:
            code = DUPLICATE_BOUNDARY if base == "boundary" else DUPLICATE_PARAMETER
            warnings.add(code, position, base)
        else:
            plain[base] = value
    for base, segments in continued.items():
        if base not in plain:
            plain[base] = "".join(v for _, v in sorted(segments, key=lambda s: s[0]))
    return _Params(head.split("(", 1)[0].strip(" \t").lower(), plain)


def _is_token(text: str) -> bool:
    return (
        bool(text)
        and text.isascii()
        and all(" " < c < "\x7f" for c in text)
        and not (set(text) & _TOKEN_STOP)
    )


@dataclass(slots=True)
class _Split:
    spans: list[tuple[int, int]]
    closed: bool
    truncated: bool


def _split_multipart(raw: bytes, start: int, end: int, boundary: bytes) -> _Split:
    """Find the body parts of a multipart body ``raw[start:end]`` (RFC 2046 section 5.1.1).

    A delimiter is ``--boundary`` at the start of a line, optionally ``--`` (close), then
    optional transport padding (SP/HTAB) and a line ending or the end of the region. The
    line ending before a delimiter belongs to the delimiter. Linear: ``pos`` only grows.
    """
    delim = b"--" + boundary
    found: list[tuple[int, int]] = []  # (delimiter start, content start after its line)
    closed = False
    truncated = False
    pos = start
    while pos < end:
        hit = raw.find(delim, pos, end)
        if hit == -1:
            break
        pos = hit + 1
        if hit != start and raw[hit - 1] != 0x0A:
            continue
        q = hit + len(delim)
        closing = raw.startswith(b"--", q, end)
        if closing:
            q += 2
        while q < end and raw[q] in (0x20, 0x09):
            q += 1
        if q < end:
            if raw[q] == 0x0A:
                q += 1
            elif raw[q] == 0x0D and q + 1 < end and raw[q + 1] == 0x0A:
                q += 2
            else:
                continue  # text after the boundary: not a delimiter line
        found.append((hit, q))
        pos = max(pos, q)
        if closing:
            closed = True
            break
        if len(found) > MAX_MIME_PARTS:
            truncated = True
            break

    spans: list[tuple[int, int]] = []
    for idx, (_, content_start) in enumerate(found):
        if idx + 1 < len(found):
            content_end = found[idx + 1][0]
            if content_end > content_start and raw[content_end - 1] == 0x0A:
                content_end -= 1
                if content_end > content_start and raw[content_end - 1] == 0x0D:
                    content_end -= 1
        elif closed or truncated:
            break  # the closing delimiter (or the cut) starts no part
        else:
            content_end = end
        spans.append((content_start, content_end))
    return _Split(spans, closed, truncated)


def _part_headers(raw: bytes, start: int, end: int, warnings: _Warnings) -> HeaderBlock | None:
    # Only the first MAX_HEADER_BYTES + 1 bytes can belong to an acceptable header block;
    # M4-01 raises header_block_too_large if no empty line ends it within that prefix.
    chunk = raw[start : min(end, start + MAX_HEADER_BYTES + 1)]
    try:
        block = parse_header_block(chunk)
    except MessageParseError:
        warnings.add(PART_HEADERS_UNPARSEABLE, start)
        return None
    if block.fields and block.fields[0].name == "":
        warnings.add(PART_MISSING_HEADERS, start)
        return None
    return block


def _first(block: HeaderBlock | None, name: str, position: int, warnings: _Warnings) -> str | None:
    if block is None:
        return None
    found = block.get_all(name)
    if not found:
        return None
    if len(found) > 1:
        warnings.add(DUPLICATE_MIME_HEADER, position, name)
    return found[0].raw_value


def _base64_estimate(raw: bytes, start: int, end: int) -> int:
    whitespace = sum(raw.count(bytes([b]), start, end) for b in _WS)
    data_chars = end - start - whitespace
    padding = 0
    q = end - 1
    while q >= start and padding < 2:
        byte = raw[q]
        if byte == 0x3D:
            padding += 1
        elif byte not in _WS:
            break
        q -= 1
    return max(0, data_chars * 3 // 4 - padding)


def _leaf_category(ctype: str, disposition: str | None, has_filename: bool) -> str:
    if disposition == "attachment":
        return CATEGORY_ATTACHMENT
    if ctype.startswith("image/"):
        return CATEGORY_INLINE_IMAGE
    if has_filename:
        return CATEGORY_ATTACHMENT
    if ctype == "text/plain":
        return CATEGORY_TEXT
    if ctype == "text/html":
        return CATEGORY_HTML
    return CATEGORY_OTHER


def parse_mime(raw: bytes) -> MimeSummary:
    """Summarise the MIME structure of a raw message. See the module docstring."""
    if not isinstance(raw, bytes | bytearray):
        raise TypeError("raw message must be bytes")
    raw = bytes(raw)
    if len(raw) > MAX_RAW_BYTES:
        raise MessageTooLarge(MESSAGE_TOO_LARGE)
    top = parse_header_block(raw)

    warnings = _Warnings()
    nodes: list[MimePart] = []
    child_lists: list[list[int]] = []
    truncated = False
    stack = [_Task(0, len(raw), 0, None, False, ())]

    while stack:
        task = stack.pop()
        if len(nodes) >= MAX_MIME_PARTS:
            truncated = True
            warnings.add(TOO_MANY_PARTS, task.start)
            break
        pos = task.start
        block = top if task.parent is None else _part_headers(raw, pos, task.end, warnings)
        header_len = block.body_offset if block is not None else 0
        body_start = min(task.start + header_len, task.end)
        body_end = task.end

        # Content-Type (RFC 2045 section 5.2 defaults; RFC 2046 section 5.1.5 for digest).
        default_type = "message/rfc822" if task.in_digest else "text/plain"
        ctype_raw = _first(block, "content-type", pos, warnings)
        params: dict[str, str] = {}
        declared = ctype_raw is not None
        ctype = default_type
        if ctype_raw is not None:
            parsed = _parse_params(ctype_raw, pos, warnings)
            params = parsed.params
            main, slash, sub = parsed.value.partition("/")
            if slash and _is_token(main) and _is_token(sub):
                ctype = parsed.value
            else:
                warnings.add(INVALID_CONTENT_TYPE, pos)
                ctype, params = "text/plain", {}

        charset: str | None = None
        if "charset" in params:
            charset = params["charset"].strip(" \t").lower()[:MAX_CHARSET_LENGTH]
            if _lookup_charset(charset) is None:
                warnings.add(UNKNOWN_CHARSET, pos)

        disposition: str | None = None
        has_filename = "name" in params
        disp_raw = _first(block, "content-disposition", pos, warnings)
        if disp_raw is not None:
            disp = _parse_params(disp_raw, pos, warnings)
            disposition = disp.value or None
            has_filename = has_filename or "filename" in disp.params

        cte = "7bit"
        cte_raw = _first(block, "content-transfer-encoding", pos, warnings)
        if cte_raw is not None:
            cte = cte_raw.split("(", 1)[0].strip(" \t").lower()
            if cte not in VALID_TRANSFER_ENCODINGS:
                warnings.add(INVALID_TRANSFER_ENCODING, pos)

        # Decide whether to descend.
        child_spans: list[tuple[int, int]] = []
        child_boundary: bytes | None = None
        container = ctype.startswith("multipart/") or ctype == "message/rfc822"
        if container and cte not in _IDENTITY_ENCODINGS:
            warnings.add(ENCODED_COMPOSITE, pos)
            container = False
        elif container and ctype.startswith("multipart/"):
            boundary_text = params.get("boundary", "").rstrip(" ")
            if not boundary_text:
                warnings.add(MISSING_BOUNDARY, pos)
                container = False
            elif not boundary_text.isascii() or not boundary_text.isprintable():
                warnings.add(INVALID_BOUNDARY, pos)
                container = False
            elif len(boundary_text) > MAX_BOUNDARY_LEN:
                warnings.add(BOUNDARY_TOO_LONG, pos)
                truncated = True
                container = False
            else:
                if not set(boundary_text) <= _BCHARS:
                    # Printable ASCII outside RFC 2046 bchars: warn, still split (lenient).
                    warnings.add(INVALID_BOUNDARY, pos)
                child_boundary = boundary_text.encode("ascii")
                if child_boundary in task.ancestors:
                    warnings.add(NESTED_BOUNDARY_REUSED, pos)
        if container and task.depth >= MAX_MIME_DEPTH:
            warnings.add(MIME_DEPTH_EXCEEDED, pos)
            truncated = True
            container = False
        if container:
            if child_boundary is not None:
                split = _split_multipart(raw, body_start, body_end, child_boundary)
                child_spans = split.spans
                if split.truncated:
                    warnings.add(TOO_MANY_PARTS, pos)
                    truncated = True
                elif not split.spans:
                    warnings.add(MULTIPART_NO_PARTS, pos)
                elif not split.closed:
                    warnings.add(MISSING_CLOSING_BOUNDARY, pos)
            else:
                child_spans = [(body_start, body_end)]

        encoded = body_end - body_start
        nul = 0
        estimate = encoded
        estimated = False
        if container:
            category = CATEGORY_MULTIPART if ctype.startswith("multipart/") else CATEGORY_MESSAGE
        else:
            category = _leaf_category(ctype, disposition, has_filename)
            nul = raw.count(b"\x00", body_start, body_end)
            if nul:
                warnings.add(NUL_IN_BODY, body_start)
            if cte in _SEVEN_BIT_ENCODINGS and _EIGHT_BIT.search(raw, body_start, body_end):
                warnings.add(EIGHT_BIT_IN_7BIT, body_start)
            if cte == "base64":
                estimate, estimated = _base64_estimate(raw, body_start, body_end), True
            elif cte == "quoted-printable":
                estimated = True  # decoded size <= encoded size

        index = len(nodes)
        nodes.append(
            MimePart(
                index=index,
                parent=task.parent,
                children=(),
                depth=task.depth,
                content_type=ctype,
                content_type_declared=declared,
                charset=charset,
                disposition=disposition,
                has_filename=has_filename,
                transfer_encoding=cte,
                category=category,
                offset=task.start,
                header_bytes=body_start - task.start,
                encoded_size=encoded,
                estimated_decoded_size=estimate,
                decoded_size_estimated=estimated,
                nul_bytes=nul,
            )
        )
        child_lists.append([])
        if task.parent is not None:
            child_lists[task.parent].append(index)

        ancestors = task.ancestors + ((child_boundary,) if child_boundary is not None else ())
        in_digest = ctype == "multipart/digest"
        for span_start, span_end in reversed(child_spans):
            stack.append(_Task(span_start, span_end, task.depth + 1, index, in_digest, ancestors))

    parts = tuple(replace(node, children=tuple(child_lists[node.index])) for node in nodes)
    leaves = [p for p in parts if p.category not in (CATEGORY_MULTIPART, CATEGORY_MESSAGE)]

    def total(category: str) -> int:
        return sum(p.encoded_size for p in leaves if p.category == category)

    has_alternative = any(
        p.content_type == "multipart/alternative"
        and {"text/plain", "text/html"} <= {parts[c].content_type for c in p.children}
        for p in parts
    )
    totals = MimeTotals(
        total_bytes=len(raw),
        header_bytes=top.body_offset,
        body_bytes=len(raw) - top.body_offset,
        text_bytes=total(CATEGORY_TEXT),
        html_bytes=total(CATEGORY_HTML),
        attachment_bytes=total(CATEGORY_ATTACHMENT),
        inline_image_bytes=total(CATEGORY_INLINE_IMAGE),
        other_bytes=total(CATEGORY_OTHER),
        nul_bytes=sum(p.nul_bytes for p in leaves),
    )
    return MimeSummary(
        parts=parts,
        totals=totals,
        has_text_plain=any(p.category == CATEGORY_TEXT for p in leaves),
        has_text_html=any(p.category == CATEGORY_HTML for p in leaves),
        has_alternative=has_alternative,
        max_depth=max(p.depth for p in parts),
        truncated=truncated,
        warnings=tuple(warnings.items),
    )
