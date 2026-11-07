"""List-Unsubscribe and One-Click header facts (M5-10). Facts only; verdicts are M5-14.

Pure and offline: no DNS, no HTTP. Nothing is fetched or POSTed (a One-Click POST test would
need the guarded client, M7). Header values are hostile input.

Input: header fields already parsed by ``app.parsers.message.parse_header_block`` (unfolded,
duplicates kept, surrounding whitespace stripped). The URI syntax is read from ``raw_value``,
never from ``decoded_value``: an RFC 2047 encoded-word is not a URI, so a field whose decoded
value differs from its raw value only sets ``encoded_word``.

Sources (texts read at rfc-editor.org; vendor requirements are out of scope, M9 data):

- RFC 2369 section 2 (command syntax): the content is angle-bracket enclosed URLs; whitespace
  inside the brackets is to be ignored by clients; several URLs are comma separated, in order
  of preference. Client rules: (1) if the content, after leading whitespace and comments, does
  not start with ``<`` the field SHOULD be ignored; (2) characters after a bracketed URL SHOULD
  be ignored unless the first non-whitespace/comment character is a comma; (3) if a sub-item is
  not a bracketed URL, it and all later sub-items SHOULD be ignored. Implemented here as
  ``syntax_error`` codes ``not_bracketed``, ``trailing_text`` and ``non_uri_item``; the ignored
  part never contributes URIs.
- RFC 2369 section 3: no more than one of each list field in a message (``duplicated``).
- RFC 2369 section 3.2: List-Unsubscribe, with examples using mailto (with ``?subject=`` /
  ``?body=``) and http URLs and a leading comment.
- RFC 8058 section 3.1 (mail senders): one List-Unsubscribe and one List-Unsubscribe-Post field;
  List-Unsubscribe MUST contain one HTTPS URI and MAY contain other non-HTTP/S URIs;
  List-Unsubscribe-Post MUST contain the single key/value pair ``List-Unsubscribe=One-Click``;
  a valid DKIM signature MUST cover at least both fields.
- RFC 8058 section 4: both fields MUST be in the ``h=`` tag of a valid DKIM-Signature; without
  it the receiver SHOULD NOT offer one-click.
- RFC 8058 section 5: ABNF ``postarg = "List-Unsubscribe=One-Click"``. ABNF literal strings are
  case insensitive (RFC 5234 section 2.3), so ``post_value_matches_abnf`` compares ASCII
  case-insensitively while ``post_value_exact`` compares exactly. The ABNF also allows at most
  one WSP before the value; the header parser strips surrounding whitespace, so that is not
  evaluated here.

Derived facts (definitions chosen here, not taken from the RFCs):

- ``one_click_eligible``: exactly one List-Unsubscribe field with a parsed ``https`` URI that
  has a valid host, and exactly one List-Unsubscribe-Post field whose value matches the ABNF.
  DKIM coverage is a separate fact (``one_click_signed``) because it may be unknown.
- ``dkim_signed_headers``: the caller passes one ``h=`` list per DKIM signature it has verified
  as valid. ``None`` means unknown and every ``*_signed`` fact is ``None`` (never "ok"); an
  empty list means "no valid signature" and the facts are ``False``. Names are compared ASCII
  case-insensitively. When a field is duplicated, a name in ``h=`` does not say which instance
  is signed; ``duplicated`` is reported alongside.
- ``https_uri_present`` / ``http_uri_present`` / ``mailto_uri_present`` are ``None`` (unknown)
  instead of ``False`` when part of the input was not evaluated (field or URI caps, over-long
  value, NUL byte, a URI of that kind that could not be read).
- mailto (RFC 6068 section 2): addresses come from the ``to`` part and from ``to=`` hfields;
  ``mailto:?to=a@x.example`` is valid. Undecodable percent-encoding, a malformed hfield with no
  address found, or a quoted-string local part make the URI not evaluated.
- https URIs whose authority is not introduced by exactly ``//`` (RFC 3986 sections 3 and 3.2;
  ``https:x.example/u``, ``https:///x.example/u``, backslashes instead of slashes) keep the host a
  browser would use but set ``nonstandard_authority`` and do not count for
  ``https_uri_present`` or One-Click.

Host extraction for http(s) URIs reuses the M5-09 static link analysis
(``app.parsers.content_links.analyze_links``). Caps (:data:`MAX_FIELDS`, :data:`MAX_URIS`,
:data:`MAX_VALUE_LENGTH`, :data:`MAX_URI_LENGTH`, :data:`MAX_POST_ECHO`) are conservative bounds
chosen here, not taken from any specification. All scans are linear in the input size.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, replace
from urllib.parse import unquote_to_bytes

from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.parsers.content_links import LinkInfo, LinkLimits, analyze_links
from app.parsers.message import HeaderBlock, HeaderField

LIST_UNSUBSCRIBE = "list-unsubscribe"
LIST_UNSUBSCRIBE_POST = "list-unsubscribe-post"
ONE_CLICK_VALUE = "List-Unsubscribe=One-Click"

MAX_FIELDS = 10  # instances of each field analyzed
MAX_URIS = 32  # URIs analyzed per field
MAX_VALUE_LENGTH = 8192  # characters of a field value
MAX_URI_LENGTH = 2048  # characters of one URI
MAX_POST_ECHO = 128  # characters of a List-Unsubscribe-Post value kept in the facts

# Field-level syntax error codes.
EMPTY_VALUE = "empty_value"
NOT_BRACKETED = "not_bracketed"  # RFC 2369 section 2, rule 1
TRAILING_TEXT = "trailing_text"  # RFC 2369 section 2, rule 2
NON_URI_ITEM = "non_uri_item"  # RFC 2369 section 2, rule 3
UNTERMINATED_BRACKET = "unterminated_bracket"
UNTERMINATED_COMMENT = "unterminated_comment"
VALUE_TOO_LONG = "value_too_long"
NUL_BYTE = "nul_byte"

_WSP = " \t\r\n"
_NO_WSP = str.maketrans("", "", _WSP)


@dataclass(frozen=True)
class UnsubscribeUri:
    index: int  # position in the field's URI list
    uri: str | None  # bracket content with whitespace removed; None when over the length cap
    kind: str  # https | http | mailto | other | relative | empty | too_long
    scheme: str | None = None  # lowercase
    host: str | None = None  # http(s): ASCII host or canonical IP literal
    ip_literal: bool = False
    has_userinfo: bool = False
    mailto_domain: str | None = None  # ASCII domain of the first mailto address
    mailto_has_query: bool = False  # ?subject=, ?body=, ...
    whitespace_removed: bool = False  # whitespace inside the brackets (RFC 2369 section 2)
    # http(s) without a "//" authority (RFC 3986 sections 3 and 3.2), see M5-09 LinkInfo; the
    # host is still extracted, but such an https URI does not count for One-Click.
    nonstandard_authority: bool = False
    evaluated: bool = True  # False: the URI could not be read (e.g. bad mailto encoding)
    # control_character | host_* / empty_host / invalid_ipv4 / invalid_ipv6 / port (M5-09) |
    # mailto_no_address | mailto_domain_<reason> | not evaluated: mailto_percent_encoding,
    # mailto_hfield, mailto_quoted_local_part
    malformed: str | None = None


@dataclass(frozen=True)
class ListUnsubscribeField:
    position: int  # byte offset of the field in the message (HeaderField.position)
    uris: tuple[UnsubscribeUri, ...] = ()
    syntax_error: str | None = None
    evaluated: bool = True  # False: value over the cap or containing NUL; nothing parsed
    capped: bool = False  # more than MAX_URIS bracketed URIs; the rest were not analyzed
    comments: bool = False  # RFC 5322 style comments between items
    encoded_word: bool = False  # decoded_value differs from raw_value (RFC 2047)


@dataclass(frozen=True)
class ListUnsubscribeFacts:
    present: bool = False
    field_count: int = 0
    duplicated: bool = False  # RFC 2369 section 3 / RFC 8058 section 3.1: one field
    fields: tuple[ListUnsubscribeField, ...] = ()  # first MAX_FIELDS instances
    https_uri_present: bool | None = False  # https URI, valid host, "//" authority
    http_uri_present: bool | None = False  # http (non-TLS) URI with a valid host
    mailto_uri_present: bool | None = False  # mailto URI with a valid domain
    post_present: bool = False
    post_count: int = 0
    post_duplicated: bool = False
    post_values: tuple[str, ...] = ()  # raw values capped at MAX_POST_ECHO, controls -> U+FFFD
    post_value_exact: bool | None = None  # None: no Post field; True: every value is exact
    post_value_matches_abnf: bool | None = None  # ASCII case-insensitive (RFC 5234 2.3)
    one_click_eligible: bool = False
    list_unsubscribe_signed: bool | None = None  # None: unknown or field absent
    post_signed: bool | None = None
    one_click_signed: bool | None = None  # both names in the same h= list


class _Unterminated(Exception):
    pass


def _skip_cfws(value: str, i: int) -> tuple[int, bool]:
    """Skip whitespace and (nested, backslash-quoted) comments. Returns (index, saw_comment)."""
    n = len(value)
    saw = False
    while i < n:
        c = value[i]
        if c in _WSP:
            i += 1
        elif c == "(":
            saw = True
            depth = 0
            while i < n:
                c = value[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            else:
                raise _Unterminated
        else:
            break
    return i, saw


def _split_items(value: str) -> tuple[list[str], str | None, bool, bool]:
    """Bracketed URIs per RFC 2369 section 2. Returns (items, error, capped, comments)."""
    n = len(value)
    items: list[str] = []
    comments = False
    try:
        i, saw = _skip_cfws(value, 0)
        comments |= saw
        if i == n:
            return items, EMPTY_VALUE, False, comments
        if value[i] != "<":
            return items, NOT_BRACKETED, False, comments
        while True:
            if len(items) == MAX_URIS:
                return items, None, True, comments
            end = value.find(">", i + 1)
            if end < 0:
                return items, UNTERMINATED_BRACKET, False, comments
            items.append(value[i + 1 : end])
            i, saw = _skip_cfws(value, end + 1)
            comments |= saw
            if i == n:
                return items, None, False, comments
            if value[i] != ",":
                return items, TRAILING_TEXT, False, comments
            i, saw = _skip_cfws(value, i + 1)
            comments |= saw
            if i == n or value[i] != "<":
                return items, NON_URI_ITEM, False, comments
    except _Unterminated:
        return items, UNTERMINATED_COMMENT, False, comments


def _has_controls(value: str) -> bool:
    return any(unicodedata.category(c) == "Cc" for c in value)


def _pct(text: str) -> str:
    """Percent-decode as UTF-8; raises UnicodeDecodeError on invalid UTF-8."""
    return unquote_to_bytes(text).decode("utf-8")


def _mailto(uri: UnsubscribeUri, text: str) -> UnsubscribeUri:
    """RFC 6068 section 2: ``"mailto:" [ to ] [ hfields ]``; addresses are in ``to`` and in
    ``to=`` hfields (``mailto:?to=a@x.example`` is valid). The first address's domain is
    reported. Input that cannot be read is ``evaluated=False``, never "no address"."""
    body = text.split(":", 1)[1]
    to_part, sep, query = body.partition("?")
    base = UnsubscribeUri(
        uri.index,
        uri.uri,
        "mailto",
        scheme="mailto",
        mailto_has_query=bool(sep),
        whitespace_removed=uri.whitespace_removed,
    )
    bad_hfield = False
    try:
        encoded = [to_part] if to_part else []
        for hfield in query.split("&") if sep else []:
            name, eq, value = hfield.partition("=")
            if not eq:
                bad_hfield = True  # RFC 6068 section 2: hfield = hfname "=" hfvalue
            elif _pct(name).lower() == "to":
                encoded.append(value)
        addresses = [a for part in encoded for a in _pct(part).split(",") if a]
    except UnicodeDecodeError:
        return replace(base, malformed="mailto_percent_encoding", evaluated=False)
    if not addresses:
        if bad_hfield:
            return replace(base, malformed="mailto_hfield", evaluated=False)
        return replace(base, malformed="mailto_no_address")
    first = addresses[0]
    if '"' in first:
        # A quoted-string local part may contain "," or "@"; not split reliably here.
        return replace(base, malformed="mailto_quoted_local_part", evaluated=False)
    local, at, domain = first.rpartition("@")
    if not at or not local:
        return replace(base, malformed="mailto_no_address")
    try:
        return replace(base, mailto_domain=to_ascii_domain(domain))
    except InvalidDomainName as exc:
        return replace(base, malformed=f"mailto_domain_{exc.reason}")


def _from_link(uri: UnsubscribeUri, text: str, link: LinkInfo) -> UnsubscribeUri:
    if link.kind == "too_long":
        return replace(uri, uri=None, kind="too_long")
    if link.kind == "empty":
        return replace(uri, kind="empty")
    if link.kind == "relative" or link.protocol_relative:
        return replace(uri, kind="relative")
    if link.kind == "mailto":
        return _mailto(uri, text)
    if link.kind == "web" and link.scheme in ("http", "https"):
        return replace(
            uri,
            kind=link.scheme,
            scheme=link.scheme,
            host=link.host,
            ip_literal=link.ip_literal,
            has_userinfo=link.has_userinfo,
            nonstandard_authority=link.nonstandard_authority,
            malformed=link.malformed,
        )
    return replace(uri, kind="other", scheme=link.scheme)


def _analyze_uris(items: list[str]) -> tuple[UnsubscribeUri, ...]:
    texts = [item.translate(_NO_WSP) for item in items]
    links = analyze_links(
        [("", t) for t in texts],
        sender_domains=(),
        shorteners=(),
        limits=LinkLimits(max_links=MAX_URIS, max_url_length=MAX_URI_LENGTH),
    ).links
    out: list[UnsubscribeUri] = []
    for i, (item, text, link) in enumerate(zip(items, texts, links, strict=True)):
        base = UnsubscribeUri(i, text, "other", whitespace_removed=text != item)
        uri = _from_link(base, text, link)
        if uri.malformed is None and uri.kind != "too_long" and _has_controls(text):
            uri = replace(uri, malformed="control_character")
        out.append(uri)
    return tuple(out)


def _analyze_field(field: HeaderField) -> ListUnsubscribeField:
    raw = field.raw_value
    encoded = field.decoded_value != raw
    if "\x00" in raw:
        return ListUnsubscribeField(field.position, (), NUL_BYTE, False, encoded_word=encoded)
    if len(raw) > MAX_VALUE_LENGTH:
        return ListUnsubscribeField(field.position, (), VALUE_TOO_LONG, False, encoded_word=encoded)
    items, error, capped, comments = _split_items(raw)
    return ListUnsubscribeField(
        field.position,
        _analyze_uris(items),
        error,
        True,
        capped,
        comments,
        encoded,
    )


def _presence(fields: tuple[ListUnsubscribeField, ...], total: int, kind: str) -> bool | None:
    for f in fields:
        for uri in f.uris:
            if uri.kind == kind and uri.malformed is None:
                if kind == "https" and uri.nonstandard_authority:
                    continue
                return True
    unknown = total > len(fields) or any(
        not f.evaluated
        or f.capped
        or any(u.kind == "too_long" or (u.kind == kind and not u.evaluated) for u in f.uris)
        for f in fields
    )
    return None if unknown else False


def _signed_sets(dkim_signed_headers: Iterable[Iterable[str]]) -> list[frozenset[str]]:
    out: list[frozenset[str]] = []
    for h in dkim_signed_headers:
        if isinstance(h, str):
            raise TypeError("dkim_signed_headers must be an iterable of h= name lists")
        out.append(frozenset(name.strip(_WSP).lower() for name in h if isinstance(name, str)))
    return out


def _fields(fields: list[HeaderField], name: str) -> list[HeaderField]:
    return [f for f in fields if f.name and f.name.lower() == name]


def _echo(value: str) -> str:
    """Capped copy of a value for the facts; control characters (NUL, ...) become U+FFFD."""
    return "".join(
        "\ufffd" if unicodedata.category(c) == "Cc" else c for c in value[:MAX_POST_ECHO]
    )


def analyze_list_unsubscribe(
    headers: HeaderBlock | Iterable[HeaderField],
    *,
    dkim_signed_headers: Iterable[Iterable[str]] | None = None,
) -> ListUnsubscribeFacts:
    """Facts about List-Unsubscribe / List-Unsubscribe-Post. See the module docstring."""
    all_fields = list(headers.fields) if isinstance(headers, HeaderBlock) else list(headers)
    lu = _fields(all_fields, LIST_UNSUBSCRIBE)
    post = _fields(all_fields, LIST_UNSUBSCRIBE_POST)

    analyzed = tuple(_analyze_field(f) for f in lu[:MAX_FIELDS])
    https = _presence(analyzed, len(lu), "https")
    http = _presence(analyzed, len(lu), "http")
    mailto = _presence(analyzed, len(lu), "mailto")

    post_raw = [f.raw_value for f in post]
    exact: bool | None = None
    abnf: bool | None = None
    if post_raw:
        exact = all(v == ONE_CLICK_VALUE for v in post_raw)
        abnf = all(v.isascii() and v.lower() == ONE_CLICK_VALUE.lower() for v in post_raw)

    eligible = len(lu) == 1 and https is True and len(post) == 1 and abnf is True

    lu_signed: bool | None = None
    post_signed: bool | None = None
    both_signed: bool | None = None
    if dkim_signed_headers is not None:
        sets = _signed_sets(dkim_signed_headers)
        if lu:
            lu_signed = any(LIST_UNSUBSCRIBE in s for s in sets)
        if post:
            post_signed = any(LIST_UNSUBSCRIBE_POST in s for s in sets)
        if lu and post:
            both_signed = any(LIST_UNSUBSCRIBE in s and LIST_UNSUBSCRIBE_POST in s for s in sets)

    return ListUnsubscribeFacts(
        present=bool(lu),
        field_count=len(lu),
        duplicated=len(lu) > 1,
        fields=analyzed,
        https_uri_present=https,
        http_uri_present=http,
        mailto_uri_present=mailto,
        post_present=bool(post),
        post_count=len(post),
        post_duplicated=len(post) > 1,
        post_values=tuple(_echo(v) for v in post_raw[:MAX_FIELDS]),
        post_value_exact=exact,
        post_value_matches_abnf=abnf,
        one_click_eligible=eligible,
        list_unsubscribe_signed=lu_signed,
        post_signed=post_signed,
        one_click_signed=both_signed,
    )


__all__ = [
    "ListUnsubscribeFacts",
    "ListUnsubscribeField",
    "UnsubscribeUri",
    "analyze_list_unsubscribe",
]
