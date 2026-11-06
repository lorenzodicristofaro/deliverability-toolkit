"""DMARC record parser (RFC 7489 sections 6.3 and 6.4).

Pure syntax: no DNS, no network, no organizational-domain fallback, no external
destination authorization (M3-11) and no findings (M3-09/10).

``parse_dmarc`` never raises on bad input. It returns a :class:`DmarcRecord` with every
tag found (unknown tags are kept) and a list of :class:`ParseIssue` (shared with the SPF
parser). Severity convention:

- ``"error"``: the record or tag does not match the RFC 7489 section 6.4 ABNF, violates a
  MUST of section 6.3 (``v`` first and exactly ``DMARC1``, ``p`` present, ``pct`` 0-100,
  ``ri`` 32-bit) or RFC 6376 section 3.2 (no duplicate tags), or could not be fully parsed
  (resource bounds). Section 6.3 says syntax errors outside ``v``/``p`` SHOULD be discarded
  in favour of defaults, so an error on such a tag does not mean receivers ignore the record;
  checks decide the impact.
- ``"warning"``: accepted but unusual (unknown tag, uppercase value, non-``mailto`` URI).

Grammar notes, all from the RFC text:

- The record is a DKIM-style tag-list (RFC 7489 section 6.3 referencing RFC 6376
  section 3.2): ``tag-name = ALPHA *( ALPHA / DIGIT / "_" )``, values are ``%x21-3A /
  %x3C-7E`` plus inner whitespace. Whitespace (SP / HTAB) around ``;`` and ``=`` is allowed
  by ``dmarc-sep`` and ``*WSP "=" *WSP``.
- ABNF quoted strings are case-insensitive (RFC 5234 section 2.3), so ``P=Reject`` matches
  the grammar; it is reported as a warning. The version uses ``%x`` values and "MUST match
  precisely", so ``v=dmarc1`` is an error. RFC 6376 says tags are case-sensitive; tag names
  are matched case-insensitively here (ticket M3-05) with an ``uppercase_tag_name`` warning.
- ``dmarc-record`` starts with ``dmarc-version`` (no leading whitespace) followed by
  ``dmarc-sep``; a bare ``v=DMARC1`` is accepted because section 7.1 uses it for external
  report authorization records.
- ``dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]``; commas and ``!`` inside a
  URI MUST be percent-encoded, units are powers of two and the number fits in 64 bits.
- ``rf`` keywords follow RFC 5321 ``Ldh-str``; only ``afrf`` is registered.
- DMARCbis tags (``np``, ``psd``, ``t``) are NOT recognised: their RFC status was not
  verified for this ticket (unverified), so they are kept as unknown tags.

Resource bounds: input is cut at :data:`MAX_RECORD_LENGTH` characters, :data:`MAX_TAGS`
tags and :data:`MAX_URIS` report URIs (rua + ruf). Every step is a linear scan; no regular
expressions are used.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.parsers.spf import IssueSeverity, ParseIssue

MAX_RECORD_LENGTH = 4096
MAX_TAGS = 50
MAX_URIS = 20

VERSION = "DMARC1"
POLICIES: frozenset[str] = frozenset({"none", "quarantine", "reject"})
ALIGNMENTS: frozenset[str] = frozenset({"r", "s"})
FO_OPTIONS: frozenset[str] = frozenset({"0", "1", "d", "s"})
REGISTERED_REPORT_FORMATS: frozenset[str] = frozenset({"afrf"})
KNOWN_TAGS: frozenset[str] = frozenset(
    {"v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"}
)
MAX_RI = 2**32 - 1
MAX_SIZE_NUMBER = 2**64 - 1
SIZE_UNITS: dict[str, int] = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30, "t": 2**40}

# Issue codes (stable, lowercase).
EMPTY_RECORD = "empty_record"
RECORD_TOO_LONG = "record_too_long"
TOO_MANY_TAGS = "too_many_tags"
TOO_MANY_URIS = "too_many_uris"
NON_ASCII = "non_ascii"
CONTROL_CHARACTER = "control_character"
LEADING_WHITESPACE = "leading_whitespace"
MISSING_VERSION = "missing_version"
VERSION_NOT_FIRST = "version_not_first"
BAD_VERSION = "bad_version"
VERSION_CASE = "version_case"
MISSING_POLICY = "missing_policy"
POLICY_NOT_SECOND = "policy_not_second"
INVALID_POLICY = "invalid_policy"
INVALID_PCT = "invalid_pct"
PCT_OUT_OF_RANGE = "pct_out_of_range"
INVALID_ALIGNMENT = "invalid_alignment"
INVALID_FO = "invalid_fo"
INVALID_RF = "invalid_rf"
UNKNOWN_REPORT_FORMAT = "unknown_report_format"
INVALID_INTERVAL = "invalid_interval"
INTERVAL_OUT_OF_RANGE = "interval_out_of_range"
INVALID_URI = "invalid_uri"
INVALID_URI_DOMAIN = "invalid_uri_domain"
UNSUPPORTED_URI_SCHEME = "unsupported_uri_scheme"
MULTIPLE_MAILTO_ADDRESSES = "multiple_mailto_addresses"
BAD_SIZE_SUFFIX = "bad_size_suffix"
INVALID_TAG = "invalid_tag"
EMPTY_TAG = "empty_tag"
EMPTY_VALUE = "empty_value"
DUPLICATE_TAG = "duplicate_tag"
UNKNOWN_TAG = "unknown_tag"
UPPERCASE_TAG_NAME = "uppercase_tag_name"
UPPERCASE_VALUE = "uppercase_value"

_WSP = " \t"
_ASCII_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = frozenset("0123456789")
_HEXDIG = _DIGITS | frozenset("abcdefABCDEF")
_ALNUM = _ASCII_ALPHA | _DIGITS
_TAG_NAME_CHARS = _ALNUM | frozenset("_")
_SCHEME_CHARS = _ALNUM | frozenset("+-.")
# RFC 3986 unreserved + gen-delims + sub-delims, minus "!" and "," (section 6.4: MUST be
# encoded) and ";" (the tag separator). "%" is checked separately as pct-encoded.
_URI_CHARS = _ALNUM | frozenset("-._~:/?#[]@$&'()*+=")


@dataclass(frozen=True, slots=True)
class DmarcUri:
    """One ``rua``/``ruf`` entry. ``domain`` is the lowercased A-label mail domain of a valid
    ``mailto:`` URI (for external destination checks), else ``None``."""

    raw: str
    position: int
    uri: str  # without the size suffix
    scheme: str  # lowercased, "" when missing
    size_limit: int | None = None  # bytes, units are powers of two
    domain: str | None = None
    valid: bool = True


@dataclass(frozen=True, slots=True)
class DmarcTag:
    raw: str
    position: int
    name: str  # lowercased
    value: str  # surrounding whitespace removed
    known: bool
    valid: bool = True


@dataclass(frozen=True, slots=True)
class DmarcRecord:
    raw: str
    version: str | None  # "DMARC1" when present, first and exact; else None
    tags: tuple[DmarcTag, ...]
    issues: tuple[ParseIssue, ...]
    rua: tuple[DmarcUri, ...] = ()
    ruf: tuple[DmarcUri, ...] = ()
    truncated: bool = False

    @property
    def is_valid(self) -> bool:
        return self.version is not None and not any(i.severity == "error" for i in self.issues)

    def tag(self, name: str) -> DmarcTag | None:
        """First occurrence of a tag (case-insensitive name)."""
        lname = name.lower()
        return next((t for t in self.tags if t.name == lname), None)

    def _valid_value(self, name: str) -> str | None:
        t = self.tag(name)
        return t.value.lower() if t is not None and t.valid else None

    @property
    def p(self) -> str | None:
        return self._valid_value("p")

    @property
    def sp(self) -> str | None:
        return self._valid_value("sp")

    @property
    def adkim(self) -> str | None:
        return self._valid_value("adkim")

    @property
    def aspf(self) -> str | None:
        return self._valid_value("aspf")

    @property
    def pct(self) -> int | None:
        v = self._valid_value("pct")
        return int(v) if v is not None else None

    @property
    def ri(self) -> int | None:
        v = self._valid_value("ri")
        return int(v) if v is not None else None

    @property
    def fo(self) -> tuple[str, ...]:
        v = self._valid_value("fo")
        return tuple(_split_list(v, ":")[0]) if v is not None else ()

    @property
    def rf(self) -> tuple[str, ...]:
        v = self._valid_value("rf")
        return tuple(_split_list(v, ":")[0]) if v is not None else ()

    def issue_codes(self) -> tuple[str, ...]:
        return tuple(i.code for i in self.issues)


def is_dmarc_record(text: str) -> bool:
    """True when ``text`` starts with ``dmarc-version`` (RFC 7489 section 6.4) followed by
    ``dmarc-sep`` or the end of the record (section 6.6.3 steps 2 and 4).

    ``v`` is case-insensitive (ABNF quoted string), ``DMARC1`` must match exactly.
    """
    if not isinstance(text, str) or not text or text[0] not in "vV":
        return False
    i = _skip_wsp(text, 1)
    if i >= len(text) or text[i] != "=":
        return False
    i = _skip_wsp(text, i + 1)
    if text[i : i + len(VERSION)] != VERSION:
        return False
    i = _skip_wsp(text, i + len(VERSION))
    return i == len(text) or text[i] == ";"


def parse_dmarc(text: str) -> DmarcRecord:
    """Parse a DMARC TXT record (strings already concatenated). Never raises."""
    if not isinstance(text, str):
        return DmarcRecord(raw="", version=None, tags=(), issues=(ParseIssue(EMPTY_RECORD, "", 0),))
    issues: list[ParseIssue] = []
    raw = text
    truncated = False
    if len(text) > MAX_RECORD_LENGTH:
        text = text[:MAX_RECORD_LENGTH]
        truncated = True
        issues.append(ParseIssue(RECORD_TOO_LONG, "", MAX_RECORD_LENGTH))
    if not text.strip(_WSP):
        issues.append(ParseIssue(EMPTY_RECORD, "", 0))
        return DmarcRecord(
            raw=raw, version=None, tags=(), issues=tuple(issues), truncated=truncated
        )

    _check_chars(text, issues)
    if text[0] in _WSP:
        issues.append(ParseIssue(LEADING_WHITESPACE, "", 0))

    segments = _split_segments(text, issues)
    if len(segments) > MAX_TAGS:
        issues.append(ParseIssue(TOO_MANY_TAGS, "", segments[MAX_TAGS][1]))
        segments = segments[:MAX_TAGS]
        truncated = True

    tags: list[DmarcTag] = []
    rua: list[DmarcUri] = []
    ruf: list[DmarcUri] = []
    seen: set[str] = set()
    uri_budget = [MAX_URIS]
    for seg, pos in segments:
        tag_issues: list[ParseIssue] = []
        tag = _parse_tag(seg, pos, tag_issues)
        if tag is None:
            issues.extend(tag_issues)
            continue
        if tag.name in seen:
            tag_issues.append(ParseIssue(DUPLICATE_TAG, seg, pos))
        elif tag.known:
            uris = _check_value(tag, tag_issues, uri_budget)
            if tag.name == "rua":
                rua.extend(uris)
            elif tag.name == "ruf":
                ruf.extend(uris)
        seen.add(tag.name)
        valid = not any(i.severity == "error" for i in tag_issues)
        if not valid:
            tag = DmarcTag(tag.raw, tag.position, tag.name, tag.value, tag.known, valid=False)
        tags.append(tag)
        issues.extend(tag_issues)
    if uri_budget[0] < 0:
        truncated = True

    version = _check_structure(tags, issues)
    return DmarcRecord(
        raw=raw,
        version=version,
        tags=tuple(tags),
        issues=tuple(issues),
        rua=tuple(rua),
        ruf=tuple(ruf),
        truncated=truncated,
    )


def _skip_wsp(text: str, i: int) -> int:
    while i < len(text) and text[i] in _WSP:
        i += 1
    return i


def _check_chars(text: str, issues: list[ParseIssue]) -> None:
    """Report the first non-ASCII and the first control character (HTAB is WSP)."""
    seen: set[str] = set()
    for i, ch in enumerate(text):
        o = ord(ch)
        if 0x20 <= o <= 0x7E or ch == "\t":
            continue
        code = NON_ASCII if o > 0x7F else CONTROL_CHARACTER
        if code not in seen:
            seen.add(code)
            issues.append(ParseIssue(code, "", i))
            if len(seen) == 2:
                return


def _split_segments(text: str, issues: list[ParseIssue]) -> list[tuple[str, int]]:
    """Split on ";" in one pass. Returns (segment without surrounding WSP, its offset).

    One trailing ";" (optionally followed by WSP) is allowed by ``[dmarc-sep]``; any other
    empty segment (``;;``, a leading ``;``, or ``; ;``) is reported once per occurrence.
    """
    out: list[tuple[str, int]] = []
    start = 0
    n = len(text)
    while start <= n:
        end = text.find(";", start)
        last = end == -1
        if last:
            end = n
        lo = _skip_wsp(text, start)
        hi = end
        while hi > lo and text[hi - 1] in _WSP:
            hi -= 1
        if lo < hi:
            out.append((text[lo:hi], lo))
        elif not (last and start > 0):
            issues.append(ParseIssue(EMPTY_TAG, "", start))
        if last:
            break
        start = end + 1
    return out


def _parse_tag(seg: str, pos: int, issues: list[ParseIssue]) -> DmarcTag | None:
    """``tag-name *WSP "=" *WSP tag-value``. Returns None when there is no usable name."""
    if seg[0] not in _ASCII_ALPHA:
        issues.append(ParseIssue(INVALID_TAG, seg, pos))
        return None
    i = 1
    while i < len(seg) and seg[i] in _TAG_NAME_CHARS:
        i += 1
    name = seg[:i]
    j = _skip_wsp(seg, i)
    if j >= len(seg) or seg[j] != "=":
        issues.append(ParseIssue(INVALID_TAG, seg, pos))
        return None
    value = seg[_skip_wsp(seg, j + 1) :]
    lname = name.lower()
    known = lname in KNOWN_TAGS
    if name != lname:
        issues.append(ParseIssue(UPPERCASE_TAG_NAME, seg, pos, "warning"))
    if not known:
        issues.append(ParseIssue(UNKNOWN_TAG, seg, pos, "warning"))
    return DmarcTag(raw=seg, position=pos, name=lname, value=value, known=known)


def _check_value(tag: DmarcTag, issues: list[ParseIssue], uri_budget: list[int]) -> list[DmarcUri]:
    """Validate a known tag's value; returns parsed URIs for rua/ruf."""
    name, value, seg, pos = tag.name, tag.value, tag.raw, tag.position

    def issue(code: str, severity: IssueSeverity = "error") -> None:
        issues.append(ParseIssue(code, seg, pos, severity))

    if name == "v":
        return []  # checked in _check_structure
    if not value:
        issue(EMPTY_VALUE)
        return []
    lvalue = value.lower()
    if name in ("p", "sp"):
        if lvalue not in POLICIES:
            issue(INVALID_POLICY)
        elif value != lvalue:
            issue(UPPERCASE_VALUE, "warning")
    elif name in ("adkim", "aspf"):
        if lvalue not in ALIGNMENTS:
            issue(INVALID_ALIGNMENT)
        elif value != lvalue:
            issue(UPPERCASE_VALUE, "warning")
    elif name == "pct":
        if any(c not in _DIGITS for c in value):
            issue(INVALID_PCT)
        elif len(value) > 3 or int(value) > 100:
            issue(PCT_OUT_OF_RANGE)
    elif name == "ri":
        if any(c not in _DIGITS for c in value):
            issue(INVALID_INTERVAL)
        elif len(value.lstrip("0")) > 10 or int(value) > MAX_RI:
            issue(INTERVAL_OUT_OF_RANGE)
    elif name == "fo":
        items, ok = _split_list(value, ":")
        if not ok or any(o.lower() not in FO_OPTIONS for o in items):
            issue(INVALID_FO)
        elif value != lvalue:
            issue(UPPERCASE_VALUE, "warning")
    elif name == "rf":
        # ABNF allows *WSP only before ":" in rf; whitespace after it is tolerated here.
        items, ok = _split_list(value, ":")
        if not ok or not all(_is_keyword(k) for k in items):
            issue(INVALID_RF)
        elif any(k.lower() not in REGISTERED_REPORT_FORMATS for k in items):
            issue(UNKNOWN_REPORT_FORMAT, "warning")
    elif name in ("rua", "ruf"):
        return _parse_uri_list(value, seg, pos + len(seg) - len(value), issues, uri_budget)
    return []


def _split_list(value: str, sep: str) -> tuple[list[str], bool]:
    """Split on ``sep`` stripping WSP; ok is False when an item is empty."""
    items = [p.strip(_WSP) for p in value.split(sep)]
    return items, all(items)


def _is_keyword(k: str) -> bool:
    """RFC 5321 ``Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig``."""
    return bool(k) and k[-1] in _ALNUM and all(c in _ALNUM or c == "-" for c in k)


def _parse_uri_list(
    value: str, seg: str, value_pos: int, issues: list[ParseIssue], uri_budget: list[int]
) -> list[DmarcUri]:
    out: list[DmarcUri] = []
    offset = 0
    for part in value.split(","):
        item_pos = value_pos + offset + (len(part) - len(part.lstrip(_WSP)))
        offset += len(part) + 1
        item = part.strip(_WSP)
        if uri_budget[0] <= 0:
            if uri_budget[0] == 0:
                issues.append(ParseIssue(TOO_MANY_URIS, seg, item_pos))
                uri_budget[0] = -1
            break
        uri_budget[0] -= 1
        out.append(_parse_uri(item, item_pos, seg, issues))
    return out


def _parse_uri(item: str, pos: int, seg: str, issues: list[ParseIssue]) -> DmarcUri:
    def bad(code: str, uri: str = item, scheme: str = "") -> DmarcUri:
        issues.append(ParseIssue(code, seg, pos))
        return DmarcUri(raw=item, position=pos, uri=uri, scheme=scheme, valid=False)

    if not item:
        return bad(INVALID_URI)
    uri, bang, suffix = item.partition("!")
    size_limit: int | None = None
    if bang:
        size_limit = _parse_size(suffix)
        if size_limit is None:
            return bad(BAD_SIZE_SUFFIX, uri)
    # scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"  (RFC 3986 section 3.1)
    colon = uri.find(":")
    if colon < 1 or uri[0] not in _ASCII_ALPHA or any(c not in _SCHEME_CHARS for c in uri[:colon]):
        return bad(INVALID_URI, uri)
    scheme = uri[:colon].lower()
    rest = uri[colon + 1 :]
    if not rest or not _valid_uri_chars(rest):
        return bad(INVALID_URI, uri, scheme)
    if scheme != "mailto":
        issues.append(ParseIssue(UNSUPPORTED_URI_SCHEME, seg, pos, "warning"))
        return DmarcUri(raw=item, position=pos, uri=uri, scheme=scheme, size_limit=size_limit)

    # RFC 6068: mailto:[to][?hfields]; to = addr-spec *("," addr-spec), percent-encoded.
    try:
        to = unquote_to_bytes(rest.partition("?")[0]).decode("utf-8")
    except UnicodeDecodeError:
        return bad(INVALID_URI, uri, scheme)
    if "," in to:
        issues.append(ParseIssue(MULTIPLE_MAILTO_ADDRESSES, seg, pos, "warning"))
        return DmarcUri(raw=item, position=pos, uri=uri, scheme=scheme, size_limit=size_limit)
    local, at, host = to.rpartition("@")
    if not at or not local:
        return bad(INVALID_URI, uri, scheme)
    try:
        domain = to_ascii_domain(host) if host == host.strip(" \t\r\n") else None
    except InvalidDomainName:
        domain = None
    if domain is None:
        return bad(INVALID_URI_DOMAIN, uri, scheme)
    return DmarcUri(
        raw=item, position=pos, uri=uri, scheme=scheme, size_limit=size_limit, domain=domain
    )


def _valid_uri_chars(s: str) -> bool:
    """Only RFC 3986 characters; every "%" starts a pct-encoded triplet."""
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "%":
            if i + 2 >= n or s[i + 1] not in _HEXDIG or s[i + 2] not in _HEXDIG:
                return False
            i += 3
            continue
        if c not in _URI_CHARS:
            return False
        i += 1
    return True


def _parse_size(suffix: str) -> int | None:
    """``1*DIGIT [ "k" / "m" / "g" / "t" ]``; the number fits in an unsigned 64-bit int."""
    unit = ""
    if suffix and suffix[-1].lower() in SIZE_UNITS:
        unit = suffix[-1].lower()
        suffix = suffix[:-1]
    if not suffix or any(c not in _DIGITS for c in suffix) or len(suffix.lstrip("0")) > 20:
        return None
    number = int(suffix)
    if number > MAX_SIZE_NUMBER:
        return None
    return number * SIZE_UNITS[unit]


def _check_structure(tags: list[DmarcTag], issues: list[ParseIssue]) -> str | None:
    """``v`` first and exactly ``DMARC1``; ``p`` present (directly after ``v`` per ABNF)."""
    version: str | None = None
    first = tags[0] if tags else None
    v_tags = [t for t in tags if t.name == "v"]
    if first is not None and first.name == "v":
        if first.value == VERSION:
            version = VERSION
        elif first.value.upper() == VERSION:
            issues.append(ParseIssue(VERSION_CASE, first.raw, first.position))
        else:
            issues.append(ParseIssue(BAD_VERSION, first.raw, first.position))
    elif v_tags:
        issues.append(ParseIssue(VERSION_NOT_FIRST, v_tags[0].raw, v_tags[0].position))
    else:
        issues.append(ParseIssue(MISSING_VERSION, "", 0))

    p_tags = [t for t in tags if t.name == "p"]
    if not p_tags:
        # Section 7.1 report authorization records legitimately have no p.
        issues.append(ParseIssue(MISSING_POLICY, "", 0))
    elif first is not None and first.name == "v" and (len(tags) < 2 or tags[1].name != "p"):
        issues.append(ParseIssue(POLICY_NOT_SECOND, p_tags[0].raw, p_tags[0].position, "warning"))
    return version
