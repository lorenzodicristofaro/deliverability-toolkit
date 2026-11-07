"""Authentication-Results header parser (RFC 8601).

Pure and offline: no DNS, no network, no filesystem, no database. The parser never
re-evaluates SPF, DKIM, DMARC or ARC and never verifies a signature; it only reports what
the receiving server WROTE in its ``Authentication-Results`` header fields.

``parse_authentication_results`` parses one header value and returns a frozen
:class:`AuthResHeader`; ``parse_all_authentication_results`` parses every
``Authentication-Results`` field of a :class:`~app.parsers.message.HeaderBlock` (multiple
fields are allowed), topmost (most recently added) first.

Trust is NOT decided here. RFC 8601 sections 5 and 7.1 say a header field is only meaningful
when its authserv-id belongs to the receiving ADMD and it was added inside the trust
boundary; anyone upstream can write a forged one. This module only exposes ``authserv_id``,
``index`` (0 = topmost) and ``position`` (byte offset in the message) so later analysis can
warn about forged, unexpected or duplicate authserv-ids. No vendor-specific format is assumed.

Grammar (RFC 8601 section 2.2): ``authserv-id [version] ( "; none" / 1*( ";" resinfo ) )``
where resinfo is ``method[/version]=result [reason=value] *(ptype.property=pvalue)``.

- Comments ``( ... )`` (nested, with quoted-pairs) are stripped wherever CFWS is allowed;
  quoted strings are unquoted. CFWS around ``/``, ``.`` and ``=`` is accepted (appendix B.7).
- Method, result, ptype and property are keywords and are compared case-insensitively; they
  are reported in lowercase. Values (authserv-id, pvalue, reason) are kept as written. The
  exact source text of each resinfo is in :attr:`ResInfo.raw`.
- Methods whose result set is listed in :data:`KNOWN_RESULTS` (RFC 8601 section 2.7,
  RFC 7489 section 11.2, RFC 8617 section 10.1) have their result checked. Methods in
  :data:`REGISTERED_METHODS` (RFC 8601 section 2.7.5) are accepted without checking the
  result. Any other method, or an unlisted result, is kept verbatim (lowercased) with
  ``unknown_value=True`` and an ``unknown_value`` warning; it is never rejected.
- The unfolded ``raw_value`` is parsed, not the RFC 2047 decoded value: encoded-words are
  not part of this structured field and are reported with an ``encoded_word`` warning.

Malformed input never raises, except: :class:`AuthResTooLarge` for a value over
:data:`MAX_AUTHRES_LENGTH` (``authres_too_large``) and :class:`InvalidAuthenticationResults`
for a NUL character (``nul_byte``). Exceptions carry a stable ``code`` and never echo input.
Everything else is reported as :class:`~app.parsers.spf.ParseIssue` with a stable code and a
position that is the 0-based character offset inside the header value. Severity ``error``
means part of the header could not be used (the resinfo or authserv-id is missing);
``warning`` means it was kept. At most :data:`MAX_RESINFO` resinfo entries are kept; past
that ``truncated`` is set with a ``too_many_resinfo`` warning. Issues are capped at
:data:`MAX_ISSUES` (then one ``too_many_issues``). All scans are linear in the input size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from app.parsers.message import MAX_UNFOLDED_HEADER, HeaderBlock
from app.parsers.spf import IssueSeverity, ParseIssue

HEADER_NAME = "Authentication-Results"

MAX_AUTHRES_LENGTH = MAX_UNFOLDED_HEADER
MAX_RESINFO = 200
MAX_ISSUES = 200
MAX_VERSION_DIGITS = 9

# Error codes raised as exceptions (stable, lowercase).
AUTHRES_TOO_LARGE = "authres_too_large"
NUL_BYTE = "nul_byte"

# Issue codes (stable, lowercase).
MISSING_AUTHSERV_ID = "missing_authserv_id"
INVALID_AUTHSERV_ID = "invalid_authserv_id"
INVALID_VERSION = "invalid_version"
UNSUPPORTED_VERSION = "unsupported_version"
UNTERMINATED_QUOTE = "unterminated_quote"
UNTERMINATED_COMMENT = "unterminated_comment"
NO_RESINFO = "no_resinfo"
EMPTY_RESINFO = "empty_resinfo"
UNEXPECTED_NONE = "unexpected_none"
INVALID_RESINFO = "invalid_resinfo"
MISSING_EQUALS = "missing_equals"
EMPTY_RESULT = "empty_result"
INVALID_KEYWORD = "invalid_keyword"
INVALID_METHOD_VERSION = "invalid_method_version"
UNKNOWN_VALUE = "unknown_value"
INVALID_PROPERTY = "invalid_property"
UNKNOWN_PTYPE = "unknown_ptype"
EMPTY_PROPERTY_VALUE = "empty_property_value"
DUPLICATE_REASON = "duplicate_reason"
UNEXPECTED_TOKEN = "unexpected_token"
CONFLICTING_RESULTS = "conflicting_results"
ENCODED_WORD = "encoded_word"
TOO_MANY_RESINFO = "too_many_resinfo"
TOO_MANY_ISSUES = "too_many_issues"

# Result sets by method. Sources: RFC 8601 sections 2.7.1-2.7.4 (dkim, spf, iprev, auth),
# RFC 7489 section 11.2 (dmarc), RFC 8617 section 10.1 (arc).
KNOWN_RESULTS: dict[str, frozenset[str]] = {
    "dkim": frozenset({"none", "pass", "fail", "policy", "neutral", "temperror", "permerror"}),
    "spf": frozenset(
        {"none", "pass", "fail", "softfail", "policy", "neutral", "temperror", "permerror"}
    ),
    "iprev": frozenset({"pass", "fail", "temperror", "permerror"}),
    "auth": frozenset({"none", "pass", "fail", "temperror", "permerror"}),
    "dmarc": frozenset({"none", "pass", "fail", "temperror", "permerror"}),
    "arc": frozenset({"none", "pass", "fail"}),
}
# RFC 8601 section 2.7.5: registered elsewhere; result sets not checked here.
REGISTERED_METHODS: frozenset[str] = frozenset({"vbr", "dkim-atps", "dkim-adsp", "rrvs", "smime"})
# RFC 8601 section 2.3: initial property types.
KNOWN_PTYPES: frozenset[str] = frozenset({"body", "header", "policy", "smtp"})

TYPED_METHODS: tuple[str, ...] = ("spf", "dkim", "dmarc", "arc")

# RFC 5321 section 4.1.2: Keyword = Ldh-str.
_KEYWORD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?")
# RFC 2045 section 5.1 tspecials (minus those the lexer already splits on).
_TSPECIALS = frozenset("<>@,:\\/[]?")
_ENCODED_WORD = re.compile(r"=\?[^?\s]+\?[BbQq]\?[^?\s]*\?=")
_WSP = frozenset(" \t\r\n")
_WORD_STOP = frozenset(' \t\r\n();="')
_JOINERS = "./"


class AuthResParseError(ValueError):
    """The header value cannot be parsed at all. ``code`` is stable; no input is echoed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AuthResTooLarge(AuthResParseError):
    """Header value over :data:`MAX_AUTHRES_LENGTH`."""


class InvalidAuthenticationResults(AuthResParseError):
    """The header value contains a NUL character."""


@dataclass(frozen=True, slots=True)
class AuthResProperty:
    """One ``ptype.property=value`` pair; ``ptype``/``property`` lowercase, value as written."""

    ptype: str
    property: str
    value: str
    position: int


@dataclass(frozen=True, slots=True)
class ResInfo:
    """One stated result: ``method[/version]=result`` plus reason and properties.

    ``unknown_value`` is True when the method is not recognised or the result is not in the
    method's result set. ``raw`` is the exact source text of the entry (comments included).
    """

    method: str
    method_version: int | None
    result: str
    reason: str | None
    properties: tuple[AuthResProperty, ...]
    raw: str
    position: int
    unknown_value: bool

    def get(self, ptype: str, prop: str) -> str | None:
        """First value of ``ptype.prop`` (case-insensitive names), or None."""
        pt, pr = ptype.lower(), prop.lower()
        for p in self.properties:
            if p.ptype == pt and p.property == pr:
                return p.value
        return None

    # Typed accessors for recognised methods (RFC 8601 2.7.1/2.7.2, RFC 7489 11.1,
    # RFC 8617 10.2). They return None when the property is absent.
    @property
    def smtp_mailfrom(self) -> str | None:
        return self.get("smtp", "mailfrom")

    @property
    def smtp_helo(self) -> str | None:
        return self.get("smtp", "helo")

    @property
    def header_d(self) -> str | None:
        return self.get("header", "d")

    @property
    def header_i(self) -> str | None:
        return self.get("header", "i")

    @property
    def header_s(self) -> str | None:
        return self.get("header", "s")

    @property
    def header_a(self) -> str | None:
        return self.get("header", "a")

    @property
    def header_b(self) -> str | None:
        return self.get("header", "b")

    @property
    def header_from(self) -> str | None:
        return self.get("header", "from")

    @property
    def policy(self) -> tuple[AuthResProperty, ...]:
        """All ``policy.*`` properties, in order."""
        return tuple(p for p in self.properties if p.ptype == "policy")


@dataclass(frozen=True, slots=True)
class AuthResHeader:
    """One parsed Authentication-Results field.

    ``authserv_id`` is None when missing. ``no_result`` is True for the ``; none`` form.
    ``position`` is the field's byte offset in the message (0 for a standalone value) and
    ``index`` its order among Authentication-Results fields (0 = topmost). Trust is not
    decided here (see the module docstring).
    """

    authserv_id: str | None
    version: int | None
    no_result: bool
    resinfo: tuple[ResInfo, ...]
    raw: str
    position: int
    index: int
    truncated: bool
    issues: tuple[ParseIssue, ...]

    def by_method(self) -> dict[str, tuple[ResInfo, ...]]:
        """Resinfo grouped by method; methods in first-seen order, duplicates kept in order."""
        groups: dict[str, list[ResInfo]] = {}
        for info in self.resinfo:
            groups.setdefault(info.method, []).append(info)
        return {method: tuple(items) for method, items in groups.items()}

    def _of(self, method: str) -> tuple[ResInfo, ...]:
        return tuple(r for r in self.resinfo if r.method == method)

    @property
    def spf(self) -> tuple[ResInfo, ...]:
        return self._of("spf")

    @property
    def dkim(self) -> tuple[ResInfo, ...]:
        return self._of("dkim")

    @property
    def dmarc(self) -> tuple[ResInfo, ...]:
        return self._of("dmarc")

    @property
    def arc(self) -> tuple[ResInfo, ...]:
        return self._of("arc")

    @property
    def other(self) -> tuple[ResInfo, ...]:
        """Resinfo for every method other than spf, dkim, dmarc and arc, in order."""
        return tuple(r for r in self.resinfo if r.method not in TYPED_METHODS)


class _Issues:
    def __init__(self) -> None:
        self.items: list[ParseIssue] = []
        self._full = False

    def add(self, code: str, position: int, severity: IssueSeverity = "warning") -> None:
        if self._full:
            return
        if len(self.items) >= MAX_ISSUES:
            self.items.append(ParseIssue(TOO_MANY_ISSUES, "", position, "warning"))
            self._full = True
            return
        # term is always empty: issues never echo header content.
        self.items.append(ParseIssue(code, "", position, severity))


_Kind = Literal["word", "qstr", ";", "="]


@dataclass(frozen=True, slots=True)
class _Tok:
    kind: _Kind
    text: str
    start: int
    end: int


def _skip_comment(value: str, i: int, issues: _Issues) -> int:
    """``value[i]`` is ``(``; return the index after the matching ``)`` or len(value)."""
    depth = 0
    n = len(value)
    start = i
    while i < n:
        ch = value[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    issues.add(UNTERMINATED_COMMENT, start, "error")
    return n


def _lex(value: str, issues: _Issues) -> list[_Tok]:
    tokens: list[_Tok] = []
    n = len(value)
    i = 0
    while i < n:
        prev = i
        ch = value[i]
        if ch in _WSP:
            i += 1
        elif ch == "(":
            i = _skip_comment(value, i, issues)
        elif ch == ")":
            # A ")" with no matching "(": not CFWS and not part of any token.
            issues.add(UNEXPECTED_TOKEN, i)
            i += 1
        elif ch == ";" or ch == "=":
            tokens.append(_Tok(";" if ch == ";" else "=", ch, i, i + 1))
            i += 1
        elif ch == '"':
            start = i
            i += 1
            out: list[str] = []
            closed = False
            while i < n:
                c = value[i]
                if c == "\\" and i + 1 < n:
                    out.append(value[i + 1])
                    i += 2
                elif c == '"':
                    i += 1
                    closed = True
                    break
                else:
                    out.append(c)
                    i += 1
            if not closed:
                issues.add(UNTERMINATED_QUOTE, start, "error")
                i = n
            tokens.append(_Tok("qstr", "".join(out), start, i))
        else:
            start = i
            while i < n and value[i] not in _WORD_STOP:
                i += 1
            tokens.append(_Tok("word", value[start:i], start, i))
        if i <= prev:
            # Structural guard: every branch must consume input. Never reached by the
            # branches above; it turns a future lexer bug into a skipped char, not a hang.
            i = prev + 1
    return tokens


def _comment_tail(value: str, end: int) -> int:
    """Extend ``end`` over comments (and the CFWS between them) that directly follow it."""
    scratch = _Issues()  # comment issues were already reported by the lexer
    n = len(value)
    i = last = end
    while i < n:
        if value[i] in _WSP:
            i += 1
        elif value[i] == "(":
            i = last = _skip_comment(value, i, scratch)
        else:
            break
    return last


def _join_dotted(tokens: list[_Tok], i: int) -> tuple[str, int]:
    """Join a word with following words around ``.``/``/`` separated by CFWS (B.7)."""
    text = tokens[i].text
    i += 1
    while (
        i < len(tokens)
        and tokens[i].kind == "word"
        and (text[-1] in _JOINERS or tokens[i].text[0] in _JOINERS)
    ):
        text += tokens[i].text
        i += 1
    return text, i


def _quote(text: str) -> str:
    """Re-quote an unquoted quoted-string (RFC 5322 section 3.2.4)."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_version(text: str) -> int | None:
    if text.isascii() and text.isdigit() and len(text) <= MAX_VERSION_DIGITS:
        return int(text)
    return None


def _is_keyword(text: str) -> bool:
    return _KEYWORD.fullmatch(text) is not None


def _is_key(toks: list[_Tok], i: int) -> bool:
    """True when ``toks[i]`` starts a ``ptype.property=`` or ``reason=`` (so the value
    before it was empty)."""
    tok = toks[i]
    if tok.kind != "word":
        return False
    key, j = _join_dotted(toks, i)
    return j < len(toks) and toks[j].kind == "=" and ("." in key or key.lower() == "reason")


def _parse_resinfo(value: str, toks: list[_Tok], issues: _Issues) -> ResInfo | None:
    n = len(toks)
    first = toks[0]
    pos = first.start
    if first.kind != "word":
        issues.add(INVALID_RESINFO, pos, "error")
        return None
    method_text, i = _join_dotted(toks, 0)
    if i >= n or toks[i].kind != "=":
        issues.add(MISSING_EQUALS, pos, "error")
        return None
    i += 1
    # The result must be a word/qstr that is not itself the key of a following "=".
    if i >= n or toks[i].kind not in ("word", "qstr") or _is_key(toks, i):
        issues.add(EMPTY_RESULT, pos, "error")
        return None
    result_tok = toks[i]
    i += 1

    name, slash, version_text = method_text.partition("/")
    method = name.lower()
    method_version: int | None = None
    if slash:
        method_version = _parse_version(version_text)
        if method_version is None:
            issues.add(INVALID_METHOD_VERSION, pos)
    result = result_tok.text.lower()
    if not _is_keyword(name) or result_tok.kind != "word" or not _is_keyword(result):
        issues.add(INVALID_KEYWORD, pos)

    known = KNOWN_RESULTS.get(method)
    unknown = method not in REGISTERED_METHODS if known is None else result not in known
    if unknown:
        issues.add(UNKNOWN_VALUE, pos)

    reason: str | None = None
    props: list[AuthResProperty] = []
    while i < n:
        tok = toks[i]
        if tok.kind != "word":
            issues.add(UNEXPECTED_TOKEN, tok.start)
            i += 1
            continue
        key, j = _join_dotted(toks, i)
        if j >= n or toks[j].kind != "=":
            issues.add(MISSING_EQUALS, tok.start)
            i = j
            continue
        k = j + 1
        if k < n and toks[k].kind in ("word", "qstr") and not _is_key(toks, k):
            pvalue = toks[k].text
            i = k + 1
            if (
                toks[k].kind == "qstr"
                and i < n
                and toks[i].kind == "word"
                and toks[i].text.startswith("@")
            ):
                # pvalue = [local-part] "@" domain with a quoted-string local-part
                # (RFC 8601 section 2.2, RFC 5322 section 3.4.1): keep it quoted.
                domain, i = _join_dotted(toks, i)
                pvalue = _quote(pvalue) + domain
        else:
            pvalue = ""
            issues.add(EMPTY_PROPERTY_VALUE, tok.start)
            i = k
        lowered = key.lower()
        if lowered == "reason":
            if reason is not None:
                issues.add(DUPLICATE_REASON, tok.start)
            else:
                reason = pvalue
            continue
        ptype, dot, prop = lowered.partition(".")
        if not dot or not _is_keyword(ptype) or not _is_keyword(prop):
            issues.add(INVALID_PROPERTY, tok.start)
            continue
        if ptype not in KNOWN_PTYPES:
            issues.add(UNKNOWN_PTYPE, tok.start)
        props.append(AuthResProperty(ptype, prop, pvalue, tok.start))

    raw = value[pos : _comment_tail(value, toks[-1].end)]
    return ResInfo(method, method_version, result, reason, tuple(props), raw, pos, unknown)


def _split_segments(tokens: list[_Tok]) -> list[tuple[int, list[_Tok]]]:
    """Split on ``;``; each segment carries the position just after its ``;`` (0 first)."""
    segments: list[tuple[int, list[_Tok]]] = [(0, [])]
    for tok in tokens:
        if tok.kind == ";":
            segments.append((tok.end, []))
        else:
            segments[-1][1].append(tok)
    return segments


def _parse_authserv(toks: list[_Tok], issues: _Issues) -> tuple[str | None, int | None]:
    if not toks:
        issues.add(MISSING_AUTHSERV_ID, 0, "error")
        return None, None
    first = toks[0]
    authserv_id = first.text
    if not authserv_id:
        issues.add(MISSING_AUTHSERV_ID, first.start, "error")
        return None, None
    if first.kind == "word" and any(c in _TSPECIALS or ord(c) < 0x20 for c in authserv_id):
        issues.add(INVALID_AUTHSERV_ID, first.start)
    version: int | None = None
    rest = toks[1:]
    if rest:
        version = _parse_version(rest[0].text) if rest[0].kind == "word" else None
        if version is None or len(rest) > 1:
            issues.add(INVALID_VERSION, rest[0].start)
        if version is not None and version != 1:
            issues.add(UNSUPPORTED_VERSION, rest[0].start)
    return authserv_id, version


def _check_conflicts(resinfo: list[ResInfo], issues: _Issues) -> None:
    """Same method and same properties stated with different results."""
    seen: dict[tuple[str, tuple[tuple[str, str, str], ...]], str] = {}
    flagged: set[tuple[str, tuple[tuple[str, str, str], ...]]] = set()
    for info in resinfo:
        key = (
            info.method,
            tuple(sorted((p.ptype, p.property, p.value.lower()) for p in info.properties)),
        )
        previous = seen.setdefault(key, info.result)
        if previous != info.result and key not in flagged:
            flagged.add(key)
            issues.add(CONFLICTING_RESULTS, info.position)


def parse_authentication_results(value: str, *, position: int = 0, index: int = 0) -> AuthResHeader:
    """Parse one Authentication-Results header value. See the module docstring."""
    if not isinstance(value, str):
        raise TypeError("value must be str")
    if len(value) > MAX_AUTHRES_LENGTH:
        raise AuthResTooLarge(AUTHRES_TOO_LARGE)
    if "\x00" in value:
        raise InvalidAuthenticationResults(NUL_BYTE)

    issues = _Issues()
    match = _ENCODED_WORD.search(value)
    if match:
        issues.add(ENCODED_WORD, match.start())

    segments = _split_segments(_lex(value, issues))
    head_toks = segments[0][1]
    resinfo_segments = segments[1:]
    authserv_id: str | None
    version: int | None
    if any(t.kind == "=" for t in head_toks):
        # No authserv-id: the first segment is already a resinfo. Kept, but flagged.
        issues.add(MISSING_AUTHSERV_ID, 0, "error")
        authserv_id, version = None, None
        resinfo_segments = [segments[0], *resinfo_segments]
    else:
        authserv_id, version = _parse_authserv(head_toks, issues)

    non_empty = [(p, t) for p, t in resinfo_segments if t]
    no_result = (
        len(non_empty) == 1
        and len(non_empty[0][1]) == 1
        and non_empty[0][1][0].kind == "word"
        and non_empty[0][1][0].text.lower() == "none"
    )

    resinfo: list[ResInfo] = []
    truncated = False
    for seg_pos, toks in resinfo_segments:
        if not toks:
            issues.add(EMPTY_RESINFO, seg_pos)
            continue
        if no_result:
            continue
        if len(toks) == 1 and toks[0].kind == "word" and toks[0].text.lower() == "none":
            issues.add(UNEXPECTED_NONE, toks[0].start)
            continue
        if len(resinfo) >= MAX_RESINFO:
            truncated = True
            issues.add(TOO_MANY_RESINFO, toks[0].start)
            break
        info = _parse_resinfo(value, toks, issues)
        if info is not None:
            resinfo.append(info)

    if not no_result and not non_empty:
        issues.add(NO_RESINFO, len(value))
    _check_conflicts(resinfo, issues)

    return AuthResHeader(
        authserv_id=authserv_id,
        version=version,
        no_result=no_result,
        resinfo=tuple(resinfo),
        raw=value,
        position=position,
        index=index,
        truncated=truncated,
        issues=tuple(issues.items),
    )


def parse_all_authentication_results(block: HeaderBlock) -> tuple[AuthResHeader, ...]:
    """Parse every Authentication-Results field of ``block``, topmost (newest) first."""
    return tuple(
        parse_authentication_results(field.raw_value, position=field.position, index=i)
        for i, field in enumerate(block.get_all(HEADER_NAME))
    )
