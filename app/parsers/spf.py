"""SPF record parser (RFC 7208 sections 4.5, 4.6, 5, 6, 7 and 12).

Pure syntax: no DNS, no network, no macro expansion, no lookup counting (M3-07).

``parse_spf`` never raises on bad input. It returns an :class:`SpfRecord` with the parsed
terms and a list of :class:`ParseIssue`. Issue codes are stable lowercase identifiers;
``severity="error"`` means the record is syntactically invalid per RFC 7208 (a receiver
returns ``permerror``) or could not be fully parsed (resource bounds), ``"warning"`` means
the record is accepted but unusual or partly ignored by receivers.

Resource bounds: input is cut at :data:`MAX_RECORD_LENGTH` characters and at
:data:`MAX_TERMS` terms. Tokenisation is a single linear scan (no regular expressions),
so hostile input cannot trigger backtracking.

:class:`ParseIssue` is deliberately generic so other record parsers (DMARC, DKIM) can
reuse it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import Literal, cast

MAX_RECORD_LENGTH = 4096
MAX_TERMS = 200

IssueSeverity = Literal["error", "warning"]
Qualifier = Literal["+", "-", "~", "?"]
TermKind = Literal["mechanism", "modifier", "invalid"]
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MECHANISMS: frozenset[str] = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
KNOWN_MODIFIERS: frozenset[str] = frozenset({"redirect", "exp"})

# Issue codes (stable, lowercase). Kept as constants so checks can match on them.
EMPTY_RECORD = "empty_record"
MISSING_VERSION = "missing_version"
BAD_VERSION = "bad_version"
VERSION_CASE = "version_case"
LEADING_WHITESPACE = "leading_whitespace"
EXTRA_WHITESPACE = "extra_whitespace"
INVALID_WHITESPACE = "invalid_whitespace"
NON_ASCII = "non_ascii"
CONTROL_CHARACTER = "control_character"
RECORD_TOO_LONG = "record_too_long"
TOO_MANY_TERMS = "too_many_terms"
INVALID_TERM = "invalid_term"
UNKNOWN_MECHANISM = "unknown_mechanism"
TRAILING_GARBAGE = "trailing_garbage"
UNEXPECTED_ARGUMENT = "unexpected_argument"
EMPTY_VALUE = "empty_value"
BAD_IP = "bad_ip"
BAD_CIDR = "bad_cidr"
BAD_MACRO = "bad_macro"
MACRO_EXP_ONLY = "macro_exp_only"
INVALID_DOMAIN = "invalid_domain"
UPPERCASE_NAME = "uppercase_name"
DUPLICATE_MODIFIER = "duplicate_modifier"
UNKNOWN_MODIFIER = "unknown_modifier"
MECHANISM_AS_MODIFIER = "mechanism_as_modifier"
DUPLICATE_VERSION = "duplicate_version"
TERM_AFTER_ALL = "term_after_all"
REDIRECT_WITH_ALL = "redirect_with_all"

_QUALIFIERS = "+-~?"
_ASCII_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = frozenset("0123456789")
_ALNUM = _ASCII_ALPHA | _DIGITS
_NAME_CHARS = _ALNUM | frozenset("-_.")
_MACRO_LETTERS = frozenset("slodiphcrtv")
_MACRO_EXP_ONLY_LETTERS = frozenset("crt")
_MACRO_DELIMITERS = frozenset(".-+,/_=")
_MACRO_SHORT = frozenset("%_-")
_ASCII_WS = frozenset("\t\n\v\f\r")


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """A problem found while parsing a record.

    ``code`` is a stable lowercase identifier, ``term`` the offending token (or ``""`` for
    record-level issues) and ``position`` the 0-based character offset in the input.
    """

    code: str
    term: str
    position: int
    severity: IssueSeverity = "error"


@dataclass(frozen=True, slots=True)
class SpfTerm:
    """One parsed term. ``value`` is the raw, unexpanded argument (domain-spec, IP)."""

    raw: str
    position: int
    kind: TermKind
    name: str  # lowercased mechanism/modifier name ("" when unparseable)
    qualifier: Qualifier | None = None  # mechanisms only; "+" when omitted
    value: str | None = None
    network: IpNetwork | None = None  # ip4/ip6 only
    cidr4: int | None = None  # a/mx dual-cidr and ip4
    cidr6: int | None = None  # a/mx dual-cidr and ip6
    has_macro: bool = False
    valid: bool = True


@dataclass(frozen=True, slots=True)
class SpfRecord:
    raw: str
    version: str | None  # the version token as written, None when absent
    terms: tuple[SpfTerm, ...]
    issues: tuple[ParseIssue, ...]
    truncated: bool = False

    @property
    def is_valid(self) -> bool:
        """True when no ``error`` issue was found (receivers would not return permerror)."""
        return self.version is not None and not any(i.severity == "error" for i in self.issues)

    @property
    def mechanisms(self) -> tuple[SpfTerm, ...]:
        return tuple(t for t in self.terms if t.kind == "mechanism")

    @property
    def modifiers(self) -> tuple[SpfTerm, ...]:
        return tuple(t for t in self.terms if t.kind == "modifier")

    @property
    def redirect(self) -> SpfTerm | None:
        return next((t for t in self.modifiers if t.name == "redirect"), None)

    @property
    def exp(self) -> SpfTerm | None:
        return next((t for t in self.modifiers if t.name == "exp"), None)

    @property
    def has_macro(self) -> bool:
        return any(t.has_macro for t in self.terms)

    def issue_codes(self) -> tuple[str, ...]:
        return tuple(i.code for i in self.issues)


def is_spf_record(text: str) -> bool:
    """RFC 7208 section 4.5: the record starts with ``v=spf1`` followed by SP or end.

    The version literal is case-insensitive (section 12). Leading whitespace or any other
    separator (tab, ``-``) means the record is not an SPF record.
    """
    if not isinstance(text, str) or len(text) < 6:
        return False
    return text[:6].lower() == "v=spf1" and (len(text) == 6 or text[6] == " ")


def parse_spf(text: str) -> SpfRecord:
    """Parse an SPF TXT record (strings already concatenated). Never raises."""
    if not isinstance(text, str):
        return SpfRecord(raw="", version=None, terms=(), issues=(ParseIssue(EMPTY_RECORD, "", 0),))
    issues: list[ParseIssue] = []
    truncated = False
    raw = text
    if len(text) > MAX_RECORD_LENGTH:
        text = text[:MAX_RECORD_LENGTH]
        truncated = True
        issues.append(ParseIssue(RECORD_TOO_LONG, "", MAX_RECORD_LENGTH))

    tokens = _tokenise(text, issues)
    if not tokens:
        issues.append(ParseIssue(EMPTY_RECORD, "", 0))
        return SpfRecord(raw=raw, version=None, terms=(), issues=tuple(issues), truncated=truncated)

    version: str | None = None
    first, first_pos = tokens[0]
    lowered = first.lower()
    if lowered == "v=spf1":
        version = first
        if first != "v=spf1":
            issues.append(ParseIssue(VERSION_CASE, first, first_pos, "warning"))
        tokens = tokens[1:]
    elif lowered.startswith("v="):
        issues.append(ParseIssue(BAD_VERSION, first, first_pos))
        tokens = tokens[1:]
    else:
        issues.append(ParseIssue(MISSING_VERSION, first, first_pos))

    if len(tokens) > MAX_TERMS:
        cut_pos = tokens[MAX_TERMS][1]
        tokens = tokens[:MAX_TERMS]
        truncated = True
        issues.append(ParseIssue(TOO_MANY_TERMS, "", cut_pos))

    terms: list[SpfTerm] = []
    seen_modifiers: set[str] = set()
    all_seen = False
    for tok, pos in tokens:
        term_issues: list[ParseIssue] = []
        term = _parse_term(tok, pos, term_issues)
        if term.kind == "mechanism":
            if all_seen:
                term_issues.append(ParseIssue(TERM_AFTER_ALL, tok, pos, "warning"))
            if term.name == "all":
                all_seen = True
        elif term.kind == "modifier" and term.name in KNOWN_MODIFIERS:
            if term.name in seen_modifiers:
                term_issues.append(ParseIssue(DUPLICATE_MODIFIER, tok, pos))
            seen_modifiers.add(term.name)
        if any(i.severity == "error" for i in term_issues) and term.valid:
            term = replace(term, valid=False)
        terms.append(term)
        issues.extend(term_issues)

    if any(t.kind == "mechanism" and t.name == "all" for t in terms):
        for t in terms:
            if t.kind == "modifier" and t.name == "redirect":
                issues.append(ParseIssue(REDIRECT_WITH_ALL, t.raw, t.position, "warning"))

    return SpfRecord(
        raw=raw, version=version, terms=tuple(terms), issues=tuple(issues), truncated=truncated
    )


def _tokenise(text: str, issues: list[ParseIssue]) -> list[tuple[str, int]]:
    """Split on whitespace in one linear pass; report whitespace problems once each."""
    tokens: list[tuple[str, int]] = []
    start = -1
    run = 0  # consecutive separator characters
    reported: set[str] = set()

    def report(code: str, pos: int, severity: IssueSeverity = "error") -> None:
        if code not in reported:
            reported.add(code)
            issues.append(ParseIssue(code, "", pos, severity))

    for i, ch in enumerate(text):
        if ch == " " or ch.isspace():
            if ch in _ASCII_WS:
                report(INVALID_WHITESPACE, i)
            elif ch != " ":
                report(NON_ASCII, i)
            if start != -1:
                tokens.append((text[start:i], start))
                start = -1
                run = 0
            run += 1
            if run == 1 and i == 0:
                report(LEADING_WHITESPACE, 0)
            elif run == 2 and tokens:
                report(EXTRA_WHITESPACE, i - 1, "warning")
        else:
            if start == -1:
                start = i
            run = 0
    if start != -1:
        tokens.append((text[start:], start))
    return tokens


def _check_chars(tok: str, pos: int, issues: list[ParseIssue]) -> bool:
    """Flag characters outside visible ASCII (0x21-0x7E). Returns True when clean."""
    clean = True
    seen: set[str] = set()
    for i, ch in enumerate(tok):
        o = ord(ch)
        if 0x21 <= o <= 0x7E:
            continue
        clean = False
        code = NON_ASCII if o > 0x7F else CONTROL_CHARACTER
        if code not in seen:
            seen.add(code)
            issues.append(ParseIssue(code, tok, pos + i))
    return clean


def _parse_term(tok: str, pos: int, issues: list[ParseIssue]) -> SpfTerm:
    _check_chars(tok, pos, issues)

    # Modifier: name "=" ... where name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
    if tok[0] in _ASCII_ALPHA:
        i = 1
        while i < len(tok) and tok[i] in _NAME_CHARS:
            i += 1
        if i < len(tok) and tok[i] == "=":
            return _parse_modifier(tok, pos, tok[:i], tok[i + 1 :], issues)
    return _parse_mechanism(tok, pos, issues)


def _parse_modifier(tok: str, pos: int, name: str, value: str, issues: list[ParseIssue]) -> SpfTerm:
    lname = name.lower()
    if name != lname:
        issues.append(ParseIssue(UPPERCASE_NAME, tok, pos, "warning"))
    value_pos = pos + len(name) + 1
    has_macro = False
    if lname in KNOWN_MODIFIERS:
        if not value:
            issues.append(ParseIssue(EMPTY_VALUE, tok, pos))
        else:
            has_macro = _check_domain_spec(value, tok, value_pos, issues)
    else:
        has_macro = _check_macro_string(value, tok, value_pos, issues, allow_exp_only=True)
        if lname == "v":
            issues.append(ParseIssue(DUPLICATE_VERSION, tok, pos, "warning"))
        elif lname in MECHANISMS:
            issues.append(ParseIssue(MECHANISM_AS_MODIFIER, tok, pos, "warning"))
        else:
            issues.append(ParseIssue(UNKNOWN_MODIFIER, tok, pos, "warning"))
    return SpfTerm(
        raw=tok,
        position=pos,
        kind="modifier",
        name=lname,
        value=value,
        has_macro=has_macro,
        valid=not any(i.severity == "error" for i in issues),
    )


def _parse_mechanism(tok: str, pos: int, issues: list[ParseIssue]) -> SpfTerm:
    qualifier: Qualifier = "+"
    body = tok
    if tok[0] in _QUALIFIERS:
        qualifier = cast(Qualifier, tok[0])
        body = tok[1:]
    n = 0
    while n < len(body) and body[n] in _ALNUM:
        n += 1
    name = body[:n]
    lname = name.lower()
    arg = body[n:]
    arg_pos = pos + (len(tok) - len(body)) + n

    if not name:
        issues.append(ParseIssue(INVALID_TERM, tok, pos))
        return SpfTerm(raw=tok, position=pos, kind="invalid", name="", valid=False)
    if lname not in MECHANISMS:
        issues.append(ParseIssue(UNKNOWN_MECHANISM, tok, pos))
        return SpfTerm(raw=tok, position=pos, kind="invalid", name=lname, valid=False)
    if name != lname:
        issues.append(ParseIssue(UPPERCASE_NAME, tok, pos, "warning"))
    if arg and arg[0] not in ":/":
        issues.append(ParseIssue(TRAILING_GARBAGE, tok, arg_pos))
        return SpfTerm(
            raw=tok, position=pos, kind="mechanism", name=lname, qualifier=qualifier, valid=False
        )

    value: str | None = None
    network: IpNetwork | None = None
    cidr4: int | None = None
    cidr6: int | None = None
    has_macro = False

    if lname == "all":
        if arg:
            issues.append(ParseIssue(UNEXPECTED_ARGUMENT, tok, arg_pos))
    elif lname in ("include", "exists", "ptr"):
        if arg.startswith("/"):
            issues.append(ParseIssue(UNEXPECTED_ARGUMENT, tok, arg_pos))
        elif arg == ":" or (not arg and lname != "ptr"):
            issues.append(ParseIssue(EMPTY_VALUE, tok, pos))
        elif arg:
            value = arg[1:]
            has_macro = _check_domain_spec(value, tok, arg_pos + 1, issues)
    elif lname in ("a", "mx"):
        rest, v4, v6 = _split_dual_cidr(arg)
        if v4 is not None:
            cidr4 = _parse_cidr(v4, 32, tok, arg_pos + len(rest), issues)
        if v6 is not None:
            cidr6 = _parse_cidr(v6, 128, tok, arg_pos + len(arg) - len(v6), issues)
        if rest == ":":
            issues.append(ParseIssue(EMPTY_VALUE, tok, pos))
        elif rest.startswith(":"):
            value = rest[1:]
            has_macro = _check_domain_spec(value, tok, arg_pos + 1, issues)
        elif rest:
            issues.append(ParseIssue(TRAILING_GARBAGE, tok, arg_pos))
    else:  # ip4 / ip6
        if not arg.startswith(":") or arg == ":":
            issues.append(ParseIssue(EMPTY_VALUE if arg in ("", ":") else BAD_IP, tok, pos))
        else:
            value = arg[1:]
            network, cidr = _parse_ip(lname, value, tok, arg_pos + 1, issues)
            if lname == "ip4":
                cidr4 = cidr
            else:
                cidr6 = cidr

    return SpfTerm(
        raw=tok,
        position=pos,
        kind="mechanism",
        name=lname,
        qualifier=qualifier,
        value=value,
        network=network,
        cidr4=cidr4,
        cidr6=cidr6,
        has_macro=has_macro,
        valid=not any(i.severity == "error" for i in issues),
    )


def _is_cidr_candidate(s: str) -> bool:
    """A "/" suffix belongs to a domain-spec when it contains a macro or a dot."""
    return not any(c in ".}%{" for c in s)


def _split_dual_cidr(arg: str) -> tuple[str, str | None, str | None]:
    """Split ``[":" domain-spec] [ip4-cidr] ["/" ip6-cidr]`` from the right, linearly."""
    v4: str | None = None
    v6: str | None = None
    j = arg.rfind("/")
    if j == -1 or not _is_cidr_candidate(arg[j + 1 :]):
        return arg, None, None
    if j > 0 and arg[j - 1] == "/":
        v6 = arg[j + 1 :]
        arg = arg[: j - 1]
        j = arg.rfind("/")
        if j == -1 or not _is_cidr_candidate(arg[j + 1 :]):
            return arg, None, v6
    v4 = arg[j + 1 :]
    return arg[:j], v4, v6


def _parse_cidr(s: str, max_len: int, tok: str, pos: int, issues: list[ParseIssue]) -> int | None:
    """``"0" / %x31-39 *DIGIT`` within ``0..max_len`` (no leading zeros, ASCII digits)."""
    if (
        not s
        or len(s) > 3
        or any(c not in _DIGITS for c in s)
        or (len(s) > 1 and s[0] == "0")
        or int(s) > max_len
    ):
        issues.append(ParseIssue(BAD_CIDR, tok, pos))
        return None
    return int(s)


def _parse_ip(
    mech: str, value: str, tok: str, pos: int, issues: list[ParseIssue]
) -> tuple[IpNetwork | None, int | None]:
    addr, sep, cidr_s = value.partition("/")
    cidr: int | None = None
    max_len = 32 if mech == "ip4" else 128
    if sep:
        cidr = _parse_cidr(cidr_s, max_len, tok, pos + len(addr), issues)
        if cidr is None:
            return None, None
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    try:
        if mech == "ip4":
            # ip4-network is a strict dotted quad; ipaddress rejects leading zeros.
            if any(c not in _DIGITS and c != "." for c in addr):
                raise ValueError(addr)
            ip = ipaddress.IPv4Address(addr)
        else:
            # Python accepts "%scope" zone ids; RFC 4291 section 2.2 text form does not.
            if "%" in addr or not addr:
                raise ValueError(addr)
            ip = ipaddress.IPv6Address(addr)
    except ValueError:
        issues.append(ParseIssue(BAD_IP, tok, pos))
        return None, cidr
    prefix = max_len if cidr is None else cidr
    # strict=False: RFC 7208 compares only the high-order bits, host bits may be set.
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False), cidr


def _check_macro_string(
    s: str, tok: str, pos: int, issues: list[ParseIssue], *, allow_exp_only: bool
) -> bool:
    """Validate macro-string syntax (RFC 7208 section 7.1). Returns has_macro."""
    has_macro, _ = _scan_macros(s, tok, pos, issues, allow_exp_only=allow_exp_only)
    return has_macro


def _scan_macros(
    s: str, tok: str, pos: int, issues: list[ParseIssue], *, allow_exp_only: bool
) -> tuple[bool, bool]:
    """Linear scan of a macro-string. Returns (has_macro, ends_with_macro_expand).

    On the first syntax error a ``bad_macro`` issue is reported and scanning stops.
    """
    has_macro = False
    ends_with_macro = False
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch != "%":
            ends_with_macro = False
            i += 1
            continue
        has_macro = True
        nxt = s[i + 1] if i + 1 < n else ""
        if nxt in _MACRO_SHORT and nxt:
            i += 2
            ends_with_macro = True
            continue
        if nxt != "{":
            issues.append(ParseIssue(BAD_MACRO, tok, pos + i))
            return has_macro, False
        close = s.find("}", i + 2)
        if close == -1 or not _valid_macro_body(s[i + 2 : close]):
            issues.append(ParseIssue(BAD_MACRO, tok, pos + i))
            return has_macro, False
        if not allow_exp_only and s[i + 2].lower() in _MACRO_EXP_ONLY_LETTERS:
            issues.append(ParseIssue(MACRO_EXP_ONLY, tok, pos + i))
        i = close + 1
        ends_with_macro = True
    return has_macro, ends_with_macro


def _valid_macro_body(body: str) -> bool:
    """``macro-letter *DIGIT [ "r" ] *delimiter`` (letters case-insensitive)."""
    if not body or body[0].lower() not in _MACRO_LETTERS:
        return False
    i = 1
    digits_start = i
    while i < len(body) and body[i] in _DIGITS:
        i += 1
    digits = body[digits_start:i]
    if digits and all(c == "0" for c in digits):
        return False  # section 7.3: if a DIGIT is specified, the value MUST be nonzero
    if i < len(body) and body[i] in "rR":
        i += 1
    return all(c in _MACRO_DELIMITERS for c in body[i:])


def _check_domain_spec(s: str, tok: str, pos: int, issues: list[ParseIssue]) -> bool:
    """``domain-spec = macro-string domain-end``. Returns has_macro."""
    before = len(issues)
    has_macro, ends_with_macro = _scan_macros(s, tok, pos, issues, allow_exp_only=False)
    if any(i.code == BAD_MACRO for i in issues[before:]):
        return has_macro
    if ends_with_macro:
        return has_macro
    body = s[:-1] if s.endswith(".") else s
    dot = body.rfind(".")
    if dot == -1 or not _valid_toplabel(body[dot + 1 :]):
        issues.append(ParseIssue(INVALID_DOMAIN, tok, pos))
    return has_macro


def _valid_toplabel(label: str) -> bool:
    """``( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *( alphanum / "-" ) alphanum )``."""
    if not label or any(c not in _ALNUM and c != "-" for c in label):
        return False
    if "-" in label:
        return label[0] in _ALNUM and label[-1] in _ALNUM
    return any(c in _ASCII_ALPHA for c in label)
