"""Received chain parser and hop delays (RFC 5321 sections 4.4 and 4.1.2, RFC 5322 3.3, 4.3).

Pure and offline: hostnames and IP addresses are extracted as text only. There is NO DNS,
no reverse lookup, no whois, no geoip and no network access of any kind; nothing is stored.

Input is the ordered ``Received`` values of a :class:`~app.parsers.message.HeaderBlock`
(:func:`parse_received_chain`) or the same values as strings (:func:`parse_received_values`).
Header order is newest first (RFC 5321 section 4.4: each relay prepends its trace header),
so the result lists hops oldest to newest: ``hops[0]`` is the first relay, ``hops[-1]``
the last one, normally the receiving system.

Each value is parsed best effort against the RFC 5321 ``Stamp`` grammar::

    Stamp = From-domain By-domain Opt-info [CFWS] ";" FWS date-time
    Opt-info = [Via] [With] [ID] [For] [Additional-Registered-Clauses]

No vendor layout is assumed. The clause part is everything before the last ``;`` outside
comments, the date is everything after it. Clause keywords (``from``, ``by``, ``via``,
``with``, ``id``, ``for``) are matched case-insensitively, in any order; the first word
after a keyword is its value and comments after it belong to the clause. Extra words
(additional clauses, multi-word protocols) are ignored with ``unexpected_token``.

- ``from_host``: the ``from`` value, or None when it is an address literal.
- ``from_ip``: the first bracketed address literal (``[192.0.2.1]``, ``[IPv6:2001:db8::1]``;
  a bare IPv6 inside brackets is also accepted) in the ``from`` value or its comments,
  validated with :mod:`ipaddress`. ``from_ip_reserved`` is ``not is_global`` (private,
  loopback, documentation, ... ranges). Unbracketed addresses are not extracted.
- ``by_host``, ``via``, ``with_protocol`` and ``id`` are kept as text; ``id`` is not
  interpreted.
- ``for``: only its presence (``has_for``); the address is NOT retained in a field.
- A value that does not start with a clause keyword, or has none, keeps ``parsed=False``
  with its raw text and ``unparsed_hop``; the date is still read and the chain continues.

Dates (RFC 5322 section 3.3 and obsolete syntax of section 4.3): optional day of week,
comments anywhere, 2- and 3-digit years, numeric offsets (``-0000`` is UTC) and the
obsolete zone names ``UT``, ``GMT``, ``EST``/``EDT``, ``CST``/``CDT``, ``MST``/``MDT``,
``PST``/``PDT``. Military and other alphabetic zones are taken as ``-0000`` per section
4.3 and flagged ``date_zone_unknown``. Timestamps are UTC-aware. A date with no zone,
an invalid date (Feb 30, hour 25) or no ``;`` gives ``timestamp=None`` with
``date_no_timezone`` / ``date_invalid`` / ``date_missing``; a zone-less time is NEVER
assumed to be UTC.

Delays: ``delay_seconds`` of a hop is its timestamp minus the previous hop's, only when
both exist. Negative delays are kept as they are and flagged ``clock_skew``, never
clamped. ``total_transit_seconds`` is last hop minus first hop when both have a timestamp.

Caps: at most :data:`MAX_HOPS` values are parsed; the newest ones are kept (the older
ones are the easiest for a sender to forge) and ``truncated`` is set. A value over
:data:`MAX_HOP_BYTES` UTF-8 bytes is not parsed: its ``raw`` is cut to the cap and it gets
``hop_too_long``. Warnings are :class:`~app.parsers.spf.ParseIssue` with
``severity="warning"``, at most one per code per hop, ``term`` always empty (no input is
echoed) and ``position`` the character offset in the value. There are no regular
expressions; every scan is a single linear pass (nested comments use a depth counter).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import Literal

from app.parsers.message import HeaderBlock
from app.parsers.spf import ParseIssue

MAX_HOPS = 100
MAX_HOP_BYTES = 8 * 1024
MAX_ADDRESS_LITERAL = 64

# Warning codes (stable, lowercase).
EMPTY_RECEIVED = "empty_received"
HOP_TOO_LONG = "hop_too_long"
UNPARSED_HOP = "unparsed_hop"
UNBALANCED_COMMENT = "unbalanced_comment"
UNTERMINATED_QUOTE = "unterminated_quote"
UNEXPECTED_TOKEN = "unexpected_token"
DUPLICATE_CLAUSE = "duplicate_clause"
MISSING_CLAUSE_VALUE = "missing_clause_value"
INVALID_IP_LITERAL = "invalid_ip_literal"
NON_ASCII_HOST = "non_ascii_host"
DATE_MISSING = "date_missing"
DATE_NO_TIMEZONE = "date_no_timezone"
DATE_INVALID = "date_invalid"
DATE_ZONE_UNKNOWN = "date_zone_unknown"
CLOCK_SKEW = "clock_skew"

_KEYWORDS: frozenset[str] = frozenset({"from", "by", "via", "with", "id", "for"})
_WSP = " \t\r\n"
_DIGITS = frozenset("0123456789")
_DAYS: frozenset[str] = frozenset({"mon", "tue", "wed", "thu", "fri", "sat", "sun"})
_MONTHS: dict[str, int] = {
    name: number
    for number, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"),
        start=1,
    )
}
# RFC 5322 section 4.3 obsolete zone names, offset in hours.
_ZONES: dict[str, int] = {
    "ut": 0,
    "gmt": 0,
    "est": -5,
    "edt": -4,
    "cst": -6,
    "cdt": -5,
    "mst": -7,
    "mdt": -6,
    "pst": -8,
    "pdt": -7,
}


@dataclass(frozen=True, slots=True)
class ReceivedHop:
    """One Received hop. ``index`` 0 is the oldest hop."""

    index: int
    raw: str
    parsed: bool
    from_host: str | None
    from_ip: str | None
    from_ip_reserved: bool | None
    by_host: str | None
    via: str | None
    with_protocol: str | None
    id: str | None
    has_for: bool
    timestamp: datetime | None
    delay_seconds: int | None
    warnings: tuple[ParseIssue, ...]


@dataclass(frozen=True, slots=True)
class ReceivedChain:
    """Hops oldest to newest; ``received_count`` counts every Received value seen."""

    hops: tuple[ReceivedHop, ...]
    total_transit_seconds: int | None
    truncated: bool
    received_count: int


class _Warnings:
    def __init__(self) -> None:
        self.items: list[ParseIssue] = []
        self._seen: set[str] = set()

    def add(self, code: str, position: int) -> None:
        if code in self._seen:
            return
        self._seen.add(code)
        self.items.append(ParseIssue(code, "", position, "warning"))


@dataclass(slots=True)
class _Token:
    kind: Literal["word", "comment", "semi"]
    text: str
    position: int


def _scan_comment(value: str, start: int) -> tuple[int, bool]:
    """Return the index just past the comment opened at ``start`` and whether it closed."""
    depth = 0
    i = start
    n = len(value)
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
                return i + 1, True
        i += 1
    return n, False


def _tokenize(value: str, warnings: _Warnings) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch in _WSP:
            i += 1
        elif ch == "(":
            end, closed = _scan_comment(value, i)
            if not closed:
                warnings.add(UNBALANCED_COMMENT, i)
            inner_end = end - 1 if closed else end
            tokens.append(_Token("comment", value[i + 1 : inner_end], i))
            i = end
        elif ch == ")":
            warnings.add(UNBALANCED_COMMENT, i)
            i += 1
        elif ch == ";":
            tokens.append(_Token("semi", ";", i))
            i += 1
        else:
            start = i
            while i < n and value[i] not in _WSP and value[i] not in "();":
                if value[i] == '"':
                    i += 1
                    while i < n and value[i] != '"':
                        i += 2 if value[i] == "\\" else 1
                    if i >= n:
                        warnings.add(UNTERMINATED_QUOTE, start)
                        i = n
                        break
                i += 1
            tokens.append(_Token("word", value[start:i], start))
    return tokens


def _strip_comments(text: str) -> tuple[str, bool]:
    """Replace comments with a space; return the text and whether all comments closed."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == ")":
            return "".join(out), False
        if ch == "(":
            i, closed = _scan_comment(text, i)
            if not closed:
                return "".join(out), False
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out), True


def _is_digits(text: str, min_len: int, max_len: int) -> bool:
    return min_len <= len(text) <= max_len and all(c in _DIGITS for c in text)


def _parse_date(text: str) -> tuple[datetime | None, list[str]]:
    """Parse an RFC 5322 date-time; return the UTC timestamp and warning codes."""
    stripped, closed = _strip_comments(text)
    if not closed:
        return None, [DATE_INVALID]
    parts = stripped.replace(",", " , ").split()
    if not parts:
        return None, [DATE_MISSING]
    if parts[0].lower() in _DAYS:
        parts = parts[1:]
        if parts and parts[0] == ",":
            parts = parts[1:]
    if len(parts) == 4:
        return None, [DATE_NO_TIMEZONE]
    if len(parts) != 5:
        return None, [DATE_INVALID]
    day_s, month_s, year_s, time_s, zone_s = parts
    month = _MONTHS.get(month_s.lower())
    time_parts = time_s.split(":")
    if (
        not _is_digits(day_s, 1, 2)
        or month is None
        or not _is_digits(year_s, 2, 4)
        or len(time_parts) not in (2, 3)
        or not all(_is_digits(p, 1, 2) for p in time_parts)
    ):
        return None, [DATE_INVALID]
    year = int(year_s)
    if len(year_s) == 2:
        year += 2000 if year < 50 else 1900
    elif len(year_s) == 3:
        year += 1900
    hour, minute = int(time_parts[0]), int(time_parts[1])
    second = int(time_parts[2]) if len(time_parts) == 3 else 0

    codes: list[str] = []
    if zone_s[:1] in ("+", "-") and _is_digits(zone_s[1:], 4, 4):
        zone_h, zone_m = int(zone_s[1:3]), int(zone_s[3:5])
        if zone_h > 23 or zone_m > 59:
            return None, [DATE_INVALID]
        offset = timedelta(hours=zone_h, minutes=zone_m)
        if zone_s[0] == "-":
            offset = -offset
    elif zone_s.isascii() and zone_s.isalpha():
        hours = _ZONES.get(zone_s.lower())
        if hours is None:
            # RFC 5322 section 4.3: unknown and military zones SHOULD be taken as -0000.
            hours = 0
            codes.append(DATE_ZONE_UNKNOWN)
        offset = timedelta(hours=hours)
    else:
        return None, [DATE_INVALID]

    leap = second == 60  # RFC 5322 section 3.3 allows a leap second.
    try:
        stamp = datetime(
            year, month, int(day_s), hour, minute, 59 if leap else second, tzinfo=timezone(offset)
        )
        if leap:
            stamp += timedelta(seconds=1)
        return stamp.astimezone(UTC), codes
    except (ValueError, OverflowError):
        return None, [DATE_INVALID]


def _address_literals(text: str) -> list[tuple[str, int]]:
    """Bracketed segments of ``text`` (content, offset), in order. Linear scan."""
    found: list[tuple[str, int]] = []
    i = text.find("[")
    while i != -1:
        j = text.find("]", i + 1)
        if j == -1:
            break
        found.append((text[i + 1 : j], i))
        i = text.find("[", j + 1)
    return found


def _parse_ip(literal: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if len(literal) > MAX_ADDRESS_LITERAL or "[" in literal:
        return None
    if literal[:5].lower() == "ipv6:":
        literal = literal[5:]
        if ":" not in literal:
            return None
    try:
        return ipaddress.ip_address(literal)
    except ValueError:
        return None


@dataclass(slots=True)
class _Clause:
    value: _Token | None = None
    comments: list[_Token] = field(default_factory=list)


def _empty_hop(raw: str, parsed: bool = False) -> ReceivedHop:
    return ReceivedHop(
        index=0,
        raw=raw,
        parsed=parsed,
        from_host=None,
        from_ip=None,
        from_ip_reserved=None,
        by_host=None,
        via=None,
        with_protocol=None,
        id=None,
        has_for=False,
        timestamp=None,
        delay_seconds=None,
        warnings=(),
    )


def _too_long(value: str) -> bool:
    if len(value) > MAX_HOP_BYTES:
        return True
    return not value.isascii() and len(value.encode("utf-8", "surrogatepass")) > MAX_HOP_BYTES


def _parse_hop(value: str) -> ReceivedHop:
    warnings = _Warnings()
    if _too_long(value):
        cut = value[:MAX_HOP_BYTES].encode("utf-8", "surrogatepass")[:MAX_HOP_BYTES]
        warnings.add(HOP_TOO_LONG, MAX_HOP_BYTES)
        hop = _empty_hop(cut.decode("utf-8", "ignore"))
        return replace(hop, warnings=tuple(warnings.items))
    if not value.strip(_WSP):
        warnings.add(EMPTY_RECEIVED, 0)
        warnings.add(DATE_MISSING, 0)
        return replace(_empty_hop(value), warnings=tuple(warnings.items))

    tokens = _tokenize(value, warnings)
    semi = max((k for k, t in enumerate(tokens) if t.kind == "semi"), default=-1)
    clause_tokens = tokens if semi == -1 else tokens[:semi]

    clauses: dict[str, _Clause] = {}
    current: str | None = None
    ignoring = False
    leading_word = False
    for tok in clause_tokens:
        if tok.kind == "word" and tok.text.lower() in _KEYWORDS:
            keyword = tok.text.lower()
            if keyword in clauses:
                warnings.add(DUPLICATE_CLAUSE, tok.position)
                ignoring = True
            else:
                clauses[keyword] = _Clause()
                current, ignoring = keyword, False
            continue
        if current is None:
            if tok.kind != "comment":
                leading_word = True
                break
            continue
        if ignoring:
            continue
        clause = clauses[current]
        if tok.kind == "comment":
            clause.comments.append(tok)
        elif tok.kind == "word" and clause.value is None:
            clause.value = tok
        else:
            warnings.add(UNEXPECTED_TOKEN, tok.position)

    if semi == -1:
        timestamp: datetime | None = None
        warnings.add(DATE_MISSING, len(value))
    else:
        date_position = tokens[semi].position + 1
        timestamp, date_codes = _parse_date(value[date_position:])
        for code in date_codes:
            warnings.add(code, date_position)

    if leading_word or not clauses:
        warnings.add(UNPARSED_HOP, 0)
        return replace(_empty_hop(value), timestamp=timestamp, warnings=tuple(warnings.items))

    for keyword, clause in clauses.items():
        if clause.value is None and keyword != "for":
            warnings.add(MISSING_CLAUSE_VALUE, 0)

    def text_of(keyword: str) -> str | None:
        clause = clauses.get(keyword)
        return clause.value.text if clause and clause.value else None

    from_host = text_of("from")
    from_ip: str | None = None
    from_ip_reserved: bool | None = None
    from_clause = clauses.get("from")
    if from_clause is not None:
        sources = ([from_clause.value] if from_clause.value else []) + from_clause.comments
        for source in sources:
            for literal, offset in _address_literals(source.text):
                address = _parse_ip(literal)
                if address is None:
                    warnings.add(INVALID_IP_LITERAL, source.position + offset)
                    continue
                if from_ip is None:
                    from_ip, from_ip_reserved = str(address), not address.is_global
        if from_host is not None and from_host.startswith("[") and from_host.endswith("]"):
            from_host = None

    by_host = text_of("by")
    for host in (from_host, by_host):
        if host is not None and not host.isascii():
            warnings.add(NON_ASCII_HOST, 0)

    return ReceivedHop(
        index=0,
        raw=value,
        parsed=True,
        from_host=from_host,
        from_ip=from_ip,
        from_ip_reserved=from_ip_reserved,
        by_host=by_host,
        via=text_of("via"),
        with_protocol=text_of("with"),
        id=text_of("id"),
        has_for="for" in clauses,
        timestamp=timestamp,
        delay_seconds=None,
        warnings=tuple(warnings.items),
    )


def parse_received_values(values: Sequence[str]) -> ReceivedChain:
    """Parse Received values given in header order (newest first). See the module docstring."""
    if isinstance(values, str):
        raise TypeError("values must be a sequence of strings, not a string")
    newest_first = list(values[:MAX_HOPS])
    hops: list[ReceivedHop] = []
    previous: ReceivedHop | None = None
    for index, value in enumerate(reversed(newest_first)):
        hop = replace(_parse_hop(value), index=index)
        if previous is not None and previous.timestamp and hop.timestamp:
            delay = int((hop.timestamp - previous.timestamp).total_seconds())
            extra: tuple[ParseIssue, ...] = ()
            if delay < 0:
                extra = (ParseIssue(CLOCK_SKEW, "", 0, "warning"),)
            hop = replace(hop, delay_seconds=delay, warnings=hop.warnings + extra)
        hops.append(hop)
        previous = hop

    total: int | None = None
    if hops and hops[0].timestamp and hops[-1].timestamp:
        total = int((hops[-1].timestamp - hops[0].timestamp).total_seconds())
    return ReceivedChain(
        hops=tuple(hops),
        total_transit_seconds=total,
        truncated=len(values) > MAX_HOPS,
        received_count=len(values),
    )


def parse_received_chain(block: HeaderBlock) -> ReceivedChain:
    """Parse every ``Received`` field of ``block`` (raw values, in header order)."""
    return parse_received_values([f.raw_value for f in block.get_all("Received")])
