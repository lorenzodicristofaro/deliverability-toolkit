"""Static link analysis over the anchors of a message body (M5-09).

Input: the raw ``(text, href | None)`` pairs collected by ``app.parsers.content_html`` (M5-08).
Output: per-link facts plus message-level domain statistics. Facts only, no verdicts: findings
and i18n live in M5-14.

Purely static: no DNS, no HTTP, nothing is fetched, resolved or followed (that would need the
guarded client, M7). Every href is hostile input.

Host extraction loosely follows the WHATWG URL parser for the special schemes ``http``/``https``
(and protocol-relative ``//host``) so that the host we report is the one a browser would visit:
- leading/trailing C0 control characters and spaces are stripped, ASCII tab/CR/LF anywhere are
  removed (``java\\tscript:`` is ``javascript:``); other control characters set
  ``has_control_chars``;
- any run of ``/`` or ``\\`` after the scheme is skipped; the authority ends at ``/ \\ ? #``;
- userinfo is everything before the LAST ``@`` (``http://bank.example@evil.example`` goes to
  ``evil.example``);
- the host is percent-decoded (strict UTF-8), UTS #46 mapped, then: a host whose last label is
  numeric is parsed as IPv4 in decimal/hex/octal/short forms (``http://3232235777``,
  ``http://0x7f.1``, ``http://0177.0.0.1``) and reported in canonical dotted form; ``[...]`` is
  an IPv6 literal; anything else goes through ``app.core.domain_names.to_ascii_domain``.
Organizational domains come from ``app.core.org_domain`` (full PSL); when a host has none (it is
a public suffix itself) the host itself is used, as in ``app.services.message_findings``.

Heuristics (not vendor rules): the masked-link test extracts a host from the visible text only
when the text token has an explicit scheme, starts with ``www.``, or ends in a suffix known to
the Public Suffix List (so file names whose extension is also a TLD, such as ``readme.md`` or
``setup.zip``, are read as hosts). Without a scheme an IP is accepted from the text only as a
plain decimal dotted quad (``version 1.2`` is not read as ``1.0.0.2``). ``mixed_script``
groups Han/Hiragana/Katakana/Hangul as one script so ordinary Japanese/Korean labels are not
flagged, and it cannot see single-script homographs (an all-Cyrillic label), for which only the
``idn`` flag is set. The default caps (500 links,
4096 characters per href, 512 characters of visible text per link) are conservative bounds chosen
here, not taken from any specification.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from urllib.parse import unquote_to_bytes

import idna

from app.core.domain_names import InvalidDomainName, to_ascii_domain, to_display_name
from app.core.org_domain import _psl, organizational_domain
from app.parsers.url_shorteners import Shortener


@dataclass(frozen=True)
class LinkLimits:
    max_links: int = 500
    max_url_length: int = 4096  # characters of the raw href
    max_text_length: int = 512  # characters of visible text scanned for a host


@dataclass(frozen=True)
class LinkInfo:
    index: int  # position in the anchor list
    # web | mailto | tel | javascript | data | vbscript | other | relative | empty | no_href |
    # too_long
    kind: str
    scheme: str | None = None  # lowercase; None for relative / protocol-relative / empty
    protocol_relative: bool = False
    host: str | None = None  # ASCII (A-label) name or canonical IP literal
    host_unicode: str | None = None
    registrable_domain: str | None = None  # organizational domain, else the host itself
    ip_literal: bool = False
    non_https: bool = False  # explicit http:
    has_userinfo: bool = False
    percent_encoded_host: bool = False
    has_control_chars: bool = False
    dangerous_scheme: bool = False  # javascript:, data:, vbscript:
    idn: bool = False  # host has an xn-- label
    mixed_script: bool = False
    homograph_suspect: bool = False  # idn and (mixed_script or masked)
    text_host: str | None = None  # host shown in the visible text, if any
    masked: bool = False
    shortener: str | None = None  # matched seed domain
    shortener_verified: bool | None = None
    aligned: bool | None = None  # None: no sender domains, or no host to compare
    # host_<InvalidDomainName.reason> | empty_host | invalid_ipv4 | invalid_ipv6 | port |
    # host_percent_encoding | host_idna
    malformed: str | None = None


@dataclass(frozen=True)
class LinkAnalysis:
    links: tuple[LinkInfo, ...] = ()
    total_anchors: int = 0
    capped: bool = False
    cap_reason: str | None = None  # link_count | url_length (first one hit)
    sender_domains: tuple[str, ...] = ()  # organizational domains used for alignment
    # Web links whose host could not be parsed; they cannot be checked for alignment.
    malformed_count: int = 0
    # Links that could not be checked for alignment: malformed web links, over-length hrefs,
    # and anchors beyond the link-count cap (their kind is unknown, so all of them count).
    unevaluated_count: int = 0
    # None when no sender domain was given, no link has a host, or any link is unevaluated.
    all_aligned: bool | None = None
    unaligned_count: int | None = None  # among links with a parsed host
    # Distinct registrable domains of web links outside the sender domains (all web domains
    # when no sender is given), most common first.
    other_domains: tuple[str, ...] = ()
    dominant_domain: str | None = None
    outlier_domains: tuple[str, ...] = ()


_DANGEROUS = frozenset({"javascript", "data", "vbscript"})
_KIND_BY_SCHEME = {
    "http": "web",
    "https": "web",
    "mailto": "mailto",
    "tel": "tel",
    "javascript": "javascript",
    "data": "data",
    "vbscript": "vbscript",
}
_SCHEME_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_AUTH_END_RE = re.compile(r"[/\\?#]")
_TAB_NL = str.maketrans("", "", "\t\r\n")
_TOKEN_STRIP = "<>()[]{}\"'.,;:!?«»“”‘’"
_TEXT_TOKENS = 20
_DOTTED_QUAD = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
)
_CJK = frozenset({"CJK", "HIRAGANA", "KATAKANA", "HANGUL", "IDEOGRAPHIC"})


class _BadHost(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _Host:
    host: str
    ip: bool
    userinfo: bool
    percent: bool


def _has_controls(value: str) -> bool:
    return any(unicodedata.category(c) == "Cc" for c in value)


def _clean(href: str) -> str:
    # WHATWG: strip leading/trailing C0 controls and space, remove ASCII tab/newline anywhere.
    return href.strip("".join(chr(i) for i in range(0x21))).translate(_TAB_NL)


def _ipv4_part(part: str) -> int:
    if part[:2] in ("0x", "0X"):
        digits = part[2:]
        if not digits:
            return 0
        if not all(c in "0123456789abcdefABCDEF" for c in digits):
            raise _BadHost("invalid_ipv4")
        return int(digits, 16)
    if len(part) > 1 and part[0] == "0":
        if not all(c in "01234567" for c in part):
            raise _BadHost("invalid_ipv4")
        return int(part, 8)
    if not part.isascii() or not part.isdigit():
        raise _BadHost("invalid_ipv4")
    return int(part)


def _ends_in_number(host: str) -> bool:
    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels.pop()
    last = labels[-1]
    if last and last.isascii() and last.isdigit():
        return True
    return last[:2] in ("0x", "0X") and all(c in "0123456789abcdefABCDEF" for c in last[2:])


def _parse_ipv4(host: str) -> str:
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4 or any(not p or len(p) > 40 for p in parts):
        raise _BadHost("invalid_ipv4")
    numbers = [_ipv4_part(p) for p in parts]
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise _BadHost("invalid_ipv4")
    value = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        value += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(value))


def _is_port(value: str) -> bool:
    return value.isascii() and value.isdigit() and len(value) <= 5 and int(value) <= 65535


def _parse_host(authority: str) -> _Host:
    userinfo = "@" in authority
    hostport = authority.rsplit("@", 1)[1] if userinfo else authority
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise _BadHost("invalid_ipv6")
        literal, rest = hostport[1:end], hostport[end + 1 :]
        if rest and not (rest[0] == ":" and (rest[1:] == "" or _is_port(rest[1:]))):
            raise _BadHost("port")
        try:
            ip6 = ipaddress.IPv6Address(literal)
        except ValueError:
            raise _BadHost("invalid_ipv6") from None
        if ip6.scope_id is not None:
            raise _BadHost("invalid_ipv6")
        return _Host(f"[{ip6.compressed}]", True, userinfo, False)
    host, _, port = hostport.partition(":")
    if port and not _is_port(port):
        raise _BadHost("port")
    if not host:
        raise _BadHost("empty_host")
    percent = "%" in host
    if percent:
        try:
            host = unquote_to_bytes(host).decode("utf-8")
        except UnicodeDecodeError:
            raise _BadHost("host_percent_encoding") from None
    if _has_controls(host):
        raise _BadHost("host_forbidden_character")
    if not host.isascii():
        try:
            host = idna.uts46_remap(host, std3_rules=False, transitional=False)
        except (idna.IDNAError, UnicodeError, ValueError):
            raise _BadHost("host_idna") from None
    if _ends_in_number(host):
        return _Host(_parse_ipv4(host), True, userinfo, percent)
    try:
        name = to_ascii_domain(host)
    except InvalidDomainName as exc:
        raise _BadHost(f"host_{exc.reason}") from None
    return _Host(name, False, userinfo, percent)


def _split_web(rest: str) -> str:
    """Authority part of a special-scheme URL after ``scheme:`` (or of ``//...``)."""
    rest = rest.lstrip("/\\")
    match = _AUTH_END_RE.search(rest)
    return rest[: match.start()] if match else rest


def _org(name: str) -> str:
    try:
        return organizational_domain(name) or name
    except InvalidDomainName:
        return name


def _scripts(label: str) -> set[str]:
    out: set[str] = set()
    for char in label:
        if char.isalpha():
            script = unicodedata.name(char, "UNKNOWN").split(" ")[0]
            out.add("CJK" if script in _CJK else script)
    return out


def _mixed_script(unicode_host: str) -> bool:
    return any(len(_scripts(label)) > 1 for label in unicode_host.split("."))


def _text_host(text: str, limits: LinkLimits) -> str | None:
    """Host of the first URL-looking token of the visible text (None when there is none)."""
    tokens = text[: limits.max_text_length].split()
    for token in tokens[:_TEXT_TOKENS]:
        token = token.strip(_TOKEN_STRIP)
        if not token:
            continue
        match = _SCHEME_RE.match(token)
        explicit = False
        if match and match.group(1).lower() in ("http", "https"):
            authority = _split_web(token[match.end() :])
            explicit = True
        elif token.startswith("//"):
            authority = _split_web(token)
            explicit = True
        elif match:
            continue
        else:
            authority = _split_web(token)
            if "@" in authority:  # an e-mail address: compare its domain
                authority = authority.rsplit("@", 1)[1]
        if "." not in authority and not authority.startswith("["):
            continue
        try:
            parsed = _parse_host(authority)
        except _BadHost:
            continue
        if parsed.ip:
            # Without a scheme only a plain dotted quad counts ("version 1.2" is not an IP).
            if explicit or _DOTTED_QUAD.fullmatch(authority.partition(":")[0]):
                return parsed.host
            continue
        if explicit or parsed.host.startswith("www."):
            return parsed.host
        if _psl().publicsuffix(parsed.host, accept_unknown=False) is not None:
            return parsed.host
    return None


def _shortener_index(shorteners: Iterable[Shortener]) -> dict[str, Shortener]:
    return {s.domain: s for s in shorteners}


def _match_shortener(host: str, index: dict[str, Shortener]) -> Shortener | None:
    labels = host.split(".")
    for i in range(len(labels) - 1):
        hit = index.get(".".join(labels[i:]))
        if hit is not None:
            return hit
    return None


def _analyze_one(
    index: int,
    text: str,
    href: str | None,
    limits: LinkLimits,
    senders: frozenset[str],
    shorteners: dict[str, Shortener],
) -> LinkInfo:
    if href is None:
        return LinkInfo(index, "no_href")
    if len(href) > limits.max_url_length:
        return LinkInfo(index, "too_long")
    cleaned = _clean(href)
    controls = _has_controls(cleaned)
    if not cleaned:
        return LinkInfo(index, "empty", has_control_chars=controls)
    match = _SCHEME_RE.match(cleaned)
    scheme = match.group(1).lower() if match else None
    protocol_relative = scheme is None and cleaned[:2] in ("//", "\\\\", "/\\", "\\/")
    if scheme is None and not protocol_relative:
        return LinkInfo(index, "relative", has_control_chars=controls)
    kind = "web" if protocol_relative else _KIND_BY_SCHEME.get(scheme or "", "other")
    base = LinkInfo(
        index,
        kind,
        scheme=scheme,
        protocol_relative=protocol_relative,
        has_control_chars=controls,
        dangerous_scheme=scheme in _DANGEROUS,
        non_https=scheme == "http",
    )
    text_host = _text_host(text, limits) if kind not in ("mailto", "tel") else None
    if kind != "web":
        masked = text_host is not None and kind in _DANGEROUS
        return replace(base, text_host=text_host, masked=masked)
    rest = cleaned if protocol_relative else cleaned[match.end() if match else 0 :]
    try:
        parsed = _parse_host(_split_web(rest))
    except _BadHost as exc:
        return replace(base, malformed=exc.reason, text_host=text_host)
    host = parsed.host
    registrable = host if parsed.ip else _org(host)
    unicode_host = host if parsed.ip else to_display_name(host)
    idn = not parsed.ip and any(label.startswith("xn--") for label in host.split("."))
    mixed = idn and _mixed_script(unicode_host)
    masked = text_host is not None and _org(text_host) != registrable
    hit = None if parsed.ip else _match_shortener(host, shorteners)
    return replace(
        base,
        host=host,
        host_unicode=unicode_host,
        registrable_domain=registrable,
        ip_literal=parsed.ip,
        has_userinfo=parsed.userinfo,
        percent_encoded_host=parsed.percent,
        idn=idn,
        mixed_script=mixed,
        homograph_suspect=idn and (mixed or masked),
        text_host=text_host,
        masked=masked,
        shortener=hit.domain if hit else None,
        shortener_verified=(hit.status == "verified") if hit else None,
        aligned=(registrable in senders) if senders else None,
    )


def _sender_orgs(sender_domains: Iterable[str | None]) -> tuple[str, ...]:
    out: set[str] = set()
    for domain in sender_domains:
        if not isinstance(domain, str):
            continue
        try:
            ascii_name = to_ascii_domain(domain)
        except InvalidDomainName:
            continue
        out.add(_org(ascii_name))
    return tuple(sorted(out))


def analyze_links(
    anchors: Sequence[tuple[str, str | None]],
    *,
    sender_domains: Iterable[str | None],
    shorteners: Iterable[Shortener],
    limits: LinkLimits | None = None,
) -> LinkAnalysis:
    """Analyze anchors statically. ``sender_domains``: From domain, optional DKIM d=, optional
    tenant domain (invalid or None entries are ignored). No network, no DNS."""
    limits = limits or LinkLimits()
    senders = _sender_orgs(sender_domains)
    sender_set = frozenset(senders)
    index = _shortener_index(shorteners)
    capped = len(anchors) > limits.max_links
    cap_reason = "link_count" if capped else None
    links: list[LinkInfo] = []
    for i, (text, href) in enumerate(anchors[: limits.max_links]):
        info = _analyze_one(i, text or "", href, limits, sender_set, index)
        if info.kind == "too_long" and not capped:
            capped, cap_reason = True, "url_length"
        links.append(info)
    with_host = [link for link in links if link.registrable_domain is not None]
    malformed = sum(1 for link in links if link.kind == "web" and link.malformed is not None)
    too_long = sum(1 for link in links if link.kind == "too_long")
    unevaluated = malformed + too_long + (len(anchors) - len(links))
    all_aligned: bool | None = None
    unaligned: int | None = None
    if senders and with_host:
        unaligned = sum(1 for link in with_host if not link.aligned)
        all_aligned = unaligned == 0 if unevaluated == 0 else None
    counts = Counter(
        link.registrable_domain
        for link in with_host
        if link.registrable_domain is not None and link.registrable_domain not in sender_set
    )
    ordered = tuple(d for d, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    return LinkAnalysis(
        links=tuple(links),
        total_anchors=len(anchors),
        capped=capped,
        cap_reason=cap_reason,
        sender_domains=senders,
        malformed_count=malformed,
        unevaluated_count=unevaluated,
        all_aligned=all_aligned,
        unaligned_count=unaligned,
        other_domains=ordered,
        dominant_domain=ordered[0] if ordered else None,
        outlier_domains=ordered[1:],
    )


__all__ = ["LinkAnalysis", "LinkInfo", "LinkLimits", "analyze_links"]
