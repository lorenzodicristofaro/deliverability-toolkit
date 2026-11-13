"""URL and address policy for the guarded outbound HTTP client (M7-01, ARCHITECTURE section 9).

Pure functions: no DNS, no sockets. The address classification is
``app.dns.egress.address_reason`` (IANA special-purpose registries), not a second list.

``parse_url`` turns a caller URL (or a redirect target) into a ``Target`` or a ``FetchError``:

- scheme allowlist ``http``/``https``; port allowlist (default 80 and 443, ``FetchLimits``);
- userinfo (any ``@`` in the authority) is refused;
- whitespace, control characters and backslashes anywhere in the URL are refused;
- a bracketed IPv6 literal or a strict dotted-quad IPv4 literal is classified directly; zone ids
  are refused;
- anything else must pass ``app.core.domain_names.to_ascii_domain`` (IDNA 2008 + UTS #46,
  253/63 limits, one trailing dot removed, all-numeric last label refused), so decimal, octal,
  hex and short IPv4 spellings (``2130706433``, ``0x7f.0.0.1``, ``127.1``) never reach a resolver.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import SplitResult, urlsplit

from app.core.config import OUTBOUND_HTTP_MAX_REDIRECTS_HARD_MAX
from app.core.domain_names import InvalidDomainName, to_ascii_domain
from app.dns.egress import IPAddress, address_reason

ALLOWED_SCHEMES: tuple[str, ...] = ("http", "https")
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}
# Project choice, not an external fact: longer URLs are refused before parsing.
MAX_URL_LENGTH = 2048

# Classifies one address: None when allowed, else a stable reason code. The default is
# address_reason; tests inject a bypass through guarded_http._fetch only (never from settings).
AddressClassifier = Callable[[IPAddress], str | None]


def default_classifier(ip: IPAddress) -> str | None:
    reason = address_reason(ip)
    return None if reason is None else reason.value


class FetchErrorKind(StrEnum):
    """Closed set of failures. Callers map every kind to Check status ``error``."""

    blocked = "blocked"
    dns_error = "dns_error"
    timeout = "timeout"
    too_large = "too_large"
    too_many_redirects = "too_many_redirects"
    scheme_not_allowed = "scheme_not_allowed"
    port_not_allowed = "port_not_allowed"
    tls_error = "tls_error"
    connect_error = "connect_error"
    protocol_error = "protocol_error"


@dataclass(frozen=True, slots=True)
class FetchError:
    """A typed failure. ``detail`` is a stable code (never user input); ``hop`` is 0 for the
    first request and n for the n-th redirect."""

    kind: FetchErrorKind
    detail: str
    hop: int = 0


@dataclass(frozen=True, slots=True)
class Target:
    """A validated request target. ``host`` is the normalised ASCII host name, or the IP
    literal's compressed text when ``ip`` is set."""

    scheme: str
    host: str
    port: int
    path: str  # path plus "?query", never empty, no fragment
    ip: IPAddress | None

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == DEFAULT_PORTS[self.scheme] else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host_header}{self.path}"

    def connect_url(self, ip: IPAddress) -> str:
        """The URL actually requested: same scheme, port and path, host replaced by ``ip``."""
        host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
        return f"{self.scheme}://{host}:{self.port}{self.path}"


def _blocked(detail: str, hop: int) -> FetchError:
    return FetchError(FetchErrorKind.blocked, detail, hop)


def _bad_characters(url: str) -> bool:
    return any(c.isspace() or ord(c) < 0x20 or c in "\x7f\\" for c in url)


def _split(url: str) -> SplitResult | None:
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return None
    return parts


def parse_url(
    url: object,
    allowed_ports: tuple[int, ...],
    *,
    hop: int = 0,
    classifier: AddressClassifier = default_classifier,
) -> Target | FetchError:
    """Validate ``url`` against the scheme, port, userinfo, host and address rules."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH or _bad_characters(url):
        return _blocked("malformed", hop)
    parts = _split(url)
    if parts is None:
        return _blocked("malformed", hop)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return FetchError(FetchErrorKind.scheme_not_allowed, scheme or "missing", hop)
    if not parts.netloc:
        return _blocked("malformed", hop)
    if "@" in parts.netloc:
        return _blocked("userinfo", hop)
    raw_host = parts.hostname
    if not raw_host:
        return _blocked("malformed", hop)
    if "%" in raw_host:
        return _blocked("zone_id", hop)
    port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]
    if port not in allowed_ports:
        return FetchError(FetchErrorKind.port_not_allowed, str(port), hop)

    ip: IPAddress | None = None
    bracketed = parts.netloc.startswith("[")
    try:
        ip = ipaddress.IPv6Address(raw_host) if bracketed else ipaddress.IPv4Address(raw_host)
    except ValueError:
        if bracketed:
            return _blocked("malformed", hop)
    if ip is not None:
        reason = classifier(ip)
        if reason is not None:
            return _blocked(reason, hop)
        host = ip.compressed
    else:
        try:
            host = to_ascii_domain(raw_host)
        except InvalidDomainName as exc:
            return _blocked(f"host_{exc.reason}", hop)

    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return Target(scheme=scheme, host=host, port=port, path=path, ip=ip)


@dataclass(frozen=True, slots=True)
class FetchLimits:
    """Limits for one ``fetch`` call. All defaults are project choices, not vendor facts."""

    allowed_ports: tuple[int, ...] = (80, 443)
    max_redirects: int = 3
    connect_timeout: float = 5.0  # seconds, per connection attempt
    read_timeout: float = 10.0  # seconds, between two reads
    total_timeout: float = 20.0  # seconds, whole call incl. DNS and every redirect
    max_body_bytes: int = 1024 * 1024  # response body, counted while streaming
    max_request_body_bytes: int = 64 * 1024  # POST body (alert webhooks)
    max_header_count: int = 100  # response header fields
    max_header_bytes: int = 16 * 1024  # response header names + values

    def __post_init__(self) -> None:
        if not self.allowed_ports or any(
            isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535
            for p in self.allowed_ports
        ):
            raise ValueError("allowed_ports")
        if not 0 <= self.max_redirects <= OUTBOUND_HTTP_MAX_REDIRECTS_HARD_MAX:
            raise ValueError("max_redirects")
        for name in ("connect_timeout", "read_timeout", "total_timeout"):
            if not getattr(self, name) > 0:
                raise ValueError(name)
        for name in (
            "max_body_bytes",
            "max_request_body_bytes",
            "max_header_count",
            "max_header_bytes",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(name)
