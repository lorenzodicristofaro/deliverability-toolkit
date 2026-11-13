"""Guarded outbound HTTP client (M7-01, ARCHITECTURE section 9). The only module allowed to
import an HTTP library (``httpx2``); every outbound HTTP request in ``app/`` goes through
``fetch``.

Per hop (the first request and every redirect): validate the URL (``policy.parse_url``),
resolve A and AAAA once through the project resolver (never the OS resolver), refuse the request
if ANY answer is blocked by ``app.dns.egress.address_reason``, then connect to the first
validated address. Pinning uses httpx2's documented ``sni_hostname`` request extension: the
request URL carries the validated IP (so no second lookup happens between check and connect),
the ``Host`` header carries the original host and ``sni_hostname`` makes TLS SNI and certificate
hostname verification use the original host. No custom transport is needed.

Every hop gets a fresh transport (one connection, no keep-alive, so a TLS connection opened for
one host name is never reused for another), built with ``trust_env=False`` and no proxy; the
transport is used directly (no ``httpx2.Client``), so proxy environment variables, netrc and a
cookie jar are never consulted. ``Accept-Encoding: identity`` is sent and a response with any
other ``Content-Encoding`` is refused, so nothing is ever decompressed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal
from urllib.parse import urljoin

import httpx2

from app.core.config import Settings
from app.dns.egress import IPAddress
from app.dns.types import DnsQuestion, Resolver
from app.net.policy import (
    AddressClassifier,
    FetchError,
    FetchErrorKind,
    FetchLimits,
    Target,
    default_classifier,
    parse_url,
)

Method = Literal["GET", "HEAD", "POST"]
TransportFactory = Callable[[FetchLimits], httpx2.AsyncBaseTransport]

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Request headers a caller may set (lowercase). Host, Cookie, Proxy-*, Accept-Encoding and
# hop-by-hop headers are never accepted.
REQUEST_HEADER_ALLOWLIST = frozenset(
    {
        "accept",
        "accept-language",
        "authorization",
        "content-type",
        "if-modified-since",
        "if-none-match",
        "user-agent",
    }
)
# Dropped when a redirect changes scheme, host or port.
_CROSS_ORIGIN_DROPPED = frozenset({"authorization"})
# Response headers returned to callers (lowercase); Set-Cookie is never returned.
RESPONSE_HEADER_ALLOWLIST = frozenset(
    {
        "cache-control",
        "content-language",
        "content-length",
        "content-type",
        "date",
        "etag",
        "expires",
        "last-modified",
        "location",
        "retry-after",
    }
)
DEFAULT_USER_AGENT = "deliverability-toolkit"


@dataclass(frozen=True, slots=True)
class Hop:
    """One request: the validated URL, the pinned address and the status received."""

    url: str
    address: str
    status: int


@dataclass(frozen=True, slots=True)
class FetchResult:
    url: str  # final URL (after redirects)
    status: int
    headers: Mapping[str, str]  # allowlisted subset, lowercase names
    body: bytes  # never more than FetchLimits.max_body_bytes
    truncated: bool
    hops: tuple[Hop, ...] = field(default=())


def limits_from_settings(settings: Settings, **overrides: Any) -> FetchLimits:
    """FetchLimits with the operator's port allowlist and redirect cap; ``overrides`` sets
    other fields (validated by FetchLimits)."""
    base = FetchLimits(
        allowed_ports=settings.outbound_http_ports(),
        max_redirects=settings.outbound_http_max_redirects,
    )
    return replace(base, **overrides)


def default_transport(limits: FetchLimits) -> httpx2.AsyncBaseTransport:
    """One connection, no keep-alive, no retries, no proxy, environment ignored, TLS verified."""
    return httpx2.AsyncHTTPTransport(
        verify=True,
        trust_env=False,
        http1=True,
        http2=False,
        limits=httpx2.Limits(max_connections=1, max_keepalive_connections=0),
        proxy=None,
        retries=0,
    )


def _check_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        key = name.lower()
        if key not in REQUEST_HEADER_ALLOWLIST:
            raise ValueError(f"request header not allowed: {key}")
        if not isinstance(value, str) or any(c in value for c in "\r\n\0"):
            raise ValueError(f"invalid value for request header: {key}")
        out[key] = value
    out.setdefault("user-agent", DEFAULT_USER_AGENT)
    return out


async def _resolve(
    host: str, resolver: Resolver, classifier: AddressClassifier, hop: int
) -> list[IPAddress] | FetchError:
    """A then AAAA, once each. Any non-absence failure is a dns_error; ANY blocked answer
    blocks the request."""
    addresses: list[IPAddress] = []
    for rdtype in ("A", "AAAA"):
        result = await resolver.resolve(DnsQuestion(host, rdtype))
        if result.state.is_definitive_absence:
            continue
        if not result.state.is_ok:
            return FetchError(FetchErrorKind.dns_error, result.state.value, hop)
        for record in result.records:
            if record.rdtype != rdtype:
                continue  # CNAME chain entries
            try:
                ip = ipaddress.ip_address(record.rdata_text)
            except ValueError:
                return FetchError(FetchErrorKind.dns_error, "malformed_answer", hop)
            if (ip.version == 4) != (rdtype == "A"):
                return FetchError(FetchErrorKind.dns_error, "malformed_answer", hop)
            addresses.append(ip)
    if not addresses:
        return FetchError(FetchErrorKind.dns_error, "no_address", hop)
    for ip in addresses:
        reason = classifier(ip)
        if reason is not None:
            return FetchError(FetchErrorKind.blocked, reason, hop)
    return addresses


def _is_tls_failure(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ssl.SSLError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _map_exception(exc: httpx2.HTTPError, hop: int) -> FetchError:
    if isinstance(exc, httpx2.TimeoutException):
        return FetchError(FetchErrorKind.timeout, type(exc).__name__, hop)
    if _is_tls_failure(exc):
        return FetchError(FetchErrorKind.tls_error, type(exc).__name__, hop)
    if isinstance(exc, httpx2.ProtocolError | httpx2.DecodingError | httpx2.UnsupportedProtocol):
        return FetchError(FetchErrorKind.protocol_error, type(exc).__name__, hop)
    return FetchError(FetchErrorKind.connect_error, type(exc).__name__, hop)


@dataclass(slots=True)
class _Response:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool


async def _send(
    target: Target,
    ip: IPAddress,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    *,
    limits: FetchLimits,
    read_body: Callable[[int], bool],
    allow_truncated: bool,
    transport_factory: TransportFactory,
    hop: int,
) -> _Response | FetchError:
    request_headers = {
        **headers,
        "host": target.host_header,
        "accept-encoding": "identity",
        "connection": "close",
    }
    extensions: dict[str, object] = {
        "timeout": {
            "connect": limits.connect_timeout,
            "read": limits.read_timeout,
            "write": limits.read_timeout,
            "pool": limits.connect_timeout,
        }
    }
    if target.scheme == "https" and target.ip is None:
        extensions["sni_hostname"] = target.host
    transport = transport_factory(limits)
    try:
        request = httpx2.Request(
            method,
            target.connect_url(ip),
            headers=request_headers,
            content=body,
            extensions=extensions,
        )
        response = await transport.handle_async_request(request)
        try:
            return await _read_response(response, limits, read_body, allow_truncated, hop)
        finally:
            await response.aclose()
    except httpx2.InvalidURL:
        return FetchError(FetchErrorKind.blocked, "malformed", hop)
    except httpx2.HTTPError as exc:
        return _map_exception(exc, hop)
    finally:
        await transport.aclose()


async def _read_response(
    response: httpx2.Response,
    limits: FetchLimits,
    read_body: Callable[[int], bool],
    allow_truncated: bool,
    hop: int,
) -> _Response | FetchError:
    raw = response.headers.raw
    if len(raw) > limits.max_header_count:
        return FetchError(FetchErrorKind.too_large, "header_count", hop)
    if sum(len(k) + len(v) for k, v in raw) > limits.max_header_bytes:
        return FetchError(FetchErrorKind.too_large, "headers", hop)
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        return FetchError(FetchErrorKind.protocol_error, "content_encoding", hop)
    selected: dict[str, str] = {}
    for key, value in response.headers.multi_items():
        name = key.lower()
        if name in RESPONSE_HEADER_ALLOWLIST:
            selected[name] = f"{selected[name]}, {value}" if name in selected else value
    status = response.status_code
    if not read_body(status):
        return _Response(status, selected, b"", False)

    cap = limits.max_body_bytes
    declared = response.headers.get("content-length", "").strip()
    if declared.isascii() and declared.isdigit() and int(declared) > cap and not allow_truncated:
        return FetchError(FetchErrorKind.too_large, "body", hop)
    chunks: list[bytes] = []
    size = 0
    truncated = False
    stream = response.stream
    if not isinstance(stream, httpx2.AsyncByteStream):
        return FetchError(FetchErrorKind.protocol_error, "sync_stream", hop)
    # The raw stream: no decoding happens (Content-Encoding was refused above).
    async for chunk in stream:
        if size + len(chunk) > cap:
            if not allow_truncated:
                return FetchError(FetchErrorKind.too_large, "body", hop)
            chunks.append(chunk[: cap - size])
            truncated = True
            break  # stop reading; the stream is closed by the caller
        chunks.append(chunk)
        size += len(chunk)
    return _Response(status, selected, b"".join(chunks), truncated)


@dataclass(slots=True)
class _Progress:
    hop: int = 0


async def fetch(
    url: str,
    *,
    resolver: Resolver,
    method: Method = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    limits: FetchLimits | None = None,
    follow_redirects: bool | None = None,
    allow_truncated: bool = False,
) -> FetchResult | FetchError:
    """Fetch ``url`` under the egress policy. Never raises for network, DNS or policy
    conditions: every such failure is a ``FetchError``. Raises ValueError only for caller bugs
    (unknown method, header outside the allowlist, body on GET/HEAD).

    ``follow_redirects`` defaults to True for GET/HEAD and False for POST. ``allow_truncated``
    returns the first ``max_body_bytes`` with ``truncated=True`` instead of ``too_large``.
    """
    return await _fetch(
        url,
        resolver=resolver,
        method=method,
        headers=headers,
        body=body,
        limits=limits or FetchLimits(),
        follow_redirects=follow_redirects,
        allow_truncated=allow_truncated,
        transport_factory=default_transport,
        classifier=default_classifier,
    )


async def _fetch(
    url: str,
    *,
    resolver: Resolver,
    method: str,
    headers: Mapping[str, str] | None,
    body: bytes | None,
    limits: FetchLimits,
    follow_redirects: bool | None,
    allow_truncated: bool,
    transport_factory: TransportFactory,
    classifier: AddressClassifier,
) -> FetchResult | FetchError:
    """Implementation with the test seams (transport factory, address classifier). Production
    code calls ``fetch``; nothing in settings can reach these parameters."""
    if method not in ("GET", "HEAD", "POST"):
        raise ValueError(f"method not allowed: {method}")
    if body is not None and method != "POST":
        raise ValueError("a body is only allowed with POST")
    request_headers = _check_headers(headers)
    if body is not None and len(body) > limits.max_request_body_bytes:
        return FetchError(FetchErrorKind.too_large, "request_body", 0)
    follow = (method != "POST") if follow_redirects is None else follow_redirects
    progress = _Progress()
    try:
        async with asyncio.timeout(limits.total_timeout):
            return await _run(
                url,
                resolver=resolver,
                method=method,
                headers=request_headers,
                body=body,
                limits=limits,
                follow=follow,
                allow_truncated=allow_truncated,
                transport_factory=transport_factory,
                classifier=classifier,
                progress=progress,
            )
    except TimeoutError:
        return FetchError(FetchErrorKind.timeout, "deadline", progress.hop)


async def _run(
    url: str,
    *,
    resolver: Resolver,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    limits: FetchLimits,
    follow: bool,
    allow_truncated: bool,
    transport_factory: TransportFactory,
    classifier: AddressClassifier,
    progress: _Progress,
) -> FetchResult | FetchError:
    hops: list[Hop] = []
    visited: set[str] = set()
    previous: Target | None = None
    current_url = url

    def read_body(status: int) -> bool:
        if method == "HEAD":
            return False
        return not (follow and status in _REDIRECT_STATUSES)

    for hop in range(limits.max_redirects + 1):
        progress.hop = hop
        target = parse_url(current_url, limits.allowed_ports, hop=hop, classifier=classifier)
        if isinstance(target, FetchError):
            return target
        if previous is not None:
            if previous.scheme == "https" and target.scheme == "http":
                return FetchError(FetchErrorKind.scheme_not_allowed, "https_downgrade", hop)
            if target.origin != previous.origin:
                for name in _CROSS_ORIGIN_DROPPED:
                    headers.pop(name, None)
        if target.url in visited:
            return FetchError(FetchErrorKind.too_many_redirects, "loop", hop)
        visited.add(target.url)

        if target.ip is not None:
            ip = target.ip
        else:
            addresses = await _resolve(target.host, resolver, classifier, hop)
            if isinstance(addresses, FetchError):
                return addresses
            ip = addresses[0]  # IPv4 first (A is queried first); no fallback to others

        response = await _send(
            target,
            ip,
            method,
            headers,
            body,
            limits=limits,
            read_body=read_body,
            allow_truncated=allow_truncated,
            transport_factory=transport_factory,
            hop=hop,
        )
        if isinstance(response, FetchError):
            return response
        hops.append(Hop(target.url, ip.compressed, response.status))

        if not (follow and response.status in _REDIRECT_STATUSES):
            return FetchResult(
                url=target.url,
                status=response.status,
                headers=response.headers,
                body=response.body,
                truncated=response.truncated,
                hops=tuple(hops),
            )
        location = response.headers.get("location", "").strip()
        if not location or len(location) > 2048:
            return FetchError(FetchErrorKind.protocol_error, "bad_location", hop)
        try:
            current_url = urljoin(target.url, location)
        except ValueError:
            return FetchError(FetchErrorKind.protocol_error, "bad_location", hop)
        if response.status == 303 or (response.status in (301, 302) and method == "POST"):
            method = "HEAD" if method == "HEAD" else "GET"
            body = None
            headers.pop("content-type", None)
        previous = target

    return FetchError(FetchErrorKind.too_many_redirects, "cap", limits.max_redirects + 1)
