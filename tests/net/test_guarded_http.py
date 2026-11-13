"""Guarded outbound HTTP client (M7-01). No network: ScriptedResolver + httpx2.MockTransport, and
a server bound to 127.0.0.1 inside the test for the end-to-end cases (the loopback block is
bypassed through the test-only classifier seam of ``_fetch``)."""

from __future__ import annotations

import ast
import asyncio
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest

from app.dns.types import ResultState
from app.net import guarded_http
from app.net.guarded_http import FetchResult, _fetch, default_transport, fetch
from app.net.policy import FetchError, FetchErrorKind, FetchLimits, default_classifier
from tests.net.conftest import ScriptedResolver, hosts

PUBLIC = "93.184.216.34"
PUBLIC_2 = "93.184.216.35"
PUBLIC_V6 = "2606:2800:220:1::1"
Handler = Callable[[httpx2.Request], Awaitable[httpx2.Response] | httpx2.Response]


class Recorder:
    """Transport factory backed by MockTransport; records every request it sees."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx2.Request] = []
        self.transports = 0

    def __call__(self, limits: FetchLimits) -> httpx2.AsyncBaseTransport:
        self.transports += 1

        async def handle(request: httpx2.Request) -> httpx2.Response:
            self.requests.append(request)
            result = self.handler(request)
            if not isinstance(result, httpx2.Response):
                result = await result
            return result

        return httpx2.MockTransport(handle)


def ok(body: bytes = b"hello", **headers: str) -> Handler:
    return lambda request: httpx2.Response(200, content=body, headers=headers)


async def run(
    url: str,
    resolver: ScriptedResolver,
    recorder: Recorder,
    *,
    classifier: Any = default_classifier,
    limits: FetchLimits | None = None,
    **kwargs: Any,
) -> FetchResult | FetchError:
    args: dict[str, Any] = {
        "method": "GET",
        "headers": None,
        "body": None,
        "follow_redirects": None,
        "allow_truncated": False,
    }
    args.update(kwargs)
    return await _fetch(
        url,
        resolver=resolver,
        limits=limits or FetchLimits(),
        transport_factory=recorder,
        classifier=classifier,
        **args,
    )


def error(result: FetchResult | FetchError) -> FetchError:
    assert isinstance(result, FetchError), result
    return result


def success(result: FetchResult | FetchError) -> FetchResult:
    assert isinstance(result, FetchResult), result
    return result


# --- pinning ---------------------------------------------------------------------------------


async def test_https_request_is_pinned_to_validated_ip_with_original_host_and_sni() -> None:
    recorder = Recorder(ok(b"policy", **{"content-type": "text/plain", "set-cookie": "a=b"}))
    resolver = hosts(**{"mta-sts.example.com": PUBLIC})
    result = success(
        await run("https://MTA-STS.example.com./.well-known/x?y=1", resolver, recorder)
    )

    (request,) = recorder.requests
    assert request.url.host == PUBLIC
    assert request.url.scheme == "https" and request.url.port in (None, 443)
    assert request.url.raw_path == b"/.well-known/x?y=1"
    assert request.headers["host"] == "mta-sts.example.com"
    assert request.extensions["sni_hostname"] == "mta-sts.example.com"
    assert request.headers["accept-encoding"] == "identity"
    assert "cookie" not in request.headers
    assert result.status == 200 and result.body == b"policy" and not result.truncated
    assert result.url == "https://mta-sts.example.com/.well-known/x?y=1"
    assert dict(result.headers) == {"content-type": "text/plain", "content-length": "6"}
    assert [(h.url, h.address, h.status) for h in result.hops] == [
        ("https://mta-sts.example.com/.well-known/x?y=1", PUBLIC, 200)
    ]


async def test_ip_literal_is_not_resolved_and_has_no_sni_override() -> None:
    recorder = Recorder(ok())
    resolver = ScriptedResolver()
    success(await run(f"https://{PUBLIC}/", resolver, recorder))
    assert resolver.questions == []
    assert "sni_hostname" not in recorder.requests[0].extensions
    assert recorder.requests[0].headers["host"] == PUBLIC


async def test_ipv6_answer_is_pinned_with_brackets() -> None:
    recorder = Recorder(ok())
    success(await run("http://www.example.com/", hosts(**{"www.example.com": PUBLIC_V6}), recorder))
    assert recorder.requests[0].url.host == PUBLIC_V6
    assert recorder.requests[0].headers["host"] == "www.example.com"


async def test_dns_rebinding_no_second_lookup_between_check_and_connect() -> None:
    resolver = ScriptedResolver(
        {
            ("rebind.example.com", "A"): [[PUBLIC], ["127.0.0.1"]],
            ("rebind.example.com", "AAAA"): [ResultState.nodata],
        }
    )
    recorder = Recorder(ok())
    success(await run("https://rebind.example.com/", resolver, recorder))
    assert resolver.count("rebind.example.com", "A") == 1
    assert resolver.count("rebind.example.com", "AAAA") == 1
    assert recorder.requests[0].url.host == PUBLIC


async def test_every_hop_gets_a_fresh_transport() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/a":
            return httpx2.Response(302, headers={"location": "/b"})
        return httpx2.Response(200)

    recorder = Recorder(handler)
    success(await run("https://www.example.com/a", hosts(**{"www.example.com": PUBLIC}), recorder))
    assert recorder.transports == 2


# --- resolution ------------------------------------------------------------------------------

N = "www.example.com"


@pytest.mark.parametrize(
    ("a", "aaaa", "kind", "detail"),
    [
        ([ResultState.servfail], [ResultState.nodata], FetchErrorKind.dns_error, "servfail"),
        ([ResultState.timeout], [ResultState.nodata], FetchErrorKind.dns_error, "timeout"),
        ([ResultState.refused], [ResultState.nodata], FetchErrorKind.dns_error, "refused"),
        ([ResultState.blocked], [ResultState.nodata], FetchErrorKind.dns_error, "blocked"),
        ([ResultState.error], [ResultState.nodata], FetchErrorKind.dns_error, "error"),
        ([[PUBLIC]], [ResultState.servfail], FetchErrorKind.dns_error, "servfail"),
        ([ResultState.nxdomain], [ResultState.nxdomain], FetchErrorKind.dns_error, "no_address"),
        ([ResultState.nodata], [ResultState.nodata], FetchErrorKind.dns_error, "no_address"),
        ([["not-an-ip"]], [ResultState.nodata], FetchErrorKind.dns_error, "malformed_answer"),
        ([[PUBLIC_V6]], [ResultState.nodata], FetchErrorKind.dns_error, "malformed_answer"),
        # ANY blocked answer blocks the request: no "pick the good one"
        ([[PUBLIC, "10.0.0.1"]], [ResultState.nodata], FetchErrorKind.blocked, "private"),
        ([["10.0.0.1", PUBLIC]], [ResultState.nodata], FetchErrorKind.blocked, "private"),
        ([[PUBLIC]], [["::1"]], FetchErrorKind.blocked, "loopback"),
        ([[PUBLIC]], [["fd00:ec2::254"]], FetchErrorKind.blocked, "private"),
        ([["169.254.169.254"]], [ResultState.nodata], FetchErrorKind.blocked, "link_local"),
        ([["100.64.1.1"]], [ResultState.nodata], FetchErrorKind.blocked, "shared_address_space"),
        ([["0.0.0.0"]], [ResultState.nodata], FetchErrorKind.blocked, "unspecified"),
        ([["224.0.0.251"]], [ResultState.nodata], FetchErrorKind.blocked, "multicast"),
        ([["240.0.0.1"]], [ResultState.nodata], FetchErrorKind.blocked, "reserved"),
        ([[PUBLIC]], [["::ffff:10.0.0.1"]], FetchErrorKind.blocked, "ipv4_mapped"),
        ([[PUBLIC]], [["2002:0a00:0001::1"]], FetchErrorKind.blocked, "embedded_ipv4_blocked"),
        ([[PUBLIC]], [["64:ff9b::7f00:1"]], FetchErrorKind.blocked, "embedded_ipv4_blocked"),
        ([[PUBLIC]], [["fe80::1"]], FetchErrorKind.blocked, "link_local"),
    ],
)
async def test_resolution_outcomes(a: list[Any], aaaa: list[Any], kind: str, detail: str) -> None:
    resolver = ScriptedResolver({(N, "A"): a, (N, "AAAA"): aaaa})
    recorder = Recorder(ok())
    err = error(await run(f"https://{N}/", resolver, recorder))
    assert (err.kind, err.detail, err.hop) == (kind, detail, 0)
    assert recorder.requests == []  # nothing was sent


async def test_mixed_public_answers_connect_to_first_ipv4() -> None:
    recorder = Recorder(ok())
    resolver = hosts(**{N: [PUBLIC_V6, PUBLIC, PUBLIC_2]})
    success(await run(f"https://{N}/", resolver, recorder))
    assert recorder.requests[0].url.host == PUBLIC


# --- redirects -------------------------------------------------------------------------------


def redirects(table: dict[str, tuple[int, str | None]]) -> Handler:
    """Path -> (status, Location) for redirect responses; any other path answers 200."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        key = f"{request.headers['host']}{request.url.raw_path.decode()}"
        if key in table:
            status, location = table[key]
            headers = {"location": location} if location is not None else {}
            return httpx2.Response(status, headers=headers)
        return httpx2.Response(200, content=b"final")

    return handler


REDIRECT_RESOLVER = {
    N: PUBLIC,
    "other.example.com": PUBLIC_2,
    "internal.example.com": "10.0.0.5",
}


async def test_relative_redirect_followed_and_hops_recorded() -> None:
    recorder = Recorder(
        redirects(
            {
                f"{N}/a": (301, "/b"),
                f"{N}/b": (302, "c?x=1"),
                f"{N}/c?x=1": (307, "https://other.example.com/d"),
            }
        )
    )
    result = success(await run(f"https://{N}/a", hosts(**REDIRECT_RESOLVER), recorder))
    assert result.body == b"final"
    assert result.url == "https://other.example.com/d"
    assert [(h.url, h.address, h.status) for h in result.hops] == [
        (f"https://{N}/a", PUBLIC, 301),
        (f"https://{N}/b", PUBLIC, 302),
        (f"https://{N}/c?x=1", PUBLIC, 307),
        ("https://other.example.com/d", PUBLIC_2, 200),
    ]
    assert recorder.requests[-1].extensions["sni_hostname"] == "other.example.com"


@pytest.mark.parametrize(
    ("table", "max_redirects", "kind", "detail", "hop"),
    [
        ({f"{N}/": (302, "http://169.254.169.254/latest/")}, 3, "blocked", "link_local", 1),
        ({f"{N}/": (302, "http://[fd00:ec2::254]/")}, 3, "blocked", "private", 1),
        ({f"{N}/": (302, "https://internal.example.com/")}, 3, "blocked", "private", 1),
        (
            {f"{N}/": (302, "/2"), f"{N}/2": (302, "https://127.0.0.1/")},
            3,
            "blocked",
            "loopback",
            2,
        ),
        (
            {f"{N}/": (302, "http://www.example.com/")},
            3,
            "scheme_not_allowed",
            "https_downgrade",
            1,
        ),
        ({f"{N}/": (302, "ftp://www.example.com/")}, 3, "scheme_not_allowed", "ftp", 1),
        ({f"{N}/": (302, "javascript:alert(1)")}, 3, "scheme_not_allowed", "javascript", 1),
        ({f"{N}/": (302, "https://www.example.com:8443/")}, 3, "port_not_allowed", "8443", 1),
        ({f"{N}/": (302, "https://user@www.example.com/x")}, 3, "blocked", "userinfo", 1),
        ({f"{N}/": (302, "https://[::1/")}, 3, "protocol_error", "bad_location", 0),
        ({f"{N}/": (302, "https://nx.example.com/")}, 3, "dns_error", "no_address", 1),
        ({f"{N}/": (302, None)}, 3, "protocol_error", "bad_location", 0),
        ({f"{N}/": (302, "   ")}, 3, "protocol_error", "bad_location", 0),
        ({f"{N}/": (302, "/" + "a" * 3000)}, 3, "protocol_error", "bad_location", 0),
        ({f"{N}/": (302, "/")}, 3, "too_many_redirects", "loop", 1),
        ({f"{N}/": (302, "/b"), f"{N}/b": (302, "/")}, 3, "too_many_redirects", "loop", 2),
        ({f"{N}/": (302, "/b")}, 0, "too_many_redirects", "cap", 1),
    ],
)
async def test_redirect_failures(
    table: dict[str, tuple[int, str | None]], max_redirects: int, kind: str, detail: str, hop: int
) -> None:
    recorder = Recorder(redirects(table))
    limits = FetchLimits(max_redirects=max_redirects)
    err = error(await run(f"https://{N}/", hosts(**REDIRECT_RESOLVER), recorder, limits=limits))
    assert (err.kind, err.detail, err.hop) == (kind, detail, hop)


async def test_endless_redirect_stops_at_cap() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        n = int(request.url.path.strip("/") or 0)
        return httpx2.Response(302, headers={"location": f"/{n + 1}"})

    recorder = Recorder(handler)
    err = error(await run(f"https://{N}/0", hosts(**{N: PUBLIC}), recorder))
    assert (err.kind, err.detail, err.hop) == (FetchErrorKind.too_many_redirects, "cap", 4)
    assert len(recorder.requests) == 4  # 1 + default cap of 3


async def test_hard_max_redirects_is_five() -> None:
    with pytest.raises(ValueError):
        FetchLimits(max_redirects=6)
    FetchLimits(max_redirects=5)


async def test_http_to_https_upgrade_is_allowed() -> None:
    recorder = Recorder(redirects({f"{N}/a": (301, f"https://{N}/b")}))
    result = success(await run(f"http://{N}/a", hosts(**{N: PUBLIC}), recorder))
    assert [h.url for h in result.hops] == [f"http://{N}/a", f"https://{N}/b"]


async def test_no_follow_returns_redirect_response() -> None:
    recorder = Recorder(redirects({f"{N}/": (302, "http://10.0.0.1/")}))
    result = success(
        await run(f"https://{N}/", hosts(**{N: PUBLIC}), recorder, follow_redirects=False)
    )
    assert result.status == 302 and result.headers["location"] == "http://10.0.0.1/"
    assert len(recorder.requests) == 1


async def test_authorization_dropped_across_origins_kept_same_origin() -> None:
    recorder = Recorder(
        redirects({f"{N}/": (302, "/same"), f"{N}/same": (302, "https://other.example.com/x")})
    )
    success(
        await run(
            f"https://{N}/",
            hosts(**REDIRECT_RESOLVER),
            recorder,
            headers={"Authorization": "Bearer t", "Accept": "text/plain"},
        )
    )
    auth = [r.headers.get("authorization") for r in recorder.requests]
    assert auth == ["Bearer t", "Bearer t", None]
    assert all(r.headers["accept"] == "text/plain" for r in recorder.requests)


# --- POST (alert webhooks) -------------------------------------------------------------------


async def test_post_does_not_follow_redirects_by_default() -> None:
    recorder = Recorder(redirects({f"{N}/hook": (307, "/elsewhere")}))
    result = success(
        await run(f"https://{N}/hook", hosts(**{N: PUBLIC}), recorder, method="POST", body=b"{}")
    )
    assert result.status == 307
    assert len(recorder.requests) == 1
    assert recorder.requests[0].content == b"{}"


@pytest.mark.parametrize(
    ("status", "method", "body"),
    [(307, "POST", b"{}"), (308, "POST", b"{}"), (303, "GET", b""), (302, "GET", b"")],
)
async def test_post_redirect_method_when_following(status: int, method: str, body: bytes) -> None:
    recorder = Recorder(redirects({f"{N}/hook": (status, "/next")}))
    success(
        await run(
            f"https://{N}/hook",
            hosts(**{N: PUBLIC}),
            recorder,
            method="POST",
            body=b"{}",
            headers={"content-type": "application/json"},
            follow_redirects=True,
        )
    )
    second = recorder.requests[1]
    assert (second.method, second.content) == (method, body)


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize(
    "location",
    [
        "https://other.example.com/hook",
        "https://www.example.com:8443/hook",
        "http://other.example.com/",
    ],
)
async def test_post_cross_origin_307_308_refused(status: int, location: str) -> None:
    recorder = Recorder(redirects({f"{N}/hook": (status, location)}))
    limits = FetchLimits(allowed_ports=(80, 443, 8443))
    err = error(
        await run(
            f"http://{N}/hook",
            hosts(**REDIRECT_RESOLVER),
            recorder,
            method="POST",
            body=b"{}",
            headers={"content-type": "application/json"},
            follow_redirects=True,
            limits=limits,
        )
    )
    assert (err.kind, err.detail, err.hop) == (FetchErrorKind.blocked, "cross_origin_post", 1)
    assert len(recorder.requests) == 1  # the body went to the original origin only


async def test_post_body_is_size_capped() -> None:
    recorder = Recorder(ok())
    limits = FetchLimits(max_request_body_bytes=4)
    err = error(
        await run(
            f"https://{N}/",
            hosts(**{N: PUBLIC}),
            recorder,
            method="POST",
            body=b"12345",
            limits=limits,
        )
    )
    assert (err.kind, err.detail) == (FetchErrorKind.too_large, "request_body")
    assert recorder.requests == []


# --- caps ------------------------------------------------------------------------------------


class SlowStream(httpx2.AsyncByteStream):
    def __init__(self, chunks: int, delay: float, size: int = 1) -> None:
        self.chunks, self.delay, self.size = chunks, delay, size
        self.sent = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for _ in range(self.chunks):
            await asyncio.sleep(self.delay)
            self.sent += 1
            yield b"x" * self.size

    async def aclose(self) -> None:
        self.closed = True


async def test_slow_loris_body_hits_total_deadline() -> None:
    stream = SlowStream(chunks=10_000, delay=0.01)
    recorder = Recorder(lambda request: httpx2.Response(200, stream=stream))
    limits = FetchLimits(total_timeout=0.2)
    err = error(await run(f"https://{N}/", hosts(**{N: PUBLIC}), recorder, limits=limits))
    assert (err.kind, err.detail, err.hop) == (FetchErrorKind.timeout, "deadline", 0)
    assert stream.sent < 100


async def test_deadline_spans_redirects() -> None:
    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(0.08)
        n = int(request.url.path.strip("/") or 0)
        return httpx2.Response(302, headers={"location": f"/{n + 1}"})

    limits = FetchLimits(total_timeout=0.2, max_redirects=5)
    err = error(await run(f"https://{N}/0", hosts(**{N: PUBLIC}), Recorder(handler), limits=limits))
    assert (err.kind, err.detail, err.hop) == (FetchErrorKind.timeout, "deadline", 2)


async def test_streamed_oversize_body_stops_reading() -> None:
    stream = SlowStream(chunks=1_000, delay=0, size=1024)
    recorder = Recorder(lambda request: httpx2.Response(200, stream=stream))
    limits = FetchLimits(max_body_bytes=4096)
    err = error(await run(f"https://{N}/", hosts(**{N: PUBLIC}), recorder, limits=limits))
    assert (err.kind, err.detail) == (FetchErrorKind.too_large, "body")
    assert stream.sent == 5  # stopped at the first chunk over the cap, nothing buffered first
    assert stream.closed


async def test_declared_oversize_body_refused_before_reading() -> None:
    stream = SlowStream(chunks=10, delay=0, size=1024)
    recorder = Recorder(
        lambda request: httpx2.Response(200, stream=stream, headers={"content-length": "10240"})
    )
    err = error(
        await run(
            f"https://{N}/", hosts(**{N: PUBLIC}), recorder, limits=FetchLimits(max_body_bytes=10)
        )
    )
    assert (err.kind, err.detail) == (FetchErrorKind.too_large, "body")
    assert stream.sent == 0


async def test_allow_truncated_returns_capped_body() -> None:
    stream = SlowStream(chunks=1_000, delay=0, size=1000)
    recorder = Recorder(lambda request: httpx2.Response(200, stream=stream))
    result = success(
        await run(
            f"https://{N}/",
            hosts(**{N: PUBLIC}),
            recorder,
            limits=FetchLimits(max_body_bytes=2500),
            allow_truncated=True,
        )
    )
    assert (len(result.body), result.truncated, stream.sent) == (2500, True, 3)


@pytest.mark.parametrize(
    ("headers", "kind", "detail"),
    [
        ([(f"x-h{i}", "v") for i in range(101)], FetchErrorKind.too_large, "header_count"),
        ([("x-big", "v" * 17_000)], FetchErrorKind.too_large, "headers"),
        ([("content-encoding", "gzip")], FetchErrorKind.protocol_error, "content_encoding"),
        ([("content-encoding", "br")], FetchErrorKind.protocol_error, "content_encoding"),
    ],
)
async def test_response_header_caps(
    headers: list[tuple[str, str]], kind: FetchErrorKind, detail: str
) -> None:
    recorder = Recorder(lambda request: httpx2.Response(200, headers=headers, content=b"\x1f\x8b"))
    err = error(await run(f"https://{N}/", hosts(**{N: PUBLIC}), recorder))
    assert (err.kind, err.detail) == (kind, detail)


async def test_identity_encoding_accepted_and_head_reads_no_body() -> None:
    recorder = Recorder(ok(b"body", **{"content-encoding": "identity"}))
    result = success(await run(f"https://{N}/", hosts(**{N: PUBLIC}), recorder, method="HEAD"))
    assert result.body == b"" and recorder.requests[0].method == "HEAD"


# --- transport failures ----------------------------------------------------------------------


def _ssl_connect_error() -> httpx2.ConnectError:
    try:
        try:
            raise ssl.SSLCertVerificationError("hostname mismatch")
        except ssl.SSLError as cause:
            raise httpx2.ConnectError("tls") from cause
    except httpx2.ConnectError as exc:
        return exc


@pytest.mark.parametrize(
    ("exc", "kind"),
    [
        (httpx2.ConnectTimeout("t"), FetchErrorKind.timeout),
        (httpx2.ReadTimeout("t"), FetchErrorKind.timeout),
        (httpx2.ConnectError("refused"), FetchErrorKind.connect_error),
        (httpx2.ReadError("reset"), FetchErrorKind.connect_error),
        (_ssl_connect_error(), FetchErrorKind.tls_error),
        (httpx2.RemoteProtocolError("bad"), FetchErrorKind.protocol_error),
        (httpx2.LocalProtocolError("bad"), FetchErrorKind.protocol_error),
    ],
)
async def test_transport_exceptions_are_typed(exc: Exception, kind: FetchErrorKind) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise exc

    err = error(await run(f"https://{N}/", hosts(**{N: PUBLIC}), Recorder(handler)))
    assert err.kind is kind


async def test_other_exceptions_are_not_swallowed() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        await run(f"https://{N}/", hosts(**{N: PUBLIC}), Recorder(handler))


# --- caller bugs -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"method": "PUT"},
        {"method": "get"},
        {"method": "GET", "body": b"x"},
        {"headers": {"Cookie": "a=b"}},
        {"headers": {"Host": "evil.example"}},
        {"headers": {"Proxy-Authorization": "x"}},
        {"headers": {"Accept-Encoding": "gzip"}},
        {"headers": {"Accept": "a\r\nX-Injected: 1"}},
    ],
)
async def test_caller_bugs_raise_value_error(kwargs: dict[str, Any]) -> None:
    recorder = Recorder(ok())
    with pytest.raises(ValueError):
        await run(f"https://{N}/", hosts(**{N: PUBLIC}), recorder, **kwargs)
    assert recorder.requests == []


async def test_public_fetch_uses_default_policy() -> None:
    """fetch() has no seam: a loopback literal is blocked before any transport is built."""
    err = error(await fetch("http://127.0.0.1/", resolver=ScriptedResolver()))
    assert (err.kind, err.detail) == (FetchErrorKind.blocked, "loopback")


# --- end to end with the real transport on a loopback server --------------------------------


class LoopbackServer:
    """Minimal HTTP/1.1 server on 127.0.0.1; records raw requests."""

    def __init__(self, response: bytes, trickle: float | None = None) -> None:
        self.response = response
        self.trickle = trickle
        self.requests: list[bytes] = []
        self.port = 0
        self._server: asyncio.Server | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            self.requests.append(await reader.readuntil(b"\r\n\r\n"))
            if self.trickle is None:
                writer.write(self.response)
                await writer.drain()
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                for _ in range(100_000):
                    writer.write(b"x")
                    await writer.drain()
                    await asyncio.sleep(self.trickle)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def __aenter__(self) -> LoopbackServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._server is not None
        self._server.close()


def _allow_loopback(ip: Any) -> str | None:
    return None if ip.is_loopback else default_classifier(ip)


PROXY_CANARY = "http://10.255.255.1:3128"


async def test_real_transport_pins_ip_ignores_proxy_env_and_netrc(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, PROXY_CANARY)
    monkeypatch.setenv("NO_PROXY", "")
    netrc = tmp_path / "netrc"
    netrc.write_text("machine www.example.com login canary password canary\n")
    monkeypatch.setenv("NETRC", str(netrc))
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: s=1\r\n\r\nok"
    async with LoopbackServer(response) as server:
        resolver = hosts(**{N: "127.0.0.1"})
        result = success(
            await _fetch(
                f"http://{N}:{server.port}/p?q=1",
                resolver=resolver,
                method="GET",
                headers=None,
                body=None,
                limits=FetchLimits(allowed_ports=(server.port,)),
                follow_redirects=None,
                allow_truncated=False,
                transport_factory=default_transport,
                classifier=_allow_loopback,
            )
        )
    assert result.body == b"ok" and "set-cookie" not in result.headers
    (raw,) = server.requests
    head = raw.decode("latin-1").lower()
    assert head.startswith("get /p?q=1 http/1.1\r\n")  # origin-form: not sent to a proxy
    assert f"host: {N}:{server.port}\r\n" in head
    assert "authorization" not in head and "proxy" not in head and "cookie" not in head


async def test_real_transport_slow_loris_hits_deadline() -> None:
    async with LoopbackServer(b"", trickle=0.01) as server:
        err = error(
            await _fetch(
                f"http://{N}:{server.port}/",
                resolver=hosts(**{N: "127.0.0.1"}),
                method="GET",
                headers=None,
                body=None,
                limits=FetchLimits(allowed_ports=(server.port,), total_timeout=0.3),
                follow_redirects=None,
                allow_truncated=False,
                transport_factory=default_transport,
                classifier=_allow_loopback,
            )
        )
    assert (err.kind, err.detail) == (FetchErrorKind.timeout, "deadline")


async def test_real_transport_connect_refused_is_connect_error() -> None:
    async with LoopbackServer(b"") as server:
        port = server.port
    err = error(
        await _fetch(
            f"http://{N}:{port}/",
            resolver=hosts(**{N: "127.0.0.1"}),
            method="GET",
            headers=None,
            body=None,
            limits=FetchLimits(allowed_ports=(port,)),
            follow_redirects=None,
            allow_truncated=False,
            transport_factory=default_transport,
            classifier=_allow_loopback,
        )
    )
    assert err.kind is FetchErrorKind.connect_error


def test_default_transport_has_no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", PROXY_CANARY)
    monkeypatch.setenv("ALL_PROXY", PROXY_CANARY)
    transport = default_transport(FetchLimits())
    import httpcore2

    pool = transport._pool  # type: ignore[attr-defined]
    assert type(pool) is httpcore2.AsyncConnectionPool


# --- single entry point ----------------------------------------------------------------------

HTTP_LIBRARIES = ("httpx", "httpx2", "httpcore", "httpcore2", "requests", "aiohttp", "urllib3")
# Modules outside app/net allowed to import an HTTP library directly. None exist today.
IMPORT_ALLOWLIST: frozenset[str] = frozenset()


def _http_imports(path: Path) -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        for name in names:
            if name.split(".")[0] in HTTP_LIBRARIES or name.startswith("urllib.request"):
                found.append(name)
    return found


def test_no_http_library_imported_outside_app_net() -> None:
    root = Path(guarded_http.__file__).resolve().parents[1]
    offenders = {
        str(path.relative_to(root.parent)): imports
        for path in root.rglob("*.py")
        if "net" not in path.relative_to(root).parts[:1]
        and str(path.relative_to(root.parent)) not in IMPORT_ALLOWLIST
        and (imports := _http_imports(path))
    }
    assert offenders == {}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import httpx", ["httpx"]),
        ("import httpx2 as h", ["httpx2"]),
        ("from requests import get", ["requests", "requests.get"]),
        ("from urllib import request", ["urllib.request"]),
        ("import urllib.request", ["urllib.request"]),
        (
            "from aiohttp.client import ClientSession",
            ["aiohttp.client", "aiohttp.client.ClientSession"],
        ),
        ("from urllib.parse import urlsplit", []),
        ("import json", []),
    ],
)
def test_import_detector(tmp_path: Path, source: str, expected: list[str]) -> None:
    path = tmp_path / "m.py"
    path.write_text(source + "\n")
    assert _http_imports(path) == expected
