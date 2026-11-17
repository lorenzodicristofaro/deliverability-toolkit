"""M7-02 custom check kind `http_fetch`: schema, URL construction and evaluator.

No network: the evaluator's `fetcher` is the guarded client's own implementation
(`guarded_http._fetch`) over an in-process `httpx2.MockTransport`, with names resolved by the
scripted resolver of tests/net, so the egress policy (address classification, redirects, caps)
really runs. Sockets to anything but loopback fail these tests. The regex engine really runs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

import httpx2
import pytest

from app.checks import custom as custom_module
from app.checks.custom import CODES, MAX_EVIDENCE_CHARS, CustomDnsCheck, RunBudget
from app.checks.models import CheckContext, CheckResult, Target
from app.core.custom_check_schema import (
    DEFAULT_HTTP_BODY_BYTES,
    HTTP_HEADER_NAMES,
    MAX_DEFINITION_JSON_LENGTH,
    MAX_EXPECTED_STATUS,
    MAX_HTTP_BODY_BYTES,
    MAX_PATH_LENGTH,
    DefinitionInvalid,
    HttpFetchDefinition,
    NameRenderError,
    parse_definition,
    render_url,
)
from app.core.i18n import t
from app.core.safe_regex import MAX_TEXT_BYTES
from app.net import guarded_http
from app.net.guarded_http import RESPONSE_HEADER_ALLOWLIST, FetchResult, _fetch
from app.net.policy import FetchError, FetchErrorKind, FetchLimits, default_classifier
from tests.net.conftest import _no_network, hosts  # noqa: F401  (autouse network guard)

PUBLIC = "93.184.216.34"
NOW = datetime(2026, 11, 17, tzinfo=UTC)
TEXT = {"en": "Publish <b>it</b>.", "it": "Pubblicalo."}
LIMITS = FetchLimits()
Handler = Callable[[httpx2.Request], httpx2.Response]


def _http(**overrides: Any) -> dict[str, Any]:
    return {"host": "{domain}", "expected_status": [200]} | overrides


def _reason(definition: object) -> tuple[str, str]:
    with pytest.raises(DefinitionInvalid) as err:
        parse_definition("http_fetch", definition)
    return err.value.field, err.value.reason


# --- schema -------------------------------------------------------------------------------------


GOOD = [
    _http(),
    _http(host="mta-sts.{domain}", scheme="https", path="/.well-known/mta-sts.txt"),
    _http(host="a-b.c1.{domain}", scheme="http", path="/x?y=1&z=a:b,c;d=e~f"),
    _http(expected_status=[200, 204, 301, 404, 599, 100]),
    _http(expected_status=list(range(200, 200 + MAX_EXPECTED_STATUS))),
    _http(body_pattern="(?i)^version: stsv1", max_body_bytes=1),
    _http(max_body_bytes=MAX_HTTP_BODY_BYTES),
    _http(header={"name": "content-type"}),
    _http(header={"name": "content-type", "pattern": "^text/plain"}),
]


@pytest.mark.parametrize("definition", GOOD)
def test_good_http_definitions(definition: dict[str, Any]) -> None:
    assert isinstance(parse_definition("http_fetch", definition), HttpFetchDefinition)
    frozen = {
        k: tuple(v) if isinstance(v, list) else MappingProxyType(v) if isinstance(v, dict) else v
        for k, v in definition.items()
    }
    # Stored records come back deeply frozen.
    assert isinstance(parse_definition("http_fetch", MappingProxyType(frozen)), HttpFetchDefinition)


def test_http_defaults_and_fields() -> None:
    parsed = parse_definition("http_fetch", _http())
    assert isinstance(parsed, HttpFetchDefinition)
    assert (parsed.scheme, parsed.path, parsed.max_body_bytes) == (
        "https",
        "/",
        DEFAULT_HTTP_BODY_BYTES,
    )
    assert (parsed.body_rule, parsed.header_name, parsed.header_rule) == (None, None, None)
    full = parse_definition(
        "http_fetch",
        _http(body_pattern="ok", header={"name": "etag", "pattern": "x"}, expected_status=[204]),
    )
    assert isinstance(full, HttpFetchDefinition)
    assert full.body_rule is not None and full.body_rule.pattern == "ok"
    assert full.header_name == "etag" and full.header_rule is not None
    assert full.expected_status == (204,)


BAD = [
    ({"expected_status": [200]}, ("definition.host", "required")),
    ({"host": "{domain}"}, ("definition.expected_status", "required")),
    (_http(url="https://evil.example/"), ("definition", "unknown_key")),
    (_http(port=8443), ("definition", "unknown_key")),
    (_http(name="{domain}"), ("definition", "unknown_key")),
    (_http(rrtype="TXT"), ("definition", "unknown_key")),
    # host: only the target domain or a host under it, by construction
    (_http(host="evil.example"), ("definition.host", "placeholder_missing")),
    (_http(host="127.0.0.1"), ("definition.host", "placeholder_missing")),
    (_http(host="{domain}.evil.example"), ("definition.host", "placeholder_position")),
    (_http(host="evil{domain}"), ("definition.host", "placeholder_position")),
    (_http(host="{domain}:8080"), ("definition.host", "placeholder_position")),
    (_http(host="user@{domain}"), ("definition.host", "placeholder_position")),
    (_http(host="user@x.{domain}"), ("definition.host", "label")),
    (_http(host="_x.{domain}"), ("definition.host", "label")),
    (_http(host="a_b.{domain}"), ("definition.host", "label")),
    (_http(host="-a.{domain}"), ("definition.host", "label")),
    (_http(host="xn--bcher-kva.{domain}"), ("definition.host", "idn")),
    (_http(host="bücher.{domain}"), ("definition.host", "idn")),
    (_http(host="WWW.{domain}"), ("definition.host", "uppercase")),
    (_http(host="{domain}{domain}"), ("definition.host", "placeholder_repeated")),
    (_http(host="{Domain}"), ("definition.host", "bad_placeholder")),
    (_http(host="a..{domain}"), ("definition.host", "dots")),
    (_http(host="a b.{domain}"), ("definition.host", "whitespace")),
    (_http(host="a\x00.{domain}"), ("definition.host", "nul")),
    (_http(host=""), ("definition.host", "empty")),
    (_http(host=None), ("definition.host", "not_a_string")),
    (_http(host=["{domain}"]), ("definition.host", "not_a_string")),
    # scheme
    (_http(scheme="ftp"), ("definition.scheme", "invalid_choice")),
    (_http(scheme="HTTPS"), ("definition.scheme", "invalid_choice")),
    (_http(scheme="file"), ("definition.scheme", "invalid_choice")),
    (_http(scheme=None), ("definition.scheme", "not_a_string")),
    # path
    (_http(path=""), ("definition.path", "empty")),
    (_http(path="x"), ("definition.path", "path_start")),
    (_http(path="//evil.example/x"), ("definition.path", "path_start")),
    (_http(path="@evil.example"), ("definition.path", "path_start")),
    (_http(path="/a b"), ("definition.path", "whitespace")),
    (_http(path="/a\x00"), ("definition.path", "nul")),
    (_http(path="/a\n"), ("definition.path", "control_char")),
    (_http(path="/a\ud800"), ("definition.path", "surrogate")),
    (_http(path="/a%2e%2e"), ("definition.path", "path_chars")),
    (_http(path="/a@evil.example"), ("definition.path", "path_chars")),
    (_http(path="/a#frag"), ("definition.path", "path_chars")),
    (_http(path="/a\\b"), ("definition.path", "path_chars")),
    (_http(path="/{domain}"), ("definition.path", "path_chars")),
    (_http(path="/é"), ("definition.path", "path_chars")),
    (_http(path="/" + "a" * MAX_PATH_LENGTH), ("definition.path", "too_long")),
    (_http(path=5), ("definition.path", "not_a_string")),
    # expected statuses
    (_http(expected_status=[]), ("definition.expected_status", "empty")),
    (_http(expected_status=200), ("definition.expected_status", "not_a_list")),
    (_http(expected_status="200"), ("definition.expected_status", "not_a_list")),
    (_http(expected_status={"200": 1}), ("definition.expected_status", "not_a_list")),
    (_http(expected_status=[99]), ("definition.expected_status", "out_of_range")),
    (_http(expected_status=[600]), ("definition.expected_status", "out_of_range")),
    (_http(expected_status=[True]), ("definition.expected_status", "not_an_integer")),
    (_http(expected_status=[200.0]), ("definition.expected_status", "not_an_integer")),
    (_http(expected_status=["200"]), ("definition.expected_status", "not_an_integer")),
    (_http(expected_status=[None]), ("definition.expected_status", "not_an_integer")),
    (_http(expected_status=[200, 200]), ("definition.expected_status", "duplicate")),
    (
        _http(expected_status=list(range(200, 201 + MAX_EXPECTED_STATUS))),
        ("definition.expected_status", "too_many"),
    ),
    # body
    (_http(body_pattern="(a"), ("definition.body_pattern", "regex_invalid_syntax")),
    (_http(body_pattern=""), ("definition.body_pattern", "regex_empty")),
    (_http(body_pattern=None), ("definition.body_pattern", "regex_not_a_string")),
    (_http(body_pattern="a\x07"), ("definition.body_pattern", "control_char")),
    (_http(max_body_bytes=0), ("definition.max_body_bytes", "out_of_range")),
    (
        _http(max_body_bytes=MAX_HTTP_BODY_BYTES + 1),
        ("definition.max_body_bytes", "out_of_range"),
    ),
    (_http(max_body_bytes=True), ("definition.max_body_bytes", "not_an_integer")),
    (_http(max_body_bytes=None), ("definition.max_body_bytes", "not_an_integer")),
    (_http(max_body_bytes="10"), ("definition.max_body_bytes", "not_an_integer")),
    (_http(max_body_bytes=1.5), ("definition.max_body_bytes", "not_an_integer")),
    # header
    (_http(header="content-type"), ("definition.header", "not_an_object")),
    (_http(header=None), ("definition.header", "not_an_object")),
    (_http(header={}), ("definition.header.name", "required")),
    (_http(header={"name": "etag", "value": "x"}), ("definition.header", "unknown_key")),
    (_http(header={"name": "set-cookie"}), ("definition.header.name", "invalid_choice")),
    (_http(header={"name": "Content-Type"}), ("definition.header.name", "invalid_choice")),
    (_http(header={"name": "x-anything"}), ("definition.header.name", "invalid_choice")),
    (_http(header={"name": 5}), ("definition.header.name", "not_a_string")),
    (
        _http(header={"name": "etag", "pattern": "(a"}),
        ("definition.header.pattern", "regex_invalid_syntax"),
    ),
    (
        _http(body_pattern="é" * 1000, header={"name": "etag", "pattern": "é" * 1000}),
        ("definition", "too_large"),
    ),
    # malformed containers
    (None, ("definition", "not_an_object")),
    ("https://evil.example/", ("definition", "not_an_object")),
    ({}, ("definition", "empty")),
    ({1: 2, "host": "{domain}", "expected_status": [200]}, ("definition", "non_string_key")),
]


@pytest.mark.parametrize(("definition", "expected"), BAD, ids=[str(i) for i in range(len(BAD))])
def test_bad_http_definitions(definition: object, expected: tuple[str, str]) -> None:
    assert _reason(definition) == expected


def test_errors_never_echo_the_value() -> None:
    with pytest.raises(DefinitionInvalid) as err:
        parse_definition("http_fetch", _http(path="/secret value"))
    assert "secret" not in str(err.value)


def test_limits_agree_with_the_client_and_regex_engine() -> None:
    assert HTTP_HEADER_NAMES <= RESPONSE_HEADER_ALLOWLIST
    assert "set-cookie" not in HTTP_HEADER_NAMES
    assert FetchLimits().max_body_bytes >= MAX_HTTP_BODY_BYTES
    assert 3 * MAX_HTTP_BODY_BYTES <= MAX_TEXT_BYTES  # every invalid byte may become U+FFFD
    assert len(json.dumps(_http())) < MAX_DEFINITION_JSON_LENGTH


@pytest.mark.parametrize(
    ("overrides", "domain", "url", "host"),
    [
        ({}, "example.com", "https://example.com/", "example.com"),
        ({}, "Example.COM.", "https://example.com/", "example.com"),
        (
            {"host": "mta-sts.{domain}", "path": "/.well-known/mta-sts.txt"},
            "example.com",
            "https://mta-sts.example.com/.well-known/mta-sts.txt",
            "mta-sts.example.com",
        ),
        ({"scheme": "http", "path": "/a?b=1"}, "example.com", "http://example.com/a?b=1", None),
        ({"host": "www.{domain}"}, "bücher.example", "https://www.xn--bcher-kva.example/", None),
    ],
)
def test_render_url(overrides: dict[str, Any], domain: str, url: str, host: str | None) -> None:
    parsed = parse_definition("http_fetch", _http(**overrides))
    assert isinstance(parsed, HttpFetchDefinition)
    rendered, rendered_host = render_url(parsed, domain)
    assert rendered == url
    if host is not None:
        assert rendered_host == host


@pytest.mark.parametrize(
    ("template", "domain", "reason"),
    [
        ("{domain}", None, "invalid_domain"),
        ("{domain}", "1.2.3.4", "invalid_domain"),
        ("{domain}", "a_b.example", "invalid_domain"),
        (".".join(["a" * 63] * 3) + ".{domain}", "b" * 60 + ".example", "name_too_long"),
    ],
)
def test_render_url_errors(template: str, domain: object, reason: str) -> None:
    parsed = HttpFetchDefinition("https", template, "/", (200,), 10)
    with pytest.raises(NameRenderError) as err:
        render_url(parsed, domain)
    assert err.value.reason == reason


def test_render_url_revalidates_the_host_template() -> None:
    forged = HttpFetchDefinition("https", "evil.example", "/", (200,), 10)
    with pytest.raises(DefinitionInvalid):
        render_url(forged, "example.com")


# --- evaluator ----------------------------------------------------------------------------------


class Transport:
    """Transport factory over MockTransport; records requests and the limits it was given."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx2.Request] = []

    def __call__(self, limits: FetchLimits) -> httpx2.AsyncBaseTransport:
        def handle(request: httpx2.Request) -> httpx2.Response:
            self.requests.append(request)
            return self.handler(request)

        return httpx2.MockTransport(handle)


class Fetcher:
    """The guarded client (`_fetch`) over a Transport; records each call's arguments."""

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        url: str,
        *,
        resolver: Any,
        limits: FetchLimits | None = None,
        follow_redirects: bool | None = None,
        allow_truncated: bool = False,
    ) -> FetchResult | FetchError:
        self.calls.append(
            {
                "url": url,
                "limits": limits,
                "follow_redirects": follow_redirects,
                "allow_truncated": allow_truncated,
            }
        )
        return await _fetch(
            url,
            resolver=resolver,
            method="GET",
            headers=None,
            body=None,
            limits=limits or FetchLimits(),
            follow_redirects=follow_redirects,
            allow_truncated=allow_truncated,
            transport_factory=self.transport,
            classifier=default_classifier,
        )


def reply(status: int = 200, body: bytes = b"", **headers: str) -> Handler:
    return lambda request: httpx2.Response(status, content=body, headers=headers)


def raising(exc: type[Exception]) -> Handler:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise exc("boom", request=request)  # type: ignore[call-arg]

    return handler


def redirect_to(location: str, status: int = 302) -> Handler:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/":
            return httpx2.Response(status, headers={"location": location})
        return httpx2.Response(200, content=b"final ok")

    return handler


RESOLVER = {"example.com": PUBLIC, "www.example.com": PUBLIC, "mta-sts.example.com": PUBLIC}


async def _run(
    definition: dict[str, Any],
    handler: Handler | None = None,
    *,
    resolver: dict[str, str] | None = None,
    fetcher: Any = None,
    domain: str = "example.com",
    **overrides: Any,
) -> tuple[CheckResult, Fetcher]:
    used = fetcher if fetcher is not None else Fetcher(Transport(handler or reply()))
    values: dict[str, Any] = {
        "check_key": "acme.http",
        "kind": "http_fetch",
        "definition": definition,
        "severity": "medium",
        "remediation_text": dict(TEXT),
        "scope": "tenant",
        "fetch_limits": LIMITS,
        "fetcher": used,
        "verified_domain": domain,  # M7-21a: the gate is tested on its own below
        **overrides,
    }
    ctx = CheckContext(resolver=hosts(**(resolver or RESOLVER)), clock=lambda: NOW)
    return await CustomDnsCheck(**values).run(ctx, Target(domain=domain)), used


def _codes(result: CheckResult) -> list[str]:
    return [f.code for f in result.findings]


BODY = _http(body_pattern="^version: STSv1")
HEADER = _http(header={"name": "content-type", "pattern": "^text/plain"})
MANY_HEADERS = {f"x-h{i}": "v" for i in range(150)}

# (case, definition, handler, status, codes, reason)
OUTCOMES = [
    ("200 match", BODY, reply(body=b"version: STSv1\nmode: enforce"), "ok", [], None),
    ("200 no pattern", _http(), reply(body=b"anything"), "ok", [], None),
    (
        "200 mismatch",
        BODY,
        reply(body=b"version: STSv2"),
        "warn",
        ["CUSTOM_HTTP_BODY_MISMATCH"],
        "body_no_match",
    ),
    ("404", _http(), reply(404), "warn", ["CUSTOM_HTTP_STATUS_MISMATCH"], "status"),
    ("500", BODY, reply(500, b"oops"), "warn", ["CUSTOM_HTTP_STATUS_MISMATCH"], "status"),
    ("404 expected", _http(expected_status=[404, 410]), reply(404), "ok", [], None),
    ("redirect ok", _http(body_pattern="^final ok$"), redirect_to("/final"), "ok", [], None),
    ("redirect followed", _http(), redirect_to("https://www.example.com/x", 301), "ok", [], None),
    (
        "redirect to private ip",
        _http(),
        redirect_to("https://10.0.0.1/"),
        "error",
        ["CUSTOM_HTTP_BLOCKED"],
        "blocked",
    ),
    (
        "redirect to metadata ip",
        _http(),
        redirect_to("http://169.254.169.254/latest/meta-data/"),
        "error",
        ["CUSTOM_HTTP_BLOCKED"],
        "blocked",
    ),
    (
        "redirect to public ip literal",
        _http(),
        redirect_to(f"https://{PUBLIC}/"),
        "error",
        ["CUSTOM_HTTP_BLOCKED"],
        "redirect_off_domain",
    ),
    (
        "redirect https to http",
        _http(),
        redirect_to("http://example.com/x"),
        "error",
        ["CUSTOM_HTTP_BLOCKED"],
        "scheme_not_allowed",
    ),
    (
        "redirect to other port",
        _http(),
        redirect_to("https://example.com:8443/x"),
        "error",
        ["CUSTOM_HTTP_BLOCKED"],
        "port_not_allowed",
    ),
    (
        "redirect cap",
        _http(),
        lambda request: httpx2.Response(
            302, headers={"location": f"/n{len(request.url.path)}{request.url.path}"}
        ),
        "error",
        ["CUSTOM_HTTP_UNREACHABLE"],
        "too_many_redirects",
    ),
    (
        "redirect without location",
        _http(),
        reply(302),
        "error",
        ["CUSTOM_HTTP_UNREACHABLE"],
        "protocol_error",
    ),
    (
        "redirect loop",
        _http(),
        redirect_to("/"),
        "error",
        ["CUSTOM_HTTP_UNREACHABLE"],
        "too_many_redirects",
    ),
    (
        "timeout",
        _http(),
        raising(httpx2.ReadTimeout),
        "error",
        ["CUSTOM_HTTP_UNREACHABLE"],
        "timeout",
    ),
    (
        "connect error",
        _http(),
        raising(httpx2.ConnectError),
        "error",
        ["CUSTOM_HTTP_UNREACHABLE"],
        "connect_error",
    ),
    (
        "huge header",
        _http(),
        reply(**MANY_HEADERS),
        "error",
        ["CUSTOM_HTTP_TOO_LARGE"],
        "too_large",
    ),
    (
        "huge header value",
        _http(),
        reply(**{"x-big": "v" * 20000}),
        "error",
        ["CUSTOM_HTTP_TOO_LARGE"],
        "too_large",
    ),
    (
        "compressed body",
        _http(),
        reply(body=b"x", **{"content-encoding": "gzip"}),
        "error",
        ["CUSTOM_HTTP_UNREACHABLE"],
        "protocol_error",
    ),
    (
        "oversize, match inside the cap",
        _http(body_pattern="^head", max_body_bytes=8),
        reply(body=b"header and a long tail"),
        "ok",
        [],
        None,
    ),
    (
        "oversize, match past the cap",
        _http(body_pattern="tail", max_body_bytes=8),
        reply(body=b"header and a long tail"),
        "error",
        ["CUSTOM_HTTP_TOO_LARGE"],
        "body_truncated",
    ),
    (
        "non-utf8 body",
        _http(body_pattern="ok"),
        reply(body=b"\xff\xfeok\x80"),
        "ok",
        [],
        None,
    ),
    (
        "non-utf8 replacement char",
        _http(body_pattern="�"),
        reply(body=b"\xc3("),
        "ok",
        [],
        None,
    ),
    ("header match", HEADER, reply(**{"content-type": "text/plain"}), "ok", [], None),
    (
        "header no match",
        HEADER,
        reply(**{"content-type": "text/html"}),
        "warn",
        ["CUSTOM_HTTP_HEADER_MISMATCH"],
        "header_no_match",
    ),
    (
        "header missing",
        _http(header={"name": "etag"}),
        reply(),
        "warn",
        ["CUSTOM_HTTP_HEADER_MISMATCH"],
        "header_missing",
    ),
    (
        "header never returned by the client",
        _http(header={"name": "content-type"}),
        reply(**{"set-cookie": "a=b"}),
        "warn",
        ["CUSTOM_HTTP_HEADER_MISMATCH"],
        "header_missing",
    ),
    (
        "body and header mismatch",
        _http(body_pattern="x", header={"name": "etag"}),
        reply(body=b"y"),
        "warn",
        ["CUSTOM_HTTP_BODY_MISMATCH", "CUSTOM_HTTP_HEADER_MISMATCH"],
        "body_no_match",
    ),
]


@pytest.mark.parametrize(
    ("case", "definition", "handler", "status", "codes", "reason"),
    OUTCOMES,
    ids=[c[0] for c in OUTCOMES],
)
async def test_outcomes(
    case: str,
    definition: dict[str, Any],
    handler: Handler,
    status: str,
    codes: list[str],
    reason: str | None,
) -> None:
    result, _ = await _run(definition, handler)
    assert result.status == status
    assert _codes(result) == codes
    if reason is not None:
        assert result.data["reason"] == reason
        assert result.findings[0].params["reason"] == reason
    if status == "error":
        assert all(f.severity == "low" for f in result.findings)
        assert "remediation_text" not in result.findings[0].params


OFF_DOMAIN = [
    ("other site", "https://victim.org/secret"),
    ("sibling name", "https://evil-example.com/"),
    ("suffix trick", "https://example.com.evil.org/"),
    ("protocol relative", "//victim.org/secret"),
    ("parent of the domain", "https://com/"),
]


@pytest.mark.parametrize(("case", "location"), OFF_DOMAIN, ids=[c[0] for c in OFF_DOMAIN])
async def test_off_domain_redirect_is_refused_before_any_request(case: str, location: str) -> None:
    """A tenant domain redirecting elsewhere must not turn the check into a read-back proxy."""
    resolver = {**RESOLVER, "victim.org": PUBLIC, "evil-example.com": PUBLIC}
    resolver |= {"example.com.evil.org": PUBLIC}
    definition = _http(body_pattern="never", header={"name": "etag"})
    result, fetcher = await _run(definition, redirect_to(location), resolver=resolver)
    assert result.status == "error"
    assert _codes(result) == ["CUSTOM_HTTP_BLOCKED"]
    assert result.data["reason"] in ("redirect_off_domain", "blocked")
    (item,) = result.findings
    assert item.evidence == ()
    assert set(item.params) == {"check_key", "host", "reason"}
    assert "final_host" not in result.data and "status" not in result.data
    # Only the first, on-domain request was ever made.
    assert [r.headers["host"] for r in fetcher.transport.requests] == ["example.com"]
    assert [c["url"] for c in fetcher.calls] == ["https://example.com/"]
    assert all(c["follow_redirects"] is False for c in fetcher.calls)


async def test_off_domain_then_back_on_domain_is_still_refused() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.headers["host"] == "victim.org":
            return httpx2.Response(302, headers={"location": "https://example.com/final"})
        if request.url.path == "/":
            return httpx2.Response(302, headers={"location": "https://victim.org/x"})
        return httpx2.Response(200, content=b"final ok")

    resolver = {**RESOLVER, "victim.org": PUBLIC}
    result, fetcher = await _run(_http(), handler, resolver=resolver)
    assert result.status == "error" and result.data["reason"] == "redirect_off_domain"
    assert "victim.org" not in [r.headers["host"] for r in fetcher.transport.requests]


@pytest.mark.parametrize(
    ("location", "final"),
    [
        ("/final", "example.com"),
        ("https://www.example.com/x", "www.example.com"),
        ("https://a.b.example.com/x", "a.b.example.com"),
        ("https://EXAMPLE.com./x", "example.com"),
    ],
)
async def test_on_domain_redirects_are_followed(location: str, final: str) -> None:
    resolver = {**RESOLVER, "a.b.example.com": PUBLIC}
    result, fetcher = await _run(_http(), redirect_to(location, 301), resolver=resolver)
    assert result.status == "ok" and result.data["final_host"] == final
    assert result.data["hops"] == 2 and len(fetcher.calls) == 2


async def test_redirects_from_a_subdomain_host_may_reach_the_domain_itself() -> None:
    result, _ = await _run(_http(host="www.{domain}"), redirect_to("https://example.com/x"))
    assert result.status == "ok" and result.data["final_host"] == "example.com"


async def test_redirect_hops_respect_the_operator_cap() -> None:
    limits = FetchLimits(max_redirects=0)
    result, fetcher = await _run(_http(), redirect_to("/final"), fetch_limits=limits)
    assert result.data["reason"] == "too_many_redirects"
    assert len(fetcher.transport.requests) == 1


async def test_redirect_hops_share_the_run_budget() -> None:
    clock = [0.0]

    def handler(request: httpx2.Request) -> httpx2.Response:
        clock[0] += 5.0  # every hop costs 5 s of a 12 s budget
        return httpx2.Response(302, headers={"location": f"/h{clock[0]:.0f}"})

    budget = RunBudget(12.0, clock=lambda: clock[0])
    result, fetcher = await _run(_http(), handler, budget=budget)
    assert result.data["reason"] == "run_budget_exceeded"
    assert len(fetcher.transport.requests) == 3
    assert [c["limits"].total_timeout for c in fetcher.calls] == [12.0, 7.0, 2.0]


async def test_redirect_reports_final_host_and_hops() -> None:
    result, fetcher = await _run(_http(), redirect_to("https://www.example.com/x", 301))
    assert result.status == "ok"
    assert result.data["final_host"] == "www.example.com"
    assert result.data["hops"] == 2 and result.data["status"] == 200
    assert [r.headers["host"] for r in fetcher.transport.requests] == [
        "example.com",
        "www.example.com",
    ]


@pytest.mark.parametrize(
    ("address", "detail"),
    [
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link_local"),
        ("10.1.2.3", "private"),
        ("::1", "loopback"),
    ],
)
async def test_internal_addresses_are_blocked_never_fetched(address: str, detail: str) -> None:
    result, fetcher = await _run(_http(), resolver={"example.com": address})
    assert result.status == "error"
    assert _codes(result) == ["CUSTOM_HTTP_BLOCKED"]
    assert result.data["reason"] == "blocked"
    assert result.data["detail"] == detail
    assert fetcher.transport.requests == []


async def test_redirect_to_a_name_resolving_to_a_private_ip_is_blocked() -> None:
    resolver = {"example.com": PUBLIC, "internal.example.com": "192.168.1.10"}
    result, fetcher = await _run(
        _http(), redirect_to("https://internal.example.com/admin"), resolver=resolver
    )
    assert result.status == "error" and _codes(result) == ["CUSTOM_HTTP_BLOCKED"]
    assert result.data["hop"] == 1
    assert len(fetcher.transport.requests) == 1  # the redirect target was never contacted


async def test_dns_failure_is_unreachable_error() -> None:
    result, fetcher = await _run(_http(), resolver={"other.example": PUBLIC})
    assert result.status == "error" and _codes(result) == ["CUSTOM_HTTP_UNREACHABLE"]
    assert result.data["reason"] == "dns_error"
    assert fetcher.transport.requests == []


async def test_http_scheme_on_a_port_the_operator_did_not_allow_is_blocked_before_fetch() -> None:
    limits = FetchLimits(allowed_ports=(443,))
    fetcher = Fetcher(Transport(reply()))
    result, _ = await _run(_http(scheme="http"), fetcher=fetcher, fetch_limits=limits)
    assert _codes(result) == ["CUSTOM_HTTP_BLOCKED"]
    assert result.data["reason"] == "port_not_allowed"
    assert fetcher.calls == []


async def test_request_is_built_from_the_definition() -> None:
    definition = _http(host="mta-sts.{domain}", path="/.well-known/mta-sts.txt", max_body_bytes=99)
    result, fetcher = await _run(definition, reply(body=b"x"), domain="Example.com")
    assert result.status == "ok"
    (call,) = fetcher.calls
    assert call["url"] == "https://mta-sts.example.com/.well-known/mta-sts.txt"
    assert call["allow_truncated"] is True
    assert call["limits"].max_body_bytes == 99
    assert call["limits"].allowed_ports == LIMITS.allowed_ports
    assert call["limits"].total_timeout <= LIMITS.total_timeout
    (request,) = fetcher.transport.requests
    assert request.method == "GET" and request.url.host == PUBLIC
    assert result.data["url"] == call["url"] and result.data["host"] == "mta-sts.example.com"


async def test_without_fetch_limits_nothing_is_fetched() -> None:
    fetcher = Fetcher(Transport(reply()))
    result, _ = await _run(_http(), fetcher=fetcher, fetch_limits=None)
    assert result.status == "error" and _codes(result) == ["CUSTOM_CHECK_ERROR"]
    assert result.data["reason"] == "fetch_unconfigured"
    assert fetcher.calls == []


@pytest.mark.parametrize(
    "definition",
    [_http(host="evil.example"), _http(path="//evil.example/"), {"url": "https://x.example"}],
)
async def test_invalid_stored_definition_is_error_and_never_fetches(
    definition: dict[str, Any],
) -> None:
    fetcher = Fetcher(Transport(reply()))
    result, _ = await _run(definition, fetcher=fetcher)
    assert result.status == "error" and result.data["reason"] == "invalid_definition"
    assert fetcher.calls == []


async def test_host_that_cannot_be_built_is_error() -> None:
    template = ".".join(["a" * 63] * 3) + ".{domain}"
    result, fetcher = await _run(_http(host=template), domain="b" * 60 + ".example")
    assert result.status == "error" and result.data["reason"] == "name_too_long"
    assert fetcher.calls == []


async def test_catastrophic_regex_is_error_never_a_verdict() -> None:
    definition = _http(body_pattern="^(a+)+$")
    result, _ = await _run(definition, reply(body=b"a" * 40 + b"!"))
    assert result.status == "error" and _codes(result) == ["CUSTOM_CHECK_ERROR"]
    assert result.data["reason"] == "regex_timeout"


# --- run budget ---------------------------------------------------------------------------------


async def test_no_budget_left_never_fetches() -> None:
    fetcher = Fetcher(Transport(reply()))
    result, _ = await _run(_http(), fetcher=fetcher, budget=RunBudget(0.0))
    assert result.data["reason"] == "run_budget_exceeded" and result.status == "error"
    assert fetcher.calls == []


async def test_fetch_deadline_is_capped_by_the_run_budget() -> None:
    fetcher = Fetcher(Transport(reply()))
    await _run(_http(), fetcher=fetcher, budget=RunBudget(3.0))
    (call,) = fetcher.calls
    assert 0 < call["limits"].total_timeout <= 3.0


async def test_hanging_fetch_is_cut_at_the_budget() -> None:
    class Hanging:
        calls = 0

        async def __call__(self, url: str, **_: Any) -> FetchResult | FetchError:
            Hanging.calls += 1
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    result, _ = await _run(_http(), fetcher=Hanging(), budget=RunBudget(0.05))
    assert result.status == "error" and result.data["reason"] == "run_budget_exceeded"
    assert Hanging.calls == 1


async def test_client_deadline_inside_a_capped_budget_is_run_budget_exceeded() -> None:
    async def deadline(url: str, **_: Any) -> FetchResult | FetchError:
        return FetchError(FetchErrorKind.timeout, "deadline", 0)

    result, _ = await _run(_http(), fetcher=deadline, budget=RunBudget(1.0))
    assert result.data["reason"] == "run_budget_exceeded"
    # With the full client deadline available it is the site's timeout.
    result, _ = await _run(_http(), fetcher=deadline, budget=RunBudget(60.0))
    assert _codes(result) == ["CUSTOM_HTTP_UNREACHABLE"] and result.data["reason"] == "timeout"


# --- untrusted response -------------------------------------------------------------------------


SECRET = "SECRET-RESPONSE-TEXT"


async def test_response_text_only_reaches_bounded_evidence(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    body = f"\x1b[31m<script>{SECRET}</script>\x00".encode() + b"z" * 5000
    definition = _http(body_pattern="never", header={"name": "etag", "pattern": "never"})
    handler = reply(body=body, etag=f"<b>{SECRET}</b>")
    result, _ = await _run(definition, handler)
    assert _codes(result) == ["CUSTOM_HTTP_BODY_MISMATCH", "CUSTOM_HTTP_HEADER_MISMATCH"]
    for item in result.findings:
        assert SECRET not in json.dumps(dict(item.params), default=str)
        assert len(item.evidence) == 1 and len(item.evidence[0]) <= MAX_EVIDENCE_CHARS
        assert all(c.isprintable() for c in item.evidence[0])
    assert SECRET in result.findings[0].evidence[0]  # visible to the admin, escaped by renderers
    assert SECRET not in json.dumps(result.data, default=str)
    assert SECRET not in caplog.text


async def test_status_mismatch_params_and_remediation() -> None:
    result, _ = await _run(_http(expected_status=[200, 204]), reply(503, b"down"))
    (item,) = result.findings
    assert item.severity == "medium" and result.status == "warn"
    assert dict(item.params) == {
        "check_key": "acme.http",
        "host": "example.com",
        "final_host": "example.com",
        "status": 503,
        "reason": "status",
        "expected": "200, 204",
        "remediation_text": TEXT,
    }
    assert item.evidence == ("down",) and item.remediation_key is None


async def test_global_remediation_key_is_carried() -> None:
    result, _ = await _run(
        _http(),
        reply(404),
        scope="global",
        remediation_text=None,
        remediation_key="web.custom_checks.kind.http_fetch",
        severity="high",
    )
    (item,) = result.findings
    assert result.status == "fail" and item.remediation_key == "web.custom_checks.kind.http_fetch"
    assert "remediation_text" not in item.params


def test_default_fetcher_is_the_guarded_client() -> None:
    check = CustomDnsCheck(check_key="k", kind="http_fetch", definition=_http(), severity="low")
    assert check._fetcher is guarded_http.fetch
    assert custom_module.guarded_fetch is guarded_http.fetch


@pytest.mark.parametrize("lang", ["en", "it"])
async def test_every_http_finding_renders_with_its_params(lang: str) -> None:
    cases = [
        await _run(_http(), resolver={"example.com": "127.0.0.1"}),
        await _run(_http(), raising(httpx2.ConnectError)),
        await _run(_http(), reply(**MANY_HEADERS)),
        await _run(_http(body_pattern="z", max_body_bytes=1), reply(body=b"ab")),
        await _run(_http(), reply(404)),
        await _run(_http(body_pattern="z"), reply(body=b"a")),
        await _run(_http(header={"name": "etag"}), reply()),
        await _run(_http(), reply(), fetch_limits=None),
        await _run(_http(), reply(), verified_domain=None),
    ]
    seen = {r.findings[0].code for r, _ in cases}
    assert seen == set(CODES) - {"CUSTOM_CHECK_FAILED"}
    for result, _ in cases:
        item = result.findings[0]
        assert t(item.title_key, lang, **item.params)
        assert t(item.detail_key, lang, **item.params)


# --- ownership gate (M7-21a) ---------------------------------------------------------------------

# (case, target domain, verified_domain, other overrides, fetched)
GATE = [
    ("none", "example.com", None, {}, False),
    ("other domain", "example.com", "example.org", {}, False),
    ("parent of the target", "www.example.com", "example.com", {}, False),
    ("child of the target", "example.com", "www.example.com", {}, False),
    ("suffix lookalike", "badexample.com", "example.com", {}, False),
    ("empty", "example.com", "", {}, False),
    ("malformed", "example.com", "exa mple..com", {}, False),
    ("not a string", "example.com", 123, {}, False),
    ("before the limits check", "example.com", None, {"fetch_limits": None}, False),
    ("before the run budget", "example.com", None, {"budget": RunBudget(0.0)}, False),
    ("before url rendering", "-bad-.example.com", None, {}, False),
    ("same domain", "example.com", "example.com", {}, True),
    ("case and trailing dot", "example.com", "EXAMPLE.com.", {}, True),
]


@pytest.mark.parametrize(
    ("target", "verified", "overrides", "fetched"),
    [pytest.param(d, v, o, f, id=c) for c, d, v, o, f in GATE],
)
async def test_http_fetch_needs_the_verified_domain(
    target: str, verified: object, overrides: dict[str, Any], fetched: bool
) -> None:
    fetcher = Fetcher(Transport(reply()))
    result, _ = await _run(
        _http(),
        fetcher=fetcher,
        domain=target,
        resolver={target: PUBLIC},
        verified_domain=verified,
        **overrides,
    )
    if fetched:
        assert fetcher.calls and result.status == "ok"
        return
    assert fetcher.calls == []  # nothing was requested, not even DNS for the host
    assert result.status == "error"
    (item,) = result.findings
    assert item.code == "CUSTOM_HTTP_DOMAIN_UNVERIFIED"
    assert dict(item.params) == {"check_key": "acme.http", "reason": "domain_unverified"}
    assert result.data["reason"] == "domain_unverified"


async def test_dns_kinds_ignore_the_gate() -> None:
    check = CustomDnsCheck(
        check_key="dns.k",
        kind="dns_exists",
        definition={"name": "{domain}", "rrtype": "TXT"},
        severity="low",
        remediation_text=dict(TEXT),
    )
    ctx = CheckContext(resolver=hosts(**RESOLVER), clock=lambda: NOW)
    result = await check.run(ctx, Target(domain="example.com"))
    assert "CUSTOM_HTTP_DOMAIN_UNVERIFIED" not in [f.code for f in result.findings]
