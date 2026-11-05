"""M1-14 security headers on every response (no DB, no network)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI, HTTPException, Response
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.security_headers import CONTENT_SECURITY_POLICY, HSTS_VALUE, SECURITY_HEADERS
from app.main import create_app

KEY = "k" * 40

EXPECTED = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "x-frame-options": "DENY",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


def _app(base_url: str) -> FastAPI:
    app = create_app(
        Settings(secret_key=KEY, encryption_key=KEY, base_url=base_url)  # type: ignore[call-arg]
    )

    @app.get("/t/ok")
    def ok() -> dict[str, str]:
        return {"a": "b"}

    @app.get("/t/loosen")
    def loosen(response: Response) -> dict[str, str]:
        response.headers["Content-Security-Policy"] = "script-src * 'unsafe-inline'"
        response.headers["X-Frame-Options"] = "ALLOWALL"
        return {}

    @app.get("/t/boom")
    def boom() -> None:
        raise RuntimeError("secret-detail-do-not-leak")

    @app.get("/t/error")
    def error() -> None:
        raise HTTPException(status_code=418)

    return app


@pytest.fixture(scope="module", params=["http://localhost:8000", "https://example.test"])
def client(request: pytest.FixtureRequest) -> Iterator[tuple[TestClient, bool]]:
    with TestClient(_app(request.param)) as c:
        yield c, request.param.startswith("https://")


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/healthz", 200),
        ("HEAD", "/healthz", 200),
        ("POST", "/healthz", 405),
        ("GET", "/t/ok", 200),
        ("GET", "/t/loosen", 200),
        ("GET", "/t/error", 418),
        ("GET", "/nope", 404),
        ("POST", "/t/ok", 403),  # CSRF refusal: unsafe method without a token
    ],
)
def test_headers_on_every_response(
    client: tuple[TestClient, bool], method: str, path: str, status: int
) -> None:
    c, https = client
    response = c.request(method, path)
    assert response.status_code == status
    for name, value in EXPECTED.items():
        assert response.headers.get_list(name) == [value], name
    if https:
        assert response.headers.get_list("strict-transport-security") == ["max-age=31536000"]
    else:
        assert "strict-transport-security" not in response.headers


def test_healthz_body_unchanged(client: tuple[TestClient, bool]) -> None:
    c, _ = client
    response = c.get("/healthz")
    assert response.json() == {"status": "ok"}
    assert "set-cookie" not in response.headers


def test_csp_has_no_unsafe_sources() -> None:
    assert "unsafe-inline" not in CONTENT_SECURITY_POLICY
    assert "unsafe-eval" not in CONTENT_SECURITY_POLICY
    directives = dict(d.strip().split(" ", 1) for d in CONTENT_SECURITY_POLICY.split(";"))
    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self'"
    assert directives["frame-ancestors"] == "'none'"
    assert dict(SECURITY_HEADERS)["Content-Security-Policy"] == CONTENT_SECURITY_POLICY
    assert HSTS_VALUE == "max-age=31536000"


@pytest.mark.parametrize("base_url", ["https://example.test:8443/app", "https://localhost"])
def test_hsts_for_https_base_urls(base_url: str) -> None:
    with TestClient(_app(base_url)) as c:
        assert c.get("/healthz").headers["strict-transport-security"] == HSTS_VALUE


def test_no_hsts_without_settings() -> None:
    # No lifespan: settings unavailable -> HSTS omitted, other headers still sent.
    c = TestClient(_app("https://example.test"))
    response = c.get("/healthz")
    assert "strict-transport-security" not in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize(
    ("base_url", "https"), [("http://localhost:8000", False), ("https://example.test", True)]
)
def test_unhandled_exception_500_has_headers_and_no_details(base_url: str, https: bool) -> None:
    with TestClient(_app(base_url), raise_server_exceptions=False) as c:
        response = c.get("/t/boom")
    assert response.status_code == 500
    for name, value in EXPECTED.items():
        assert response.headers.get_list(name) == [value], name
    if https:
        assert response.headers.get_list("strict-transport-security") == [HSTS_VALUE]
    else:
        assert "strict-transport-security" not in response.headers
    # M1-16: translated HTML page instead of the plain phrase
    assert response.headers["content-type"].startswith("text/html")
    assert "<h1>Something went wrong</h1>" in response.text
    assert "secret-detail" not in response.text
    assert "RuntimeError" not in response.text


def test_unhandled_exception_still_propagates() -> None:
    with (
        TestClient(_app("http://localhost:8000")) as c,
        pytest.raises(RuntimeError, match="secret-detail"),
    ):
        c.get("/t/boom")
