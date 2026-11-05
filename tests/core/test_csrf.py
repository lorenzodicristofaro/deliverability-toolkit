"""M1-14 CSRF middleware and tokens, on minimal routes mounted in the test (no DB, no network)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.core import csrf, i18n
from app.core.config import Settings
from app.core.csrf import (
    CSRF_COOKIE_NAME,
    check_token,
    csrf_token_for,
    new_double_submit_token,
    session_csrf_token,
    valid_double_submit_cookie,
)
from app.core.i18n import t
from app.core.security import (
    SESSION_COOKIE_NAME,
    new_session_token,
    sign_session_token,
)
from app.main import create_app

KEY = "k" * 40
SECRET = SecretStr("s" * 40)
OTHER = SecretStr("t" * 40)
# PROPFIND: a custom method is checked too (deny by default).
METHODS = ["POST", "PUT", "PATCH", "DELETE", "PROPFIND"]
FORM = "application/x-www-form-urlencoded"


def _settings(base_url: str = "http://localhost:8000") -> Settings:
    return Settings(  # type: ignore[call-arg]
        secret_key=SECRET.get_secret_value(), encryption_key=KEY, base_url=base_url
    )


def _app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or _settings()
    app = create_app(cfg)

    @app.api_route("/ui/action", methods=METHODS)
    async def action(request: Request) -> dict[str, Any]:
        body = (await request.body()).decode()
        return {"ok": True, "body": body}

    @app.api_route("/ui/token", methods=["GET", "HEAD"])
    async def token(request: Request, response: Response) -> dict[str, str]:
        return {"token": csrf_token_for(request, response, cfg)}

    return app


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(_app()) as c:
        yield c


@pytest.fixture(autouse=True)
def _strict_i18n() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)


def _cookie_header(cookies: dict[str, str]) -> dict[str, str]:
    return {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())} if cookies else {}


SESSION_TOKEN = new_session_token()
SESSION_COOKIE = sign_session_token(SESSION_TOKEN, SECRET)
SESSION_CSRF = session_csrf_token(SESSION_TOKEN, SECRET)
OTHER_SESSION_CSRF = session_csrf_token(new_session_token(), SECRET)
DOUBLE = new_double_submit_token(SECRET)
OTHER_DOUBLE = new_double_submit_token(SECRET)
FORGED_DOUBLE = new_double_submit_token(OTHER)

AUTH = {SESSION_COOKIE_NAME: SESSION_COOKIE}
ANON = {CSRF_COOKIE_NAME: DOUBLE}

# (case id, cookies, where the token goes, token, expected status)
CASES: list[tuple[str, dict[str, str], str, str | None, int]] = [
    # authenticated (valid signed session cookie): session-bound token
    ("auth-valid-header", AUTH, "header", SESSION_CSRF, 200),
    ("auth-valid-form", AUTH, "form", SESSION_CSRF, 200),
    ("auth-missing", AUTH, "none", None, 403),
    ("auth-empty-header", AUTH, "header", "", 403),
    ("auth-empty-form", AUTH, "form", "", 403),
    ("auth-other-session-token", AUTH, "header", OTHER_SESSION_CSRF, 403),
    ("auth-double-submit-token", {**AUTH, **ANON}, "header", DOUBLE, 403),
    ("auth-truncated", AUTH, "header", SESSION_CSRF[:-1], 403),
    ("auth-case-changed", AUTH, "header", SESSION_CSRF.swapcase(), 403),
    ("auth-too-long", AUTH, "header", SESSION_CSRF + "x" * 5000, 403),
    ("auth-non-ascii-form", AUTH, "form", "é" * 43, 403),
    ("auth-session-cookie-as-token", AUTH, "header", SESSION_COOKIE, 403),
    # anonymous with a valid signed double-submit cookie
    ("anon-valid-header", ANON, "header", DOUBLE, 200),
    ("anon-valid-form", ANON, "form", DOUBLE, 200),
    ("anon-missing", ANON, "none", None, 403),
    ("anon-mismatch", ANON, "header", OTHER_DOUBLE, 403),
    ("anon-session-token", ANON, "header", SESSION_CSRF, 403),
    ("anon-malformed", ANON, "header", "not-a-token", 403),
    # anonymous with no / bad cookie
    ("anon-no-cookie", {}, "header", DOUBLE, 403),
    ("anon-no-cookie-no-token", {}, "none", None, 403),
    ("anon-forged-cookie", {CSRF_COOKIE_NAME: FORGED_DOUBLE}, "header", FORGED_DOUBLE, 403),
    ("anon-garbage-cookie", {CSRF_COOKIE_NAME: "x.y"}, "header", "x.y", 403),
    # tampered session cookie -> treated as anonymous (no valid double-submit cookie)
    (
        "tampered-session",
        {SESSION_COOKIE_NAME: sign_session_token(SESSION_TOKEN, OTHER)},
        "header",
        SESSION_CSRF,
        403,
    ),
]


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize(
    ("cookies", "where", "token", "status"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_unsafe_methods_matrix(
    client: TestClient,
    method: str,
    cookies: dict[str, str],
    where: str,
    token: str | None,
    status: int,
) -> None:
    headers = _cookie_header(cookies)
    content: bytes | None = None
    if where == "header":
        assert token is not None
        headers[csrf.CSRF_HEADER] = token
    elif where == "form":
        assert token is not None
        headers["Content-Type"] = FORM
        content = f"name=x&csrf_token={token}".encode()
    response = client.request(method, "/ui/action", headers=headers, content=content)
    assert response.status_code == status
    if status == 403:
        assert response.json() == {"detail": t("csrf.invalid", "en")}


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
@pytest.mark.parametrize("cookies", [{}, AUTH, ANON], ids=["none", "auth", "anon"])
def test_safe_methods_not_checked(client: TestClient, method: str, cookies: dict[str, str]) -> None:
    response = client.request(method, "/ui/token", headers=_cookie_header(cookies))
    # OPTIONS is not a declared method of the route: 405, never a CSRF 403.
    assert response.status_code == (405 if method == "OPTIONS" else 200)


def test_form_body_is_replayed_to_the_route(client: TestClient) -> None:
    body = f"name=hello&csrf_token={SESSION_CSRF}"
    response = client.post(
        "/ui/action", headers={**_cookie_header(AUTH), "Content-Type": FORM}, content=body
    )
    assert response.status_code == 200
    assert response.json()["body"] == body


@pytest.mark.parametrize(
    ("content_type", "body", "status"),
    [
        (FORM + "; charset=utf-8", f"csrf_token={SESSION_CSRF}", 200),
        (FORM, f"csrf_token={SESSION_CSRF}&csrf_token={SESSION_CSRF}", 403),  # duplicated
        (FORM, b"csrf_token=\xff\xfe", 403),  # not UTF-8
        (FORM, "csrf_token", 403),  # field without value
        (FORM, "%%%", 403),
        ("application/json", json.dumps({"csrf_token": SESSION_CSRF}), 403),
        ("multipart/form-data; boundary=x", f"csrf_token={SESSION_CSRF}", 403),
        ("text/plain", f"csrf_token={SESSION_CSRF}", 403),
    ],
    ids=["charset", "duplicate", "bad-utf8", "no-value", "garbage", "json", "multipart", "text"],
)
def test_form_parsing_malformed(
    client: TestClient, content_type: str, body: str | bytes, status: int
) -> None:
    content = body.encode() if isinstance(body, str) else body
    headers = {**_cookie_header(AUTH), "Content-Type": content_type}
    response = client.post("/ui/action", headers=headers, content=content)
    assert response.status_code == status


def test_oversized_form_body_refused(client: TestClient) -> None:
    body = f"csrf_token={SESSION_CSRF}&pad=" + "a" * csrf.MAX_FORM_BYTES
    headers = {**_cookie_header(AUTH), "Content-Type": FORM}
    assert client.post("/ui/action", headers=headers, content=body).status_code == 403


def test_header_takes_precedence_over_form(client: TestClient) -> None:
    headers = {**_cookie_header(AUTH), "Content-Type": FORM, csrf.CSRF_HEADER: "wrong"}
    body = f"csrf_token={SESSION_CSRF}"
    assert client.post("/ui/action", headers=headers, content=body).status_code == 403


@pytest.mark.parametrize(
    ("accept_language", "lang"), [(None, "en"), ("it-IT,it;q=0.9", "it"), ("fr", "en")]
)
def test_403_body_is_translated(client: TestClient, accept_language: str | None, lang: str) -> None:
    headers = {"Accept-Language": accept_language} if accept_language else {}
    response = client.post("/ui/action", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": t("csrf.invalid", lang)}
    assert response.json()["detail"] != "csrf.invalid"


def test_403_carries_security_headers(client: TestClient) -> None:
    response = client.post("/ui/action")
    assert response.status_code == 403
    assert response.headers["X-Frame-Options"] == "DENY"


# --- token helper -------------------------------------------------------------------------------


def test_helper_returns_session_bound_token_when_authenticated(client: TestClient) -> None:
    response = client.get("/ui/token", headers=_cookie_header(AUTH))
    assert response.json() == {"token": SESSION_CSRF}
    assert "set-cookie" not in response.headers


def test_helper_reuses_valid_double_submit_cookie(client: TestClient) -> None:
    response = client.get("/ui/token", headers=_cookie_header(ANON))
    assert response.json() == {"token": DOUBLE}
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(
    ("base_url", "secure"), [("http://localhost:8000", False), ("https://example.test", True)]
)
def test_helper_sets_double_submit_cookie_for_anonymous(base_url: str, secure: bool) -> None:
    with TestClient(_app(_settings(base_url))) as c:
        response = c.get("/ui/token", headers=_cookie_header({CSRF_COOKIE_NAME: "garbage"}))
        token = response.json()["token"]
        cookie = response.headers["set-cookie"]
        assert cookie.startswith(f"{CSRF_COOKIE_NAME}={token};")
        lowered = cookie.lower()
        assert "httponly" in lowered and "samesite=lax" in lowered and "path=/" in lowered
        assert ("secure" in lowered.split("; ")) is secure
        assert valid_double_submit_cookie(token, SECRET)
        # the issued pair is accepted on a pre-session form post
        post = c.post(
            "/ui/action",
            headers={**_cookie_header({CSRF_COOKIE_NAME: token}), csrf.CSRF_HEADER: token},
        )
        assert post.status_code == 200


# --- pure functions -----------------------------------------------------------------------------


def test_session_token_is_deterministic_and_key_bound() -> None:
    assert session_csrf_token(SESSION_TOKEN, SECRET) == SESSION_CSRF
    assert session_csrf_token(SESSION_TOKEN, OTHER) != SESSION_CSRF
    assert SESSION_CSRF not in SESSION_COOKIE  # not the session cookie signature


def test_double_submit_tokens_are_unique() -> None:
    assert len({new_double_submit_token(SECRET) for _ in range(50)}) == 50


@pytest.mark.parametrize(
    "value",
    [
        None,
        42,
        "",
        "x",
        DOUBLE + "x",
        DOUBLE[:-1],
        DOUBLE.replace(".", "-"),
        FORGED_DOUBLE,
        SESSION_COOKIE,  # signed with the session-cookie key, not the CSRF key
        "é" * len(DOUBLE),
        DOUBLE[:43] + "." + "=" * 43,
    ],
)
def test_valid_double_submit_cookie_rejects_malformed(value: object) -> None:
    assert valid_double_submit_cookie(value, SECRET) is False


def test_valid_double_submit_cookie_accepts_own() -> None:
    assert valid_double_submit_cookie(DOUBLE, SECRET) is True


@pytest.mark.parametrize(
    ("submitted", "cookies", "expected"),
    [
        (SESSION_CSRF, AUTH, True),
        (None, AUTH, False),
        ("é", AUTH, False),
        (DOUBLE, ANON, True),
        (None, ANON, False),
        (DOUBLE, {}, False),
        (SESSION_CSRF, {**AUTH, **ANON}, True),
        (DOUBLE, {**AUTH, **ANON}, False),
    ],
)
def test_check_token(submitted: str | None, cookies: dict[str, str], expected: bool) -> None:
    assert check_token(submitted, cookies, SECRET) is expected


# --- exemptions and fail-closed -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "status"), [("GET", 200), ("HEAD", 200), ("POST", 405), ("DELETE", 405)]
)
def test_healthz_unaffected(client: TestClient, method: str, status: int) -> None:
    response = client.request(method, "/healthz")
    assert response.status_code == status
    assert "set-cookie" not in response.headers
    if method == "GET":
        assert response.json() == {"status": "ok"}


def test_missing_settings_fail_closed() -> None:
    app = _app()
    # No lifespan run: app.state.settings is not set.
    c = TestClient(app)
    response = c.post(
        "/ui/action", headers={csrf.CSRF_HEADER: SESSION_CSRF, **_cookie_header(AUTH)}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("PROPFIND", "/nope", 403),  # unknown method on an unknown path: refused before routing
        ("MKCOL", "/ui/action", 403),
        ("propfind", "/ui/action", 403),
        ("TRACE", "/ui/token", 405),  # safe set: not checked, route rejects the method
        ("OPTIONS", "/nope", 404),
    ],
)
def test_deny_by_default_for_non_safe_methods(
    client: TestClient, method: str, path: str, status: int
) -> None:
    assert client.request(method, path).status_code == status


def test_safe_methods_set() -> None:
    assert frozenset({"GET", "HEAD", "OPTIONS", "TRACE"}) == csrf.SAFE_METHODS
