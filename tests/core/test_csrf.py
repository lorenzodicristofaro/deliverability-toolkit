"""M1-14 CSRF middleware and tokens, on minimal routes mounted in the test (no DB, no network)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.types import Message, Receive, Scope, Send

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
    name = "__Host-dt_csrf" if secure else CSRF_COOKIE_NAME  # R1-15
    with TestClient(_app(_settings(base_url))) as c:
        response = c.get("/ui/token", headers=_cookie_header({name: "garbage"}))
        token = response.json()["token"]
        cookie = response.headers["set-cookie"]
        assert cookie.startswith(f"{name}={token};")
        lowered = cookie.lower()
        assert "httponly" in lowered and "samesite=lax" in lowered and "path=/" in lowered
        assert ("secure" in lowered.split("; ")) is secure
        assert valid_double_submit_cookie(token, SECRET)
        # the issued pair is accepted on a pre-session form post
        post = c.post(
            "/ui/action",
            headers={**_cookie_header({name: token}), csrf.CSRF_HEADER: token},
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


# --- M5-01: per-route form cap ------------------------------------------------------------------

BIG_PATH = "/ui/big"
BIG_CAP = csrf.MAX_FORM_BYTES + 8192
csrf.register_form_cap(BIG_PATH, BIG_CAP)
CHUNK = 64 * 1024


def _capped_app() -> FastAPI:
    """`_app()` plus an opted-in route that caps its own body and answers 413 above it."""
    app = _app()

    @app.post(BIG_PATH)
    async def big(request: Request) -> Response:
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > BIG_CAP:
                return Response("too large", status_code=413)
        return Response(str(size), status_code=200)

    return app


@pytest.fixture(scope="module")
def capped() -> Iterator[TestClient]:
    with TestClient(_capped_app()) as c:
        yield c


def _sized(n: int, token: str | None = SESSION_CSRF, token_last: bool = False) -> bytes:
    """A urlencoded body of exactly `n` bytes, token first (browser order) or last."""
    head = f"csrf_token={token}&" if token is not None and not token_last else ""
    tail = f"&csrf_token={token}" if token is not None and token_last else ""
    pad = n - len(head) - len(tail) - len("pad=")
    assert pad >= 0
    body = (head + "pad=" + "a" * pad + tail).encode()
    assert len(body) == n
    return body


@pytest.mark.parametrize(
    ("path", "cap", "over_status"),
    [("/ui/action", csrf.MAX_FORM_BYTES, 403), (BIG_PATH, BIG_CAP, 413)],
    ids=["default", "opted-in"],
)
@pytest.mark.parametrize(("delta", "ok"), [(-1, True), (0, True), (1, False)])
def test_form_cap_boundaries(
    capped: TestClient, path: str, cap: int, over_status: int, delta: int, ok: bool
) -> None:
    """No-JS style: token in the body, at cap-1, cap and cap+1."""
    headers = {**_cookie_header(AUTH), "Content-Type": FORM}
    response = capped.post(path, headers=headers, content=_sized(cap + delta))
    assert response.status_code == (200 if ok else over_status)


@pytest.mark.parametrize(
    ("token", "token_last"),
    [(None, False), ("", False), (OTHER_SESSION_CSRF, False), (SESSION_CSRF, True)],
    ids=["missing", "empty", "wrong", "valid-but-last"],
)
@pytest.mark.parametrize("delta", [0, 1, 4 * 1024 * 1024], ids=["at-cap", "cap+1", "cap+4MiB"])
def test_opted_in_route_still_enforces_csrf(
    capped: TestClient, token: str | None, token_last: bool, delta: int
) -> None:
    """A big body is no bypass: a bad token, or one past the cap, is a CSRF 403."""
    body = _sized(BIG_CAP + delta, token, token_last)
    headers = {**_cookie_header(AUTH), "Content-Type": FORM}
    response = capped.post(BIG_PATH, headers=headers, content=body)
    if token_last and delta == 0:
        assert response.status_code == 200  # complete body: the token may be anywhere
    else:
        assert response.status_code == 403
        assert response.json() == {"detail": t("csrf.invalid", "en")}


def test_opted_in_header_token_post_uses_route_cap(capped: TestClient) -> None:
    """JS/HTMX style: the token travels in the header and only the route's cap applies."""
    headers = {**_cookie_header(AUTH), "Content-Type": FORM, "X-CSRF-Token": SESSION_CSRF}
    assert capped.post(BIG_PATH, headers=headers, content=_sized(BIG_CAP, None)).status_code == 200
    over = _sized(BIG_CAP + 1, None)
    assert capped.post(BIG_PATH, headers=headers, content=over).status_code == 413


def test_default_route_regression_missing_token_is_403(capped: TestClient) -> None:
    headers = {**_cookie_header(AUTH), "Content-Type": FORM}
    assert capped.post("/ui/action", headers=headers, content=b"a=1").status_code == 403
    assert capped.post(BIG_PATH, headers=headers, content=b"a=1").status_code == 403


class _State:
    def __init__(self) -> None:
        self.settings = _settings()


class _FakeApp:
    def __init__(self) -> None:
        self.state = _State()


async def _drive(path: str, receive: Receive, content_length: str | None = None) -> int:
    """Run CSRFMiddleware directly (session cookie, token in the body). The inner app drains
    the body like a capped route: 413 above the path's form cap, else 200."""

    async def inner(scope: Scope, inner_receive: Receive, send: Send) -> None:
        size = 0
        while True:
            message = await inner_receive()
            size += len(message.get("body", b""))
            if size > csrf.form_cap_for(path):
                await Response(status_code=413)(scope, inner_receive, send)
                return
            if not message.get("more_body", False):
                break
        await Response(status_code=200)(scope, inner_receive, send)

    headers = [
        (b"content-type", FORM.encode()),
        (b"cookie", f"{SESSION_COOKIE_NAME}={SESSION_COOKIE}".encode()),
    ]
    if content_length is not None:
        headers.append((b"content-length", content_length.encode()))
    scope = {"type": "http", "method": "POST", "path": path, "headers": headers, "app": _FakeApp()}
    statuses: list[int] = []

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    await csrf.CSRFMiddleware(inner)(scope, receive, send)
    return statuses[0]


def _chunked(first: bytes, total_chunks: int) -> tuple[Receive, list[int]]:
    """A streaming body with no Content-Length: `first`, then padding chunks; `pulled` counts
    the messages taken from the server."""
    pulled: list[int] = []

    async def receive() -> Message:
        index = len(pulled)
        pulled.append(index)
        body = first if index == 0 else b"a" * CHUNK
        return {"type": "http.request", "body": body, "more_body": index < total_chunks}

    return receive, pulled


@pytest.mark.parametrize(
    ("path", "cap", "status"),
    [("/ui/action", csrf.MAX_FORM_BYTES, 403), (BIG_PATH, BIG_CAP, 413)],
    ids=["default", "opted-in"],
)
def test_chunked_body_is_cut_at_cap(path: str, cap: int, status: int) -> None:
    first = f"csrf_token={SESSION_CSRF}&pad=".encode()
    receive, pulled = _chunked(first, 1000)
    assert asyncio.run(_drive(path, receive)) == status
    # Reading stops at the first chunk past the cap (1000 chunks were on offer).
    assert len(pulled) == _messages_to_pass(cap, first)


def _messages_to_pass(cap: int, first: bytes) -> int:
    """Messages pulled until the running size first exceeds `cap`."""
    return 1 + -(-(cap - len(first) + 1) // CHUNK)


def test_chunked_body_without_token_in_prefix_is_403() -> None:
    receive, pulled = _chunked(b"pad=", 1000)
    assert asyncio.run(_drive(BIG_PATH, receive)) == 403
    assert len(pulled) == _messages_to_pass(BIG_CAP, b"pad=")


@pytest.mark.parametrize("declared", ["abc", "-1", "1e9", str(csrf.MAX_FORM_BYTES + 1)])
def test_default_route_refuses_bad_declared_length_unread(declared: str) -> None:
    receive, pulled = _chunked(f"csrf_token={SESSION_CSRF}".encode(), 0)
    assert asyncio.run(_drive("/ui/action", receive, content_length=declared)) == 403
    assert pulled == []


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        (b"", b""),
        (b"csrf_token=abc", b""),  # the last field may be truncated: never used
        (b"csrf_token=abc&pad=aa", b"csrf_token=abc"),
        (b"a=1&b=2&c", b"a=1&b=2"),
        (b"&", b""),
    ],
)
def test_complete_fields(prefix: bytes, expected: bytes) -> None:
    assert csrf._complete_fields(prefix) == expected


@pytest.mark.parametrize(
    ("path", "max_bytes"),
    [("relative", BIG_CAP), ("/x", csrf.MAX_FORM_BYTES), ("/x", 0), ("", BIG_CAP)],
)
def test_register_form_cap_rejects_bad_input(path: str, max_bytes: int) -> None:
    with pytest.raises(ValueError):
        csrf.register_form_cap(path, max_bytes)
    assert csrf.form_cap_for(path) == csrf.MAX_FORM_BYTES


def test_unregistered_paths_keep_default_cap() -> None:
    assert csrf.form_cap_for("/ui/action") == csrf.MAX_FORM_BYTES
    assert csrf.form_cap_for(BIG_PATH + "/") == csrf.MAX_FORM_BYTES  # exact match only
    assert csrf.form_cap_for(BIG_PATH) == BIG_CAP


# --- R1-15 (AUTH-10): __Host- cookie names on https, issue time in the double-submit token -------

HTTPS = "https://example.test"
HOST_CSRF = "__Host-dt_csrf"
HOST_SESSION = "__Host-dt_session"
T0 = 1_800_000_000.0


def _https_client() -> TestClient:
    return TestClient(_app(_settings(HTTPS)), base_url="https://testserver")


def _post(c: TestClient, cookies: dict[str, str], token: str | None) -> Any:
    headers = _cookie_header(cookies)
    if token is not None:
        headers[csrf.CSRF_HEADER] = token
    return c.post("/ui/action", headers=headers)


def test_https_issues_host_prefixed_csrf_cookie() -> None:
    with _https_client() as c:
        response = c.get("/ui/token")
        token = response.json()["token"]
        cookie = response.headers["set-cookie"]
        assert cookie.startswith(f"{HOST_CSRF}={token};")
        parts = [p.strip().lower() for p in cookie.split(";")]
        assert "secure" in parts and "path=/" in parts
        assert not any(p.startswith("domain") for p in parts)
        assert _post(c, {HOST_CSRF: token}, token).status_code == 200


def test_https_ignores_unprefixed_csrf_cookie() -> None:
    # A sibling subdomain can toss `dt_csrf` but never `__Host-dt_csrf`: on https only the
    # prefixed name counts, so a tossed (even validly signed) pair is refused.
    token = new_double_submit_token(SECRET)
    with _https_client() as c:
        assert _post(c, {CSRF_COOKIE_NAME: token}, token).status_code == 403


def test_http_keeps_current_names() -> None:
    with TestClient(_app(_settings())) as c:
        response = c.get("/ui/token")
        token = response.json()["token"]
        assert response.headers["set-cookie"].startswith(f"{CSRF_COOKIE_NAME}={token};")
        assert _post(c, {CSRF_COOKIE_NAME: token}, token).status_code == 200
        # http: the prefixed names are not read
        assert _post(c, {HOST_CSRF: token}, token).status_code == 403
        assert _post(c, {HOST_SESSION: SESSION_COOKIE}, SESSION_CSRF).status_code == 403
        assert _post(c, {SESSION_COOKIE_NAME: SESSION_COOKIE}, SESSION_CSRF).status_code == 200


@pytest.mark.parametrize("name", [HOST_SESSION, SESSION_COOKIE_NAME])
def test_https_session_cookie_new_and_old_name_accepted(name: str) -> None:
    # The unprefixed session name is still read on https for one release (migration).
    with _https_client() as c:
        assert _post(c, {name: SESSION_COOKIE}, SESSION_CSRF).status_code == 200
        token = c.get("/ui/token", headers=_cookie_header({name: SESSION_COOKIE})).json()
        assert token == {"token": SESSION_CSRF}


def test_https_prefixed_session_cookie_wins_over_old_name() -> None:
    other = sign_session_token(new_session_token(), SECRET)
    with _https_client() as c:
        cookies = {SESSION_COOKIE_NAME: other, HOST_SESSION: SESSION_COOKIE}
        assert _post(c, cookies, SESSION_CSRF).status_code == 200


# (age as a function of (limit, skew), accepted)
AGES: list[tuple[str, Any, bool]] = [
    ("fresh", lambda limit, skew: 0, True),
    ("one-minute", lambda limit, skew: 60, True),
    ("at-limit", lambda limit, skew: limit, True),
    ("past-limit", lambda limit, skew: limit + 1, False),
    ("thirty-days", lambda limit, skew: 30 * 24 * 3600, False),
    ("future-within-skew", lambda limit, skew: -skew, True),
    ("future-past-skew", lambda limit, skew: -skew - 1, False),
]


@pytest.mark.parametrize(("age_of", "accepted"), [a[1:] for a in AGES], ids=[a[0] for a in AGES])
def test_double_submit_token_age(age_of: Any, accepted: bool) -> None:
    age = age_of(csrf.DOUBLE_SUBMIT_MAX_AGE_SECONDS, csrf.DOUBLE_SUBMIT_MAX_SKEW_SECONDS)
    token = new_double_submit_token(SECRET, now=T0)
    assert valid_double_submit_cookie(token, SECRET, now=T0 + age) is accepted


@pytest.mark.parametrize("base_url", ["http://localhost:8000", HTTPS])
def test_expired_double_submit_token_is_refused_403(
    base_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = new_double_submit_token(SECRET, now=T0)
    name = HOST_CSRF if base_url == HTTPS else CSRF_COOKIE_NAME
    with TestClient(_app(_settings(base_url)), base_url=base_url) as c:
        monkeypatch.setattr(csrf, "_clock", lambda: T0 + 60)
        assert _post(c, {name: token}, token).status_code == 200
        monkeypatch.setattr(csrf, "_clock", lambda: T0 + csrf.DOUBLE_SUBMIT_MAX_AGE_SECONDS + 1)
        response = _post(c, {name: token}, token)
        assert response.status_code == 403
        assert response.json() == {"detail": t("csrf.invalid", "en")}
        assert token not in response.text


def test_helper_replaces_an_expiring_double_submit_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    token = new_double_submit_token(SECRET, now=T0)
    with TestClient(_app()) as c:
        monkeypatch.setattr(csrf, "_clock", lambda: T0 + 60)
        reused = c.get("/ui/token", headers=_cookie_header({CSRF_COOKIE_NAME: token})).json()
        assert reused == {"token": token}
        late = T0 + csrf.DOUBLE_SUBMIT_MAX_AGE_SECONDS - 1
        monkeypatch.setattr(csrf, "_clock", lambda: late)
        response = c.get("/ui/token", headers=_cookie_header({CSRF_COOKIE_NAME: token}))
        fresh = response.json()["token"]
        assert fresh != token
        assert response.headers["set-cookie"].startswith(f"{CSRF_COOKIE_NAME}={fresh};")
        # a freshly rendered form always has at least half the limit left
        later = late + csrf.DOUBLE_SUBMIT_MAX_AGE_SECONDS // 2
        assert valid_double_submit_cookie(fresh, SECRET, now=later)


def _tampered_times(token: str) -> list[str]:
    nonce, issued, mac = token.split(".")
    return [
        f"{nonce}.{int(issued) + 3600}.{mac}",
        f"{nonce}.{int(issued) - 1}.{mac}",
        f"{nonce}.0{issued}.{mac}",
        f"{nonce}..{mac}",
        f"{nonce}.{issued}x.{mac}",
        f"{nonce}.-{issued}.{mac}",
        f"{nonce}.+{issued}.{mac}",
        f"{nonce}.{'1' * 40}.{mac}",
        f"{nonce}.{chr(0x0661) * len(issued)}.{mac}",  # non-ASCII digits
        f"{nonce}.{issued}.{mac}.{issued}",
        f"{nonce}.{mac}",  # pre-R1-15 format (no issue time)
    ]


@pytest.mark.parametrize("index", range(11))
def test_tampered_timestamp_refused(index: int) -> None:
    token = new_double_submit_token(SECRET, now=T0)
    assert valid_double_submit_cookie(token, SECRET, now=T0) is True
    bad = _tampered_times(token)[index]
    assert valid_double_submit_cookie(bad, SECRET, now=T0) is False
    assert check_token(bad, {CSRF_COOKIE_NAME: bad}, SECRET, now=T0) is False
