"""M1-15 login, logout, tenant switch and auth dependencies, through the real app and middleware.

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `migrated_db_url`
fixture); the schema is built by Alembic. A fast argon2 hasher keeps the suite quick. No network.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import pytest
from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from jinja2 import ChoiceLoader, DictLoader
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.permissions import Action, InstanceResource, Principal
from app.core.security import SESSION_COOKIE_NAME, hash_password, unsign_session_token
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import Membership, MembershipRole, Tenant, User, UserSession
from app.repositories import repo_for
from app.services.login_throttle import LoginThrottle
from app.web import auth as web_auth
from app.web.deps import DbDep, current_principal, require, tenant_ctx
from app.web.templating import env, render

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
PAGE = "t_auth_page.html"
HTTPS_BASE = "https://dt.example.test"
HOST_SESSION = "__Host-dt_session"
HOST_CSRF = "__Host-dt_csrf"


class Clock:
    def __init__(self) -> None:
        self.now = 5000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class World:
    client: TestClient
    app: FastAPI
    db: Session
    clock: Clock
    tenant_a: int
    tenant_b: int
    users: dict[str, int]


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


def _seed(db: Session) -> tuple[int, int, dict[str, int]]:
    a = Tenant(name="Agency A", slug="agency-a")
    b = Tenant(name="Agency B", slug="agency-b")
    pw = hash_password(PASSWORD, FAST)
    users = {
        "alice": User(email="alice@example.com", password_hash=pw),  # owner of A only
        "bob": User(email="bob@example.com", password_hash=pw),  # analyst of A
        "carol": User(email="carol@example.com", password_hash=pw),  # A (admin) and B (owner)
        "dave": User(email="dave@example.com", password_hash=pw, is_active=False),  # A, inactive
        "erin": User(email="erin@example.com", password_hash=pw),  # no memberships
        "root": User(email="root@example.com", password_hash=pw, is_instance_admin=True),
        "nopw": User(email="nopw@example.com"),
    }
    db.add_all([a, b, *users.values()])
    db.flush()
    db.add_all(
        [
            Membership(user_id=users["alice"].id, tenant_id=a.id, role=MembershipRole.OWNER),
            Membership(user_id=users["bob"].id, tenant_id=a.id, role=MembershipRole.ANALYST),
            Membership(user_id=users["carol"].id, tenant_id=a.id, role=MembershipRole.ADMIN),
            Membership(user_id=users["carol"].id, tenant_id=b.id, role=MembershipRole.OWNER),
            Membership(user_id=users["dave"].id, tenant_id=a.id, role=MembershipRole.OWNER),
        ]
    )
    db.commit()
    return a.id, b.id, {name: u.id for name, u in users.items()}


def _add_test_routes(application: FastAPI) -> None:
    @application.get("/t/whoami")
    def whoami(principal: Annotated[Principal, Depends(current_principal)]) -> dict[str, Any]:
        return {"user_id": principal.user_id, "tenant": principal.active_tenant_id}

    @application.get("/t/tenant")
    def tenant(ctx: Annotated[TenantContext, Depends(tenant_ctx)], db: DbDep) -> dict[str, Any]:
        row = repo_for(ctx, db).tenant.get()
        return {"tenant_id": ctx.tenant_id, "name": None if row is None else row.name}

    @application.get("/t/manage")
    def manage(_p: Annotated[Principal, Depends(require(Action.TENANT_MANAGE))]) -> str:
        return "ok"

    @application.get("/t/read")
    def read(_p: Annotated[Principal, Depends(require(Action.TENANT_READ))]) -> str:
        return "ok"

    @application.get("/t/instance")
    def instance(
        _p: Annotated[Principal, Depends(require(Action.INSTANCE_MANAGE, InstanceResource()))],
    ) -> str:
        return "ok"

    @application.get("/t/page", response_class=HTMLResponse)
    def page(request: Request) -> HTMLResponse:
        return render(request, PAGE, logged_in=True)


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    yield from _make_world(migrated_db_url, monkeypatch, "http://localhost:8000")


@pytest.fixture
def https_world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    yield from _make_world(migrated_db_url, monkeypatch, HTTPS_BASE)


def _make_world(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, base_url: str
) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setattr(web_auth, "PASSWORD_HASHER", FAST)
    original_loader = env.loader
    assert original_loader is not None
    env.loader = ChoiceLoader(
        [
            DictLoader({PAGE: '{% extends "base.html" %}{% block content %}x{% endblock %}'}),
            original_loader,
        ]
    )
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users = _seed(db)
    application = create_app(
        Settings(  # type: ignore[call-arg]
            database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY, base_url=base_url
        )
    )
    _add_test_routes(application)
    clock = Clock()
    application.state.login_throttle = LoginThrottle(clock=clock)
    client_base = "https://testserver" if base_url.startswith("https") else "http://testserver"
    try:
        with TestClient(application, base_url=client_base, raise_server_exceptions=True) as client:
            yield World(client, application, db, clock, tenant_a, tenant_b, users)
    finally:
        env.loader = original_loader
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def _login(
    w: World, email: str, password: str = PASSWORD, next_path: str | None = None, **kw: Any
) -> Any:
    token = _csrf(w.client.get("/login").text)
    data = {"email": email, "password": password, "csrf_token": token}
    if next_path is not None:
        data["next"] = next_path
    return w.client.post("/login", data=data, follow_redirects=False, **kw)


def _session_token(w: World) -> str:
    """The CSRF token of the current (logged-in) page."""
    return _csrf(w.client.get("/t/page").text)


def _sessions(w: World, user: str) -> list[UserSession]:
    w.db.expire_all()
    stmt = select(UserSession).where(UserSession.user_id == w.users[user]).order_by(UserSession.id)
    return list(w.db.scalars(stmt))


def _use_cookie(w: World, value: str) -> None:
    """Replace the jar's session cookie (whatever domain the server set it for)."""
    w.client.cookies.delete(SESSION_COOKIE_NAME)
    w.client.cookies.set(SESSION_COOKIE_NAME, value)


# --- login ----------------------------------------------------------------------------------


def test_login_page_renders_with_double_submit_token(world: World) -> None:
    response = world.client.get("/login", headers={"Accept-Language": "it"})
    assert response.status_code == 200
    assert "Accedi" in response.text
    assert 'action="/login"' in response.text and 'type="password"' in response.text
    assert _csrf(response.text) == world.client.cookies.get("dt_csrf")


def test_login_success_sets_session_cookie(world: World) -> None:
    response = _login(world, "Alice@Example.com", next_path="/t/whoami")
    assert response.status_code == 303
    assert response.headers["location"] == "/t/whoami"
    cookie = response.headers["set-cookie"]
    assert f"{SESSION_COOKIE_NAME}=" in cookie
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
    assert "Max-Age=43200" in cookie  # SESSION_ABSOLUTE_TIMEOUT_MINUTES default 720
    assert "Secure" not in cookie  # BASE_URL is http in this test
    me = world.client.get("/t/whoami").json()
    assert me == {"user_id": world.users["alice"], "tenant": world.tenant_a}
    assert len(_sessions(world, "alice")) == 1


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("alice@example.com", "wrong"),
        ("alice@example.com", ""),
        ("nobody@example.com", PASSWORD),
        ("dave@example.com", PASSWORD),  # inactive user cannot log in
        ("nopw@example.com", ""),
        ("nopw@example.com", PASSWORD),
        ("", ""),
        ("not-an-email", PASSWORD),
        ("@@", PASSWORD),
        ("alice@example.com\x00", PASSWORD),
        ("\x00alice@example.com", PASSWORD),
        ("alice@exa\x00mple.com", PASSWORD),
        ("alice@example.com\x01", PASSWORD),  # other control characters
        ("alice\x1f@example.com", PASSWORD),
        ("alice@example.com\x7f", PASSWORD),
        ("alice@exa\x85mple.com", PASSWORD),
        ("a" * 243 + "@example.com", PASSWORD),  # 255 chars: over the 254 cap
        ("a" * 2000 + "@example.com", PASSWORD),
    ],
)
def test_login_failure_is_generic(world: World, email: str, password: str) -> None:
    response = _login(world, email, password)
    assert response.status_code == 401
    assert "Invalid email or password." in response.text
    assert SESSION_COOKIE_NAME not in response.headers.get("set-cookie", "")
    assert world.client.get("/t/whoami").status_code == 401


def test_failure_pages_do_not_differ_between_known_and_unknown_users(world: World) -> None:
    known = _login(world, "x@example.com", "wrong").text
    unknown = _login(world, "x@example.com", "other").text
    inactive_like = _login(world, "dave@example.com", PASSWORD).text
    assert known == unknown
    assert inactive_like.replace("dave@example.com", "x@example.com") == known


def test_missing_fields_and_bad_bodies(world: World) -> None:
    token = _csrf(world.client.get("/login").text)
    headers = {"X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded"}
    for body in [b"", b"email=&password=", b"\xff\xfe", b"email=a&email=b&password=x"]:
        assert world.client.post("/login", content=body, headers=headers).status_code == 401
    too_big = b"email=a&pad=" + b"a" * 9000
    assert world.client.post("/login", content=too_big, headers=headers).status_code == 413


def test_login_requires_csrf(world: World) -> None:
    world.client.get("/login")
    data = {"email": "alice@example.com", "password": PASSWORD}
    assert world.client.post("/login", data=data).status_code == 403
    assert world.client.post("/login", data={**data, "csrf_token": "x"}).status_code == 403
    assert len(_sessions(world, "alice")) == 0


@pytest.mark.parametrize(
    ("next_path", "expected"),
    [
        ("/t/whoami", "/t/whoami"),
        ("/a?b=c", "/a?b=c"),
        ("https://evil.test/", "/"),
        ("//evil.test", "/"),
        ("/\\evil.test", "/"),
        ("/%2F%2Fevil.test", "/"),
        ("/%5Cevil.test", "/"),
        ("/%252F%252Fevil.test", "/"),
        ("javascript:alert(1)", "/"),
        ("evil.test", "/"),
        ("/a\r\nSet-Cookie: x=y", "/"),
        ("", "/"),
    ],
)
def test_login_redirect_is_local_only(world: World, next_path: str, expected: str) -> None:
    response = _login(world, "alice@example.com", next_path=next_path)
    assert response.status_code == 303
    assert response.headers["location"] == expected


def test_login_page_next_is_sanitised(world: World) -> None:
    html = world.client.get("/login", params={"next": "//evil.test"}).text
    assert 'name="next" value="/"' in html


# --- throttling -----------------------------------------------------------------------------


def test_throttle_backoff_then_lockout(world: World) -> None:
    for _ in range(5):
        assert _login(world, "alice@example.com", "wrong").status_code == 401
    throttled = _login(world, "alice@example.com", PASSWORD)  # even the right password
    assert throttled.status_code == 429
    assert throttled.headers["retry-after"] == "1"
    assert "Too many failed attempts" in throttled.text
    assert len(_sessions(world, "alice")) == 0
    for _ in range(5):
        world.clock.now += 400
        assert _login(world, "alice@example.com", "wrong").status_code == 401
    locked = _login(world, "alice@example.com", PASSWORD)
    assert locked.status_code == 429
    assert locked.headers["retry-after"] == "900"
    world.clock.now += 900
    assert _login(world, "alice@example.com", PASSWORD).status_code == 303


@pytest.mark.parametrize(
    ("email", "shown"),
    [
        ("ghost@example.com", "ghost@example.com"),  # usable input is echoed back
        ("Jos\u00e9@example.com", "Jos\u00e9@example.com"),
        ("ghost@example.com\x00", ""),  # unusable input is not
        ("gh\x01ost@example.com", ""),
        ("g" * 243 + "@example.com", ""),
        ("not-an-email", ""),
    ],
)
def test_failure_pages_echo_only_usable_email(world: World, email: str, shown: str) -> None:
    for _ in range(5):
        failed = _login(world, email, "x")
        assert failed.status_code == 401
        assert f'value="{shown}"' in failed.text
        assert 'maxlength="254"' in failed.text
    throttled = _login(world, email, "x")  # rejected input still counts towards the throttle
    assert throttled.status_code == 429
    assert f'value="{shown}"' in throttled.text
    if not shown:
        assert "\x00" not in throttled.text and "g" * 243 not in throttled.text


def test_throttle_is_per_account_and_unknown_accounts_too(world: World) -> None:
    for _ in range(5):
        _login(world, "ghost@example.com", "x")
    assert _login(world, "ghost@example.com", "x").status_code == 429
    assert _login(world, "alice@example.com", PASSWORD).status_code == 303


def test_success_resets_throttle(world: World) -> None:
    for _ in range(4):
        _login(world, "alice@example.com", "wrong")
    assert _login(world, "alice@example.com", PASSWORD).status_code == 303
    for _ in range(4):
        assert _login(world, "alice@example.com", "wrong").status_code == 401


# --- session rotation -----------------------------------------------------------------------


def test_login_rotates_session_and_csrf_token(world: World) -> None:
    _login(world, "alice@example.com")
    old_cookie = world.client.cookies[SESSION_COOKIE_NAME]
    old_csrf = _session_token(world)
    response = _login(world, "alice@example.com")  # login form posted with the session token
    assert response.status_code == 303
    new_cookie = world.client.cookies[SESSION_COOKIE_NAME]
    assert new_cookie != old_cookie
    new_csrf = _session_token(world)
    assert new_csrf != old_csrf
    rows = _sessions(world, "alice")
    assert [r.revoked_at is not None for r in rows] == [True, False]
    # The old CSRF token is refused with the new session.
    assert world.client.post("/logout", data={"csrf_token": old_csrf}).status_code == 403
    # The old cookie no longer authenticates.
    _use_cookie(world, old_cookie)
    assert world.client.get("/t/whoami").status_code == 401


def test_switch_rotates_session_keeps_absolute_expiry(world: World) -> None:
    _login(world, "carol@example.com")
    old_cookie = world.client.cookies[SESSION_COOKIE_NAME]
    old_csrf = _session_token(world)
    assert world.client.get("/t/tenant").json()["tenant_id"] == world.tenant_a
    response = world.client.post(
        "/tenants/switch",
        data={"tenant_id": str(world.tenant_b), "csrf_token": old_csrf, "next": "/t/tenant"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/t/tenant"
    assert world.client.cookies[SESSION_COOKIE_NAME] != old_cookie
    assert _session_token(world) != old_csrf
    assert world.client.get("/t/tenant").json() == {
        "tenant_id": world.tenant_b,
        "name": "Agency B",
    }
    old, new = _sessions(world, "carol")
    assert old.revoked_at is not None and new.revoked_at is None
    assert new.active_tenant_id == world.tenant_b
    assert new.expires_at == old.expires_at
    _use_cookie(world, old_cookie)
    assert world.client.get("/t/whoami").status_code == 401


# --- logout ---------------------------------------------------------------------------------


def test_logout_revokes_session_and_clears_cookie(world: World) -> None:
    _login(world, "alice@example.com")
    cookie = world.client.cookies[SESSION_COOKIE_NAME]
    response = world.client.post(
        "/logout", data={"csrf_token": _session_token(world)}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert f'{SESSION_COOKIE_NAME}=""' in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert all(r.revoked_at is not None for r in _sessions(world, "alice"))
    _use_cookie(world, cookie)
    assert world.client.get("/t/whoami").status_code == 401


# --- R1-15 (AUTH-10): __Host- cookie names on https -------------------------------------------


def _attrs(set_cookie: str) -> list[str]:
    return [p.strip().lower() for p in set_cookie.split(";")[1:]]


def _host_only_secure(set_cookie: str) -> bool:
    attrs = _attrs(set_cookie)
    return (
        "secure" in attrs and "path=/" in attrs and not any(a.startswith("domain") for a in attrs)
    )


def test_https_login_issues_host_prefixed_cookies(https_world: World) -> None:
    w = https_world
    page = w.client.get("/login")
    token = _csrf(page.text)
    csrf_cookie = page.headers["set-cookie"]
    assert csrf_cookie.startswith(f"{HOST_CSRF}={token};") and _host_only_secure(csrf_cookie)
    response = w.client.post(
        "/login",
        data={"email": "alice@example.com", "password": PASSWORD, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    cookies = response.headers.get_list("set-cookie")
    session = [c for c in cookies if c.startswith(f"{HOST_SESSION}=")]
    assert len(session) == 1 and _host_only_secure(session[0])
    assert not any(
        c.startswith(f"{SESSION_COOKIE_NAME}=") and "max-age=0" not in c.lower() for c in cookies
    )
    assert w.client.get("/t/whoami").json()["user_id"] == w.users["alice"]


def test_https_old_session_cookie_name_still_accepted(https_world: World) -> None:
    w = https_world
    _login(w, "alice@example.com")
    value = w.client.cookies[HOST_SESSION]
    w.client.cookies.delete(HOST_SESSION)
    _use_cookie(w, value)  # the pre-R1-15 name, as a browser upgraded mid-session holds it
    assert w.client.get("/t/whoami").json()["user_id"] == w.users["alice"]
    response = w.client.post(
        "/logout", data={"csrf_token": _session_token(w)}, follow_redirects=False
    )
    assert response.status_code == 303
    cleared = response.headers.get_list("set-cookie")
    for name in (HOST_SESSION, SESSION_COOKIE_NAME):
        assert any(c.startswith(f'{name}=""') and "Max-Age=0" in c for c in cleared)
    assert all(r.revoked_at is not None for r in _sessions(w, "alice"))


def test_https_login_over_old_name_moves_to_new_name(https_world: World) -> None:
    w = https_world
    _login(w, "alice@example.com")
    value = w.client.cookies[HOST_SESSION]
    w.client.cookies.delete(HOST_SESSION)
    _use_cookie(w, value)
    response = _login(w, "carol@example.com")
    assert response.status_code == 303
    cookies = response.headers.get_list("set-cookie")
    assert any(c.startswith(f"{HOST_SESSION}=") for c in cookies)
    assert any(c.startswith(f'{SESSION_COOKIE_NAME}=""') and "Max-Age=0" in c for c in cookies)
    # the presented old-name session was rotated out (revoked) by the new login
    assert all(r.revoked_at is not None for r in _sessions(w, "alice"))


def test_http_login_keeps_current_cookie_names(world: World) -> None:
    page = world.client.get("/login")
    assert page.headers["set-cookie"].startswith("dt_csrf=")
    response = _login(world, "alice@example.com")
    cookies = response.headers.get_list("set-cookie")
    assert [c.split("=", 1)[0] for c in cookies] == [SESSION_COOKIE_NAME]


def test_logout_requires_csrf(world: World) -> None:
    _login(world, "alice@example.com")
    assert world.client.post("/logout").status_code == 403
    assert world.client.post("/logout", data={"csrf_token": "x"}).status_code == 403
    assert all(r.revoked_at is None for r in _sessions(world, "alice"))


def test_logout_anonymous_is_denied(world: World) -> None:
    token = _csrf(world.client.get("/login").text)  # valid double-submit token
    response = world.client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 401


def test_logout_form_in_base_is_a_post_with_csrf(world: World) -> None:
    _login(world, "alice@example.com")
    html = world.client.get("/t/page").text
    assert '<form class="logout" method="post" action="/logout">' in html
    assert 'href="/logout"' not in html
    form = html.split('action="/logout">', 1)[1].split("</form>", 1)[0]
    assert f'name="csrf_token" value="{_session_token(world)}"' in form
    assert "Log out" in form


# --- dependencies ---------------------------------------------------------------------------


@pytest.mark.parametrize(("lang", "detail"), [("en", "Please log in"), ("it", "Accedi per")])
def test_anonymous_api_gets_401(world: World, lang: str, detail: str) -> None:
    for path in ["/t/whoami", "/t/tenant", "/t/manage", "/t/instance"]:
        response = world.client.get(path, headers={"Accept-Language": lang})
        assert response.status_code == 401
        assert response.json()["detail"].startswith(detail)


def test_anonymous_browser_is_redirected_to_login(world: World) -> None:
    response = world.client.get(
        "/t/whoami?x=1", headers={"Accept": "text/html"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Ft%2Fwhoami%3Fx%3D1"


@pytest.mark.parametrize(
    "cookie",
    ["", "garbage", "a" * 87, "x.y", f"{'a' * 43}.{'b' * 43}"],
)
def test_malformed_session_cookie_is_anonymous(world: World, cookie: str) -> None:
    _use_cookie(world, cookie)
    assert world.client.get("/t/whoami").status_code == 401


def test_deactivated_user_loses_session(world: World) -> None:
    _login(world, "alice@example.com")
    assert world.client.get("/t/whoami").status_code == 200
    user = world.db.get(User, world.users["alice"])
    assert user is not None
    user.is_active = False
    world.db.commit()
    assert world.client.get("/t/whoami").status_code == 401


def test_user_without_membership_has_no_tenant_context(world: World) -> None:
    _login(world, "erin@example.com")
    assert world.client.get("/t/whoami").json()["tenant"] is None
    assert world.client.get("/t/tenant").status_code == 404
    assert world.client.get("/t/read").status_code == 404


def _set_active_tenant(w: World, user: str, tenant_id: int) -> None:
    for row in _sessions(w, user):
        row.active_tenant_id = tenant_id
    w.db.commit()


def test_foreign_active_tenant_in_session_fails_closed(world: World) -> None:
    _login(world, "alice@example.com")
    _set_active_tenant(world, "alice", world.tenant_b)  # tampered/stale: no membership in B
    assert world.client.get("/t/whoami").json()["tenant"] is None
    assert world.client.get("/t/tenant").status_code == 404
    assert world.client.get("/t/read").status_code == 404


def test_removed_membership_fails_closed(world: World) -> None:
    _login(world, "alice@example.com")
    assert world.client.get("/t/tenant").status_code == 200
    membership = world.db.scalars(
        select(Membership).where(Membership.user_id == world.users["alice"])
    ).one()
    world.db.delete(membership)
    world.db.commit()
    assert world.client.get("/t/tenant").status_code == 404
    assert world.client.get("/t/manage").status_code == 404


@pytest.mark.parametrize(
    ("user", "path", "status"),
    [
        ("alice", "/t/manage", 200),  # owner
        ("alice", "/t/read", 200),
        ("bob", "/t/manage", 404),  # analyst: no tenant.manage
        ("bob", "/t/read", 200),
        ("carol", "/t/manage", 404),  # admin of A: no tenant.manage
        ("root", "/t/instance", 200),  # instance admin flag
        ("root", "/t/read", 404),  # ...grants no tenant access
        ("alice", "/t/instance", 404),
    ],
)
def test_require_uses_can(world: World, user: str, path: str, status: int) -> None:
    _login(world, f"{user}@example.com")
    assert world.client.get(path).status_code == status


# --- tenant switch --------------------------------------------------------------------------


def _switch(w: World, tenant_id: str, token: str | None = None) -> Any:
    data = {"tenant_id": tenant_id, "csrf_token": token or _session_token(w)}
    return w.client.post("/tenants/switch", data=data, follow_redirects=False)


def test_user_of_tenant_a_cannot_switch_to_tenant_b(world: World) -> None:
    _login(world, "alice@example.com")
    cookie = world.client.cookies[SESSION_COOKIE_NAME]
    response = _switch(world, str(world.tenant_b))
    assert response.status_code == 404
    assert response.json()["detail"] == "Tenant not found."
    assert world.client.cookies[SESSION_COOKIE_NAME] == cookie
    assert world.client.get("/t/tenant").json()["tenant_id"] == world.tenant_a
    rows = _sessions(world, "alice")
    assert len(rows) == 1 and rows[0].revoked_at is None


def test_switch_denied_browser_gets_translated_404_page(world: World) -> None:
    _login(world, "alice@example.com")
    response = world.client.post(
        "/tenants/switch",
        data={"tenant_id": str(world.tenant_b), "csrf_token": _session_token(world)},
        headers={"Accept": "text/html", "Accept-Language": "it"},
    )
    assert response.status_code == 404
    assert "Pagina non trovata" in response.text


@pytest.mark.parametrize(
    "tenant_id", ["", "0", "-1", "abc", "1.5", " 1", "１", "9" * 30, "99999", "1e3", "0x1"]
)
def test_switch_malformed_or_unknown_tenant(world: World, tenant_id: str) -> None:
    _login(world, "carol@example.com")
    assert _switch(world, tenant_id).status_code == 404
    assert world.client.get("/t/tenant").json()["tenant_id"] == world.tenant_a


def test_switch_losing_a_concurrent_revoke_creates_no_session(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login(world, "carol@example.com")
    token = _session_token(world)
    cookie = world.client.cookies[SESSION_COOKIE_NAME]
    real_revoke = web_auth.revoke_session

    def raced(db: Session, session_id: object, **kw: Any) -> bool:
        real_revoke(db, session_id, **kw)  # the concurrent request revoked it first
        return bool(real_revoke(db, session_id, **kw))  # ...so this request's revoke finds none

    monkeypatch.setattr(web_auth, "revoke_session", raced)
    assert _switch(world, str(world.tenant_b), token).status_code == 404
    assert world.client.cookies[SESSION_COOKIE_NAME] == cookie
    rows = _sessions(world, "carol")
    assert len(rows) == 1  # no new session was issued
    assert rows[0].revoked_at is None  # rolled back: the race simulation left nothing behind


def test_switch_anonymous_is_denied(world: World) -> None:
    token = _csrf(world.client.get("/login").text)
    response = world.client.post(
        "/tenants/switch", data={"tenant_id": str(world.tenant_a), "csrf_token": token}
    )
    assert response.status_code == 401


def test_switch_requires_csrf(world: World) -> None:
    _login(world, "carol@example.com")
    response = world.client.post("/tenants/switch", data={"tenant_id": str(world.tenant_b)})
    assert response.status_code == 403
    assert world.client.get("/t/tenant").json()["tenant_id"] == world.tenant_a


def test_switch_body_too_large(world: World) -> None:
    _login(world, "carol@example.com")
    token = _session_token(world)
    response = world.client.post(
        "/tenants/switch",
        content=b"tenant_id=1&pad=" + b"a" * 9000,
        headers={"X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413


def test_switch_never_extends_expired_session(world: World) -> None:
    _login(world, "carol@example.com")
    token = _session_token(world)
    (row,) = _sessions(world, "carol")
    row.expires_at = datetime.now(UTC) + timedelta(seconds=120)
    world.db.commit()
    response = _switch(world, str(world.tenant_b), token)
    assert response.status_code == 303
    max_age = int(re.search(r"Max-Age=(\d+)", response.headers["set-cookie"]).group(1))  # type: ignore[union-attr]
    assert 0 < max_age <= 120


# --- logging --------------------------------------------------------------------------------


def test_logs_contain_no_credentials(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    _login(world, "alice@example.com", "wrong-password-xyz")
    _login(world, "alice@example.com")
    cookie = world.client.cookies[SESSION_COOKIE_NAME]
    token = unsign_session_token(cookie, Settings(secret_key=KEY, encryption_key=KEY).secret_key)  # type: ignore[call-arg]
    assert token is not None
    _switch(world, str(world.tenant_b))
    world.client.post("/logout", data={"csrf_token": _session_token(world)})
    text = "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert "login failed" in text and "login succeeded" in text
    for secret in [PASSWORD, "wrong-password-xyz", "alice@example.com", cookie, token]:
        assert secret not in text
