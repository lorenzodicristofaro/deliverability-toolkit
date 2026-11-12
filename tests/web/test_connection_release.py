"""R1-02 (AUTH-01): no pooled DB connection is held while a route awaits DNS or reads a body.

The authentication dependency ends its transaction once the `AuthSession` is built, so a route
holds a connection only while it queries. Each route below awaits slow work (DNS with a 20 s
deadline, or a body of several MiB); a spy replaces the awaited function and records
`engine.pool.checkedout()` from inside it. The concurrency test parks 20 slow DNS lookups (a
fake resolver that waits on an event) and checks that `/healthz`, a login and an authenticated
page still answer meanwhile. Coordination is by events and counters, never by wall-clock time.
No network: the DNS backend is the fake of tests/support/dns_backend.py.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx2
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.pool import QueuePool

from app.api.v1 import dns_tools as api_dns
from app.api.v1 import message as api_message
from app.api.v1.dns_tools import dns_backend
from app.core.config import Settings
from app.core.csrf import CSRF_HEADER, session_csrf_token
from app.core.db import create_db_engine, create_session_factory
from app.core.security import SESSION_COOKIE_NAME, hash_password, unsign_session_token
from app.main import create_app
from app.models import User
from app.web import authentication as web_auth
from app.web import dns_tools as web_dns
from app.web import message as web_message
from tests.api.test_domains import KEY, World, _cookie, _seed, call
from tests.support.dns_backend import fake_backend

PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
FORM = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"}
MESSAGE = "From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
CONCURRENT = 20


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    analyst = db.scalars(select(User).where(User.id == users["analyst"])).one()
    analyst.password_hash = hash_password(PASSWORD, FAST)
    db.commit()
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    backend, _ = fake_backend()
    application.dependency_overrides[dns_backend] = lambda: backend
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def app_engine(w: World) -> Engine:
    engine = w.client.app.state.db_engine  # type: ignore[attr-defined]
    assert isinstance(engine, Engine)
    return engine


def spy(monkeypatch: pytest.MonkeyPatch, w: World, target: Any, name: str, seen: list[int]) -> None:
    """Replace `target.name` by a wrapper that records `checkedout()` from inside the call."""
    original: Callable[..., Any] = getattr(target, name)
    if inspect.iscoroutinefunction(original):

        async def wrapper_async(*args: Any, **kwargs: Any) -> Any:
            seen.append(app_engine(w).pool.checkedout())  # type: ignore[attr-defined]
            return await original(*args, **kwargs)

        monkeypatch.setattr(target, name, wrapper_async)
    else:

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            seen.append(app_engine(w).pool.checkedout())  # type: ignore[attr-defined]
            return original(*args, **kwargs)

        monkeypatch.setattr(target, name, wrapper)


@dataclass(frozen=True)
class Route:
    method: str
    path: str  # "{assigned}" is replaced by the id of the assigned domain
    spies: tuple[tuple[Any, str], ...]
    body: dict[str, Any] | None = None  # JSON body
    form: dict[str, str] | None = None  # urlencoded form
    raw: tuple[str, str] | None = None  # (content type, text)


NAME_A = {"name": "example.com", "type": "A"}
ROUTES: dict[str, Route] = {
    "web authentication tab": Route(
        "GET", "/domains/{assigned}/authentication", ((web_auth, "run_checks"),)
    ),
    "web dns lookup": Route(
        "POST", "/tools/dns/lookup", ((web_dns, "read_form"), (web_dns, "lookup")), form=NAME_A
    ),
    "web dns reverse": Route(
        "POST",
        "/tools/dns/reverse",
        ((web_dns, "read_form"), (web_dns, "reverse")),
        form={"ip": "192.0.2.10"},
    ),
    "web dns trace": Route(
        "POST", "/tools/dns/trace", ((web_dns, "read_form"), (web_dns, "trace")), form=NAME_A
    ),
    "web dns propagation": Route(
        "POST",
        "/tools/dns/propagation",
        ((web_dns, "read_form"), (web_dns, "check_propagation")),
        form=NAME_A,
    ),
    "api dns lookup": Route("POST", "/api/v1/dns/lookup", ((api_dns, "lookup"),), body=NAME_A),
    "api dns reverse": Route(
        "POST", "/api/v1/dns/reverse", ((api_dns, "reverse"),), body={"ip": "192.0.2.10"}
    ),
    "api dns trace": Route("POST", "/api/v1/dns/trace", ((api_dns, "trace"),), body=NAME_A),
    "api dns propagation": Route(
        "POST",
        "/api/v1/dns/propagation",
        ((api_dns, "check_propagation"),),
        body={**NAME_A, "resolver_ids": ["google", "quad9"]},
    ),
    "web message analyzer": Route(
        "POST",
        "/tools/message",
        ((web_message, "_read_capped"), (web_message, "analyze_message")),
        form={"raw": MESSAGE},
    ),
    "api message analyzer": Route(
        "POST",
        "/api/v1/message/analyze",
        ((api_message, "_read_capped"), (api_message, "analyze_message")),
        raw=("message/rfc822", MESSAGE),
    ),
}


def send(w: World, route: Route) -> Any:
    path = route.path.format(assigned=w.domains["assigned"])
    if route.form is not None:
        content = urlencode(route.form).encode()
        return call(w, "owner", route.method, path, content=content, headers=dict(FORM))
    if route.raw is not None:
        headers = {"Content-Type": route.raw[0]}
        return call(w, "owner", route.method, path, content=route.raw[1].encode(), headers=headers)
    if route.method == "GET":
        return call(w, "owner", "GET", path, headers={"Accept": "text/html"})
    return call(w, "owner", route.method, path, json=route.body)


def test_pool_is_the_default_queue_pool(world: World) -> None:
    """The exhaustion scenario of AUTH-01 rests on these defaults (5 + 10 overflow, 30 s)."""
    assert world.client.get("/healthz").status_code == 200
    call(world, "owner", "GET", "/tools/dns", headers={"Accept": "text/html"})
    pool = app_engine(world).pool
    assert isinstance(pool, QueuePool)
    assert (pool.size(), pool._max_overflow, pool.timeout()) == (5, 10, 30)


@pytest.mark.parametrize("name", list(ROUTES))
def test_no_connection_is_checked_out_during_the_awaited_call(
    world: World, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    route = ROUTES[name]
    seen: dict[str, list[int]] = {}
    for target, attr in route.spies:
        seen[attr] = []
        spy(monkeypatch, world, target, attr, seen[attr])
    r = send(world, route)
    assert r.status_code == 200, r.text[:300]
    assert all(seen.values()), f"spy not reached: {seen}"
    assert seen == {attr: [0] * len(v) for attr, v in seen.items()}


# --- concurrency --------------------------------------------------------------------------------


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, html[:300]
    return match.group(1)


async def test_slow_dns_requests_do_not_block_health_and_login(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """20 lookups parked inside a slow (fake) resolver: more than the pool's 15 connections.
    /healthz, a login and an authenticated page must answer while they wait."""
    entered = 0
    all_in = asyncio.Event()
    release = asyncio.Event()
    original = api_dns.lookup

    async def slow_lookup(*args: Any, **kwargs: Any) -> Any:
        nonlocal entered
        entered += 1
        if entered == CONCURRENT:
            all_in.set()
        await release.wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(api_dns, "lookup", slow_lookup)
    app = world.client.app
    transport = httpx2.ASGITransport(app=app)  # type: ignore[arg-type]
    base = "http://testserver"

    cookie, csrf = _api_session(world)

    async def slow_request() -> int:
        async with httpx2.AsyncClient(transport=transport, base_url=base) as client:
            client.cookies.set(SESSION_COOKIE_NAME, cookie)
            r = await client.post("/api/v1/dns/lookup", json=NAME_A, headers={CSRF_HEADER: csrf})
            return r.status_code

    slow = [asyncio.create_task(slow_request()) for _ in range(CONCURRENT)]
    waiter = asyncio.create_task(all_in.wait())
    done, _ = await asyncio.wait({waiter, *slow}, return_when=asyncio.FIRST_COMPLETED)
    if waiter not in done:  # a request ended before release: a pool timeout or the deadline
        started = entered
        release.set()
        results = await asyncio.gather(*slow, return_exceptions=True)
        pytest.fail(f"{started} of {CONCURRENT} lookups started before one ended: {results}")
    try:
        assert app_engine(world).pool.checkedout() == 0  # type: ignore[attr-defined]
        async with httpx2.AsyncClient(transport=transport, base_url=base) as client:
            assert (await client.get("/healthz")).status_code == 200
            token = _csrf((await client.get("/login")).text)
            login = await client.post(
                "/login",
                data={"email": "analyst@example.com", "password": PASSWORD, "csrf_token": token},
                follow_redirects=False,
            )
            assert login.status_code == 303, login.text[:300]
            assert SESSION_COOKIE_NAME in login.cookies
            page = await client.get("/tools/dns", headers={"Accept": "text/html"})
            assert page.status_code == 200
        assert entered == CONCURRENT and not any(task.done() for task in slow)
    finally:
        release.set()
        statuses = await asyncio.gather(*slow, return_exceptions=True)
    assert statuses == [200] * CONCURRENT


def _api_session(w: World) -> tuple[str, str]:
    """A session cookie and its CSRF token for the tenant A owner (reused across requests)."""
    cookie = _cookie(w, "owner", "a")
    token = unsign_session_token(cookie, w.settings.secret_key)
    assert token is not None
    return cookie, session_csrf_token(token, w.settings.secret_key)
