"""M3-16 DKIM SSE stream: tenancy/permissions through the real app, event order and content,
disconnect cancellation, the deadline, DNS-failure rows and HTML escaping. Fake resolver only:
no network. The generated tenancy matrix (tests/tenancy/test_matrix.py) also covers both routes.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterator
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.dns_tools import dns_backend
from app.checks.dkim_selectors import list_selectors
from app.checks.models import CheckContext
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.dns.types import DnsQuestion, DnsResult
from app.main import create_app
from app.models import Membership
from app.web.checks_stream import dkim_events, sse
from tests.api.test_domains import B_SECRET_NAME, KEY, ROOT, World, _seed, call
from tests.support.dns_backend import fake_backend

SELECTORS = [s.name for s in list_selectors()]
HOSTILE = 'v=DKIM1; k=rsa; p="><script>alert(1)</script><img src=x onerror=alert(2)>'
HOSTILE_SELECTOR_NAME = "<b>evil</b>"


def _zone(domain: str) -> list[dict[str, Any]]:
    return [
        {"name": domain, "type": "TXT", "ttl": 300, "rdata": ["v=spf1 -all"]},
        {
            "name": f"default._domainkey.{domain}",
            "type": "TXT",
            "ttl": 300,
            "rdata": [HOSTILE],
        },
        {"name": f"google._domainkey.{domain}", "type": "TXT", "state": "servfail", "rcode": 2},
        {"name": f"k1._domainkey.{domain}", "type": "TXT", "state": "timeout"},
    ]


ZONES: dict[str, list[dict[str, Any]]] = {
    "default": [*_zone("assigned.example"), *_zone("unassigned.example"), *_zone("example.com")]
}
ACCEPT = {"Accept": "text/event-stream"}
HTML = {"Accept": "text/html"}


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    backend, _ = fake_backend(ZONES)
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


def dpath(world: World, which: str) -> str:
    return f"/domains/{world.domains[which]}/authentication/dkim/stream"


FREE = "/tools/dkim/stream?name=example.com"


def parse(body: str) -> list[tuple[str, str]]:
    """(event, data) pairs of an SSE body; multi-line data is joined with newlines."""
    frames = []
    for block in body.strip().split("\n\n"):
        event, data = "", []
        for line in block.split("\n"):
            if line.startswith("event: "):
                event = line[len("event: ") :]
            elif line.startswith("data: "):
                data.append(line[len("data: ") :])
            else:
                raise AssertionError(f"unexpected SSE line {line!r}")
        frames.append((event, "\n".join(data)))
    return frames


def get(world: World, who: str, path: str, **kw: Any) -> Any:
    return call(world, who, "GET", path, headers=kw.pop("headers", ACCEPT), **kw)


def browse(world: World, path: str) -> Any:
    """Anonymous browser navigation: the 303 to /login is not followed."""
    world.client.cookies.clear()
    return world.client.get(path, headers=HTML, follow_redirects=False)


def set_toggles(world: World, user: str, toggles: dict[str, bool]) -> None:
    membership = world.db.scalars(
        select(Membership).where(Membership.user_id == world.users[user])
    ).one()
    membership.feature_toggles = toggles
    world.db.commit()


# --- tenancy and permissions: domain route ------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_assigned_domain_streams_for_every_role(world: World, who: str) -> None:
    r = get(world, who, dpath(world, "assigned"))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")


@pytest.mark.parametrize(("who", "status"), [("owner", 200), ("analyst", 200), ("viewer", 404)])
def test_unassigned_domain(world: World, who: str, status: int) -> None:
    r = get(world, who, dpath(world, "unassigned"))
    assert r.status_code == status
    if status == 404:
        assert "event:" not in r.text


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_tenant_a_cannot_stream_tenant_b_domain(world: World, who: str) -> None:
    r = get(world, who, dpath(world, "other"))
    assert r.status_code == 404
    assert B_SECRET_NAME not in r.text and "event:" not in r.text


def test_foreign_active_tenant_is_404(world: World) -> None:
    assert get(world, "analyst", dpath(world, "assigned"), tenant="b").status_code == 404


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_check_run_toggle_false_denies(world: World, who: str) -> None:
    set_toggles(world, who, {"check.run": False})
    r = get(world, who, dpath(world, "assigned"))
    assert r.status_code == 403
    assert "event:" not in r.text


def test_toggle_false_on_unassigned_viewer_is_still_404(world: World) -> None:
    set_toggles(world, "viewer", {"check.run": False})
    assert get(world, "viewer", dpath(world, "unassigned")).status_code == 404


@pytest.mark.parametrize("domain_id", ["999999", "abc", "-1", "1" * 40])
def test_unknown_or_malformed_domain_id_is_404(world: World, domain_id: str) -> None:
    r = get(world, "owner", f"/domains/{domain_id}/authentication/dkim/stream")
    assert r.status_code == 404


def test_anonymous(world: World) -> None:
    assert get(world, "anon", dpath(world, "assigned")).status_code == 401
    r = browse(world, dpath(world, "assigned"))
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")


# --- tenancy and permissions: free route --------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "status"), [("owner", 200), ("admin", 200), ("analyst", 200), ("viewer", 403)]
)
def test_free_route_roles(world: World, who: str, status: int) -> None:
    r = get(world, who, FREE)
    assert r.status_code == status
    if status == 403:
        assert "event:" not in r.text


def test_free_route_toggle_denies_and_foreign_tenant_404(world: World) -> None:
    assert get(world, "analyst", FREE, tenant="b").status_code == 404
    set_toggles(world, "analyst", {"dns.tools": False})
    assert get(world, "analyst", FREE).status_code == 403


def test_free_route_anonymous(world: World) -> None:
    assert get(world, "anon", FREE).status_code == 401
    assert browse(world, FREE).status_code == 303


@pytest.mark.parametrize(
    "query", ["", "?name=", "?name=not%20a%20domain", "?name=a..b", "?name=%00"]
)
def test_free_route_invalid_name_is_422(world: World, query: str) -> None:
    r = get(world, "owner", f"/tools/dkim/stream{query}")
    assert r.status_code == 422
    assert "event:" not in r.text


def test_free_route_denied_before_name_validation(world: World) -> None:
    assert get(world, "viewer", "/tools/dkim/stream?name=").status_code == 403


# --- stream content -----------------------------------------------------------------------------


def test_headers(world: World) -> None:
    r = get(world, "owner", dpath(world, "assigned"))
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-accel-buffering"] == "no"
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert "<script" not in r.text.replace("&lt;script", "")


def test_one_event_per_selector_then_done(world: World) -> None:
    frames = parse(get(world, "analyst", dpath(world, "assigned")).text)
    assert [e for e, _ in frames[:-1]] == ["selector"] * len(SELECTORS)
    assert frames[-1][0] == "done"
    seen = re.findall(r'data-selector="([^"]*)"', "\n".join(d for _, d in frames[:-1]))
    assert sorted(seen) == sorted(SELECTORS)


def test_dns_failures_are_error_rows_never_not_found(world: World) -> None:
    frames = parse(get(world, "analyst", dpath(world, "assigned")).text)
    rows = {
        m.group(1): m.group(2)
        for _, d in frames[:-1]
        if (m := re.search(r'data-selector="([^"]*)" data-state="([^"]*)"', d))
    }
    assert rows["google"] == "error" and rows["k1"] == "error"
    assert rows["default"] == "found"
    assert rows["mail"] == "not_found"
    done = frames[-1][1]
    assert 'data-code="DKIM_PROBE_ERRORS"' in done
    assert t("checks.dkim.not_enumerable", "en") in frames[0][1]


def test_states_equal_the_rest_check(world: World) -> None:
    streamed = parse(get(world, "analyst", dpath(world, "assigned")).text)[:-1]
    stream_states = {
        m.group(1): m.group(2)
        for _, d in streamed
        if (m := re.search(r'data-selector="([^"]*)" data-state="([^"]*)"', d))
    }
    rest = call(
        world,
        "analyst",
        "POST",
        f"/api/v1/domains/{world.domains['assigned']}/checks/dkim",
    )
    assert rest.status_code == 200
    assert stream_states == {s["selector"]: s["state"] for s in rest.json()["data"]["selectors"]}
    done = parse(get(world, "analyst", dpath(world, "assigned")).text)[-1][1]
    rest_codes = {f["code"] for f in rest.json()["findings"]}
    assert set(re.findall(r'data-code="([A-Z_]+)"', done)) == rest_codes


def test_hostile_txt_is_escaped(world: World) -> None:
    body = get(world, "analyst", dpath(world, "assigned")).text
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "onerror=alert(2)&gt;" in body


def test_free_route_streams_and_is_localized(world: World) -> None:
    r = call(world, "owner", "GET", FREE, headers={**ACCEPT, "Accept-Language": "it"})
    frames = parse(r.text)
    assert frames[-1][0] == "done" and len(frames) == len(SELECTORS) + 1
    assert t("checks.dkim.not_enumerable", "it") in frames[0][1]


# --- generator behaviour (no HTTP) --------------------------------------------------------------


class Hanging:
    """A resolver that never answers; records how many lookups started and were cancelled."""

    identity = "hanging"

    def __init__(self) -> None:
        self.started = 0
        self.cancelled = 0

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.started += 1
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        raise AssertionError("unreachable")


async def _until(predicate: Any) -> None:
    for _ in range(200):
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not reached")


async def test_cancelling_the_stream_cancels_the_probe() -> None:
    resolver = Hanging()
    ctx = CheckContext(resolver=resolver)
    events = dkim_events(ctx, "example.com", "en", selectors=["a", "b", "c"])
    task = asyncio.create_task(anext(events))
    await _until(lambda: resolver.started >= 3)
    task.cancel()  # what Starlette does to the response task on client disconnect
    with pytest.raises(asyncio.CancelledError):
        await task
    await _until(lambda: resolver.cancelled == resolver.started)
    assert resolver.cancelled == 3


async def test_aclose_after_first_event_stops_the_remaining_probes() -> None:
    class Mixed(Hanging):
        async def resolve(self, question: DnsQuestion) -> DnsResult:
            if question.name.startswith("fast."):
                from app.dns.types import ResultState

                return DnsResult(question=question, state=ResultState.nxdomain, rcode=3)
            return await super().resolve(question)

    resolver = Mixed()
    ctx = CheckContext(resolver=resolver)
    events = dkim_events(ctx, "example.com", "en", selectors=["fast", "slow1", "slow2"])
    first = await anext(events)
    assert first.startswith("event: selector\n") and 'data-selector="fast"' in first
    await events.aclose()
    assert resolver.cancelled == resolver.started >= 2
    assert "slow1" not in first


async def test_deadline_stops_the_probe_and_reports_incomplete() -> None:
    resolver = Hanging()
    ctx = CheckContext(resolver=resolver)
    frames = [
        f
        async for f in dkim_events(ctx, "example.com", "en", selectors=["a", "b"], deadline_s=0.05)
    ]
    assert len(frames) == 1
    event, data = parse(frames[0])[0]
    assert event == "done"
    assert 'data-complete="0"' in data and "dkim-findings" in data and "data-code" not in data
    assert resolver.cancelled == resolver.started == 2


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        ("<p>x</p>", "event: e\ndata: <p>x</p>\n\n"),
        ("a\nb", "event: e\ndata: a\ndata: b\n\n"),
        ("a\r\nb\rc", "event: e\ndata: a\ndata: b\ndata: c\n\n"),
        ("", "event: e\ndata: \n\n"),
    ],
)
def test_sse_framing_never_embeds_a_raw_newline(html: str, expected: str) -> None:
    assert sse("e", html) == expected


async def test_hostile_selector_name_is_escaped() -> None:
    from app.dns.types import ResultState

    class Nx:
        identity = "nx"

        async def resolve(self, question: DnsQuestion) -> DnsResult:
            return DnsResult(question=question, state=ResultState.nxdomain, rcode=3)

    ctx = CheckContext(resolver=Nx())
    frames = [
        f async for f in dkim_events(ctx, "example.com", "en", selectors=[HOSTILE_SELECTOR_NAME])
    ]
    body = "".join(frames)
    assert "<b>" not in body
    assert "&lt;b&gt;evil&lt;/b&gt;" in body
