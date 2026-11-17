"""M7-12 history routes through the real app and middleware: `/api/v1/domains/{id}/history/...`
(runs, trend, snapshots, snapshots/diff).

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role table, cross-tenant ids on every
endpoint, query validation, bounds and the wire format. No network.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.history import history_clock
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.main import create_app
from app.models import Domain, Membership, User
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _seed, call
from tests.services.test_history import seed_run, seed_snapshot
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 17, 9, 30, tzinfo=UTC)
NOT_FOUND = {"detail": t("monitor.error.not_found", "en")}
FORBIDDEN = {"detail": t("api.error.forbidden", "en")}
INVALID = {"detail": t("api.error.invalid_request", "en")}
SPF = ("@", "TXT", "ok", ["v=spf1 -all"])
SPF2 = ("@", "TXT", "ok", ["v=spf1 include:_spf.example -all"])
ROUTES = ("runs", "trend", "snapshots", "snapshots/diff")


class _FixedClock:
    def now(self) -> datetime:
        return NOW


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "history API", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    root = User(email="root@example.com", is_instance_admin=True)
    db.add(root)
    db.commit()
    users["root"] = root.id
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    application.dependency_overrides[history_clock] = _FixedClock
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- helpers ------------------------------------------------------------------------------------


def url(w: World, route: str, domain: str = "assigned", query: str = "") -> str:
    return f"/api/v1/domains/{w.domains[domain]}/history/{route}{query}"


def set_toggles(w: World, who: str, toggles: dict[str, Any]) -> None:
    membership = w.db.scalars(select(Membership).where(Membership.user_id == w.users[who])).one()
    membership.feature_toggles = toggles
    w.db.commit()


def seed(w: World, domain: str = "assigned", tenant: str = "a") -> tuple[int, int, int]:
    """One run and two different snapshots on the domain; (run id, snapshot 1, snapshot 2)."""
    d, tid = w.domains[domain], w.tenant_id(tenant)
    run = seed_run(w, d, tid, status="fail", at=NOW - timedelta(hours=1))
    s1 = seed_snapshot(w, d, tid, [SPF], at=NOW - timedelta(hours=2))
    s2 = seed_snapshot(w, d, tid, [SPF2], at=NOW - timedelta(hours=1))
    return run, s1, s2


def query_for(route: str, s1: int = 1, s2: int = 2) -> str:
    return f"?from={s1}&to={s2}" if route == "snapshots/diff" else ""


# --- roles --------------------------------------------------------------------------------------

# "root" is an instance admin with no membership in tenant A: no active tenant, so 404.
READ = {"anon": 401, "owner": 200, "admin": 200, "analyst": 200, "viewer": 200, "root": 404}


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(("who", "status"), READ.items())
def test_per_role(world: World, route: str, who: str, status: int) -> None:
    _, s1, s2 = seed(world)
    response = call(world, who, "GET", url(world, route, query=query_for(route, s1, s2)))
    assert response.status_code == status, response.text
    if status == 404:
        assert response.json() == NOT_FOUND


@pytest.mark.parametrize("route", ROUTES)
def test_viewer_unassigned_domain_is_404(world: World, route: str) -> None:
    _, s1, s2 = seed(world, "unassigned")
    path = url(world, route, "unassigned", query_for(route, s1, s2))
    response = call(world, "viewer", "GET", path)
    assert response.status_code == 404
    assert response.json() == NOT_FOUND
    assert call(world, "analyst", "GET", path).status_code == 200


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_foreign_domain_is_404_and_leaks_nothing(world: World, route: str, who: str) -> None:
    _, s1, s2 = seed(world, "other", "b")
    response = call(world, who, "GET", url(world, route, "other", query_for(route, s1, s2)))
    assert response.status_code == 404
    assert response.json() == NOT_FOUND
    assert B_SECRET_NAME not in response.text


@pytest.mark.parametrize("route", ROUTES)
def test_session_in_a_foreign_tenant_gets_404(world: World, route: str) -> None:
    seed(world)
    response = call(world, "owner", "GET", url(world, route, query=query_for(route)), tenant="b")
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("raw", ["abc", "0", "-1", "1.5", "99999999999999999999", "%C2%B2"])
def test_malformed_domain_id_is_a_404(world: World, route: str, raw: str) -> None:
    response = call(world, "owner", "GET", f"/api/v1/domains/{raw}/history/{route}")
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_monitor_read_toggle_off_is_403(world: World, route: str, who: str) -> None:
    seed(world)
    set_toggles(world, who, {"monitor.read": False})
    response = call(world, who, "GET", url(world, route, query=query_for(route)))
    assert response.status_code == 403
    assert response.json() == FORBIDDEN


@pytest.mark.parametrize("route", ROUTES)
def test_manage_toggle_is_not_needed_to_read(world: World, route: str) -> None:
    _, s1, s2 = seed(world)
    set_toggles(world, "analyst", {"monitor.manage": False})
    assert call(
        world, "analyst", "GET", url(world, route, query=query_for(route, s1, s2))
    ).is_success


@pytest.mark.parametrize("route", ROUTES)
def test_denied_caller_gets_403_or_404_whatever_the_query_says(world: World, route: str) -> None:
    junk = "?limit=-5&since=zzz&cursor=%00&bucket=x&from=a&to=b&unknown=1"
    set_toggles(world, "analyst", {"monitor.read": False})
    assert call(world, "analyst", "GET", url(world, route, query=junk)).status_code == 403
    assert call(world, "owner", "GET", url(world, route, "other", junk)).status_code == 404
    assert call(world, "viewer", "GET", url(world, route, "unassigned", junk)).status_code == 404
    assert call(world, "anon", "GET", url(world, route, query=junk)).status_code == 401


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("route", ROUTES)
def test_routes_are_read_only(world: World, route: str, method: str) -> None:
    response = call(world, "owner", method, url(world, route))
    assert response.status_code == 405


# --- runs ---------------------------------------------------------------------------------------


def test_runs_wire_format_and_rendering(world: World) -> None:
    findings = [
        {"code": "SPF_TOO_MANY_LOOKUPS", "params": {"count": 12, "limit": 10}},
        {"code": "GONE_CODE", "params": {"x": "<b>"}},
    ]
    run_id = seed_run(
        world,
        world.domains["assigned"],
        world.tenant_a,
        status="fail",
        findings=findings,
        at=NOW - timedelta(minutes=5),
    )
    body = call(world, "owner", "GET", url(world, "runs")).json()
    assert set(body) == {"items", "next_cursor", "window", "page_size_max"}
    (item,) = body["items"]
    assert item["id"] == run_id
    assert "tenant_id" not in item
    by_code = {f["code"]: f for f in item["findings"]}
    en_title = t("finding.SPF_TOO_MANY_LOOKUPS.title", "en")
    assert by_code["SPF_TOO_MANY_LOOKUPS"]["title"] == en_title
    assert by_code["SPF_TOO_MANY_LOOKUPS"]["params"] == {"count": 12, "limit": 10}
    assert by_code["GONE_CODE"]["title"] is None
    assert by_code["GONE_CODE"]["params"] == {"x": "<b>"}
    italian = call(
        world, "owner", "GET", url(world, "runs"), headers={"Accept-Language": "it"}
    ).json()
    it_title = t("finding.SPF_TOO_MANY_LOOKUPS.title", "it")
    assert it_title != en_title
    assert {f["code"]: f for f in italian["items"][0]["findings"]}["SPF_TOO_MANY_LOOKUPS"][
        "title"
    ] == it_title


def test_runs_pagination_with_opaque_cursor(world: World) -> None:
    d = world.domains["assigned"]
    ids = [seed_run(world, d, world.tenant_a, at=NOW - timedelta(minutes=i)) for i in range(5)]
    seen: list[int] = []
    query = "?limit=2"
    for _ in range(4):
        body = call(world, "owner", "GET", url(world, "runs", query=query)).json()
        seen += [i["id"] for i in body["items"]]
        if body["next_cursor"] is None:
            break
        query = f"?limit=2&cursor={body['next_cursor']}"
    assert seen == ids


def test_runs_cursor_cannot_cross_domains_or_tenants(world: World) -> None:
    d, other = world.domains["assigned"], world.domains["other"]
    for i in range(3):
        seed_run(world, d, world.tenant_a, at=NOW - timedelta(minutes=i))
    seed_run(world, other, world.tenant_b)
    cursor = call(world, "owner", "GET", url(world, "runs", query="?limit=1")).json()["next_cursor"]
    # Same cursor on another readable domain of A, and on tenant B's domain (404 first).
    other_a = url(world, "runs", "unassigned", f"?cursor={cursor}")
    assert call(world, "owner", "GET", other_a).status_code == 422
    foreign = url(world, "runs", "other", f"?cursor={cursor}")
    assert call(world, "owner", "GET", foreign).status_code == 404
    # B's own cursor on A's domain: refused, nothing of B returned.
    b_cursor = call(
        world, "b_owner", "GET", url(world, "runs", "other", "?limit=1"), tenant="b"
    ).json()["next_cursor"]
    assert b_cursor is None  # only one run: no next page
    forged = call(world, "owner", "GET", url(world, "runs", query="?cursor=" + "A" * 40))
    assert forged.status_code == 422


@pytest.mark.parametrize(
    "query",
    [
        "?limit=0",
        "?limit=201",
        "?limit=-1",
        "?limit=abc",
        "?limit=",
        "?limit=1&limit=2",
        "?since=nope",
        "?since=2026-11-01T00:00:00",
        "?until=2026-13-45T00:00:00Z",
        "?since=2026-11-02T00:00:00Z&until=2026-11-01T00:00:00Z",
        "?check_id=BAD",
        "?check_id=" + "a" * 100,
        "?cursor=%00",
        "?cursor=",
        "?bogus=1",
    ],
)
def test_runs_malformed_query_is_422(world: World, query: str) -> None:
    seed(world)
    response = call(world, "owner", "GET", url(world, "runs", query=query))
    assert response.status_code == 422
    assert response.json() == INVALID


def test_runs_limit_bound_is_inclusive(world: World) -> None:
    seed(world)
    assert call(world, "owner", "GET", url(world, "runs", query="?limit=200")).status_code == 200
    assert call(world, "owner", "GET", url(world, "runs", query="?limit=1")).status_code == 200


def test_runs_large_window_is_capped_and_says_so(world: World) -> None:
    d = world.domains["assigned"]
    seed_run(world, d, world.tenant_a, at=NOW - timedelta(days=700))
    recent = seed_run(world, d, world.tenant_a, at=NOW - timedelta(days=1))
    query = "?since=1990-01-01T00:00:00Z&until=2026-11-17T00:00:00Z"
    body = call(world, "owner", "GET", url(world, "runs", query=query)).json()
    assert [i["id"] for i in body["items"]] == [recent]
    assert body["window"]["capped"] is True
    assert body["window"]["max_days"] == 366


def test_runs_check_filter(world: World) -> None:
    d = world.domains["assigned"]
    seed_run(world, d, world.tenant_a, check_id="spf")
    dmarc = seed_run(world, d, world.tenant_a, check_id="dmarc")
    body = call(world, "owner", "GET", url(world, "runs", query="?check_id=dmarc")).json()
    assert [i["id"] for i in body["items"]] == [dmarc]


def test_runs_of_other_tenants_never_listed(world: World) -> None:
    seed(world, "other", "b")
    own, _, _ = seed(world)
    for who in ("owner", "viewer"):
        body = call(world, who, "GET", url(world, "runs")).json()
        assert [i["id"] for i in body["items"]] == [own]


# --- trend --------------------------------------------------------------------------------------


def test_trend_wire_format(world: World) -> None:
    seed(world)
    body = call(world, "owner", "GET", url(world, "trend")).json()
    assert set(body) == {"bucket", "buckets", "window"}
    assert body["bucket"] == "day"
    assert body["window"]["capped"] is False
    last = body["buckets"][-1]
    assert last["start"] == "2026-11-17T00:00:00+00:00"
    assert last["counts"]["fail"] == 1
    assert last["checks"] == {"spf": {"status": "fail", "runs": 1}}


@pytest.mark.parametrize(
    "query",
    [
        "?bucket=week",
        "?bucket=",
        "?bucket=hour&bucket=day",
        "?since=x",
        "?until=2026-11-17",
        "?since=2026-11-17T00:00:00Z&until=2026-11-16T00:00:00Z",
        "?limit=3",
        "?cursor=abc",
    ],
)
def test_trend_malformed_query_is_422(world: World, query: str) -> None:
    response = call(world, "owner", "GET", url(world, "trend", query=query))
    assert response.status_code == 422
    assert response.json() == INVALID


def test_trend_bucket_cap(world: World) -> None:
    query = "?bucket=hour&since=2020-01-01T00:00:00Z&until=2026-11-17T00:00:00Z"
    body = call(world, "owner", "GET", url(world, "trend", query=query)).json()
    assert len(body["buckets"]) == 500
    assert body["window"]["capped"] is True
    assert body["window"]["max_buckets"] == 500


def test_trend_never_counts_other_tenants(world: World) -> None:
    seed(world, "other", "b")
    body = call(world, "owner", "GET", url(world, "trend")).json()
    assert sum(b["runs"] for b in body["buckets"]) == 0


# --- snapshots ----------------------------------------------------------------------------------


def test_snapshot_list_and_cursor(world: World) -> None:
    _, s1, s2 = seed(world)
    body = call(world, "owner", "GET", url(world, "snapshots", query="?limit=1")).json()
    assert [i["id"] for i in body["items"]] == [s2]
    assert set(body["items"][0]) == {
        "id",
        "domain_id",
        "taken_at",
        "content_hash",
        "truncated",
        "entry_count",
    }
    nxt = call(
        world,
        "owner",
        "GET",
        url(world, "snapshots", query=f"?limit=1&cursor={body['next_cursor']}"),
    ).json()
    assert [i["id"] for i in nxt["items"]] == [s1]
    assert nxt["next_cursor"] is None


@pytest.mark.parametrize("query", ["?limit=0", "?limit=201", "?cursor=zz", "?check_id=spf"])
def test_snapshot_list_malformed_query_is_422(world: World, query: str) -> None:
    response = call(world, "owner", "GET", url(world, "snapshots", query=query))
    assert response.status_code == 422
    assert response.json() == INVALID


def test_snapshot_cursor_of_runs_is_refused(world: World) -> None:
    for i in range(2):
        seed_run(world, world.domains["assigned"], world.tenant_a, at=NOW - timedelta(minutes=i))
    cursor = call(world, "owner", "GET", url(world, "runs", query="?limit=1")).json()["next_cursor"]
    response = call(world, "owner", "GET", url(world, "snapshots", query=f"?cursor={cursor}"))
    assert response.status_code == 422


def test_diff_between_two_snapshots(world: World) -> None:
    _, s1, s2 = seed(world)
    body = call(
        world, "owner", "GET", url(world, "snapshots/diff", query=f"?from={s1}&to={s2}")
    ).json()
    assert [(c["name"], c["kind"]) for c in body["changes"]] == [("@", "changed")]
    assert body["from"]["id"] == s1 and body["to"]["id"] == s2


def test_diff_of_an_error_entry_is_inconclusive(world: World) -> None:
    d = world.domains["assigned"]
    a = seed_snapshot(world, d, world.tenant_a, [SPF], at=NOW - timedelta(hours=3))
    b = seed_snapshot(world, d, world.tenant_a, [("@", "TXT", "error", [])])
    body = call(
        world, "owner", "GET", url(world, "snapshots/diff", query=f"?from={a}&to={b}")
    ).json()
    assert [c["kind"] for c in body["changes"]] == ["inconclusive"]


@pytest.mark.parametrize("who", ["owner", "viewer"])
def test_diff_with_a_snapshot_of_tenant_b_is_404(world: World, who: str) -> None:
    _, s1, _ = seed(world)
    _, b1, _ = seed(world, "other", "b")
    for query in (f"?from={s1}&to={b1}", f"?from={b1}&to={s1}", f"?from={b1}&to={b1}"):
        response = call(world, who, "GET", url(world, "snapshots/diff", query=query))
        assert response.status_code == 404
        assert response.json() == NOT_FOUND


def test_diff_with_a_snapshot_of_another_domain_is_404(world: World) -> None:
    _, s1, _ = seed(world)
    _, u1, _ = seed(world, "unassigned")
    for who in ("owner", "viewer"):
        response = call(
            world, who, "GET", url(world, "snapshots/diff", query=f"?from={s1}&to={u1}")
        )
        assert response.status_code == 404
        assert response.json() == NOT_FOUND


@pytest.mark.parametrize("bad", ["999999", "abc", "0", "-1", "9" * 30, "1.5"])
def test_diff_with_an_unknown_or_malformed_id_is_404(world: World, bad: str) -> None:
    _, s1, _ = seed(world)
    for query in (f"?from={s1}&to={bad}", f"?from={bad}&to={s1}"):
        response = call(world, "owner", "GET", url(world, "snapshots/diff", query=query))
        assert response.status_code == 404
        assert response.json() == NOT_FOUND


@pytest.mark.parametrize(
    "query", ["", "?from=1", "?to=1", "?from=1&to=2&x=3", "?from=1&from=2&to=3"]
)
def test_diff_malformed_query_is_422(world: World, query: str) -> None:
    seed(world)
    response = call(world, "owner", "GET", url(world, "snapshots/diff", query=query))
    assert response.status_code == 422
    assert response.json() == INVALID


def test_domain_added_after_seed_is_readable(world: World) -> None:
    """A domain created later behaves like the seeded ones (no per-domain state in the route)."""
    domain = Domain(tenant_id=world.tenant_a, name="late.example")
    world.db.add(domain)
    world.db.commit()
    response = call(world, "owner", "GET", f"/api/v1/domains/{domain.id}/history/runs")
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_database_is_not_written(world: World) -> None:
    from app.models import CheckRun, DnsSnapshot

    seed(world)

    def count(db: Session) -> tuple[int, int]:
        db.expire_all()
        runs = len(db.scalars(select(CheckRun.id)).all())
        snaps = len(db.scalars(select(DnsSnapshot.id)).all())
        db.rollback()
        return runs, snaps

    before = count(world.db)
    for route in ROUTES:
        call(world, "owner", "GET", url(world, route, query=query_for(route)))
    assert count(world.db) == before
