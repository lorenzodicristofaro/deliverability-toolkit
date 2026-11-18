"""M7-13 Monitoring tab: `/domains/{id}/monitoring` and its save / delete forms, through the real
app and middleware.

Per role (owner, admin, analyst: controls; client viewer: read-only, writes refused), tenancy
(tenant B domain, a session whose active tenant is B, unassigned domain for a client viewer,
malformed ids, no active tenant), toggles, CSRF, form validation, hostile DNS text in the diff
view and in finding texts, empty states, en and it rendering in strict i18n mode, and the SVG
chart model (table-driven, malformed input included). No network: a socket guard allows only the
test database.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.history import history_clock
from app.api.v1.monitors import monitor_clock
from app.core import i18n
from app.core.config import Settings
from app.core.csrf import session_csrf_token
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import load_catalogue
from app.core.security import SESSION_COOKIE_NAME, unsign_session_token
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import Membership, User
from app.models.check_run import STATUSES
from app.repositories import repo_for
from app.repositories.monitor_targets import MonitorTargetRecord
from app.web.monitoring import CHART_H, PAD_B, PAD_T, bucket_label, build_chart
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _cookie, _seed, call
from tests.services.test_history import seed_run, seed_snapshot
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 17, 9, 30, tzinfo=UTC)
HTML = {"Accept": "text/html"}
HOSTILE_TXT = '"><script>alert(1)</script>'
HOSTILE_ESCAPED = "&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
SPF = ("@", "TXT", "ok", ["v=spf1 -all"])
MANAGERS = ["owner", "admin", "analyst"]
ROLES = [*MANAGERS, "viewer"]
BAD_INTERVAL = "monitor.error.invalid_interval"
BAD_CHECKS = "monitor.error.invalid_checks"
VALID_FORM = {"interval_seconds": "3600", "check_ids": ["spf", "dmarc"], "enabled": "1"}


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
    install(monkeypatch, "monitoring UI", db_endpoint())


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
    application.dependency_overrides[monitor_clock] = _FixedClock
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


def path(w: World, which: str = "assigned", suffix: str = "") -> str:
    return f"/domains/{w.domains[which]}/monitoring{suffix}"


def get(w: World, who: str, url: str, *, tenant: str = "a", lang: str = "en") -> Any:
    return call(w, who, "GET", url, tenant=tenant, headers={**HTML, "Accept-Language": lang})


def post_as(
    w: World,
    who: str,
    url: str,
    form: dict[str, Any] | None = None,
    *,
    tenant: str = "a",
    csrf: bool = True,
) -> Any:
    """A form POST as `who`: session cookie set, CSRF token in the form (or omitted)."""
    fields: dict[str, Any] = dict(form or {})
    w.client.cookies.clear()
    if who != "anon":
        cookie = _cookie(w, who, tenant)
        w.client.cookies.set(SESSION_COOKIE_NAME, cookie)
        if csrf:
            token = unsign_session_token(cookie, w.settings.secret_key)
            assert token is not None
            fields["csrf_token"] = session_csrf_token(token, w.settings.secret_key)
    return w.client.post(
        url,
        content=urlencode(fields, doseq=True).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", **HTML},
        follow_redirects=False,
    )


def main_of(html: str) -> str:
    """The page content after the title (the layout has its own forms: logout, language)."""
    return html.split('data-testid="monitor-title"')[1]


def set_toggles(w: World, who: str, toggles: dict[str, Any]) -> None:
    membership = w.db.scalars(select(Membership).where(Membership.user_id == w.users[who])).one()
    membership.feature_toggles = toggles
    w.db.commit()


def target(w: World, domain: str = "assigned") -> MonitorTargetRecord | None:
    w.db.expire_all()
    tenant = w.tenant_b if domain == "other" else w.tenant_a
    record = repo_for(TenantContext(tenant, None), w.db).monitor_targets.get_for_domain(
        w.domains[domain]
    )
    w.db.rollback()
    return record


def make_target(w: World, domain: str = "assigned", **fields: Any) -> MonitorTargetRecord:
    tenant = w.tenant_b if domain == "other" else w.tenant_a
    values = {"check_ids": ["spf"], "interval_seconds": 86400, "enabled": True, **fields}
    record = repo_for(TenantContext(tenant, None), w.db).monitor_targets.create(
        w.domains[domain], next_run_at=NOW, **values
    )
    assert record is not None
    w.db.commit()
    return record


def seed_history(w: World, domain: str = "assigned") -> tuple[int, int]:
    """Runs of two checks and two different snapshots; (snapshot 1, snapshot 2)."""
    d = w.domains[domain]
    tid = w.tenant_b if domain == "other" else w.tenant_a
    seed_run(w, d, tid, check_id="spf", status="ok", at=NOW - timedelta(days=2))
    seed_run(w, d, tid, check_id="spf", status="fail", at=NOW - timedelta(hours=1))
    seed_run(w, d, tid, check_id="dmarc", status="warn", at=NOW - timedelta(hours=2))
    s1 = seed_snapshot(w, d, tid, [SPF], at=NOW - timedelta(hours=3))
    s2 = seed_snapshot(
        w, d, tid, [("@", "TXT", "ok", ["v=spf1 include:_spf.example -all"])], at=NOW
    )
    return s1, s2


# --- render per role ----------------------------------------------------------------------------


@pytest.mark.parametrize("who", MANAGERS)
def test_manager_sees_controls(world: World, who: str) -> None:
    make_target(world)
    r = get(world, who, path(world))
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    body = main_of(r.text)
    assert 'data-testid="monitor-form"' in body
    assert 'data-testid="monitor-delete"' in body
    assert body.count('name="csrf_token"') == 2  # save + delete


def test_viewer_is_read_only(world: World) -> None:
    make_target(world)
    seed_history(world)
    r = get(world, "viewer", path(world))
    assert r.status_code == 200
    body = main_of(r.text)
    assert 'data-testid="monitor-form"' not in body
    assert 'data-testid="monitor-delete"' not in body
    assert body.count("<form") == 1  # only the GET form of the diff view
    assert body.count('<form method="get"') == 1
    assert 'name="csrf_token"' not in body
    assert 'data-testid="chart-svg"' in body  # the read side is all there
    assert 'data-testid="diff-table"' in body


def test_anonymous_get_redirects_to_login(world: World) -> None:
    world.client.cookies.clear()
    r = world.client.get(path(world), headers=HTML, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_no_active_tenant_is_404(world: World) -> None:
    assert get(world, "root", path(world)).status_code == 404


# --- tenancy ------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", ROLES)
def test_foreign_domain_is_404_and_leaks_nothing(world: World, who: str) -> None:
    make_target(world, "other")
    seed_history(world, "other")
    for response in (
        get(world, who, path(world, "other")),
        post_as(world, who, path(world, "other"), VALID_FORM),
        post_as(world, who, path(world, "other", "/delete")),
    ):
        assert response.status_code == 404
        assert B_SECRET_NAME not in response.text
    assert target(world, "other") is not None
    assert target(world, "other").check_ids == ("spf",)  # type: ignore[union-attr]


@pytest.mark.parametrize("who", ROLES)
def test_session_in_tenant_b_gets_404_for_a_domain(world: World, who: str) -> None:
    who = "b_viewer" if who in ("viewer",) else "b_owner"
    assert get(world, who, path(world), tenant="b").status_code == 404
    assert post_as(world, who, path(world), VALID_FORM, tenant="b").status_code == 404
    assert target(world) is None


def test_viewer_unassigned_domain_is_404(world: World) -> None:
    make_target(world, "unassigned")
    assert get(world, "viewer", path(world, "unassigned")).status_code == 404
    assert post_as(world, "viewer", path(world, "unassigned"), VALID_FORM).status_code == 404
    assert post_as(world, "viewer", path(world, "unassigned", "/delete")).status_code == 404
    assert target(world, "unassigned") is not None


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "2147483648", "1.5", "%20"])
def test_malformed_domain_id_is_404(world: World, raw: str) -> None:
    assert get(world, "owner", f"/domains/{raw}/monitoring").status_code == 404
    assert post_as(world, "owner", f"/domains/{raw}/monitoring", VALID_FORM).status_code == 404


@pytest.mark.parametrize("who", ROLES)
def test_monitor_read_toggle_off_is_403(world: World, who: str) -> None:
    set_toggles(world, who, {"monitor.read": False})
    r = get(world, who, path(world))
    assert r.status_code == 403
    assert 'data-testid="monitor-title"' not in r.text


def test_denied_caller_gets_403_or_404_whatever_the_query_says(world: World) -> None:
    junk = "?bucket=x&cursor=%00&from=a&to=b"
    set_toggles(world, "analyst", {"monitor.read": False})
    assert get(world, "analyst", path(world, suffix=junk)).status_code == 403
    assert get(world, "owner", path(world, "other", junk)).status_code == 404


# --- writes -------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", MANAGERS)
def test_manager_creates_then_updates(world: World, who: str) -> None:
    r = post_as(world, who, path(world), VALID_FORM)
    assert r.status_code == 303
    assert r.headers["location"] == path(world, suffix="?notice=saved")
    created = target(world)
    assert created is not None
    assert set(created.check_ids) == {"spf", "dmarc"}
    assert created.interval_seconds == 3600 and created.enabled is True
    r = post_as(world, who, path(world), {"interval_seconds": "86400", "check_ids": ["dkim"]})
    assert r.status_code == 303
    changed = target(world)
    assert changed is not None and changed.id == created.id
    assert changed.check_ids == ("dkim",)
    assert changed.interval_seconds == 86400 and changed.enabled is False
    page = get(world, who, r.headers["location"])
    assert 'data-testid="monitor-flash"' in page.text


@pytest.mark.parametrize("who", MANAGERS)
def test_manager_deletes(world: World, who: str) -> None:
    make_target(world)
    r = post_as(world, who, path(world, suffix="/delete"))
    assert r.status_code == 303
    assert target(world) is None
    assert post_as(world, who, path(world, suffix="/delete")).status_code == 404


def test_viewer_writes_are_403(world: World) -> None:
    make_target(world)
    assert post_as(world, "viewer", path(world), VALID_FORM).status_code == 403
    assert post_as(world, "viewer", path(world, suffix="/delete")).status_code == 403
    assert target(world).check_ids == ("spf",)  # type: ignore[union-attr]


def test_manage_toggle_off_is_403(world: World) -> None:
    set_toggles(world, "analyst", {"monitor.manage": False})
    assert post_as(world, "analyst", path(world), VALID_FORM).status_code == 403
    assert target(world) is None
    page = get(world, "analyst", path(world))
    assert page.status_code == 200
    assert 'data-testid="monitor-form"' not in page.text


@pytest.mark.parametrize("suffix", ["", "/delete"])
def test_anonymous_post_is_401_and_missing_csrf_403(world: World, suffix: str) -> None:
    make_target(world)
    anon = call(world, "anon", "POST", path(world, suffix=suffix), headers=HTML)
    assert anon.status_code == 401
    assert (
        post_as(world, "owner", path(world, suffix=suffix), VALID_FORM, csrf=False).status_code
        == 403
    )
    assert target(world).check_ids == ("spf",)  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("form", "key"),
    [
        ({"interval_seconds": "60", "check_ids": ["spf"]}, BAD_INTERVAL),
        ({"interval_seconds": "abc", "check_ids": ["spf"]}, BAD_INTERVAL),
        ({"interval_seconds": "9" * 30, "check_ids": ["spf"]}, BAD_INTERVAL),
        ({"check_ids": ["spf"]}, BAD_INTERVAL),
        ({"interval_seconds": ["3600", "86400"], "check_ids": ["spf"]}, BAD_INTERVAL),
        ({"interval_seconds": "3600"}, BAD_CHECKS),
        ({"interval_seconds": "3600", "check_ids": ["spf\x00"]}, BAD_CHECKS),
        ({"interval_seconds": "3600", "check_ids": ["spf", "spf"]}, BAD_CHECKS),
        ({"interval_seconds": "3600", "check_ids": ["nope"]}, "monitor.error.unknown_check"),
        ({"interval_seconds": "3600", "check_ids": ["x" * 200]}, BAD_CHECKS),
        ({"interval_seconds": "3600", "check_ids": ["spf"] * 65}, BAD_CHECKS),
        ({"interval_seconds": "3600", "check_ids": ["spf"], "enabled": ["1", "1"]},
         "api.error.invalid_request"),
        ({"interval_seconds": " 3600", "check_ids": ["spf"]}, BAD_INTERVAL),
    ],
    ids=["short", "text", "huge", "missing", "repeated", "no-checks", "nul", "dup", "unknown",
         "long", "too-many", "enabled-twice", "padded"],
)  # fmt: skip
def test_invalid_form_is_422_and_stores_nothing(
    world: World, form: dict[str, Any], key: str
) -> None:
    r = post_as(world, "owner", path(world), form)
    assert r.status_code == 422
    assert i18n.t(key, "en") in r.text
    assert "\x00" not in r.text and "x" * 200 not in r.text
    assert target(world) is None


def test_oversized_form_is_413(world: World) -> None:
    r = post_as(world, "owner", path(world), {"interval_seconds": "3600", "pad": "x" * 200_000})
    assert r.status_code == 413
    assert target(world) is None


# --- hostile text ---------------------------------------------------------------------------------


def test_hostile_txt_value_in_diff_is_escaped(world: World) -> None:
    d, tid = world.domains["assigned"], world.tenant_a
    seed_snapshot(world, d, tid, [SPF], at=NOW - timedelta(hours=2))
    seed_snapshot(world, d, tid, [("@", "TXT", "ok", [HOSTILE_TXT, "zero\u200bwidth\x1b"])], at=NOW)
    for who in ROLES:
        r = get(world, who, path(world))
        assert r.status_code == 200
        assert 'data-testid="diff-table"' in r.text
        assert "<script>alert(1)</script>" not in r.text
        assert HOSTILE_ESCAPED in r.text
        assert "\u200b" not in r.text and "\x1b" not in r.text
        assert "width" in r.text  # the rest of the value is shown


def test_hostile_finding_param_is_escaped(world: World) -> None:
    seed_run(
        world,
        world.domains["assigned"],
        world.tenant_a,
        check_id="dnsbl",
        status="fail",
        at=NOW - timedelta(minutes=5),
        findings=[{"code": "DNSBL_LISTED", "params": {"list": "<img src=x onerror=alert(1)>"}}],
    )
    r = get(world, "owner", path(world))
    assert r.status_code == 200
    assert "<img src=x" not in r.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in r.text


# --- content and empty states ---------------------------------------------------------------------


def test_empty_states(world: World) -> None:
    r = get(world, "owner", path(world))
    assert r.status_code == 200
    for testid in ("monitor-target-empty", "chart-empty", "history-empty", "diff-empty"):
        assert f'data-testid="{testid}"' in r.text
    assert 'data-testid="chart-svg"' not in r.text
    assert 'data-testid="monitor-delete"' not in r.text
    assert i18n.t("monitor.tab.create", "en") in r.text


def test_one_snapshot_has_no_diff(world: World) -> None:
    seed_snapshot(world, world.domains["assigned"], world.tenant_a, [SPF], at=NOW)
    r = get(world, "owner", path(world))
    assert 'data-testid="diff-empty"' in r.text and 'data-testid="diff-table"' not in r.text


def test_page_shows_target_last_status_history_trend_and_diff(world: World) -> None:
    make_target(world, check_ids=["spf", "dmarc", "dkim"], interval_seconds=21600, enabled=False)
    seed_history(world)
    r = get(world, "analyst", path(world))
    assert r.status_code == 200
    body = main_of(r.text)
    en = load_catalogue("en")
    assert en["monitor.tab.interval.six_hours"] in body
    assert en["monitor.tab.disabled"] in body
    assert f'data-testid="last-spf">{en["checks.status.fail"]}<' in body
    assert f'data-testid="last-dmarc">{en["checks.status.warn"]}<' in body
    assert f'data-testid="last-dkim">{en["monitor.tab.never"]}<' in body
    assert body.count("<tr data-run=") == 3
    assert 'class="chart-bar status-fail"' in body and 'class="chart-bar status-ok"' in body
    assert 'data-testid="chart-strip"' in body
    assert "2026-11-17" in body  # day bucket labelled by its start
    assert 'data-testid="diff-table"' in body
    assert en["monitor.diff.kind.changed"] in body
    assert "<script" not in body


def test_hour_buckets_are_labelled_by_their_start(world: World) -> None:
    seed_history(world)
    r = get(world, "owner", path(world, suffix="?bucket=hour"))
    assert r.status_code == 200
    assert "2026-11-17 08:00" in r.text  # the fail run at 08:30 UTC
    assert 'aria-current="page" data-testid="bucket-hour"' in r.text


def test_history_pagination(world: World) -> None:
    for i in range(30):
        seed_run(world, world.domains["assigned"], world.tenant_a, at=NOW - timedelta(minutes=i))
    first = get(world, "owner", path(world))
    assert first.text.count("<tr data-run=") == 25
    marker = 'data-testid="history-older"'
    assert marker in first.text
    href = first.text.split(marker)[0].rsplit('href="', 1)[1].split('"', 1)[0]
    second = get(world, "owner", href.replace("&amp;", "&"))
    assert second.status_code == 200
    assert second.text.count("<tr data-run=") == 5
    assert marker not in second.text


@pytest.mark.parametrize(
    "query",
    ["?bucket=week", "?bucket=day&bucket=hour", "?cursor=zzz", "?cursor=%00", "?from=1&from=2"],
)
def test_malformed_query_is_422(world: World, query: str) -> None:
    r = get(world, "owner", path(world, suffix=query))
    assert r.status_code == 422


def test_other_query_params_are_ignored(world: World) -> None:
    assert get(world, "owner", path(world, suffix="?unknown=1&limit=-4")).status_code == 200


def test_explicit_diff_and_unknown_snapshot(world: World) -> None:
    s1, s2 = seed_history(world)
    r = get(world, "owner", path(world, suffix=f"?from={s2}&to={s1}"))
    assert r.status_code == 200 and 'data-testid="diff-table"' in r.text
    same = get(world, "owner", path(world, suffix=f"?from={s1}&to={s1}"))
    assert 'data-testid="diff-none"' in same.text
    for query in (f"?from={s1}&to=999999", f"?from={s1}", "?from=abc&to=x"):
        bad = get(world, "owner", path(world, suffix=query))
        assert bad.status_code == 200
        assert 'data-testid="diff-note"' in bad.text and 'data-testid="diff-table"' not in bad.text


def test_snapshot_of_tenant_b_is_not_diffed(world: World) -> None:
    seed_history(world)
    b1, b2 = seed_history(world, "other")
    r = get(world, "owner", path(world, suffix=f"?from={b1}&to={b2}"))
    assert r.status_code == 200
    assert 'data-testid="diff-note"' in r.text
    assert B_SECRET_NAME not in r.text


@pytest.mark.parametrize("lang", ["en", "it"])
def test_renders_in_both_languages_without_missing_keys(world: World, lang: str) -> None:
    """Strict i18n mode is on: a missing key raises and fails the render."""
    make_target(world)
    seed_history(world)
    r = get(world, "owner", path(world), lang=lang)
    assert r.status_code == 200
    catalogue = load_catalogue(lang)
    assert catalogue["monitor.tab.title"] in r.text
    assert catalogue["monitor.chart.title"] in r.text
    assert catalogue["monitor.diff.title"] in r.text
    empty = get(world, "viewer", path(world, "assigned"), lang=lang)
    assert empty.status_code == 200


def test_new_keys_exist_in_both_locales() -> None:
    en, it = load_catalogue("en"), load_catalogue("it")
    new = {k for k in en if k.startswith(("monitor.tab.", "monitor.chart.", "monitor.diff."))}
    assert new and new == {k for k in it if k.startswith(("monitor.tab.", "monitor.chart.",
                                                          "monitor.diff."))}  # fmt: skip


# --- chart model ----------------------------------------------------------------------------------


def _bucket(start: str, counts: Any = None, checks: Any = None) -> dict[str, Any]:
    return {"start": start, "counts": counts or {}, "checks": checks or {}}


@pytest.mark.parametrize(
    ("trend", "bars", "total"),
    [
        ({}, 0, 0),
        ({"buckets": None}, 0, 0),
        ({"buckets": "nope"}, 0, 0),
        ({"buckets": [1, "x", None]}, 0, 0),
        ({"buckets": [_bucket("2026-11-17T00:00:00+00:00")]}, 1, 0),
        ({"buckets": [_bucket("2026-11-17T00:00:00+00:00", {"ok": 2, "fail": 1})]}, 1, 3),
        ({"buckets": [_bucket("bad", {"ok": -5, "fail": "3", "warn": True, "x": 9})]}, 1, 0),
        ({"buckets": [_bucket("2026-11-17T00:00:00+00:00", ["ok"])]}, 1, 0),
        ({"buckets": [_bucket(f"2026-11-{d:02d}T00:00:00+00:00", {"ok": d}) for d in range(1, 31)]},
         30, 465),
    ],
    ids=["empty", "none", "string", "junk-items", "zero", "counts", "bad-values", "list-counts",
         "month"],
)  # fmt: skip
def test_build_chart(trend: dict[str, Any], bars: int, total: int) -> None:
    chart = build_chart(trend, ["spf"])
    assert len(chart.bars) == bars
    assert chart.total_runs == total
    for bar in chart.bars:
        for seg in bar.segments:
            assert seg.status in STATUSES
            assert seg.y >= PAD_T - 0.01 and seg.y + seg.height <= CHART_H - PAD_B + 0.01
            assert seg.width > 0 and seg.height > 0
    assert len(chart.x_labels) <= 6


def test_build_chart_stacks_and_strips() -> None:
    trend = {
        "bucket": "hour",
        "buckets": [
            _bucket(
                "2026-11-17T08:00:00+00:00",
                {"ok": 1, "fail": 3},
                {"spf": {"status": "fail", "runs": 3}, "dmarc": {"status": "<b>", "runs": 1},
                 "evil": {"status": "ok", "runs": 1}},
            ),
            _bucket("2026-11-17T09:00:00+00:00"),
        ],
        "window": {"capped": True, "truncated": False},
    }  # fmt: skip
    chart = build_chart(trend, ["spf", "dmarc"])
    assert chart.capped and not chart.truncated
    first = chart.bars[0]
    assert first.label == "2026-11-17 08:00" and first.runs == 4
    assert [s.status for s in first.segments] == ["ok", "fail"]
    tallest = first.segments[-1]
    assert tallest.y == pytest.approx(PAD_T)  # the tallest bar reaches the top
    assert [r.check_id for r in chart.strip] == ["spf", "dmarc"]  # only the asked checks
    spf, dmarc = chart.strip
    assert spf.cells[0].status == "fail" and spf.cells[0].runs == 3
    assert spf.cells[1].status is None
    assert dmarc.cells[0].status is None  # an unknown status is never a CSS class
    assert [t.value for t in chart.ticks] == [0, 2, 4]


@pytest.mark.parametrize(
    ("start", "unit", "label"),
    [
        ("2026-11-17T00:00:00+00:00", "day", "2026-11-17"),
        ("2026-11-17T08:00:00+00:00", "hour", "2026-11-17 08:00"),
        ("", "day", ""),
        ("not a date", "hour", ""),
        ("<script>", "day", ""),
    ],
)
def test_bucket_label(start: str, unit: str, label: str) -> None:
    assert bucket_label(start, unit) == label
