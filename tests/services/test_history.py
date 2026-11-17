"""M7-12 history service: query parsing, cursors, bucket rules and caps, finding rendering,
permission order (404 before 403, DomainAccess above the repository), snapshot diff.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL. No network.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

import pytest
from sqlalchemy.orm import Session

from app.core import i18n
from app.core.db import create_db_engine, create_session_factory
from app.core.permissions import MembershipGrant, Principal
from app.core.tenancy import TenantContext
from app.models import Domain, MembershipRole, Tenant, User
from app.models.check_run import STATUSES
from app.repositories import repo_for
from app.repositories.check_runs import StoredFinding
from app.services import history
from app.services.dns_diff import build_entry, build_snapshot, to_stored
from app.services.history import (
    MAX_BUCKETS,
    MAX_PAGE_SIZE,
    MAX_WINDOW,
    HistoryInvalid,
    HistoryService,
    decode_cursor,
    encode_cursor,
    render_finding,
)
from app.services.monitors import MonitorForbidden, MonitorNotFound
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 17, 12, 30, tzinfo=UTC)
SECRET = "tenantb-secret.example"


class FixedClock:
    def now(self) -> datetime:
        return NOW


@dataclass
class World:
    db: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]

    def service(self, who: str, toggles: dict[str, Any] | None = None) -> HistoryService:
        roles = {
            "owner": MembershipRole.OWNER,
            "admin": MembershipRole.ADMIN,
            "analyst": MembershipRole.ANALYST,
            "viewer": MembershipRole.CLIENT_VIEWER,
        }
        if who == "root":
            return HistoryService(
                self.db,
                None,
                Principal(self.users["root"], True, is_instance_admin=True),
                clock=FixedClock(),
            )
        grant = MembershipGrant(
            self.tenant_a,
            roles[who],
            domain_ids=frozenset({self.domains["a"]}) if who == "viewer" else frozenset(),
            feature_toggles=MappingProxyType(toggles or {}),
        )
        principal = Principal(self.users[who], True, False, self.tenant_a, (grant,))
        ctx = TenantContext(self.tenant_a, self.users[who])
        return HistoryService(self.db, ctx, principal, clock=FixedClock())


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "history service", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str) -> Iterator[World]:
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        a, b = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        names = ("owner", "admin", "analyst", "viewer", "root")
        users = {n: User(email=f"{n}@example.com") for n in names}
        db.add_all([a, b, *users.values()])
        db.flush()
        domains = {
            "a": Domain(tenant_id=a.id, name="a.example"),
            "a2": Domain(tenant_id=a.id, name="a2.example"),
            "b": Domain(tenant_id=b.id, name=SECRET),
        }
        db.add_all(domains.values())
        db.commit()
        yield World(
            db,
            a.id,
            b.id,
            {n: u.id for n, u in users.items()},
            {n: d.id for n, d in domains.items()},
        )
    finally:
        db.close()
        engine.dispose()


# --- seeding (shared with tests/api/test_history_api.py) ----------------------------------------


def seed_run(
    w: Any,
    domain_id: int,
    tenant_id: int,
    *,
    check_id: str = "spf",
    status: str = "ok",
    at: datetime = NOW,
    findings: list[Any] | None = None,
) -> int:
    ctx = TenantContext(tenant_id, None)
    record = repo_for(ctx, w.db).check_runs.record(
        domain_id,
        check_id=check_id,
        status=status,
        started_at=at,
        duration_ms=5,
        source="scheduled",
        findings=findings or [],
    )
    assert record is not None
    w.db.commit()
    return record.id


def seed_snapshot(
    w: Any,
    domain_id: int,
    tenant_id: int,
    entries: list[tuple[str, str, str, list[str]]],
    *,
    at: datetime = NOW,
) -> int:
    snap = build_snapshot(build_entry(n, t, s, v) for n, t, s, v in entries)
    stored, truncated = to_stored(snap)
    record = repo_for(TenantContext(tenant_id, None), w.db).dns_snapshots.record(
        domain_id, taken_at=at, content_hash=snap.content_hash, entries=stored, truncated=truncated
    )
    assert record is not None
    w.db.commit()
    return record.id


# --- cursor -------------------------------------------------------------------------------------


def test_cursor_round_trip() -> None:
    at = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    assert decode_cursor(encode_cursor("r", 7, at, 99), "r", 7) == (at, 99)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "!!!",
        "a" * 201,
        "bm90LWpzb24",  # not json
        "W10",  # []
        "W1sicisxLDEsMV0",  # not the expected shape
        "WyJyIiw3LDEsMSw1XQ",  # wrong arity
        "WyJyIiw3LCIxIiwxXQ",  # string timestamp
        "WyJyIiw3LDEsMF0",  # id 0
        "WyJyIiw3LDEsLTFd",  # id -1
        "WyJyIiw3LHRydWUsMV0",  # bool timestamp
        "WyJyIiw3LDk5OTk5OTk5OTk5OTk5OTk5OTk5LDFd",  # beyond year 9999
        "WyJyIiw3LC05OTk5OTk5OTk5OTk5OTk5OTk5LDFd",  # before the epoch
        "w6lpw6k",  # not base64 text
    ],
)
def test_malformed_cursor_is_invalid(raw: str) -> None:
    with pytest.raises(HistoryInvalid):
        decode_cursor(raw, "r", 7)


def test_cursor_is_bound_to_domain_and_kind() -> None:
    token = encode_cursor("r", 7, NOW, 5)
    for kind, domain in (("r", 8), ("s", 7)):
        with pytest.raises(HistoryInvalid):
            decode_cursor(token, kind, domain)


# --- findings -----------------------------------------------------------------------------------


def test_finding_rendered_per_language() -> None:
    finding = StoredFinding("SPF_TOO_MANY_LOOKUPS", {"count": 12, "limit": 10})
    en = render_finding(finding, "en")
    it = render_finding(finding, "it")
    assert en["code"] == "SPF_TOO_MANY_LOOKUPS"
    assert en["params"] == {"count": 12, "limit": 10}
    assert en["title"] == i18n.t("finding.SPF_TOO_MANY_LOOKUPS.title", "en")
    assert "12" in en["detail"]
    assert it["title"] == i18n.t("finding.SPF_TOO_MANY_LOOKUPS.title", "it")
    assert it["title"] != en["title"]
    assert en["remediation"]


@pytest.mark.parametrize(
    "params",
    [{}, {"unrelated": 1}, {"count": None}, {"key": "x", "lang": "y", "count": 1, "limit": 2}],
)
def test_finding_with_incomplete_params_never_raises(params: Mapping[str, Any]) -> None:
    out = render_finding(StoredFinding("SPF_TOO_MANY_LOOKUPS", params), "en")
    assert out["code"] == "SPF_TOO_MANY_LOOKUPS"
    assert out["params"] == dict(params)
    assert out["title"] is not None  # the title has no placeholders


@pytest.mark.parametrize(
    "params", [{}, {"count": 12}, {"limit": 10}, {"unrelated": 1}, {"key": "x", "lang": "y"}]
)
def test_missing_placeholder_gives_null_text_with_strict_mode_off(
    params: Mapping[str, Any],
) -> None:
    # Strict off (production): `t()` would return the raw template, so `{count}` must never show.
    i18n.set_strict(False)
    for lang in ("en", "it"):
        out = render_finding(StoredFinding("SPF_TOO_MANY_LOOKUPS", params), lang)
        assert out["detail"] is None
        assert out["title"] == i18n.t("finding.SPF_TOO_MANY_LOOKUPS.title", lang)
        assert out["remediation"] is not None
        assert not any("{" in (out[k] or "") for k in ("title", "detail", "remediation"))


def test_complete_params_render_with_strict_mode_off() -> None:
    i18n.set_strict(False)
    out = render_finding(StoredFinding("SPF_TOO_MANY_LOOKUPS", {"count": 12, "limit": 10}), "en")
    assert out["detail"] is not None and "12" in out["detail"] and "{" not in out["detail"]


@pytest.mark.parametrize("code", ["NO_SUCH_CODE", "SPF_TOO_MANY_LOOKUP", "X"])
def test_unknown_code_has_null_texts_and_keeps_params(code: str) -> None:
    out = render_finding(StoredFinding(code, {"v": "<script>"}), "it")
    assert (out["title"], out["detail"], out["remediation"]) == (None, None, None)
    assert out["params"] == {"v": "<script>"}


def test_dns_text_in_params_is_made_visible() -> None:
    params = {"rdtype": "TXT", "name": "a\x00b", "part": "x", "esp": "e", "state": "s"}
    out = render_finding(StoredFinding("ESP_DNS_ERROR", params), "en")
    assert "\x00" not in out["detail"]
    assert "\\x00" in out["detail"]


# --- authorization ------------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_assigned_domain_readable_by_every_role(world: World, who: str) -> None:
    assert world.service(who).check_read(world.domains["a"]) == world.domains["a"]


@pytest.mark.parametrize("who", ["owner", "admin", "analyst"])
def test_unassigned_domain_readable_except_for_the_viewer(world: World, who: str) -> None:
    assert world.service(who).check_read(world.domains["a2"]) == world.domains["a2"]
    with pytest.raises(MonitorNotFound):
        world.service("viewer").check_read(world.domains["a2"])


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer", "root"])
@pytest.mark.parametrize("raw", [None, 0, -1, "x", 10**30, 2**63])
def test_malformed_ids_are_not_found(world: World, who: str, raw: object) -> None:
    with pytest.raises(MonitorNotFound):
        world.service(who).check_read(raw)


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_foreign_domain_is_not_found(world: World, who: str) -> None:
    with pytest.raises(MonitorNotFound):
        world.service(who).check_read(world.domains["b"])


def test_no_tenant_is_not_found(world: World) -> None:
    with pytest.raises(MonitorNotFound):
        world.service("root").check_read(world.domains["a"])


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_monitor_read_toggle_off_is_forbidden_after_the_404_checks(world: World, who: str) -> None:
    svc = world.service(who, {"monitor.read": False})
    with pytest.raises(MonitorForbidden):
        svc.check_read(world.domains["a"])
    with pytest.raises(MonitorNotFound):
        svc.check_read(world.domains["b"])


def test_domain_read_toggle_off_is_not_found(world: World) -> None:
    with pytest.raises(MonitorNotFound):
        world.service("analyst", {"domain.read": False}).check_read(world.domains["a"])


# --- query parameters ---------------------------------------------------------------------------


# Moments outside MIN_MOMENT..MAX_MOMENT, including the datetime limits that used to overflow the
# window arithmetic (default `since = until - 7d`, `_ceil` adding a bucket) into a 500.
OUT_OF_RANGE: list[dict[str, str]] = [
    {"until": "0001-01-01T00:00:00Z"},
    {"since": "0001-01-01T00:00:00Z"},
    {"until": "9999-12-31T23:30:00Z"},
    {"until": "9999-12-31T23:59:59.999999+00:00"},
    {"since": "9999-12-31T23:30:00Z", "until": "9999-12-31T23:40:00Z"},
    {"since": "0001-01-01T00:00:00Z", "until": "2026-11-01T00:00:00Z"},
    {"since": "1969-12-31T23:59:59.999999Z"},
    {"until": "1970-01-01T00:59:59+01:00"},
    {"until": "9000-01-01T00:00:00.000001Z"},
    {"until": "9000-01-01T00:00:00-00:01"},
    {"since": "0001-01-01T00:00:00+14:00"},
    {"until": "9999-12-31T23:59:59-14:00"},
]


@pytest.mark.parametrize(
    "params",
    [
        {"limit": "0"},
        {"limit": str(MAX_PAGE_SIZE + 1)},
        {"limit": "-1"},
        {"limit": "1.5"},
        {"limit": " 5"},
        {"limit": "٣"},
        {"limit": "99999"},
        {"limit": ""},
        {"since": "yesterday"},
        {"since": "2026-11-01"},  # no offset
        {"since": "2026-11-01T00:00:00"},  # naive
        {"since": "2026-13-01T00:00:00Z"},
        {"until": "x" * 100},
        {"since": "2026-11-02T00:00:00Z", "until": "2026-11-01T00:00:00Z"},
        {"since": "2026-11-01T00:00:00Z", "until": "2026-11-01T00:00:00Z"},
        *OUT_OF_RANGE,
        {"check_id": "SPF"},
        {"check_id": "a b"},
        {"check_id": "a" * 97},
        {"check_id": ""},
        {"cursor": "x"},
        {"unknown": "1"},
    ],
)
def test_runs_rejects_malformed_params(world: World, params: dict[str, str]) -> None:
    with pytest.raises(HistoryInvalid):
        world.service("owner").runs(world.domains["a"], params, "en")


@pytest.mark.parametrize(
    "params",
    [
        {"bucket": "week"},
        {"bucket": ""},
        {"limit": "5"},
        {"cursor": "x"},
        {"since": "bad"},
        {"since": "2026-11-02T00:00:00Z", "until": "2026-11-01T00:00:00Z"},
        *OUT_OF_RANGE,
        {"bucket": "hour", "since": "9999-12-31T23:30:00Z", "until": "9999-12-31T23:40:00Z"},
    ],
)
def test_trend_rejects_malformed_params(world: World, params: dict[str, str]) -> None:
    with pytest.raises(HistoryInvalid):
        world.service("owner").trend(world.domains["a"], params)


@pytest.mark.parametrize(
    "params",
    [{"limit": "0"}, {"limit": "201"}, {"cursor": "!"}, {"check_id": "spf"}, {"x": "1"}],
)
def test_snapshots_reject_malformed_params(world: World, params: dict[str, str]) -> None:
    with pytest.raises(HistoryInvalid):
        world.service("owner").snapshots(world.domains["a"], params)


@pytest.mark.parametrize(
    "params",
    [
        {"since": "1970-01-01T00:00:00Z"},
        {"until": "9000-01-01T00:00:00Z"},
        {"since": "1970-01-01T00:00:00Z", "until": "9000-01-01T00:00:00Z"},
        {"since": "1970-01-01T01:00:00+01:00", "until": "1970-01-02T00:00:00Z"},
    ],
)
def test_bounds_are_inclusive(world: World, params: dict[str, str]) -> None:
    service = world.service("owner")
    assert service.runs(world.domains["a"], params, "en")["items"] == []
    assert service.trend(world.domains["a"], params)["buckets"]


def test_trend_default_window_before_the_minimum_is_fine(world: World) -> None:
    # `until` at the lower bound: the default `since` (until - 7 days) is before 1970, no error.
    out = world.service("owner").trend(world.domains["a"], {"until": "1970-01-01T00:00:00Z"})
    assert out["window"]["until"] == "1970-01-01T00:00:00+00:00"
    assert len(out["buckets"]) == 7


class _EndOfTimeClock:
    def now(self) -> datetime:
        return datetime(9999, 12, 31, 23, 30, tzinfo=UTC)


def test_trend_arithmetic_overflow_is_invalid_not_a_crash(world: World) -> None:
    # Not reachable through the parser bounds; the guard still turns an overflow into a 422.
    service = world.service("owner")
    service._clock = _EndOfTimeClock()
    with pytest.raises(HistoryInvalid):
        service.trend(world.domains["a"], {})


# --- runs ---------------------------------------------------------------------------------------


def test_runs_pagination_walks_every_run_once(world: World) -> None:
    ids = [
        seed_run(world, world.domains["a"], world.tenant_a, at=NOW - timedelta(minutes=i))
        for i in range(7)
    ]
    svc = world.service("owner")
    seen: list[int] = []
    params: dict[str, str] = {"limit": "3"}
    for _ in range(5):
        page = svc.runs(world.domains["a"], params, "en")
        seen += [i["id"] for i in page["items"]]
        if page["next_cursor"] is None:
            break
        params = {"limit": "3", "cursor": page["next_cursor"]}
    assert seen == ids  # newest first == insertion order here (decreasing started_at)
    assert page["next_cursor"] is None


def test_runs_same_instant_is_ordered_by_id(world: World) -> None:
    ids = [seed_run(world, world.domains["a"], world.tenant_a) for _ in range(4)]
    svc = world.service("owner")
    first = svc.runs(world.domains["a"], {"limit": "2"}, "en")
    second = svc.runs(world.domains["a"], {"limit": "2", "cursor": first["next_cursor"]}, "en")
    assert [i["id"] for i in first["items"] + second["items"]] == sorted(ids, reverse=True)
    assert second["next_cursor"] is None


def test_runs_cursor_of_another_domain_is_refused(world: World) -> None:
    for i in range(3):
        seed_run(world, world.domains["a"], world.tenant_a, at=NOW - timedelta(minutes=i))
    page = world.service("owner").runs(world.domains["a"], {"limit": "1"}, "en")
    with pytest.raises(HistoryInvalid):
        world.service("owner").runs(world.domains["a2"], {"cursor": page["next_cursor"]}, "en")


def test_runs_window_and_check_filter(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    seed_run(world, d, t, check_id="spf", at=NOW - timedelta(days=3))
    keep = seed_run(world, d, t, check_id="dmarc", at=NOW - timedelta(days=1))
    seed_run(world, d, t, check_id="spf", at=NOW - timedelta(days=1))
    page = world.service("owner").runs(
        d,
        {
            "check_id": "dmarc",
            "since": (NOW - timedelta(days=2)).isoformat(),
            "until": NOW.isoformat().replace("+00:00", "Z"),
        },
        "en",
    )
    assert [i["id"] for i in page["items"]] == [keep]
    assert page["window"]["capped"] is False


def test_runs_wide_window_is_capped_to_the_maximum(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    seed_run(world, d, t, at=NOW - timedelta(days=500))
    recent = seed_run(world, d, t, at=NOW - timedelta(days=10))
    page = world.service("owner").runs(
        d,
        {"since": (NOW - timedelta(days=3000)).isoformat(), "until": NOW.isoformat()},
        "en",
    )
    assert [i["id"] for i in page["items"]] == [recent]
    assert page["window"]["capped"] is True
    assert page["window"]["max_days"] == MAX_WINDOW.days
    assert page["window"]["since"] == (NOW - MAX_WINDOW).isoformat()


def test_runs_render_findings_for_the_language(world: World) -> None:
    findings = [
        {"code": "SPF_TOO_MANY_LOOKUPS", "params": {"count": 11, "limit": 10}},
        {"code": "LEGACY_GONE", "params": {}},
    ]
    seed_run(world, world.domains["a"], world.tenant_a, status="fail", findings=findings)
    item = world.service("owner").runs(world.domains["a"], {}, "it")["items"][0]
    by_code = {f["code"]: f for f in item["findings"]}
    title = i18n.t("finding.SPF_TOO_MANY_LOOKUPS.title", "it")
    assert by_code["SPF_TOO_MANY_LOOKUPS"]["title"] == title
    assert by_code["LEGACY_GONE"]["title"] is None


def test_runs_never_include_other_tenants_rows(world: World) -> None:
    seed_run(world, world.domains["b"], world.tenant_b)
    own = seed_run(world, world.domains["a"], world.tenant_a)
    page = world.service("owner").runs(world.domains["a"], {}, "en")
    assert [i["id"] for i in page["items"]] == [own]
    with pytest.raises(MonitorNotFound):
        world.service("owner").check_read(world.domains["b"])


# --- trend --------------------------------------------------------------------------------------


def test_trend_buckets_are_utc_aligned_and_cover_the_window(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    seed_run(world, d, t, status="ok", at=datetime(2026, 11, 16, 0, 0, tzinfo=UTC))
    seed_run(world, d, t, status="fail", at=datetime(2026, 11, 16, 23, 59, 59, tzinfo=UTC))
    seed_run(world, d, t, status="warn", check_id="dmarc", at=datetime(2026, 11, 17, 8, tzinfo=UTC))
    out = world.service("owner").trend(
        d, {"since": "2026-11-15T23:30:00Z", "until": "2026-11-17T09:00:00Z"}
    )
    starts = [b["start"] for b in out["buckets"]]
    assert starts == [
        "2026-11-15T00:00:00+00:00",
        "2026-11-16T00:00:00+00:00",
        "2026-11-17T00:00:00+00:00",
    ]
    nov15, nov16, nov17 = out["buckets"]
    assert nov15["runs"] == 0 and nov15["checks"] == {}
    assert nov16["counts"] == {"ok": 1, "info": 0, "warn": 0, "fail": 1, "error": 0}
    # The check's status is that of its LATEST run in the bucket.
    assert nov16["checks"] == {"spf": {"status": "fail", "runs": 2}}
    assert nov17["checks"] == {"dmarc": {"status": "warn", "runs": 1}}
    assert out["window"]["capped"] is False


def test_trend_offsets_are_converted_to_utc(world: World) -> None:
    out = world.service("owner").trend(
        world.domains["a"],
        {"bucket": "hour", "since": "2026-11-17T10:30:00+02:00", "until": "2026-11-17T09:30:00Z"},
    )
    assert [b["start"] for b in out["buckets"]] == [
        "2026-11-17T08:00:00+00:00",
        "2026-11-17T09:00:00+00:00",
    ]


def test_trend_run_exactly_on_until_is_excluded(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    seed_run(world, d, t, at=datetime(2026, 11, 17, 9, tzinfo=UTC))
    out = world.service("owner").trend(
        d, {"bucket": "hour", "since": "2026-11-17T08:00:00Z", "until": "2026-11-17T09:00:00Z"}
    )
    assert sum(b["runs"] for b in out["buckets"]) == 0


def test_trend_defaults_to_seven_days_ending_now(world: World) -> None:
    out = world.service("owner").trend(world.domains["a"], {})
    assert out["bucket"] == "day"
    assert len(out["buckets"]) == 8  # 7 days back from 12:30 touches 8 UTC days
    assert out["window"]["until"] == "2026-11-18T00:00:00+00:00"


def test_trend_bucket_cap_keeps_the_newest_buckets(world: World) -> None:
    out = world.service("owner").trend(
        world.domains["a"],
        {"bucket": "hour", "since": "2026-01-01T00:00:00Z", "until": "2026-11-17T00:00:00Z"},
    )
    assert len(out["buckets"]) == MAX_BUCKETS
    assert out["window"]["capped"] is True
    assert out["window"]["max_buckets"] == MAX_BUCKETS
    assert out["buckets"][-1]["start"] == "2026-11-16T23:00:00+00:00"
    assert out["buckets"][0]["start"] == "2026-10-27T04:00:00+00:00"


def test_trend_day_window_is_capped_by_the_maximum_window(world: World) -> None:
    out = world.service("owner").trend(
        world.domains["a"], {"since": "2000-01-01T00:00:00Z", "until": "2026-11-17T00:00:00Z"}
    )
    assert len(out["buckets"]) == MAX_WINDOW.days
    assert out["window"]["capped"] is True


def test_trend_scan_cap_drops_the_oldest_partial_bucket(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(history, "MAX_TREND_RUNS", 5)
    d, t = world.domains["a"], world.tenant_a
    for day in range(1, 5):
        for minute in range(2):
            seed_run(world, d, t, at=datetime(2026, 11, day, 10, minute, tzinfo=UTC))
    out = world.service("owner").trend(
        d, {"since": "2026-11-01T00:00:00Z", "until": "2026-11-05T00:00:00Z"}
    )
    assert out["window"]["truncated"] is True
    # The 5 newest runs are read: days 4, 3 and one of day 2; day 2 is incomplete and dropped.
    assert [b["start"][:10] for b in out["buckets"]] == ["2026-11-03", "2026-11-04"]
    assert [b["runs"] for b in out["buckets"]] == [2, 2]


def test_trend_other_tenant_runs_never_counted(world: World) -> None:
    seed_run(world, world.domains["b"], world.tenant_b)
    out = world.service("owner").trend(world.domains["a"], {})
    assert sum(b["runs"] for b in out["buckets"]) == 0


# --- M7-12b: the repository aggregation answers exactly like the M7-12 scan ---------------------


def _legacy_trend(service: HistoryService, domain_id: int, params: Mapping[str, str]) -> Any:
    """The M7-12 trend (full CheckRun rows paged with list_for_domain, bucketed here), kept
    verbatim as the reference of the equivalence tests below."""
    check_id = history._check_id(params.get("check_id"))
    unit = params.get("bucket", history.DEFAULT_BUCKET)
    size = history.BUCKETS[unit]
    until = history._moment(params.get("until")) or service._clock.now().astimezone(UTC)
    since = history._moment(params.get("since")) or until - history.DEFAULT_TREND_WINDOW
    first, end = history._floor(since, size), history._ceil(until, size)
    capped = False
    limit_buckets = min(MAX_BUCKETS, MAX_WINDOW // size)
    if (end - first) // size > limit_buckets:
        first, capped = end - limit_buckets * size, True
    starts = [first + i * size for i in range(int((end - first) // size))]
    repo = service._repos().check_runs
    runs: list[Any] = []
    cursor = None
    truncated = False
    while True:
        page = repo.list_for_domain(
            domain_id,
            check_id=check_id,
            since=first,
            until=end,
            limit=min(1000, history.MAX_TREND_RUNS - len(runs)),
            cursor=cursor,
        )
        runs.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            break
        if len(runs) >= history.MAX_TREND_RUNS:
            truncated = True
            break
    if truncated:
        first = history._floor(runs[-1].started_at, size) + size
        starts = [s for s in starts if s >= first]
        runs = [r for r in runs if r.started_at >= first]
    buckets: list[dict[str, Any]] = [
        {"start": s.isoformat(), "runs": 0, "counts": dict.fromkeys(STATUSES, 0), "checks": {}}
        for s in starts
    ]
    index = {s: i for i, s in enumerate(starts)}
    for run in runs:
        slot = buckets[index[history._floor(run.started_at, size)]]
        slot["runs"] += 1
        slot["counts"][run.status] += 1
        entry = slot["checks"].setdefault(run.check_id, {"status": run.status, "runs": 0})
        entry["runs"] += 1
    return {
        "bucket": unit,
        "buckets": buckets,
        "window": {
            "since": starts[0].isoformat() if starts else first.isoformat(),
            "until": end.isoformat(),
            "capped": capped,
            "truncated": truncated,
            "max_buckets": MAX_BUCKETS,
            "max_days": MAX_WINDOW.days,
        },
    }


_H0 = datetime(2026, 11, 17, 9, tzinfo=UTC)
_US = timedelta(microseconds=1)
# (offset from _H0, check, status, domain key, tenant key)
_EQUIV_RUNS: list[tuple[timedelta, str, str, str, str]] = [
    (timedelta(0), "spf", "ok", "a", "a"),  # exactly on the hour / day edge
    (-_US, "spf", "fail", "a", "a"),  # last microsecond of the previous bucket
    (timedelta(minutes=10), "spf", "warn", "a", "a"),
    (timedelta(minutes=10), "spf", "error", "a", "a"),  # tie: higher id is the latest
    (timedelta(minutes=10), "dmarc", "info", "a", "a"),
    (timedelta(minutes=59, seconds=59), "dkim", "ok", "a", "a"),
    (timedelta(hours=1), "dkim", "fail", "a", "a"),
    (timedelta(hours=-9), "spf", "warn", "a", "a"),  # 00:00 UTC: day edge
    (timedelta(hours=-9) - _US, "dmarc", "error", "a", "a"),
    (timedelta(days=-3, minutes=5), "spf", "ok", "a", "a"),
    (timedelta(hours=3), "custom:global:x", "warn", "a", "a"),
    (timedelta(hours=14, minutes=59, seconds=59), "spf", "ok", "a", "a"),  # 23:59:59 UTC
    (timedelta(hours=15), "spf", "fail", "a", "a"),  # next day: outside some windows
    (timedelta(0), "spf", "fail", "a2", "a"),  # same tenant, other domain
    (timedelta(minutes=10), "spf", "fail", "b", "b"),  # other tenant
]


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"bucket": "hour"},
        {"bucket": "hour", "since": "2026-11-17T08:30:00Z", "until": "2026-11-17T10:30:00Z"},
        {"bucket": "hour", "since": "2026-11-17T09:00:00Z", "until": "2026-11-17T10:00:00Z"},
        {"bucket": "hour", "since": "2026-11-17T10:30:00+02:00", "until": "2026-11-17T12:00:00Z"},
        {"since": "2026-11-16T23:59:59.999999Z", "until": "2026-11-18T00:00:00Z"},
        {"since": "2026-11-17T00:00:00Z", "until": "2026-11-17T23:59:59Z"},
        {"since": "2026-11-17T00:00:00Z", "until": "2026-11-18T00:00:00.000001Z"},
        {"since": "2026-11-01T05:00:00-07:00", "until": "2026-11-20T00:00:00Z"},
        {"bucket": "hour", "check_id": "spf"},
        {"check_id": "dmarc", "since": "2026-11-10T00:00:00Z"},
        {"check_id": "nosuch"},
        {"bucket": "hour", "since": "2026-01-01T00:00:00Z", "until": "2026-11-17T12:00:00Z"},
        {"since": "2000-01-01T00:00:00Z", "until": "2026-11-18T00:00:00Z"},
        {"until": "1970-01-01T00:00:00Z"},
        {"since": "2030-01-01T00:00:00Z", "until": "2030-01-03T00:00:00Z"},
    ],
)
@pytest.mark.parametrize("cap", [20000, 9, 4, 1])
def test_trend_matches_the_m7_12_scan(
    world: World, monkeypatch: pytest.MonkeyPatch, params: dict[str, str], cap: int
) -> None:
    monkeypatch.setattr(history, "MAX_TREND_RUNS", cap)
    for delta, check, status, domain, tenant in _EQUIV_RUNS:
        tid = world.tenant_a if tenant == "a" else world.tenant_b
        seed_run(world, world.domains[domain], tid, check_id=check, status=status, at=_H0 + delta)
    service = world.service("owner")
    new = service.trend(world.domains["a"], params)
    assert new == _legacy_trend(service, world.domains["a"], params)
    # Key order is part of the wire format too.
    assert [list(b) for b in new["buckets"]] == [
        ["start", "runs", "counts", "checks"] for _ in new["buckets"]
    ]
    for b in new["buckets"]:
        assert list(b["counts"]) == list(STATUSES)
    legacy = _legacy_trend(service, world.domains["a"], params)
    for b_new, b_old in zip(new["buckets"], legacy["buckets"], strict=True):
        assert list(b_new["checks"]) == list(b_old["checks"])


# --- snapshots and diff -------------------------------------------------------------------------

SPF1 = ("@", "TXT", "ok", ["v=spf1 -all"])
SPF2 = ("@", "TXT", "ok", ["v=spf1 include:_spf.example -all"])
NO_DMARC = ("_dmarc", "TXT", "nodata", [])


def test_snapshot_list_paginates_newest_first(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    ids = [seed_snapshot(world, d, t, [SPF1], at=NOW - timedelta(hours=i)) for i in range(5)]
    seed_snapshot(world, world.domains["b"], world.tenant_b, [SPF1])
    svc = world.service("analyst")
    seen: list[int] = []
    params = {"limit": "2"}
    while True:
        page = svc.snapshots(d, params)
        seen += [i["id"] for i in page["items"]]
        assert all(i["entry_count"] == 1 for i in page["items"])
        if page["next_cursor"] is None:
            break
        params = {"limit": "2", "cursor": page["next_cursor"]}
    assert seen == ids


def test_diff_reports_changes(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    a = seed_snapshot(world, d, t, [SPF1, NO_DMARC], at=NOW - timedelta(hours=2))
    b = seed_snapshot(world, d, t, [SPF2, NO_DMARC])
    out = world.service("owner").diff(d, {"from": str(a), "to": str(b)})
    assert [(c["name"], c["type"], c["kind"]) for c in out["changes"]] == [("@", "TXT", "changed")]
    assert out["changes"][0]["before_values"] == ["v=spf1 -all"]
    assert out["from"]["id"] == a and out["to"]["id"] == b
    same = world.service("owner").diff(d, {"from": str(a), "to": str(a)})
    assert same["changes"] == []


def test_diff_error_entry_is_inconclusive(world: World) -> None:
    d, t = world.domains["a"], world.tenant_a
    a = seed_snapshot(world, d, t, [SPF1], at=NOW - timedelta(hours=2))
    b = seed_snapshot(world, d, t, [("@", "TXT", "error", [])])
    out = world.service("owner").diff(d, {"from": str(a), "to": str(b)})
    assert [c["kind"] for c in out["changes"]] == ["inconclusive"]


@pytest.mark.parametrize("which", ["from", "to"])
@pytest.mark.parametrize("kind", ["missing", "foreign_tenant", "other_domain", "malformed", "huge"])
def test_diff_with_an_unusable_id_is_not_found(world: World, which: str, kind: str) -> None:
    d, t = world.domains["a"], world.tenant_a
    good = seed_snapshot(world, d, t, [SPF1])
    bad = {
        "missing": "999999",
        "foreign_tenant": str(seed_snapshot(world, world.domains["b"], world.tenant_b, [SPF1])),
        "other_domain": str(seed_snapshot(world, world.domains["a2"], t, [SPF1])),
        "malformed": "abc",
        "huge": "9" * 30,
    }[kind]
    params = {"from": str(good), "to": str(good)}
    params[which] = bad
    with pytest.raises(MonitorNotFound):
        world.service("owner").diff(d, params)


@pytest.mark.parametrize(
    "params", [{}, {"from": "1"}, {"to": "1"}, {"from": "1", "to": "2", "x": "3"}]
)
def test_diff_needs_both_ids(world: World, params: dict[str, str]) -> None:
    with pytest.raises(HistoryInvalid):
        world.service("owner").diff(world.domains["a"], params)
