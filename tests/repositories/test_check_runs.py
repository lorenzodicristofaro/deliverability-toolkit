"""M7-07 check run history: the tenant repository (record, get, list, latest, isolation).

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). The schema
is built by Alembic. No network.
"""

import dataclasses
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from app.checks.custom import CustomDnsCheck
from app.checks.models import Finding
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import CheckRun, Tenant
from app.models.check_run import (
    MAX_CHECK_ID_LENGTH,
    MAX_FINDINGS,
    MAX_FINDINGS_BYTES,
    SOURCES,
    STATUSES,
)
from app.models.custom_check import MAX_KEY_LENGTH
from app.models.custom_check import SCOPES as CUSTOM_SCOPES
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.check_runs import (
    CheckRunInvalid,
    CheckRunRecord,
    CheckRunRepository,
    RunCursor,
    normalize_findings,
)

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**31, 2**63, [1], b"1"]


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    session: Session
    tenant_a: int
    tenant_b: int
    domains: dict[str, int]

    def repos(self, tenant: str = "a") -> TenantRepositories:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, None), self.session)

    def repo(self, tenant: str = "a") -> CheckRunRepository:
        return self.repos(tenant).check_runs

    def record(
        self,
        domain: str = "a1",
        tenant: str = "a",
        at: datetime = T0,
        **kw: Any,
    ) -> CheckRunRecord:
        kw.setdefault("check_id", "spf")
        kw.setdefault("status", "ok")
        kw.setdefault("duration_ms", 12)
        kw.setdefault("source", "manual")
        kw.setdefault("findings", [])
        rec = self.repo(tenant).record(self.domains[domain], started_at=at, **kw)
        assert rec is not None
        return rec

    def count(self) -> int:
        """Raw row count (bypassing the repository)."""
        self.session.expire_all()
        return int(self.session.scalar(select(func.count()).select_from(CheckRun)) or 0)


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        session.add_all([ta, tb])
        session.flush()
        a = repo_for(TenantContext(ta.id, None), session).domains
        b = repo_for(TenantContext(tb.id, None), session).domains
        domains = {
            "a1": a.create("a.example").id,
            "a2": a.create("a2.example").id,
            "b1": b.create("b.example").id,
        }
        session.commit()
        yield World(session, ta.id, tb.id, domains)
    finally:
        session.close()


# --- basics ------------------------------------------------------------------------------------


def test_statuses_match_the_check_contract() -> None:
    from typing import get_args

    from app.checks.models import Status

    assert set(STATUSES) == set(get_args(Status))
    assert set(SOURCES) == {"scheduled", "manual"}


def test_repo_for_exposes_check_runs() -> None:
    assert "check_runs" in {f.name for f in dataclasses.fields(TenantRepositories)}


def test_repository_requires_a_tenant_context(world: World) -> None:
    with pytest.raises(TypeError):
        CheckRunRepository(world.tenant_a, world.session)  # type: ignore[arg-type]


def test_record_and_get(world: World) -> None:
    rec = world.record(
        status="warn",
        source="scheduled",
        duration_ms=42,
        findings=[{"code": "SPF_TOO_MANY_LOOKUPS", "params": {"count": 11}}],
    )
    assert (rec.check_id, rec.status, rec.source, rec.duration_ms) == (
        "spf",
        "warn",
        "scheduled",
        42,
    )
    assert rec.started_at == T0 and rec.started_at.utcoffset() == timedelta(0)
    assert rec.findings_truncated is False and len(rec.findings_hash) == 64
    assert [(f.code, dict(f.params)) for f in rec.findings] == [
        ("SPF_TOO_MANY_LOOKUPS", {"count": 11})
    ]
    assert world.repo().get(rec.id) == rec


def test_record_converts_to_utc(world: World) -> None:
    plus2 = timezone(timedelta(hours=2))
    rec = world.record(at=datetime(2026, 11, 17, 14, 0, tzinfo=plus2))
    assert rec.started_at == T0 and rec.started_at.utcoffset() == timedelta(0)


@pytest.mark.parametrize("status", STATUSES)
def test_every_contract_status_is_accepted(world: World, status: str) -> None:
    assert world.record(status=status).status == status


def test_record_accepts_finding_objects_and_stores_codes_and_params_only(world: World) -> None:
    finding = Finding(
        code="SPF_X",
        severity="high",
        title_key="t.key",
        detail_key="d.key",
        params={"b": 1, "a": ["x"]},
        evidence=("v=spf1 secret-looking-text",),
        docs_url="https://example.com/docs",
    )
    rec = world.record(findings=[finding])
    assert [(f.code, dict(f.params)) for f in rec.findings] == [("SPF_X", {"a": ["x"], "b": 1})]
    raw = world.session.execute(text("SELECT findings FROM check_runs")).scalar_one()
    stored = raw if isinstance(raw, list) else json.loads(raw)
    assert stored == [{"code": "SPF_X", "params": {"a": ["x"], "b": 1}}]
    dumped = json.dumps(stored)
    for absent in ("t.key", "d.key", "secret-looking-text", "example.com", "severity"):
        assert absent not in dumped


# --- check ids: every id a check can produce is storable ---------------------------------------


def _custom_id(key: str, scope: object) -> str:
    return CustomDnsCheck(
        check_key=key, kind="dns_exists", definition={}, severity="low", scope=scope
    ).id


def test_check_id_width_covers_every_custom_check_id() -> None:
    longest_key = "k" * MAX_KEY_LENGTH
    ids = [_custom_id(longest_key, scope) for scope in (*CUSTOM_SCOPES, "bogus")]
    assert ids[0] == f"custom:global:{longest_key}"  # the key was accepted, not replaced
    assert max(len(i) for i in ids) <= MAX_CHECK_ID_LENGTH


@pytest.mark.parametrize("scope", CUSTOM_SCOPES)
@pytest.mark.parametrize(
    "key", ["k" * MAX_KEY_LENGTH, "a", "0a_b.c-d" + "z" * (MAX_KEY_LENGTH - 8)]
)
def test_custom_check_ids_with_the_longest_key_are_recorded(
    world: World, scope: str, key: str
) -> None:
    check_id = _custom_id(key, scope)
    assert check_id == f"custom:{scope}:{key}"
    rec = world.record(check_id=check_id)
    assert rec.check_id == check_id
    got = world.repo().get(rec.id)
    assert got is not None and got.check_id == check_id


# --- invalid input -----------------------------------------------------------------------------

GOOD: dict[str, Any] = {
    "check_id": "spf",
    "status": "ok",
    "started_at": T0,
    "duration_ms": 1,
    "source": "manual",
    "findings": [],
}
BAD_VALUES = [
    ("check_id", None, "check_id"),
    ("check_id", "", "check_id"),
    ("check_id", "SPF", "check_id"),
    ("check_id", "a b", "check_id"),
    ("check_id", "x" * (MAX_CHECK_ID_LENGTH + 1), "check_id"),
    ("check_id", "custom:global:" + "k" * 90, "check_id"),
    ("check_id", "custom:global:a b", "check_id"),
    ("check_id", 5, "check_id"),
    ("status", "bogus", "status"),
    ("status", "OK", "status"),
    ("status", None, "status"),
    ("status", 1, "status"),
    ("source", "cron", "source"),
    ("source", None, "source"),
    ("started_at", datetime(2026, 11, 17, 12, 0), "started_at"),
    ("started_at", "2026-11-17", "started_at"),
    ("started_at", None, "started_at"),
    ("duration_ms", -1, "duration_ms"),
    ("duration_ms", True, "duration_ms"),
    ("duration_ms", 1.5, "duration_ms"),
    ("duration_ms", "5", "duration_ms"),
    ("duration_ms", 2**31, "duration_ms"),
    ("findings", None, "findings"),
    ("findings", "x", "findings"),
    ("findings", {"code": "A"}, "findings"),
    ("findings", ["x"], "findings"),
    ("findings", [{"code": "lower"}], "findings"),
    ("findings", [{"code": 5}], "findings"),
    ("findings", [{"params": {}}], "findings"),
    ("findings", [{"code": "A", "params": "x"}], "findings"),
    ("findings", [{"code": "A", "params": {1: "x"}}], "findings"),
    ("findings", [{"code": "A", "params": {"x": object()}}], "findings"),
    ("findings", [{"code": "A", "params": {"x": float("nan")}}], "findings"),
    ("findings", [{"code": "A", "params": {"x": float("inf")}}], "findings"),
    ("findings", [{"code": "A", "params": {"a": {"b": {"c": {"d": {"e": 1}}}}}}], "findings"),
]


@pytest.mark.parametrize(
    ("field", "value", "reported"),
    BAD_VALUES,
    ids=[f"{f}={v!r:.20}" for f, v, _ in BAD_VALUES],
)
def test_bad_values_are_rejected_and_nothing_is_written(
    world: World, field: str, value: object, reported: str
) -> None:
    kwargs = {**GOOD, field: value}
    with pytest.raises(CheckRunInvalid) as exc:
        world.repo().record(world.domains["a1"], **kwargs)
    assert exc.value.field == reported
    assert repr(value) not in str(exc.value) or value in (None, "")
    assert world.count() == 0


@pytest.mark.parametrize("value", MALFORMED_IDS)
def test_malformed_domain_ids_are_a_miss(world: World, value: object) -> None:
    assert world.repo().record(value, **GOOD) is None
    assert world.repo().list_for_domain(value).items == ()
    assert world.repo().latest_per_check(value) == []
    assert world.repo().get(value) is None
    assert world.count() == 0


def test_unknown_domain_is_a_miss(world: World) -> None:
    assert world.repo().record(9999, **GOOD) is None
    assert world.count() == 0


# --- findings: bounded, deterministic ------------------------------------------------------------


def test_hash_is_deterministic_and_order_and_key_order_independent() -> None:
    a = [{"code": "A", "params": {"x": 1, "y": 2}}, {"code": "B", "params": {}}]
    b = [{"code": "B", "params": {}}, {"code": "A", "params": {"y": 2, "x": 1}}]
    ha = normalize_findings(a)
    assert ha == normalize_findings(a) == normalize_findings(b)
    assert ha[2] != normalize_findings([{"code": "A", "params": {"x": 1, "y": 3}}])[2]
    assert ha[2] != normalize_findings([])[2]
    assert (
        normalize_findings([{"code": "A"}])[2]
        == normalize_findings([{"code": "A", "params": {}}])[2]
    )


def test_same_findings_in_two_runs_share_the_hash(world: World) -> None:
    f = [{"code": "A", "params": {"n": 1}}]
    one = world.record(findings=f)
    two = world.record(findings=f, at=T0 + timedelta(hours=1))
    other = world.record(findings=[{"code": "A", "params": {"n": 2}}])
    assert one.findings_hash == two.findings_hash != other.findings_hash


def test_findings_over_the_count_cap_are_truncated_with_a_flag(world: World) -> None:
    findings = [{"code": f"C{i:04d}", "params": {}} for i in range(MAX_FINDINGS + 5)]
    rec = world.record(findings=findings)
    assert rec.findings_truncated is True
    assert len(rec.findings) == MAX_FINDINGS
    assert [f.code for f in rec.findings] == [f"C{i:04d}" for i in range(MAX_FINDINGS)]
    # the hash still covers every finding
    assert rec.findings_hash == normalize_findings(findings)[2]
    assert rec.findings_hash != normalize_findings(findings[:MAX_FINDINGS])[2]


def test_findings_over_the_byte_cap_are_truncated_with_a_flag(world: World) -> None:
    findings = [{"code": f"C{i:03d}", "params": {"text": "x" * 1000}} for i in range(40)]
    rec = world.record(findings=findings)
    assert rec.findings_truncated is True and 0 < len(rec.findings) < 40
    # The cap holds on the text as stored, not on a more compact serialization.
    stored = world.session.execute(
        text("SELECT CAST(findings AS TEXT) FROM check_runs")
    ).scalar_one()
    assert len(stored.encode()) <= MAX_FINDINGS_BYTES
    kept, truncated, _ = normalize_findings(findings)
    assert truncated and stored == json.dumps(kept)
    # and the cap is tight: one more finding would not fit
    assert (
        len(json.dumps(normalize_findings(findings)[0] + [findings[len(kept)]]))
        > MAX_FINDINGS_BYTES
    )


@pytest.mark.parametrize("n_items", [1, 2, 3, 16])
def test_byte_cap_boundary_counts_the_stored_separators(n_items: int) -> None:
    # Items sized so the stored text (with ", " between items) is exactly the cap.
    overhead = len(json.dumps([{"code": "A", "params": {"t": ""}}] * n_items))
    pad = (MAX_FINDINGS_BYTES - overhead) // n_items
    extra = MAX_FINDINGS_BYTES - overhead - pad * n_items
    findings = [
        {"code": "A", "params": {"t": "x" * (pad + (extra if i == 0 else 0))}}
        for i in range(n_items)
    ]
    kept, truncated, _ = normalize_findings(findings)
    assert len(json.dumps(kept)) == MAX_FINDINGS_BYTES and not truncated
    findings[0]["params"]["t"] += "x"  # type: ignore[index]
    kept, truncated, _ = normalize_findings(findings)
    assert truncated and len(json.dumps(kept)) <= MAX_FINDINGS_BYTES


def test_a_single_oversized_finding_is_dropped_with_a_flag(world: World) -> None:
    rec = world.record(findings=[{"code": "BIG", "params": {"t": "x" * (MAX_FINDINGS_BYTES + 1)}}])
    assert rec.findings == () and rec.findings_truncated is True


def test_non_ascii_params_are_bounded_by_bytes() -> None:
    kept, truncated, _ = normalize_findings([{"code": "A", "params": {"t": "è" * 20000}}])
    assert kept == [] and truncated


def test_within_the_caps_nothing_is_truncated(world: World) -> None:
    rec = world.record(
        findings=[{"code": f"C{i}", "params": {"i": i}} for i in range(MAX_FINDINGS)]
    )
    assert rec.findings_truncated is False and len(rec.findings) == MAX_FINDINGS


# --- list: filters, window, keyset pagination ----------------------------------------------------


def _hours(n: int) -> datetime:
    return T0 + timedelta(hours=n)


def test_list_is_newest_first_and_filters_by_check_and_window(world: World) -> None:
    ids = {
        (c, h): world.record(check_id=c, at=_hours(h)).id
        for c in ("spf", "dmarc")
        for h in (0, 1, 2, 3)
    }
    world.record(domain="a2", at=_hours(1))  # another domain
    repo = world.repo()
    d = world.domains["a1"]
    everything = repo.list_for_domain(d).items
    assert [r.started_at for r in everything] == sorted(
        (r.started_at for r in everything), reverse=True
    )
    assert len(everything) == 8 and {r.domain_id for r in everything} == {d}
    spf = repo.list_for_domain(d, check_id="spf").items
    assert [r.id for r in spf] == [ids[("spf", h)] for h in (3, 2, 1, 0)]
    window = repo.list_for_domain(d, check_id="spf", since=_hours(1), until=_hours(3)).items
    assert [r.id for r in window] == [ids[("spf", 2)], ids[("spf", 1)]]  # since incl., until excl.
    assert repo.list_for_domain(d, until=T0).items == ()
    assert repo.list_for_domain(d, check_id="nope").items == ()


def test_keyset_pagination_visits_every_row_once_in_order(world: World) -> None:
    # 9 rows, with ties on started_at (same instant) to exercise the id tie-breaker
    expected: list[int] = []
    for h in (0, 0, 0, 1, 1, 2, 3, 3, 3):
        expected.append(world.record(at=_hours(h)).id)
    ordered = [
        r.id
        for r in sorted(
            world.repo().list_for_domain(world.domains["a1"]).items,
            key=lambda r: (r.started_at, r.id),
            reverse=True,
        )
    ]
    for size in (1, 2, 3, 4, 9, 10):
        seen: list[int] = []
        cursor: RunCursor | None = None
        pages = 0
        while True:
            page = world.repo().list_for_domain(world.domains["a1"], limit=size, cursor=cursor)
            assert len(page.items) <= size
            seen += [r.id for r in page.items]
            pages += 1
            if page.next_cursor is None:
                break
            assert len(page.items) == size
            cursor = page.next_cursor
        assert seen == ordered, size
        assert len(set(seen)) == 9
        assert pages == -(-9 // size)
    assert sorted(expected) == sorted(ordered)


def test_pagination_is_stable_when_newer_rows_arrive_between_pages(world: World) -> None:
    for h in range(4):
        world.record(at=_hours(h))
    first = world.repo().list_for_domain(world.domains["a1"], limit=2)
    world.record(at=_hours(10))  # newer than everything: must not shift the next page
    second = world.repo().list_for_domain(world.domains["a1"], limit=2, cursor=first.next_cursor)
    assert [r.started_at for r in first.items + second.items] == [
        _hours(3),
        _hours(2),
        _hours(1),
        _hours(0),
    ]


def test_pagination_with_filters(world: World) -> None:
    for h in range(6):
        world.record(check_id="spf" if h % 2 == 0 else "dmarc", at=_hours(h))
    d = world.domains["a1"]
    p1 = world.repo().list_for_domain(d, check_id="spf", limit=2)
    p2 = world.repo().list_for_domain(d, check_id="spf", limit=2, cursor=p1.next_cursor)
    assert [r.started_at for r in p1.items + p2.items] == [_hours(4), _hours(2), _hours(0)]
    assert p2.next_cursor is None


BAD_LISTS: list[dict[str, Any]] = [
    {"limit": 0},
    {"limit": -1},
    {"limit": MAX_LIMIT + 1},
    {"limit": True},
    {"limit": "5"},
    {"limit": 1.5},
    {"check_id": "BAD ID"},
    {"since": datetime(2026, 1, 1)},
    {"until": "2026-01-01"},
    {"cursor": (T0, 1)},
    {"cursor": RunCursor(datetime(2026, 1, 1), 1)},
    {"cursor": RunCursor(T0, "1")},  # type: ignore[arg-type]
    {"cursor": RunCursor(T0, True)},
]


@pytest.mark.parametrize("kwargs", BAD_LISTS, ids=[repr(k)[:40] for k in BAD_LISTS])
def test_bad_list_arguments_are_rejected(world: World, kwargs: dict[str, Any]) -> None:
    with pytest.raises((ValueError, CheckRunInvalid)):
        world.repo().list_for_domain(world.domains["a1"], **kwargs)


# --- latest per check ----------------------------------------------------------------------------


def test_latest_per_check(world: World) -> None:
    world.record(check_id="spf", at=_hours(0), status="fail")
    newest_spf = world.record(check_id="spf", at=_hours(2), status="ok")
    world.record(check_id="spf", at=_hours(1), status="warn")
    only_dmarc = world.record(check_id="dmarc", at=_hours(0), status="info")
    world.record(check_id="dkim", at=_hours(5), domain="a2")  # another domain
    latest = world.repo().latest_per_check(world.domains["a1"])
    assert [r.id for r in latest] == [only_dmarc.id, newest_spf.id]  # by check id
    assert world.repo().latest_per_check(world.domains["a2"])[0].check_id == "dkim"


def test_latest_per_check_breaks_ties_by_id(world: World) -> None:
    world.record(at=T0, status="fail")
    second = world.record(at=T0, status="ok")
    assert [r.id for r in world.repo().latest_per_check(world.domains["a1"])] == [second.id]


def test_latest_per_check_with_no_runs(world: World) -> None:
    assert world.repo().latest_per_check(world.domains["a1"]) == []


# --- latest non-error run (M7-10b) ----------------------------------------------------------------


def test_latest_non_error_survives_any_number_of_error_runs(world: World) -> None:
    world.record(check_id="dnsbl", at=_hours(0), status="ok")
    baseline = world.record(check_id="dnsbl", at=_hours(1), status="fail")
    for h in range(2, 2 + MAX_LIMIT + 5):  # more error runs than any page could hold
        world.record(check_id="dnsbl", at=_hours(h), status="error")
    world.record(check_id="spf", at=_hours(5000), status="ok")  # another check
    world.record("a2", check_id="dnsbl", at=_hours(5000), status="ok")  # another domain
    assert world.repo().latest_non_error(world.domains["a1"], "dnsbl") == baseline


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], None),
        (["error"], None),
        (["error", "error"], None),
        (["ok"], 0),
        (["info", "error"], 0),
        (["warn", "fail", "error"], 1),
        (["error", "ok", "error"], 1),
        (["ok", "error", "warn"], 2),
    ],
)
def test_latest_non_error_table(world: World, statuses: list[str], expected: int | None) -> None:
    runs = [world.record(check_id="spf", at=_hours(h), status=s) for h, s in enumerate(statuses)]
    got = world.repo().latest_non_error(world.domains["a1"], "spf")
    assert got == (None if expected is None else runs[expected])


def test_latest_non_error_breaks_ties_by_id(world: World) -> None:
    world.record(at=T0, status="fail")
    second = world.record(at=T0, status="ok")
    world.record(at=T0, status="error")
    assert world.repo().latest_non_error(world.domains["a1"], "spf") == second


@pytest.mark.parametrize("value", MALFORMED_IDS, ids=repr)
def test_latest_non_error_malformed_domain_is_a_miss(world: World, value: object) -> None:
    world.record()
    assert world.repo().latest_non_error(value, "spf") is None


def test_latest_non_error_unknown_domain_is_a_miss(world: World) -> None:
    assert world.repo().latest_non_error(999_999, "spf") is None


@pytest.mark.parametrize("check_id", [None, "", "SPF", "a b", 3, "x" * (MAX_CHECK_ID_LENGTH + 1)])
def test_latest_non_error_rejects_a_malformed_check_id(world: World, check_id: object) -> None:
    with pytest.raises(CheckRunInvalid):
        world.repo().latest_non_error(world.domains["a1"], check_id)


def test_latest_non_error_never_crosses_tenants(world: World) -> None:
    a_run = world.record("a1", "a", check_id="dnsbl", at=_hours(1), status="ok")
    b_run = world.record("b1", "b", check_id="dnsbl", at=_hours(2), status="fail")
    world.record("a1", "a", check_id="dnsbl", at=_hours(3), status="error")
    assert world.repo("a").latest_non_error(world.domains["b1"], "dnsbl") is None
    assert world.repo("b").latest_non_error(world.domains["a1"], "dnsbl") is None
    assert world.repo("a").latest_non_error(world.domains["a1"], "dnsbl") == a_run
    assert world.repo("b").latest_non_error(world.domains["b1"], "dnsbl") == b_run


# --- cross-tenant isolation ----------------------------------------------------------------------


def test_cannot_record_on_another_tenants_domain(world: World) -> None:
    assert world.repo("a").record(world.domains["b1"], **GOOD) is None
    assert world.repo("b").record(world.domains["a1"], **GOOD) is None
    assert world.count() == 0


def test_tenants_cannot_read_list_or_see_latest_of_each_other(world: World) -> None:
    a_run = world.record("a1", "a", check_id="spf", at=_hours(1))
    b_run = world.record("b1", "b", check_id="spf", at=_hours(2))
    assert world.repo("a").get(b_run.id) is None
    assert world.repo("b").get(a_run.id) is None
    assert world.repo("a").get(a_run.id) == a_run
    # listing another tenant's domain, with or without filters, is empty
    for kw in ({}, {"check_id": "spf"}, {"since": T0}, {"until": _hours(99)}):
        assert world.repo("a").list_for_domain(world.domains["b1"], **kw).items == ()
        assert world.repo("b").list_for_domain(world.domains["a1"], **kw).items == ()
    assert [r.id for r in world.repo("a").list_for_domain(world.domains["a1"]).items] == [a_run.id]
    assert world.repo("a").latest_per_check(world.domains["b1"]) == []
    assert world.repo("b").latest_per_check(world.domains["a1"]) == []
    assert [r.id for r in world.repo("b").latest_per_check(world.domains["b1"])] == [b_run.id]


def test_a_cursor_from_another_tenant_leaks_nothing(world: World) -> None:
    for h in range(3):
        world.record("a1", "a", at=_hours(h))
        world.record("b1", "b", at=_hours(h))
    page = world.repo("a").list_for_domain(world.domains["a1"], limit=1)
    assert (
        world.repo("b").list_for_domain(world.domains["a1"], limit=1, cursor=page.next_cursor).items
        == ()
    )
    own = world.repo("b").list_for_domain(world.domains["b1"], limit=10, cursor=page.next_cursor)
    assert {r.domain_id for r in own.items} <= {world.domains["b1"]}


def test_the_database_rejects_a_foreign_domain_even_bypassing_the_repository(
    world: World,
) -> None:
    from sqlalchemy.exc import IntegrityError

    world.session.add(
        CheckRun(
            tenant_id=world.tenant_a,
            domain_id=world.domains["b1"],
            check_id="spf",
            status="ok",
            started_at=T0,
            duration_ms=1,
            source="manual",
            findings=[],
            findings_hash="h",
        )
    )
    with pytest.raises(IntegrityError):
        world.session.flush()
    world.session.rollback()


# --- cascade -------------------------------------------------------------------------------------


def test_domain_delete_cascades_to_runs(world: World) -> None:
    world.record("a1")
    keep = world.record("a2")
    assert world.repos("a").domains.delete(world.domains["a1"]) is True
    world.session.commit()
    assert world.count() == 1
    assert world.repo().get(keep.id) == keep


def test_tenant_delete_cascades_to_runs(world: World) -> None:
    world.record("a1")
    other = world.record("b1", "b")
    world.session.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": world.tenant_a})
    world.session.commit()
    assert world.count() == 1
    assert world.repo("b").get(other.id) == other
