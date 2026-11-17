"""M7-06 monitor targets: the tenant repository and the scheduler's `due_targets`.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). The schema
is built by Alembic. No network.
"""

import dataclasses
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from app.checks.registry import load_builtin_checks
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import MonitorTarget, Tenant
from app.models.monitor_target import ALLOWED_INTERVALS_SECONDS, MIN_INTERVAL_SECONDS
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.monitor_targets import (
    DueTarget,
    MonitorSchedulerRepository,
    MonitorTargetExists,
    MonitorTargetInvalid,
    MonitorTargetRecord,
    MonitorTargetRepository,
)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**31, 2**63, [1], b"1"]
CHECKS = ["spf", "dmarc"]


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

    def repo(self, tenant: str = "a") -> MonitorTargetRepository:
        return self.repos(tenant).monitor_targets

    def create(
        self, domain: str, tenant: str = "a", at: datetime = NOW, **kw: Any
    ) -> MonitorTargetRecord:
        kw.setdefault("check_ids", CHECKS)
        kw.setdefault("interval_seconds", 3600)
        rec = self.repo(tenant).create(self.domains[domain], next_run_at=at, **kw)
        assert rec is not None
        return rec

    def rows(self) -> list[tuple[int, int]]:
        """(tenant_id, domain_id) of every row (raw read, bypassing the repository)."""
        self.session.expire_all()
        stmt = select(MonitorTarget.tenant_id, MonitorTarget.domain_id).order_by(MonitorTarget.id)
        return [(r[0], r[1]) for r in self.session.execute(stmt).all()]


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
            "a3": a.create("a3.example").id,
            "b1": b.create("b.example").id,
            "b2": b.create("b2.example").id,
        }
        session.commit()
        yield World(session, ta.id, tb.id, domains)
    finally:
        session.close()


# --- basics ------------------------------------------------------------------------------------


def test_constants_and_registry() -> None:
    assert min(ALLOWED_INTERVALS_SECONDS) == MIN_INTERVAL_SECONDS
    assert load_builtin_checks().all_ids()  # the allowlist is not empty


def test_repo_for_exposes_monitor_targets() -> None:
    assert "monitor_targets" in {f.name for f in dataclasses.fields(TenantRepositories)}


def test_repository_requires_a_tenant_context(world: World) -> None:
    with pytest.raises(TypeError):
        MonitorTargetRepository(world.tenant_a, world.session)  # type: ignore[arg-type]


def test_create_get_list(world: World) -> None:
    rec = world.create("a1", check_ids=["spf", "dkim"], interval_seconds=21600)
    assert rec.check_ids == ("dkim", "spf")  # stored sorted
    assert rec.interval_seconds == 21600 and rec.enabled is True
    assert rec.next_run_at == NOW and rec.last_run_at is None and rec.last_status is None
    assert rec.created_at is not None and rec.updated_at is not None
    assert world.repo().get(rec.id) == rec
    assert world.repo().get_for_domain(world.domains["a1"]) == rec
    world.create("a2")
    assert [r.domain_id for r in world.repo().list()] == [world.domains["a1"], world.domains["a2"]]
    assert world.repo().list(limit=1, offset=1)[0].domain_id == world.domains["a2"]


def test_create_converts_to_utc(world: World) -> None:
    plus2 = timezone(timedelta(hours=2))
    rec = world.create("a1", at=datetime(2026, 11, 17, 14, 0, tzinfo=plus2))
    assert rec.next_run_at == NOW and rec.next_run_at.utcoffset() == timedelta(0)


def test_one_target_per_domain(world: World) -> None:
    world.create("a1")
    with pytest.raises(MonitorTargetExists):
        world.repo().create(
            world.domains["a1"], check_ids=CHECKS, interval_seconds=3600, next_run_at=NOW
        )
    assert len(world.rows()) == 1


def test_update_changes_only_given_fields(world: World) -> None:
    rec = world.create("a1")
    later = NOW + timedelta(hours=1)
    upd = world.repo().update(
        rec.id,
        enabled=False,
        interval_seconds=86400,
        last_run_at=NOW,
        last_status="warn",
        next_run_at=later,
        check_ids=["dkim"],
    )
    assert upd is not None
    assert (upd.enabled, upd.interval_seconds, upd.last_status) == (False, 86400, "warn")
    assert (upd.last_run_at, upd.next_run_at, upd.check_ids) == (NOW, later, ("dkim",))
    assert upd.domain_id == rec.domain_id
    partial = world.repo().update(rec.id, last_status=None)
    assert partial is not None and partial.last_status is None and partial.enabled is False
    assert partial.interval_seconds == 86400


def test_delete(world: World) -> None:
    rec = world.create("a1")
    assert world.repo().delete(rec.id) is True
    assert world.repo().get(rec.id) is None
    assert world.repo().delete(rec.id) is False
    assert world.rows() == []


# --- validation --------------------------------------------------------------------------------

BAD_CHECK_IDS: list[tuple[Any, str]] = [
    (None, "not_a_list"),
    ("spf", "not_a_list"),
    ({"spf"}, "not_a_list"),
    ([], "empty"),
    ([1], "not_a_string"),
    (["spf", None], "not_a_string"),
    (["spf", "spf"], "duplicate"),
    (["nope"], "unknown_check"),
    (["spf", "nope"], "unknown_check"),
    (["SPF"], "unknown_check"),
    ([""], "unknown_check"),
]
BAD_INTERVALS: list[tuple[Any, str]] = [
    (None, "not_an_int"),
    ("3600", "not_an_int"),
    (3600.0, "not_an_int"),
    (True, "not_an_int"),
    (0, "not_allowed"),
    (-3600, "not_allowed"),
    (MIN_INTERVAL_SECONDS - 1, "not_allowed"),
    (MIN_INTERVAL_SECONDS + 1, "not_allowed"),
    (2**63, "not_allowed"),
]


@pytest.mark.parametrize(("value", "reason"), BAD_CHECK_IDS, ids=repr)
def test_create_rejects_bad_check_ids(world: World, value: Any, reason: str) -> None:
    with pytest.raises(MonitorTargetInvalid) as exc:
        world.repo().create(
            world.domains["a1"], check_ids=value, interval_seconds=3600, next_run_at=NOW
        )
    assert (exc.value.field, exc.value.reason) == ("check_ids", reason)
    assert world.rows() == []


@pytest.mark.parametrize(("value", "reason"), BAD_INTERVALS, ids=repr)
def test_create_rejects_bad_interval(world: World, value: Any, reason: str) -> None:
    with pytest.raises(MonitorTargetInvalid) as exc:
        world.repo().create(
            world.domains["a1"], check_ids=CHECKS, interval_seconds=value, next_run_at=NOW
        )
    assert (exc.value.field, exc.value.reason) == ("interval_seconds", reason)
    assert world.rows() == []


@pytest.mark.parametrize("interval", ALLOWED_INTERVALS_SECONDS)
def test_every_allowed_interval_is_accepted(world: World, interval: int) -> None:
    assert world.create("a1", interval_seconds=interval).interval_seconds == interval


@pytest.mark.parametrize("check_id", load_builtin_checks().all_ids())
def test_every_registry_check_is_accepted(world: World, check_id: str) -> None:
    assert world.create("a1", check_ids=[check_id]).check_ids == (check_id,)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("enabled", 1, "not_a_bool"),
        ("enabled", "true", "not_a_bool"),
        ("enabled", None, "not_a_bool"),
        ("next_run_at", None, "not_aware"),
        ("next_run_at", "2026-11-17T12:00:00Z", "not_aware"),
        ("next_run_at", datetime(2026, 11, 17, 12, 0), "not_aware"),
    ],
    ids=repr,
)
def test_create_rejects_bad_scalars(world: World, field: str, value: Any, reason: str) -> None:
    kw: dict[str, Any] = {"check_ids": CHECKS, "interval_seconds": 3600, "next_run_at": NOW}
    kw[field] = value
    with pytest.raises(MonitorTargetInvalid) as exc:
        world.repo().create(world.domains["a1"], **kw)
    assert (exc.value.field, exc.value.reason) == (field, reason)
    assert world.rows() == []


@pytest.mark.parametrize(
    ("kwargs", "field"),
    [
        ({"check_ids": ["nope"]}, "check_ids"),
        ({"check_ids": []}, "check_ids"),
        ({"interval_seconds": 60}, "interval_seconds"),
        ({"enabled": "yes"}, "enabled"),
        ({"next_run_at": datetime(2026, 1, 1)}, "next_run_at"),
        ({"last_run_at": datetime(2026, 1, 1)}, "last_run_at"),
        ({"last_run_at": None}, "last_run_at"),
        ({"last_status": "bogus"}, "last_status"),
        ({"last_status": 3}, "last_status"),
    ],
    ids=repr,
)
def test_update_rejects_bad_values_and_changes_nothing(
    world: World, kwargs: dict[str, Any], field: str
) -> None:
    rec = world.create("a1")
    with pytest.raises(MonitorTargetInvalid) as exc:
        world.repo().update(rec.id, **kwargs)
    assert exc.value.field == field
    assert world.repo().get(rec.id) == rec


def test_update_cannot_touch_tenant_or_domain(world: World) -> None:
    rec = world.create("a1")
    for key in ("tenant_id", "domain_id", "id"):
        with pytest.raises(TypeError):
            world.repo().update(rec.id, **{key: 1})


@pytest.mark.parametrize("bad", MALFORMED_IDS, ids=repr)
def test_malformed_ids_behave_like_missing(world: World, bad: Any) -> None:
    kw: dict[str, Any] = {"check_ids": CHECKS, "interval_seconds": 3600, "next_run_at": NOW}
    assert world.repo().get(bad) is None
    assert world.repo().get_for_domain(bad) is None
    assert world.repo().update(bad, enabled=False) is None
    assert world.repo().delete(bad) is False
    assert world.repo().create(bad, **kw) is None
    assert world.rows() == []


@pytest.mark.parametrize(
    ("limit", "offset"), [(-1, 0), (MAX_LIMIT + 1, 0), (True, 0), ("1", 0), (1, -1), (1, True)]
)
def test_list_rejects_bad_paging(world: World, limit: Any, offset: Any) -> None:
    with pytest.raises(ValueError):
        world.repo().list(limit=limit, offset=offset)


# --- tenant isolation ----------------------------------------------------------------------------


def test_domain_of_another_tenant_is_rejected_at_insert(world: World) -> None:
    assert (
        world.repo("a").create(
            world.domains["b1"], check_ids=CHECKS, interval_seconds=3600, next_run_at=NOW
        )
        is None
    )
    assert world.rows() == []


def test_unknown_domain_is_rejected_at_insert(world: World) -> None:
    assert (
        world.repo().create(999, check_ids=CHECKS, interval_seconds=3600, next_run_at=NOW) is None
    )
    assert world.rows() == []


def test_tenant_cannot_read_another_tenants_targets(world: World) -> None:
    b = world.create("b1", tenant="b")
    assert world.repo("a").get(b.id) is None
    assert world.repo("a").get_for_domain(world.domains["b1"]) is None
    assert world.repo("a").list() == []
    assert world.repo("b").get(b.id) == b
    assert world.repo("b").list() == [b]


def test_tenant_cannot_update_another_tenants_target(world: World) -> None:
    b = world.create("b1", tenant="b")
    assert world.repo("a").update(b.id, enabled=False, interval_seconds=86400) is None
    assert world.repo("b").get(b.id) == b


def test_tenant_cannot_delete_another_tenants_target(world: World) -> None:
    b = world.create("b1", tenant="b")
    assert world.repo("a").delete(b.id) is False
    assert world.repo("b").get(b.id) == b
    assert world.rows() == [(world.tenant_b, world.domains["b1"])]


def test_each_tenant_sees_only_its_own_targets(world: World) -> None:
    a = world.create("a1")
    b = world.create("b1", tenant="b")
    assert world.repo("a").list() == [a]
    assert world.repo("b").list() == [b]
    assert world.repo("a").get_for_domain(world.domains["a1"]) == a


def test_rows_are_written_with_the_context_tenant(world: World) -> None:
    world.create("a1")
    world.create("b1", tenant="b")
    assert world.rows() == [
        (world.tenant_a, world.domains["a1"]),
        (world.tenant_b, world.domains["b1"]),
    ]


# --- cascades through the repository path --------------------------------------------------------


def test_domain_delete_cascades(world: World) -> None:
    world.create("a1")
    world.create("a2")
    world.create("b1", tenant="b")
    world.session.commit()
    assert world.repos().domains.delete(world.domains["a1"])
    world.session.commit()
    assert world.rows() == [
        (world.tenant_a, world.domains["a2"]),
        (world.tenant_b, world.domains["b1"]),
    ]


def test_tenant_delete_cascades(world: World) -> None:
    world.create("a1")
    world.create("b1", tenant="b")
    world.session.commit()
    world.session.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": world.tenant_a})
    world.session.commit()
    assert world.rows() == [(world.tenant_b, world.domains["b1"])]


# --- due_targets -------------------------------------------------------------------------------


def _scheduler(world: World) -> MonitorSchedulerRepository:
    return MonitorSchedulerRepository(world.session)


def test_due_targets_filters_orders_limits_and_carries_tenant(world: World) -> None:
    t = timedelta
    late = world.create("a1", at=NOW - t(minutes=1))
    oldest = world.create("b1", tenant="b", at=NOW - t(hours=3))
    on_the_dot = world.create("a2", at=NOW)
    world.create("a3", at=NOW + t(seconds=1))  # not yet due
    world.create("b2", tenant="b", at=NOW - t(hours=9), enabled=False)  # disabled
    due = _scheduler(world).due_targets(NOW, 10)
    assert [d.id for d in due] == [oldest.id, late.id, on_the_dot.id]
    assert [d.tenant_id for d in due] == [world.tenant_b, world.tenant_a, world.tenant_a]
    assert due[0] == DueTarget(
        id=oldest.id,
        tenant_id=world.tenant_b,
        domain_id=world.domains["b1"],
        check_ids=oldest.check_ids,
        interval_seconds=3600,
        next_run_at=oldest.next_run_at,
    )
    assert [d.id for d in _scheduler(world).due_targets(NOW, 2)] == [oldest.id, late.id]
    assert [d.id for d in _scheduler(world).due_targets(NOW, 1)] == [oldest.id]


def test_due_targets_ties_are_ordered_by_id(world: World) -> None:
    first = world.create("a1")
    second = world.create("b1", tenant="b")
    third = world.create("a2")
    assert [d.id for d in _scheduler(world).due_targets(NOW, 10)] == [
        first.id,
        second.id,
        third.id,
    ]


def test_due_targets_rebuilds_a_tenant_context(world: World) -> None:
    b = world.create("b1", tenant="b")
    (due,) = _scheduler(world).due_targets(NOW, 10)
    ctx = TenantContext(due.tenant_id, None)
    assert repo_for(ctx, world.session).monitor_targets.get(due.id) == b
    other = repo_for(TenantContext(world.tenant_a, None), world.session)
    assert other.monitor_targets.get(due.id) is None


def test_due_targets_follows_updates(world: World) -> None:
    rec = world.create("a1")
    assert len(_scheduler(world).due_targets(NOW, 10)) == 1
    world.repo().update(rec.id, next_run_at=NOW + timedelta(hours=1))
    assert _scheduler(world).due_targets(NOW, 10) == []
    world.repo().update(rec.id, next_run_at=NOW, enabled=False)
    assert _scheduler(world).due_targets(NOW, 10) == []


def test_due_targets_compares_in_utc(world: World) -> None:
    world.create("a1", at=NOW)
    plus2 = timezone(timedelta(hours=2))
    assert _scheduler(world).due_targets(datetime(2026, 11, 17, 13, 59, tzinfo=plus2), 10) == []
    assert len(_scheduler(world).due_targets(datetime(2026, 11, 17, 14, 0, tzinfo=plus2), 10)) == 1


def test_due_targets_empty(world: World) -> None:
    assert _scheduler(world).due_targets(NOW, 10) == []


@pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1, True, None, "5", 1.0])
def test_due_targets_rejects_bad_limit(world: World, limit: Any) -> None:
    with pytest.raises(ValueError):
        _scheduler(world).due_targets(NOW, limit)


@pytest.mark.parametrize("now", [None, "2026-11-17", datetime(2026, 11, 17), 0])
def test_due_targets_rejects_bad_now(world: World, now: Any) -> None:
    with pytest.raises(MonitorTargetInvalid):
        _scheduler(world).due_targets(now, 10)


def test_due_targets_and_claim_are_the_only_public_cross_tenant_methods() -> None:
    public = {n for n in vars(MonitorSchedulerRepository) if not n.startswith("_")}
    assert public == {"due_targets", "claim"}


# --- claim (M7-09) -----------------------------------------------------------------------------

LATER = NOW + timedelta(hours=1)


def _next_run(world: World, target_id: int) -> datetime:
    world.session.expire_all()
    rec = world.repo("a").get(target_id) or world.repo("b").get(target_id)
    assert rec is not None
    return rec.next_run_at


def test_claim_moves_next_run_once(world: World) -> None:
    rec = world.create("b1", tenant="b")
    (due,) = _scheduler(world).due_targets(NOW, 10)
    assert _scheduler(world).claim(due.id, due.next_run_at, LATER) is True
    assert _next_run(world, rec.id) == LATER
    # A second claim with the value read before the first one loses.
    assert _scheduler(world).claim(due.id, due.next_run_at, LATER + timedelta(hours=1)) is False
    assert _next_run(world, rec.id) == LATER
    assert _scheduler(world).due_targets(NOW, 10) == []


def test_claim_changes_nothing_else(world: World) -> None:
    rec = world.create("a1", check_ids=["spf"], interval_seconds=21600)
    assert _scheduler(world).claim(rec.id, rec.next_run_at, LATER)
    world.session.expire_all()
    after = world.repo().get(rec.id)
    assert after is not None
    assert (after.check_ids, after.interval_seconds, after.enabled, after.domain_id) == (
        rec.check_ids,
        rec.interval_seconds,
        rec.enabled,
        rec.domain_id,
    )
    assert after.last_run_at is None and after.last_status is None


def test_claim_accepts_other_offsets(world: World) -> None:
    rec = world.create("a1")
    plus2 = timezone(timedelta(hours=2))
    assert _scheduler(world).claim(rec.id, NOW.astimezone(plus2), LATER.astimezone(plus2))
    assert _next_run(world, rec.id) == LATER


def test_claim_loses_on_disabled_deleted_or_moved_targets(world: World) -> None:
    disabled = world.create("a1", enabled=False)
    assert _scheduler(world).claim(disabled.id, NOW, LATER) is False
    moved = world.create("a2")
    world.repo().update(moved.id, next_run_at=NOW + timedelta(minutes=5))
    assert _scheduler(world).claim(moved.id, NOW, LATER) is False
    gone = world.create("a3")
    world.repo().delete(gone.id)
    assert _scheduler(world).claim(gone.id, NOW, LATER) is False


@pytest.mark.parametrize("target_id", MALFORMED_IDS)
def test_claim_malformed_id_is_a_miss(world: World, target_id: Any) -> None:
    world.create("a1")
    assert _scheduler(world).claim(target_id, NOW, LATER) is False


@pytest.mark.parametrize("bad", [None, "2026-11-17", datetime(2026, 11, 17), 0])
def test_claim_rejects_naive_or_bad_datetimes(world: World, bad: Any) -> None:
    rec = world.create("a1")
    with pytest.raises(MonitorTargetInvalid):
        _scheduler(world).claim(rec.id, bad, LATER)
    with pytest.raises(MonitorTargetInvalid):
        _scheduler(world).claim(rec.id, NOW, bad)
    assert _next_run(world, rec.id) == NOW


def test_concurrent_claims_have_exactly_one_winner(world: World, engine: Engine) -> None:
    """Two schedulers (own sessions, own connections) read the same due target, then claim it
    at the same time from two threads: exactly one UPDATE wins."""
    rec = world.create("a1")
    world.session.commit()
    factory = create_session_factory(engine)
    sessions = [factory(), factory()]
    try:
        dues = [MonitorSchedulerRepository(s).due_targets(NOW, 10) for s in sessions]
        for s in sessions:
            s.commit()  # the reads are done; each claim runs in its own transaction
        assert [d[0].id for d in dues] == [rec.id, rec.id]
        barrier = threading.Barrier(2)

        def claim(i: int) -> bool:
            barrier.wait(timeout=10)
            won = MonitorSchedulerRepository(sessions[i]).claim(
                rec.id, dues[i][0].next_run_at, LATER + timedelta(minutes=i)
            )
            sessions[i].commit()
            return won

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, [0, 1]))
    finally:
        for s in sessions:
            s.close()
    assert sorted(results) == [False, True]
    assert _next_run(world, rec.id) == LATER + timedelta(minutes=results.index(True))
