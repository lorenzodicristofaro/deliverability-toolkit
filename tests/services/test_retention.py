"""M7-07 retention of raw check runs: the policy, the setting and `prune_check_runs`.

Fake clock only (`now` is a parameter); no real time dependence. Runs on SQLite and, when
TEST_DATABASE_URL is set, on PostgreSQL. No network.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import (
    CHECK_RUN_RETENTION_DAYS_MAX,
    CHECK_RUN_RETENTION_DAYS_MIN,
    DEFAULT_CHECK_RUN_RETENTION_DAYS,
    DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS,
    DNS_SNAPSHOT_RETENTION_DAYS_MAX,
    DNS_SNAPSHOT_RETENTION_DAYS_MIN,
    ConfigError,
    Settings,
)
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import CheckRun, DnsSnapshot, Domain, Tenant
from app.repositories import check_runs as check_runs_module
from app.repositories import repo_for
from app.repositories.check_runs import CheckRunRetentionRepository
from app.repositories.dns_snapshots import DnsSnapshotRetentionRepository
from app.services.retention import (
    RetentionPolicy,
    policy_from_settings,
    prune_check_runs,
    prune_dns_snapshots,
)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
SECRET = "s3cr3t-value-DO-NOT-LEAK-0123456789abcdef"
ENC = "enc-value-DO-NOT-LEAK-0123456789abcdef-xyz"


# --- the setting and the policy ------------------------------------------------------------------


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.delenv("CHECK_RUN_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("DNS_SNAPSHOT_RETENTION_DAYS", raising=False)
    for name, value in {"SECRET_KEY": SECRET, "ENCRYPTION_KEY": ENC, **env}.items():
        monkeypatch.setenv(name, value)
    return Settings()  # type: ignore[call-arg]


def test_setting_default_and_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _settings(monkeypatch).check_run_retention_days == DEFAULT_CHECK_RUN_RETENTION_DAYS
    for days in (CHECK_RUN_RETENTION_DAYS_MIN, 30, CHECK_RUN_RETENTION_DAYS_MAX):
        s = _settings(monkeypatch, CHECK_RUN_RETENTION_DAYS=str(days))
        assert policy_from_settings(s) == RetentionPolicy(days)


@pytest.mark.parametrize(
    "raw", ["0", "-1", str(CHECK_RUN_RETENTION_DAYS_MAX + 1), "abc", "", "1.5", "NaN"]
)
def test_setting_rejects_out_of_range_and_malformed(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    with pytest.raises(ConfigError) as exc:
        _settings(monkeypatch, CHECK_RUN_RETENTION_DAYS=raw)
    assert exc.value.params == {"name": "CHECK_RUN_RETENTION_DAYS"}


@pytest.mark.parametrize(
    "days",
    [0, -1, CHECK_RUN_RETENTION_DAYS_MAX + 1, True, 1.5, "30", None],
)
def test_policy_rejects_out_of_range_and_malformed(days: Any) -> None:
    with pytest.raises(ValueError):
        RetentionPolicy(days)


# --- pruning -------------------------------------------------------------------------------------


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
    tenants: dict[str, int]
    domains: dict[str, int]

    def add(self, tenant: str, started_at: datetime, check_id: str = "spf") -> int:
        run = repo_for(TenantContext(self.tenants[tenant], None), self.session).check_runs.record(
            self.domains[tenant],
            check_id=check_id,
            status="ok",
            started_at=started_at,
            duration_ms=1,
            source="scheduled",
            findings=[],
        )
        assert run is not None
        return run.id

    def remaining(self) -> list[int]:
        self.session.expire_all()
        return list(self.session.scalars(select(CheckRun.id).order_by(CheckRun.id)))


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        session.add_all([ta, tb])
        session.flush()
        da = repo_for(TenantContext(ta.id, None), session).domains.create("a.example")
        db = repo_for(TenantContext(tb.id, None), session).domains.create("b.example")
        session.commit()
        yield World(session, {"a": ta.id, "b": tb.id}, {"a": da.id, "b": db.id})
    finally:
        session.close()


def test_prune_deletes_old_runs_of_every_tenant_and_keeps_recent(world: World) -> None:
    policy = RetentionPolicy(30)
    old_a = world.add("a", NOW - timedelta(days=31))
    old_b = world.add("b", NOW - timedelta(days=400))
    new_a = world.add("a", NOW - timedelta(days=29))
    new_b = world.add("b", NOW)
    future = world.add("a", NOW + timedelta(days=5))
    assert prune_check_runs(world.session, NOW, policy) == 2
    assert world.remaining() == sorted([new_a, new_b, future])
    assert old_a not in world.remaining() and old_b not in world.remaining()


def test_prune_boundary_is_exactly_now_minus_days(world: World) -> None:
    cutoff = NOW - timedelta(days=30)
    just_before = world.add("a", cutoff - timedelta(microseconds=1))
    on_cutoff = world.add("a", cutoff)
    just_after = world.add("a", cutoff + timedelta(microseconds=1))
    assert prune_check_runs(world.session, NOW, RetentionPolicy(30)) == 1
    assert just_before not in world.remaining()
    assert {on_cutoff, just_after} <= set(world.remaining())


def test_fake_clock_moves_the_window(world: World) -> None:
    world.add("a", NOW - timedelta(days=10))
    policy = RetentionPolicy(30)
    assert prune_check_runs(world.session, NOW, policy) == 0
    assert prune_check_runs(world.session, NOW + timedelta(days=20), policy) == 0  # 30 days old
    assert prune_check_runs(world.session, NOW + timedelta(days=21), policy) == 1
    assert world.remaining() == []


def test_prune_is_idempotent_and_handles_an_empty_table(world: World) -> None:
    policy = RetentionPolicy(1)
    assert prune_check_runs(world.session, NOW, policy) == 0
    world.add("a", NOW - timedelta(days=5))
    assert prune_check_runs(world.session, NOW, policy) == 1
    assert prune_check_runs(world.session, NOW, policy) == 0


def test_prune_works_in_batches(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(check_runs_module, "PRUNE_BATCH", 3)
    for i in range(8):
        world.add("a" if i % 2 else "b", NOW - timedelta(days=60, hours=i))
    keep = world.add("a", NOW)
    assert prune_check_runs(world.session, NOW, RetentionPolicy(30)) == 8
    assert world.remaining() == [keep]


def test_prune_leaves_other_tables_alone(world: World) -> None:
    world.add("a", NOW - timedelta(days=999))
    prune_check_runs(world.session, NOW, RetentionPolicy(1))
    assert world.session.scalar(select(func.count()).select_from(Domain)) == 2
    assert world.session.scalar(select(func.count()).select_from(Tenant)) == 2


@pytest.mark.parametrize("now", [datetime(2026, 11, 17, 12, 0), "2026-11-17", None, 0], ids=repr)
def test_prune_rejects_a_naive_or_malformed_clock(world: World, now: Any) -> None:
    world.add("a", NOW - timedelta(days=999))
    with pytest.raises(ValueError):
        prune_check_runs(world.session, now, RetentionPolicy(1))
    assert len(world.remaining()) == 1


def test_prune_rejects_a_non_policy(world: World) -> None:
    with pytest.raises(TypeError):
        prune_check_runs(world.session, NOW, 30)  # type: ignore[arg-type]


def test_system_repository_is_explicit_and_not_part_of_repo_for(world: World) -> None:
    repos = repo_for(TenantContext(world.tenants["a"], None), world.session)
    assert not hasattr(repos, "check_run_retention")
    assert not hasattr(repos.check_runs, "prune_all_tenants")
    assert hasattr(CheckRunRetentionRepository, "prune_all_tenants")


# --- DNS snapshots (M7-08) -----------------------------------------------------------------------

SNAP_HASH = "a" * 64


def test_snapshot_setting_default_bounds_and_the_longer_than_runs_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    s = _settings(monkeypatch)
    assert s.dns_snapshot_retention_days == DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS
    assert policy_from_settings(s) == RetentionPolicy(90, DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS)
    assert DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS > DEFAULT_CHECK_RUN_RETENTION_DAYS
    for days in (DNS_SNAPSHOT_RETENTION_DAYS_MIN, DNS_SNAPSHOT_RETENTION_DAYS_MAX):
        monkeypatch.setenv("DNS_SNAPSHOT_RETENTION_DAYS", str(days))
        assert Settings().dns_snapshot_retention_days == days  # type: ignore[call-arg]
    # Runs kept longer than the snapshot setting: snapshots are raised to the run window.
    monkeypatch.setenv("DNS_SNAPSHOT_RETENTION_DAYS", "10")
    monkeypatch.setenv("CHECK_RUN_RETENTION_DAYS", "500")
    assert policy_from_settings(Settings()).dns_snapshot_days == 500  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "raw", ["0", "-1", str(DNS_SNAPSHOT_RETENTION_DAYS_MAX + 1), "abc", "", "1.5", "NaN"]
)
def test_snapshot_setting_rejects_out_of_range_and_malformed(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    with pytest.raises(ConfigError) as exc:
        _settings(monkeypatch, DNS_SNAPSHOT_RETENTION_DAYS=raw)
    assert exc.value.params == {"name": "DNS_SNAPSHOT_RETENTION_DAYS"}


def test_policy_resolves_the_snapshot_window_and_never_shortens_it_below_runs() -> None:
    assert RetentionPolicy(30).dns_snapshot_days == DEFAULT_DNS_SNAPSHOT_RETENTION_DAYS
    assert RetentionPolicy(1000).dns_snapshot_days == 1000
    assert RetentionPolicy(30, 30).dns_snapshot_days == 30


@pytest.mark.parametrize(
    "snaps", [0, -1, DNS_SNAPSHOT_RETENTION_DAYS_MAX + 1, True, 1.5, "30", 29], ids=repr
)
def test_policy_rejects_a_bad_snapshot_window(snaps: Any) -> None:
    with pytest.raises(ValueError):
        RetentionPolicy(30, snaps)


class SnapWorld(World):
    def snap(self, tenant: str, taken_at: datetime) -> int:
        repos = repo_for(TenantContext(self.tenants[tenant], None), self.session)
        rec = repos.dns_snapshots.record(
            self.domains[tenant], taken_at=taken_at, content_hash=SNAP_HASH, entries=[]
        )
        assert rec is not None
        return rec.id

    def snaps(self) -> list[int]:
        self.session.expire_all()
        return list(self.session.scalars(select(DnsSnapshot.id).order_by(DnsSnapshot.id)))


@pytest.fixture
def swold(world: World) -> SnapWorld:
    return SnapWorld(world.session, world.tenants, world.domains)


def test_snapshots_outlive_runs_with_the_same_clock(swold: SnapWorld) -> None:
    policy = RetentionPolicy(30)  # snapshots: 365 days
    swold.add("a", NOW - timedelta(days=40))
    old = swold.snap("a", NOW - timedelta(days=100))
    newer = swold.snap("a", NOW - timedelta(days=100) + timedelta(hours=1))
    assert prune_check_runs(swold.session, NOW, policy) == 1
    assert swold.snaps() == [old, newer]  # 100 days: past the run window, inside the snapshot one
    assert prune_dns_snapshots(swold.session, NOW, policy) == 0
    assert prune_dns_snapshots(swold.session, NOW + timedelta(days=266), policy) == 1
    assert swold.snaps() == [newer]  # the newest of the domain is the baseline: it stays


def test_prune_snapshots_every_tenant_and_keeps_the_newest_per_domain(swold: SnapWorld) -> None:
    policy = RetentionPolicy(30, 60)
    old_a = swold.snap("a", NOW - timedelta(days=200))
    old_b = swold.snap("b", NOW - timedelta(days=300))
    new_a = swold.snap("a", NOW - timedelta(days=59))
    only_old_b = swold.snap("b", NOW - timedelta(days=100))  # newer than old_b, still too old
    assert prune_dns_snapshots(swold.session, NOW, policy) == 2
    assert swold.snaps() == sorted([new_a, only_old_b])
    assert old_a not in swold.snaps() and old_b not in swold.snaps()
    # Idempotent: the last snapshot of each domain is never pruned, however old.
    assert prune_dns_snapshots(swold.session, NOW + timedelta(days=9999), policy) == 0
    assert swold.snaps() == sorted([new_a, only_old_b])


def test_prune_snapshots_boundary_and_equal_times(swold: SnapWorld) -> None:
    policy = RetentionPolicy(30, 60)
    cutoff = NOW - timedelta(days=60)
    just_before = swold.snap("a", cutoff - timedelta(microseconds=1))
    on_cutoff = swold.snap("a", cutoff)
    tie_1 = swold.snap("a", NOW)
    tie_2 = swold.snap("a", NOW)
    assert prune_dns_snapshots(swold.session, NOW, policy) == 1
    assert just_before not in swold.snaps()
    assert {on_cutoff, tie_1, tie_2} == set(swold.snaps())
    # With equal times the later id is the newest; only older rows are ever removed.
    assert prune_dns_snapshots(swold.session, NOW + timedelta(days=61), policy) == 2
    assert swold.snaps() == [tie_2]


def test_prune_snapshots_in_batches(swold: SnapWorld, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.repositories import dns_snapshots as module

    monkeypatch.setattr(module, "PRUNE_BATCH", 3)
    for i in range(8):
        swold.snap("a" if i % 2 else "b", NOW - timedelta(days=400, hours=i))
    keep_a = swold.snap("a", NOW)
    keep_b = swold.snap("b", NOW)
    assert prune_dns_snapshots(swold.session, NOW, RetentionPolicy(30)) == 8
    assert swold.snaps() == sorted([keep_a, keep_b])


def test_prune_snapshots_leaves_other_tables_alone(swold: SnapWorld) -> None:
    swold.add("a", NOW - timedelta(days=999))
    swold.snap("a", NOW - timedelta(days=999))
    swold.snap("a", NOW - timedelta(days=998))
    prune_dns_snapshots(swold.session, NOW, RetentionPolicy(1, 1))
    assert len(swold.snaps()) == 1 and len(swold.remaining()) == 1
    assert swold.session.scalar(select(func.count()).select_from(Domain)) == 2


@pytest.mark.parametrize("now", [datetime(2026, 11, 17, 12, 0), "2026-11-17", None, 0], ids=repr)
def test_prune_snapshots_rejects_a_naive_or_malformed_clock(swold: SnapWorld, now: Any) -> None:
    swold.snap("a", NOW - timedelta(days=999))
    swold.snap("a", NOW - timedelta(days=998))
    with pytest.raises(ValueError):
        prune_dns_snapshots(swold.session, now, RetentionPolicy(1, 1))
    assert len(swold.snaps()) == 2


def test_prune_snapshots_rejects_a_non_policy(swold: SnapWorld) -> None:
    with pytest.raises(TypeError):
        prune_dns_snapshots(swold.session, NOW, 30)  # type: ignore[arg-type]


def test_snapshot_system_repository_is_explicit_and_not_part_of_repo_for(swold: SnapWorld) -> None:
    repos = repo_for(TenantContext(swold.tenants["a"], None), swold.session)
    assert not hasattr(repos, "dns_snapshot_retention")
    assert not hasattr(repos.dns_snapshots, "prune_all_tenants")
    assert hasattr(DnsSnapshotRetentionRepository, "prune_all_tenants")
