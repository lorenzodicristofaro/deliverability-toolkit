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
    ConfigError,
    Settings,
)
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import CheckRun, Domain, Tenant
from app.repositories import check_runs as check_runs_module
from app.repositories import repo_for
from app.repositories.check_runs import CheckRunRetentionRepository
from app.services.retention import RetentionPolicy, policy_from_settings, prune_check_runs

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
SECRET = "s3cr3t-value-DO-NOT-LEAK-0123456789abcdef"
ENC = "enc-value-DO-NOT-LEAK-0123456789abcdef-xyz"


# --- the setting and the policy ------------------------------------------------------------------


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    monkeypatch.delenv("CHECK_RUN_RETENTION_DAYS", raising=False)
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
