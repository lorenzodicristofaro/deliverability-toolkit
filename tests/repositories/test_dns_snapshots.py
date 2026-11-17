"""M7-08 DNS snapshots: the tenant repository (record, get, latest, list, isolation, bounds).

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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import DnsSnapshot, Tenant
from app.models.dns_snapshot import MAX_ENTRIES, MAX_ENTRIES_BYTES
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.dns_snapshots import (
    DnsSnapshotInvalid,
    DnsSnapshotRecord,
    DnsSnapshotRepository,
)
from app.services.dns_diff import MAX_NAME_LENGTH, build_entry, build_snapshot, to_stored

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**31, 2**63, [1], b"1"]
SNAP = build_snapshot([build_entry("@", "TXT", "ok", ["v=spf1 -all"])])
ENTRIES, _ = to_stored(SNAP)
GOOD: dict[str, Any] = {
    "taken_at": T0,
    "content_hash": SNAP.content_hash,
    "entries": ENTRIES,
    "truncated": False,
}


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

    def repo(self, tenant: str = "a") -> DnsSnapshotRepository:
        return self.repos(tenant).dns_snapshots

    def record(
        self, domain: str = "a1", tenant: str = "a", at: datetime = T0, **kw: Any
    ) -> DnsSnapshotRecord:
        rec = self.repo(tenant).record(self.domains[domain], **{**GOOD, "taken_at": at, **kw})
        assert rec is not None
        return rec

    def count(self) -> int:
        self.session.expire_all()
        return int(self.session.scalar(select(func.count()).select_from(DnsSnapshot)) or 0)


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


def _hours(n: int) -> datetime:
    return T0 + timedelta(hours=n)


# --- basics ------------------------------------------------------------------------------------


def test_repo_for_exposes_dns_snapshots() -> None:
    assert "dns_snapshots" in {f.name for f in dataclasses.fields(TenantRepositories)}


def test_repository_requires_a_tenant_context(world: World) -> None:
    with pytest.raises(TypeError):
        DnsSnapshotRepository(world.tenant_a, world.session)  # type: ignore[arg-type]


def test_record_and_get(world: World) -> None:
    rec = world.record(truncated=True)
    assert rec.taken_at == T0 and rec.taken_at.utcoffset() == timedelta(0)
    assert rec.content_hash == SNAP.content_hash and rec.truncated is True
    assert [dict(e) for e in rec.entries] == ENTRIES
    assert world.repo().get(rec.id) == rec


def test_record_converts_to_utc(world: World) -> None:
    rec = world.record(at=datetime(2026, 11, 17, 14, 0, tzinfo=timezone(timedelta(hours=2))))
    assert rec.taken_at == T0 and rec.taken_at.utcoffset() == timedelta(0)


def test_latest_and_list_are_newest_first_with_a_stable_tiebreak(world: World) -> None:
    first = world.record(at=_hours(1))
    third = world.record(at=_hours(3))
    second = world.record(at=_hours(2))
    tie = world.record(at=_hours(3))
    assert world.repo().latest(world.domains["a1"]) == tie  # same time: the later id wins
    got = world.repo().list_for_domain(world.domains["a1"])
    assert [r.id for r in got] == [tie.id, third.id, second.id, first.id]
    assert [r.id for r in world.repo().list_for_domain(world.domains["a1"], limit=2)] == [
        tie.id,
        third.id,
    ]


def test_latest_is_per_domain_and_none_without_snapshots(world: World) -> None:
    other = world.record("a2", at=_hours(9))
    assert world.repo().latest(world.domains["a1"]) is None
    assert world.repo().latest(world.domains["a2"]) == other
    assert world.repo().list_for_domain(world.domains["a1"]) == []


@pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1, True, 1.5, "5", None])
def test_list_rejects_a_bad_limit(world: World, limit: Any) -> None:
    with pytest.raises(ValueError):
        world.repo().list_for_domain(world.domains["a1"], limit=limit)


@pytest.mark.parametrize("value", MALFORMED_IDS, ids=repr)
def test_malformed_ids_are_a_miss(world: World, value: Any) -> None:
    assert world.repo().record(value, **GOOD) is None
    assert world.repo().get(value) is None
    assert world.repo().latest(value) is None
    assert world.repo().list_for_domain(value) == []
    assert world.count() == 0


def test_unknown_domain_is_a_miss(world: World) -> None:
    assert world.repo().record(999_999, **GOOD) is None
    assert world.count() == 0


# --- validation: nothing is written on a bad value ----------------------------------------------

_BIG_ITEM = {"name": "@", "type": "TXT", "state": "ok", "count": 1, "eh": "a" * 64, "values": []}

BAD = [
    ("content_hash", "content_hash", "A" * 64),
    ("content_hash", "content_hash", "a" * 63),
    ("content_hash", "content_hash", None),
    ("entries", "entries", "not a list"),
    ("entries", "entries", None),
    ("entries", "entries", [1]),
    ("entries", "entries", [[]]),
    ("entries", "entries", [{"x": float("nan")}]),
    ("entries", "entries", [{"x": object()}]),
    ("entries", "entries", [{"x": "a\x00b"}]),
    ("entries", "entries", [{"x": 1}] * (MAX_ENTRIES + 1)),
    ("entries", "entries", [{"x": "y" * (MAX_ENTRIES_BYTES + 1)}]),
    ("entries", "entries", [{"x": "中" * (MAX_ENTRIES_BYTES // 6 + 1)}]),
    ("taken_at", "taken_at", datetime(2026, 11, 17, 12, 0)),
    ("taken_at", "taken_at", "2026-11-17"),
    ("taken_at", "taken_at", None),
    ("truncated", "truncated", 1),
    ("truncated", "truncated", None),
]


@pytest.mark.parametrize(
    ("field", "key", "value"), BAD, ids=[f"{k}-{i}" for i, (_, k, _) in enumerate(BAD)]
)
def test_bad_values_are_rejected_and_nothing_is_written(
    world: World, field: str, key: str, value: Any
) -> None:
    with pytest.raises(DnsSnapshotInvalid) as exc:
        world.repo().record(world.domains["a1"], **{**GOOD, key: value})
    assert exc.value.field == field
    assert world.count() == 0


def test_the_error_never_contains_the_value(world: World) -> None:
    with pytest.raises(DnsSnapshotInvalid) as exc:
        world.repo().record(world.domains["a1"], **{**GOOD, "content_hash": "SECRET-VALUE"})
    assert "SECRET-VALUE" not in str(exc.value)


def test_size_is_measured_on_the_stored_text(world: World) -> None:
    # Just inside the cap as stored: 6 bytes per non-ASCII character in the JSON text.
    overhead = len(json.dumps([{"x": ""}]))
    fits = [{"x": "中" * ((MAX_ENTRIES_BYTES - overhead) // 6)}]
    assert len(json.dumps(fits)) <= MAX_ENTRIES_BYTES
    rec = world.repo().record(world.domains["a1"], **{**GOOD, "entries": fits})
    assert rec is not None and world.repo().get(rec.id) is not None
    over = [{"x": "中" * ((MAX_ENTRIES_BYTES - overhead) // 6 + 1)}]
    assert len(json.dumps(over)) > MAX_ENTRIES_BYTES
    with pytest.raises(DnsSnapshotInvalid):
        world.repo().record(world.domains["a1"], **{**GOOD, "entries": over})


def test_max_entries_and_longest_name_round_trip(world: World) -> None:
    # The longest relative name: a 63-character selector label plus the DKIM suffix.
    entries = [
        build_entry(f"{'s' * 60}{i:03d}._domainkey", "TXT", "nodata", [])
        for i in range(MAX_ENTRIES)
    ]
    assert all(len(e.name) == 63 + len("._domainkey") <= MAX_NAME_LENGTH for e in entries)
    snapshot = build_snapshot(entries)
    stored, _ = to_stored(snapshot)
    rec = world.repo().record(
        world.domains["a1"], **{**GOOD, "content_hash": snapshot.content_hash, "entries": stored}
    )
    assert rec is not None
    got = world.repo().get(rec.id)
    assert got is not None and len(got.entries) == MAX_ENTRIES
    assert got.entries[-1]["name"] == sorted(e.name for e in entries)[-1]


def test_hostile_text_round_trips_as_stored(world: World) -> None:
    value = "‮é中\U0001f600 ' \" \\ ; DROP TABLE dns_snapshots;--"
    entries = [{**ENTRIES[0], "values": [{"h": "a" * 64, "v": value}]}]
    rec = world.repo().record(world.domains["a1"], **{**GOOD, "entries": entries})
    assert rec is not None
    assert world.repo().get(rec.id).entries[0]["values"][0]["v"] == value  # type: ignore[union-attr]


# --- cross-tenant isolation ----------------------------------------------------------------------


def test_another_tenants_domain_behaves_like_a_missing_one(world: World) -> None:
    assert world.repo("b").record(world.domains["a1"], **GOOD) is None
    assert world.count() == 0


def test_reads_never_cross_tenants(world: World) -> None:
    a_snap = world.record("a1", "a", at=_hours(1))
    b_snap = world.record("b1", "b", at=_hours(2))
    assert world.repo("b").get(a_snap.id) is None
    assert world.repo("a").get(b_snap.id) is None
    assert world.repo("b").latest(world.domains["a1"]) is None
    assert world.repo("b").list_for_domain(world.domains["a1"]) == []
    assert [r.id for r in world.repo("b").list_for_domain(world.domains["b1"])] == [b_snap.id]
    assert world.repo("a").latest(world.domains["b1"]) is None


def test_the_database_rejects_a_foreign_domain_even_bypassing_the_repository(
    world: World,
) -> None:
    # Raw insert as tenant B of tenant A's domain: the composite FK refuses it.
    stmt = text(
        "INSERT INTO dns_snapshots (tenant_id, domain_id, taken_at, content_hash, entries) "
        "VALUES (:t, :d, '2026-11-17 10:00:00+00', :h, '[]')"
    )
    with pytest.raises(IntegrityError):
        world.session.execute(stmt, {"t": world.tenant_b, "d": world.domains["a1"], "h": "a" * 64})
    world.session.rollback()


def test_tenant_of_a_persisted_snapshot_cannot_be_changed(world: World) -> None:
    from app.repositories.base import TenantScopeError

    rec = world.record()
    row = world.session.get(DnsSnapshot, rec.id)
    assert row is not None
    with pytest.raises(TenantScopeError):
        row.tenant_id = world.tenant_b
    world.session.rollback()


def test_deleting_a_domain_or_tenant_cascades(world: World) -> None:
    world.record("a1")
    world.record("a2")
    world.record("b1", "b")
    world.session.execute(text("DELETE FROM domains WHERE name = 'a.example'"))
    world.session.commit()
    assert world.count() == 2
    world.session.execute(text("DELETE FROM tenants WHERE slug = 'a'"))
    world.session.commit()
    assert world.count() == 1
