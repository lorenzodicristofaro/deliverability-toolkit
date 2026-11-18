"""M7-14 alert repositories: alerts (idempotent insert, streams), deliveries (idempotent add,
conditional claim / sent / failed), rules, validation and tenant isolation.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). The schema
is built by Alembic. No network.
"""

from __future__ import annotations

import dataclasses
import hashlib
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Alert, AlertDelivery, Tenant
from app.repositories import TenantRepositories, repo_for
from app.repositories.alerts import (
    INVALID_ERROR,
    AlertDeliveryRepository,
    AlertInvalid,
    AlertReleaseRepository,
    AlertRepository,
    AlertRuleRepository,
    error_code,
)
from app.repositories.base import MAX_LIMIT

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**31, 2**63, [1], b"1"]


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


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

    def repos(self, tenant: str = "a", session: Session | None = None) -> TenantRepositories:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return repo_for(TenantContext(tid, None), session or self.session)

    def insert(self, domain: str = "a1", tenant: str = "a", **kw: Any) -> Any:
        kw.setdefault("kind", "new_listing")
        kw.setdefault("stream", h("stream"))
        kw.setdefault("fingerprint", h("fp"))
        kw.setdefault("state_hash", h("state"))
        kw.setdefault("code", "ALERT_NEW_LISTING")
        kw.setdefault("params", {"subject": "list.example"})
        kw.setdefault("suppressed", False)
        kw.setdefault("created_at", T0)
        return self.repos(tenant).alerts.insert_if_absent(self.domains[domain], **kw)

    def alert(self, **kw: Any) -> Any:
        rec = self.insert(**kw)
        assert rec is not None
        return rec

    def count(self, model: Any) -> int:
        self.session.expire_all()
        return int(self.session.scalar(select(func.count()).select_from(model)) or 0)


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


def test_repo_for_exposes_the_alert_repositories() -> None:
    names = {f.name for f in dataclasses.fields(TenantRepositories)}
    assert {"alerts", "alert_deliveries", "alert_rules"} <= names


@pytest.mark.parametrize("cls", [AlertRepository, AlertDeliveryRepository, AlertRuleRepository])
def test_repositories_require_a_tenant_context(world: World, cls: Any) -> None:
    with pytest.raises(TypeError):
        cls(world.tenant_a, world.session)


def test_insert_and_get(world: World) -> None:
    rec = world.alert(params={"subject": "zen", "after": "listed"})
    world.session.commit()
    got = world.repos().alerts.get(rec.id)
    assert got == rec
    assert got.kind == "new_listing" and got.params == {"subject": "zen", "after": "listed"}
    assert got.created_at == T0 and got.suppressed is False


def test_insert_is_idempotent_on_fingerprint_and_state_hash(world: World) -> None:
    first = world.alert()
    assert world.insert() is None  # same (tenant, fingerprint, state_hash)
    assert world.insert(params={"subject": "other"}, created_at=T0 + timedelta(1)) is None
    other = world.alert(state_hash=h("next position"))
    assert other.id != first.id
    world.session.commit()
    assert world.count(Alert) == 2


def test_same_key_in_two_tenants_is_two_alerts(world: World) -> None:
    world.alert()
    world.alert(domain="b1", tenant="b")
    world.session.commit()
    assert world.count(Alert) == 2


@pytest.mark.parametrize("bad", MALFORMED_IDS, ids=repr)
def test_insert_on_a_malformed_domain_is_none(world: World, bad: object) -> None:
    assert (
        world.repos().alerts.insert_if_absent(
            bad,
            kind="new_listing",
            stream=h("s"),
            fingerprint=h("f"),
            state_hash=h("x"),
            code="ALERT_NEW_LISTING",
            params={},
            suppressed=False,
            created_at=T0,
        )
        is None
    )


def test_insert_on_a_foreign_domain_is_none(world: World) -> None:
    assert world.insert(domain="b1", tenant="a") is None
    world.session.commit()
    assert world.count(Alert) == 0


INVALID = [
    ("kind", "bogus"),
    ("kind", None),
    ("kind", 1),
    ("stream", "short"),
    ("stream", "G" * 64),
    ("stream", h("x").upper()),
    ("stream", None),
    ("fingerprint", ""),
    ("fingerprint", h("x") + "\n"),
    ("state_hash", 123),
    ("code", "lower_case"),
    ("code", "A" * 65),
    ("code", "ALERT X"),
    ("code", None),
    ("params", None),
    ("params", ["subject"]),
    ("params", {"subject": 1}),
    ("params", {"subject": "x" * 513}),
    ("params", {"": "x"}),
    ("params", {"k" * 33: "x"}),
    ("params", {1: "x"}),
    ("params", {f"k{i}": "x" for i in range(9)}),
    ("params", {"nested": {"a": "b"}}),
    ("suppressed", 1),
    ("suppressed", None),
    ("created_at", datetime(2026, 1, 1)),
    ("created_at", "2026-01-01"),
]


@pytest.mark.parametrize(("field", "value"), INVALID, ids=[f"{f}={v!r}"[:60] for f, v in INVALID])
def test_insert_rejects_malformed_values(world: World, field: str, value: object) -> None:
    with pytest.raises(AlertInvalid) as info:
        world.insert(**{field: value})
    assert info.value.field == field


def test_latest_in_stream_and_last_unsuppressed(world: World) -> None:
    repo = world.repos().alerts
    assert repo.latest_in_stream(world.domains["a1"], h("stream")) is None
    first = world.alert(created_at=T0)
    second = world.alert(state_hash=h("2"), suppressed=True, created_at=T0 + timedelta(1))
    world.alert(stream=h("other"), state_hash=h("3"), fingerprint=h("fp3"))
    world.session.commit()
    latest = repo.latest_in_stream(world.domains["a1"], h("stream"))
    assert latest is not None and latest.id == second.id
    assert repo.last_unsuppressed_at(h("fp")) == first.created_at
    assert repo.last_unsuppressed_at(h("unknown")) is None
    assert repo.latest_in_stream(world.domains["a2"], h("stream")) is None
    with pytest.raises(AlertInvalid):
        repo.latest_in_stream(world.domains["a1"], "nope")
    with pytest.raises(AlertInvalid):
        repo.last_unsuppressed_at("nope")


@pytest.mark.parametrize("bad", MALFORMED_IDS, ids=repr)
def test_reads_with_malformed_ids_are_empty(world: World, bad: object) -> None:
    repos = world.repos()
    assert repos.alerts.get(bad) is None
    assert repos.alerts.list_for_domain(bad) == []
    assert repos.alerts.latest_in_stream(bad, h("stream")) is None
    assert repos.alert_deliveries.get(bad) is None
    assert repos.alert_deliveries.for_alert(bad) == []
    assert repos.alert_deliveries.add_pending(bad, [1], T0) == []


@pytest.mark.parametrize("limit", [0, -1, MAX_LIMIT + 1, 10**6, "5", 2.0, None, True])
def test_list_limit_is_validated(world: World, limit: object) -> None:
    with pytest.raises(AlertInvalid):
        world.repos().alerts.list_for_domain(world.domains["a1"], limit=limit)  # type: ignore[arg-type]


# --- tenant isolation --------------------------------------------------------------------------


def test_tenant_b_sees_nothing_of_tenant_a(world: World) -> None:
    alert = world.alert()
    delivery = world.repos().alert_deliveries.add_pending(alert.id, [7], T0)[0]
    world.repos().alert_rules.add("new_listing", 7)
    world.session.commit()
    b = world.repos("b")
    assert b.alerts.get(alert.id) is None
    assert b.alerts.list_for_domain(world.domains["a1"]) == []
    assert b.alerts.latest_in_stream(world.domains["a1"], h("stream")) is None
    assert b.alerts.last_unsuppressed_at(h("fp")) is None
    assert b.alert_deliveries.get(delivery.id) is None
    assert b.alert_deliveries.for_alert(alert.id) == []
    assert b.alert_deliveries.due(T0) == []
    assert b.alert_deliveries.add_pending(alert.id, [8], T0) == []
    assert b.alert_deliveries.claim(delivery.id, 0, T0, T0 + timedelta(minutes=5)) is False
    assert b.alert_deliveries.mark_sent(delivery.id, 0, T0) is False
    assert b.alert_deliveries.mark_failed(delivery.id, 0, "timeout", None) is False
    assert b.alert_rules.list_all() == []
    assert b.alert_rules.channels_for("new_listing") == []
    assert b.alert_rules.remove("new_listing", 7) is False
    world.session.commit()
    # Tenant A's rows are untouched by tenant B's attempts.
    a = world.repos()
    assert a.alert_deliveries.get(delivery.id) == delivery
    assert len(a.alert_deliveries.for_alert(alert.id)) == 1
    assert a.alert_rules.channels_for("new_listing") == [7]


def test_moving_an_alert_to_another_tenant_is_refused(world: World) -> None:
    alert = world.alert()
    world.session.commit()
    row = world.session.get(Alert, alert.id)
    assert row is not None
    with pytest.raises(Exception):  # noqa: B017 - tenant guard or FK, both refuse
        row.tenant_id = world.tenant_b
        world.session.flush()
    world.session.rollback()


# --- deliveries --------------------------------------------------------------------------------


def test_add_pending_is_idempotent(world: World) -> None:
    alert = world.alert()
    repo = world.repos().alert_deliveries
    created = repo.add_pending(alert.id, [3, 1, 3], T0)
    assert [(d.channel_id, d.status, d.attempts, d.next_attempt_at) for d in created] == [
        (1, "pending", 0, T0),
        (3, "pending", 0, T0),
    ]
    assert repo.add_pending(alert.id, [1, 3], T0 + timedelta(1)) == []
    assert [d.channel_id for d in repo.add_pending(alert.id, [2, 3], T0)] == [2]
    assert repo.add_pending(alert.id, [], T0) == []
    world.session.commit()
    assert world.count(AlertDelivery) == 3


@pytest.mark.parametrize("bad", [[0], [-1], ["1"], [None], [2**31], [True]], ids=repr)
def test_add_pending_rejects_malformed_channels(world: World, bad: list[object]) -> None:
    alert = world.alert()
    with pytest.raises(AlertInvalid):
        world.repos().alert_deliveries.add_pending(alert.id, bad, T0)


def test_due_claim_sent(world: World) -> None:
    alert = world.alert()
    repo = world.repos().alert_deliveries
    d = repo.add_pending(alert.id, [1], T0)[0]
    assert repo.due(T0 - timedelta(seconds=1)) == []
    assert [x.id for x in repo.due(T0)] == [d.id]
    lease = T0 + timedelta(minutes=5)
    assert repo.claim(d.id, 0, T0, lease) is True
    assert repo.claim(d.id, 0, T0, lease) is False  # attempt count moved on
    assert repo.claim(d.id, 1, T0, lease) is False  # leased: not due before the lease ends
    assert repo.due(T0) == []
    assert repo.mark_sent(d.id, 0, T0) is False  # stale attempt
    assert repo.mark_sent(d.id, 1, T0) is True
    got = repo.get(d.id)
    assert got is not None and (got.status, got.attempts, got.sent_at) == ("sent", 1, T0)
    assert got.next_attempt_at is None
    # A sent delivery never moves again, whatever a stale worker does.
    assert repo.mark_failed(d.id, 1, "timeout", lease) is False
    assert repo.mark_sent(d.id, 1, T0) is False
    assert repo.claim(d.id, 1, lease, lease) is False
    assert repo.due(lease + timedelta(days=1)) == []


def test_failed_then_abandoned(world: World) -> None:
    alert = world.alert()
    repo = world.repos().alert_deliveries
    d = repo.add_pending(alert.id, [1], T0)[0]
    assert repo.claim(d.id, 0, T0, T0 + timedelta(minutes=5))
    retry = T0 + timedelta(minutes=1)
    assert repo.mark_failed(d.id, 1, "timeout", retry) is True
    got = repo.get(d.id)
    assert got is not None and (got.status, got.last_error, got.next_attempt_at) == (
        "failed",
        "timeout",
        retry,
    )
    assert [x.id for x in repo.due(retry)] == [d.id]
    assert repo.claim(d.id, 1, retry, retry + timedelta(minutes=5))
    assert repo.mark_failed(d.id, 2, "Bearer s3cr3t token", None) is True
    got = repo.get(d.id)
    assert got is not None and (got.status, got.last_error, got.next_attempt_at) == (
        "abandoned",
        INVALID_ERROR,
        None,
    )
    assert repo.due(retry + timedelta(days=1)) == []


def test_mark_abandoned_is_guarded_like_mark_sent(world: World) -> None:
    alert = world.alert()
    repo = world.repos().alert_deliveries
    d = repo.add_pending(alert.id, [1], T0)[0]
    assert repo.mark_abandoned(d.id, 1, "http_4xx") is False  # not claimed yet
    assert repo.claim(d.id, 0, T0, T0 + timedelta(minutes=5))
    assert repo.mark_abandoned(d.id, 0, "http_4xx") is False  # stale attempt count
    assert repo.mark_abandoned(d.id, 1, "http_4xx") is True
    got = repo.get(d.id)
    assert got is not None and (got.status, got.attempts, got.last_error) == (
        "abandoned",
        1,
        "http_4xx",
    )
    assert got.next_attempt_at is None
    assert repo.mark_abandoned(d.id, 1, "http_4xx") is False  # already final
    assert repo.mark_sent(d.id, 1, T0) is False
    other = repo.add_pending(world.alert(state_hash=h("2")).id, [1], T0)[0]
    assert repo.claim(other.id, 0, T0, T0 + timedelta(minutes=5))
    assert repo.mark_sent(other.id, 1, T0) is True
    assert repo.mark_abandoned(other.id, 1, "http_4xx") is False  # a sent one never moves
    assert repo.mark_abandoned(other.id, 1, "Bearer s3cr3t") is False


def test_due_order_and_limit(world: World) -> None:
    repo = world.repos().alert_deliveries
    a1 = world.alert()
    a2 = world.alert(state_hash=h("2"))
    late = repo.add_pending(a1.id, [1], T0 + timedelta(minutes=2))[0]
    early = repo.add_pending(a2.id, [1], T0)[0]
    now = T0 + timedelta(minutes=3)
    assert [d.id for d in repo.due(now)] == [early.id, late.id]
    assert [d.id for d in repo.due(now, limit=1)] == [early.id]
    with pytest.raises(AlertInvalid):
        repo.due(datetime(2026, 1, 1))
    with pytest.raises(AlertInvalid):
        repo.due(now, limit=0)


@pytest.mark.parametrize(
    ("args"),
    [(None, 0), ("1", 0), (1, -1), (1, "0"), (1, None), (1, True)],
    ids=repr,
)
def test_conditional_updates_reject_malformed_arguments(
    world: World, args: tuple[Any, Any]
) -> None:
    repo = world.repos().alert_deliveries
    with pytest.raises(AlertInvalid):
        repo.mark_sent(args[0], args[1], T0)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("timeout", "timeout"),
        ("http_5xx", "http_5xx"),
        ("tls.handshake-failed", "tls.handshake-failed"),
        ("", INVALID_ERROR),
        ("Timeout", INVALID_ERROR),
        ("has space", INVALID_ERROR),
        ("x" * 65, INVALID_ERROR),
        ("token=abc\n", INVALID_ERROR),
        (None, INVALID_ERROR),
        (500, INVALID_ERROR),
        ("_leading", INVALID_ERROR),
    ],
    ids=repr,
)
def test_error_code_never_stores_free_text(value: object, expected: str) -> None:
    assert error_code(value) == expected


def test_alert_delete_cascades_to_deliveries(world: World) -> None:
    alert = world.alert()
    world.repos().alert_deliveries.add_pending(alert.id, [1, 2], T0)
    world.session.commit()
    row = world.session.get(Alert, alert.id)
    world.session.delete(row)
    world.session.commit()
    assert world.count(AlertDelivery) == 0


# --- rules -------------------------------------------------------------------------------------


def test_rules_add_list_remove(world: World) -> None:
    rules = world.repos().alert_rules
    assert rules.channels_for("new_listing") == []  # default: no delivery
    first = rules.add("new_listing", 5)
    assert rules.add("new_listing", 5) == first  # idempotent
    rules.add("new_listing", 2)
    rules.add("record_changed", 5)
    assert rules.channels_for("new_listing") == [2, 5]
    assert rules.channels_for("listing_cleared") == []
    assert [(r.kind, r.channel_id) for r in rules.list_all()] == [
        ("new_listing", 2),
        ("new_listing", 5),
        ("record_changed", 5),
    ]
    assert rules.remove("new_listing", 5) is True
    assert rules.remove("new_listing", 5) is False
    assert rules.channels_for("new_listing") == [2]


@pytest.mark.parametrize(
    ("kind", "channel"),
    [("bogus", 1), (None, 1), ("new_listing", 0), ("new_listing", "1"), ("new_listing", None)],
    ids=repr,
)
def test_rules_reject_malformed_values(world: World, kind: object, channel: object) -> None:
    rules = world.repos().alert_rules
    with pytest.raises(AlertInvalid):
        rules.add(kind, channel)
    with pytest.raises(AlertInvalid):
        rules.remove(kind, channel)


# --- concurrency -------------------------------------------------------------------------------


def test_concurrent_inserts_of_the_same_alert_leave_one_row(world: World, engine: Engine) -> None:
    """Two emitters (own sessions, own connections) insert the same alert at the same time from
    two threads: one row, one winner. On SQLite the database serializes the writers (the loser
    may get `database is locked` instead of the conflict); either way one row exists."""
    factory = create_session_factory(engine)
    sessions = [factory(), factory()]
    barrier = threading.Barrier(2)

    def insert(i: int) -> str:
        repos = world.repos(session=sessions[i])
        barrier.wait(timeout=10)
        try:
            rec = repos.alerts.insert_if_absent(
                world.domains["a1"],
                kind="new_listing",
                stream=h("stream"),
                fingerprint=h("fp"),
                state_hash=h("state"),
                code="ALERT_NEW_LISTING",
                params={},
                suppressed=False,
                created_at=T0,
            )
            sessions[i].commit()
        except Exception:  # noqa: BLE001 - SQLite lock contention
            sessions[i].rollback()
            return "error"
        return "won" if rec is not None else "lost"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = sorted(pool.map(insert, [0, 1]))
    finally:
        for s in sessions:
            s.close()
    assert results.count("won") == 1
    if engine.dialect.name == "postgresql":
        assert results == ["lost", "won"]
    assert world.count(Alert) == 1


def test_concurrent_claims_have_exactly_one_winner(world: World, engine: Engine) -> None:
    alert = world.alert()
    d = world.repos().alert_deliveries.add_pending(alert.id, [1], T0)[0]
    world.session.commit()
    factory = create_session_factory(engine)
    sessions = [factory(), factory()]
    barrier = threading.Barrier(2)

    def claim(i: int) -> bool | None:
        repo = world.repos(session=sessions[i]).alert_deliveries
        barrier.wait(timeout=10)
        try:
            won = repo.claim(d.id, 0, T0, T0 + timedelta(minutes=5 + i))
            sessions[i].commit()
        except Exception:  # noqa: BLE001 - SQLite lock contention
            sessions[i].rollback()
            return None
        return won

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, [0, 1]))
    finally:
        for s in sessions:
            s.close()
    assert results.count(True) == 1
    world.session.expire_all()
    got = world.repos().alert_deliveries.get(d.id)
    assert got is not None and got.attempts == 1


# --- suppressed heads (release of suppressed state) ---------------------------------------------


def test_suppressed_stream_heads_and_latest_unsuppressed(world: World) -> None:
    delivered = world.alert(state_hash=h("1"))
    head = world.alert(state_hash=h("2"), fingerprint=h("fp2"), suppressed=True)
    # Another stream whose suppressed alert is no longer its head.
    world.alert(stream=h("s2"), state_hash=h("3"), suppressed=True)
    world.alert(stream=h("s2"), state_hash=h("4"))
    # The same stream key on another domain is another stream.
    other = world.alert(domain="a2", state_hash=h("5"), suppressed=True)
    world.alert(domain="b1", tenant="b", state_hash=h("6"), suppressed=True)
    world.session.commit()
    repo = world.repos().alerts
    assert [a.id for a in repo.suppressed_stream_heads()] == [head.id, other.id]
    assert [a.id for a in repo.suppressed_stream_heads(limit=1)] == [head.id]
    found = repo.latest_unsuppressed_in_stream(world.domains["a1"], h("stream"))
    assert found is not None and found.id == delivered.id
    assert repo.latest_unsuppressed_in_stream(world.domains["a2"], h("stream")) is None
    assert repo.latest_unsuppressed_in_stream("x", h("stream")) is None
    with pytest.raises(AlertInvalid):
        repo.latest_unsuppressed_in_stream(world.domains["a1"], "nope")
    with pytest.raises(AlertInvalid):
        repo.suppressed_stream_heads(limit=0)
    b = world.repos("b").alerts
    assert len(b.suppressed_stream_heads()) == 1
    assert b.latest_unsuppressed_in_stream(world.domains["a1"], h("stream")) is None


# --- cross-tenant release candidates (M7-14c) ---------------------------------------------------

M = timedelta(minutes=1)


def _flapped(world: World, tenant: str, domain: str, start: datetime, tag: str) -> None:
    """fp1 sent at start, fp2 sent at +5 min, fp1 again suppressed at +10 min (the head)."""
    stream = h(f"s-{tag}")
    for i, (fp, suppressed) in enumerate([("1", False), ("2", False), ("1", True)]):
        world.alert(
            tenant=tenant, domain=domain, stream=stream, fingerprint=h(f"{tag}{fp}"),
            state_hash=h(f"{tag}{i}"), suppressed=suppressed, created_at=start + 5 * i * M,
        )  # fmt: skip


def test_tenants_with_suppressed_heads_are_listed_when_due_longest_first(world: World) -> None:
    _flapped(world, "a", "a1", T0, "a")  # due at T0 + 60 min
    _flapped(world, "b", "b1", T0 - 30 * M, "b")  # due at T0 + 30 min
    world.session.commit()
    system = AlertReleaseRepository(world.session)
    hour = timedelta(hours=1)
    a, b = world.tenant_a, world.tenant_b
    assert system.tenants_with_suppressed_heads(T0 + 29 * M, 10, window=hour) == []
    assert system.tenants_with_suppressed_heads(T0 + 30 * M, 10, window=hour) == [b]
    assert system.tenants_with_suppressed_heads(T0 + 60 * M, 10, window=hour) == [b, a]
    assert system.tenants_with_suppressed_heads(T0 + 60 * M, 1, window=hour) == [b]
    # Without a window every head counts, but never one created after `now`.
    assert system.tenants_with_suppressed_heads(T0 + 10 * M, 10) == [b, a]
    assert system.tenants_with_suppressed_heads(T0 + 9 * M, 10) == [b]
    # Released (a newer delivered alert heads the stream): B leaves the set.
    world.alert(
        tenant="b", domain="b1", stream=h("s-b"), fingerprint=h("b1"), state_hash=h("released"),
        created_at=T0 + 31 * M,
    )  # fmt: skip
    world.session.commit()
    assert system.tenants_with_suppressed_heads(T0 + 60 * M, 10, window=hour) == [a]


def test_suppressed_head_equal_to_the_delivered_state_is_not_listed(world: World) -> None:
    world.alert(stream=h("s"), fingerprint=h("x"), state_hash=h("1"), created_at=T0)
    world.alert(stream=h("s"), fingerprint=h("y"), state_hash=h("2"), suppressed=True)
    world.alert(stream=h("s"), fingerprint=h("x"), state_hash=h("3"), suppressed=True)
    world.session.commit()
    system = AlertReleaseRepository(world.session)
    assert system.tenants_with_suppressed_heads(T0 + timedelta(days=1), 10) == []


@pytest.mark.parametrize(
    ("now", "limit", "window"),
    [
        (datetime(2026, 1, 1), 1, timedelta(0)),
        ("2026-01-01T00:00:00Z", 1, timedelta(0)),
        (T0, 0, timedelta(0)),
        (T0, MAX_LIMIT + 1, timedelta(0)),
        (T0, True, timedelta(0)),
        (T0, "5", timedelta(0)),
        (T0, 5, timedelta(seconds=-1)),
        (T0, 5, 60),
    ],
    ids=repr,
)
def test_tenants_with_suppressed_heads_rejects_malformed(
    world: World, now: Any, limit: Any, window: Any
) -> None:
    with pytest.raises(AlertInvalid):
        AlertReleaseRepository(world.session).tenants_with_suppressed_heads(
            now, limit, window=window
        )
