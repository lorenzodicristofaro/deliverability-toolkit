"""M7-05c `DnsblEnablementRepository`: the only access path to `dnsbl_list_enablements`.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). No network.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.models import DnsblListEnablement, User
from app.repositories import DnsblEnablementRepository
from app.repositories.dnsbl_enablement import (
    DnsblEnablementInvalid,
    DnsblEnablementRecord,
    EnablementConflict,
    valid_list_id,
)

NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)


@pytest.fixture
def engine(migrated_db_url: str) -> Iterator[Engine]:
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    session = create_session_factory(engine)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def actor(db: Session) -> int:
    user = User(email="root@example.com", is_instance_admin=True)
    db.add(user)
    db.commit()
    return user.id


def _enable(repo: DnsblEnablementRepository, list_id: Any = "surbl-multi", **kw: Any) -> Any:
    args: dict[str, Any] = {
        "actor": None,
        "policy_acknowledged": True,
        "unverified_confirmed": False,
        "now": NOW,
    }
    args.update(kw)
    return repo.enable(list_id, **args)


def _rows(db: Session) -> list[tuple[Any, ...]]:
    db.expire_all()
    found = db.execute(
        select(
            DnsblListEnablement.list_id,
            DnsblListEnablement.enabled_by,
            DnsblListEnablement.policy_acknowledged,
            DnsblListEnablement.unverified_confirmed,
        ).order_by(DnsblListEnablement.list_id)
    ).all()
    return [tuple(r) for r in found]


# --- reads and writes ----------------------------------------------------------------------------


def test_empty_table(db: Session) -> None:
    repo = DnsblEnablementRepository(db)
    assert repo.enabled_ids() == frozenset()
    assert repo.records() == []
    assert repo.get("surbl-multi") is None


def test_enable_get_records_and_ids(db: Session, actor: int) -> None:
    repo = DnsblEnablementRepository(db)
    record = _enable(repo, actor=actor, unverified_confirmed=True)
    db.commit()
    assert record == DnsblEnablementRecord(
        list_id="surbl-multi",
        enabled_by=actor,
        enabled_at=record.enabled_at,
        policy_acknowledged=True,
        policy_acknowledged_at=record.policy_acknowledged_at,
        unverified_confirmed=True,
    )
    assert record.enabled_at == record.policy_acknowledged_at
    _enable(repo, "uribl-multi")
    db.commit()
    assert repo.enabled_ids() == frozenset({"surbl-multi", "uribl-multi"})
    assert [r.list_id for r in repo.records()] == ["surbl-multi", "uribl-multi"]
    fetched = repo.get("surbl-multi")
    assert fetched is not None and fetched.enabled_by == actor
    assert _rows(db) == [("surbl-multi", actor, True, True), ("uribl-multi", None, True, False)]


def test_records_are_immutable(db: Session) -> None:
    record = _enable(DnsblEnablementRepository(db))
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.list_id = "other"  # type: ignore[misc]


def test_re_enable_refreshes_the_row(db: Session, actor: int) -> None:
    repo = DnsblEnablementRepository(db)
    _enable(repo, unverified_confirmed=True)
    db.commit()
    again = _enable(repo, actor=actor, now=LATER)
    db.commit()
    assert again.enabled_by == actor and again.unverified_confirmed is False
    assert again.enabled_at == again.policy_acknowledged_at
    assert _rows(db) == [("surbl-multi", actor, True, False)]


def test_disable(db: Session) -> None:
    repo = DnsblEnablementRepository(db)
    _enable(repo)
    db.commit()
    assert repo.disable("surbl-multi") is True
    db.commit()
    assert repo.disable("surbl-multi") is False
    assert repo.enabled_ids() == frozenset()


def test_concurrent_first_enable_is_a_conflict(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A writer whose read saw no row (another session inserted meanwhile) loses on the unique
    list_id with `EnablementConflict`, not a raw IntegrityError."""
    factory = create_session_factory(engine)
    with factory() as first, factory() as second:
        _enable(DnsblEnablementRepository(first))
        first.commit()
        stale = DnsblEnablementRepository(second)
        monkeypatch.setattr(stale, "_row", lambda _list_id: None)
        with pytest.raises(EnablementConflict):
            _enable(stale, now=LATER)
        second.rollback()
        assert DnsblEnablementRepository(second).enabled_ids() == frozenset({"surbl-multi"})


# --- validation (table-driven, malformed input) ---------------------------------------------------

VALID_IDS = ["a", "0", "spamcop-bl", "a" * 40, "x-1-2"]
INVALID_IDS: list[Any] = [
    "",
    "-lead",
    "UPPER",
    "a" * 41,
    "with space",
    "dot.ted",
    "under_score",
    "ü-umlaut",
    "nul\x00",
    "line\n",
    None,
    1,
    True,
    b"surbl",
    ["surbl"],
]


@pytest.mark.parametrize("list_id", VALID_IDS)
def test_valid_list_ids(db: Session, list_id: str) -> None:
    assert valid_list_id(list_id)
    repo = DnsblEnablementRepository(db)
    assert _enable(repo, list_id).list_id == list_id
    db.commit()
    assert repo.enabled_ids() == frozenset({list_id})


@pytest.mark.parametrize("list_id", INVALID_IDS)
def test_invalid_list_ids(db: Session, list_id: Any) -> None:
    repo = DnsblEnablementRepository(db)
    assert not valid_list_id(list_id)
    with pytest.raises(DnsblEnablementInvalid) as err:
        _enable(repo, list_id)
    assert (err.value.field, err.value.reason) == ("list_id", "invalid")
    assert str(err.value) == "dnsbl enablement list_id rejected: invalid"  # never the value
    assert repo.get(list_id) is None
    assert repo.disable(list_id) is False
    assert _rows(db) == []


INVALID_ARGS: list[tuple[str, dict[str, Any], str, str]] = [
    ("ack_false", {"policy_acknowledged": False}, "policy_acknowledged", "required"),
    ("ack_missing_none", {"policy_acknowledged": None}, "policy_acknowledged", "not_a_bool"),
    ("ack_int", {"policy_acknowledged": 1}, "policy_acknowledged", "not_a_bool"),
    ("ack_str", {"policy_acknowledged": "true"}, "policy_acknowledged", "not_a_bool"),
    ("confirm_int", {"unverified_confirmed": 0}, "unverified_confirmed", "not_a_bool"),
    ("confirm_none", {"unverified_confirmed": None}, "unverified_confirmed", "not_a_bool"),
    ("naive_now", {"now": datetime(2026, 11, 14)}, "now", "not_aware"),
    ("str_now", {"now": "2026-11-14T10:00:00Z"}, "now", "not_aware"),
    ("actor_zero", {"actor": 0}, "enabled_by", "invalid"),
    ("actor_bool", {"actor": True}, "enabled_by", "invalid"),
    ("actor_str", {"actor": "1"}, "enabled_by", "invalid"),
]


@pytest.mark.parametrize(
    ("case", "kwargs", "field", "reason"), INVALID_ARGS, ids=[c[0] for c in INVALID_ARGS]
)
def test_invalid_arguments(
    db: Session, case: str, kwargs: dict[str, Any], field: str, reason: str
) -> None:
    with pytest.raises(DnsblEnablementInvalid) as err:
        _enable(DnsblEnablementRepository(db), **kwargs)
    assert (err.value.field, err.value.reason) == (field, reason)
    assert _rows(db) == []


def test_other_timezones_are_accepted(db: Session) -> None:
    record = _enable(
        DnsblEnablementRepository(db),
        now=datetime(2026, 11, 14, tzinfo=timezone(timedelta(hours=2))),
    )
    db.commit()
    assert record.enabled_at.tzinfo is not None
