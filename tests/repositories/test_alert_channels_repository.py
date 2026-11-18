"""M7-15 alert channel repositories: tenant scoping, value validation (table-driven, malformed
input), cascade of rules and deliveries on delete, the dispatch loop's cross-tenant read and the
secret rotation entry point. Runs on SQLite and, with TEST_DATABASE_URL, on PostgreSQL. No network.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import AlertChannel, AlertDelivery, AlertRule, Tenant
from app.repositories import repo_for
from app.repositories.alert_channels import (
    AlertChannelInvalid,
    AlertChannelSecretRotation,
    AlertDispatchRepository,
)
from app.repositories.base import MAX_LIMIT

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
HASH = "a" * 64


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
def tenants(db: Session) -> tuple[TenantContext, TenantContext]:
    a, b = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
    db.add_all([a, b])
    db.commit()
    return TenantContext(a.id, None), TenantContext(b.id, None)


def _create(db: Session, ctx: TenantContext, name: str = "ops", **kw: Any) -> int:
    values: dict[str, Any] = {
        "kind": "webhook",
        "name": name,
        "enabled": True,
        "config": {},
        "secret_token": "token-ciphertext",
        "secret_fields": ["url"],
        "now": T0,
    }
    values.update(kw)
    record = repo_for(ctx, db).alert_channels.create(**values)
    db.commit()
    return record.id


def test_create_get_list_and_record_has_no_secret(db: Session, tenants: Any) -> None:
    a, _ = tenants
    cid = _create(db, a, name="  ops  ")
    repo = repo_for(a, db).alert_channels
    record = repo.get(cid)
    assert record is not None
    assert (record.kind, record.name, record.enabled, record.secret_fields) == (
        "webhook",
        "ops",
        True,
        ("url",),
    )
    assert record.created_at == record.updated_at == T0
    assert "token-ciphertext" not in repr(record)
    assert not hasattr(record, "secret")
    assert [r.id for r in repo.list_all()] == [cid]
    assert repo.secret_token(cid) == "token-ciphertext"
    assert repo.count() == 1


def test_other_tenant_sees_nothing(db: Session, tenants: Any) -> None:
    a, b = tenants
    cid = _create(db, a)
    other = repo_for(b, db).alert_channels
    assert other.get(cid) is None
    assert other.secret_token(cid) is None
    assert other.list_all() == []
    assert other.update(cid, now=T0, name="stolen") is None
    assert other.delete(cid) is False
    db.commit()
    assert repo_for(a, db).alert_channels.get(cid) is not None


@pytest.mark.parametrize("bad", [None, 0, -1, True, "1", 1.0, 2**31, 2**63])
def test_malformed_ids_are_missing(db: Session, tenants: Any, bad: Any) -> None:
    repo = repo_for(tenants[0], db).alert_channels
    assert repo.get(bad) is None
    assert repo.secret_token(bad) is None
    assert repo.delete(bad) is False


CREATE_REJECTS = [
    ("kind", {"kind": "sms"}),
    ("kind", {"kind": None}),
    ("name", {"name": ""}),
    ("name", {"name": "   "}),
    ("name", {"name": "x" * 101}),
    ("name", {"name": "bad\nname"}),
    ("name", {"name": "bad\x00"}),
    ("name", {"name": 5}),
    ("enabled", {"enabled": 1}),
    ("enabled", {"enabled": "true"}),
    ("config", {"config": ["x"]}),
    ("config", {"config": {1: "x"}}),
    ("secret", {"secret_token": None, "secret_fields": ["url"]}),
    ("secret", {"secret_token": "", "secret_fields": ["url"]}),
    ("secret", {"secret_token": "t", "secret_fields": []}),
    ("secret_fields", {"secret_fields": "url"}),
    ("secret_fields", {"secret_fields": ["url", "url"]}),
    ("secret_fields", {"secret_fields": [""]}),
    ("secret_fields", {"secret_fields": [1]}),
    ("secret_fields", {"secret_fields": [f"f{i}" for i in range(9)]}),
    ("now", {"now": datetime(2026, 1, 1)}),
    ("now", {"now": "2026-01-01"}),
]


@pytest.mark.parametrize(
    ("field", "override"), CREATE_REJECTS, ids=[repr(c) for c in CREATE_REJECTS]
)
def test_create_rejects_malformed_values(
    db: Session, tenants: Any, field: str, override: dict[str, Any]
) -> None:
    with pytest.raises(AlertChannelInvalid) as info:
        _create(db, tenants[0], **override)
    assert info.value.field == field
    for value in override.values():
        if isinstance(value, str) and len(value) > 3:
            assert value not in str(info.value)


def test_no_secret_is_allowed(db: Session, tenants: Any) -> None:
    cid = _create(
        db, tenants[0], kind="email", config={"recipients": ["a@x.example"]}, secret_token=None,
        secret_fields=[],
    )  # fmt: skip
    record = repo_for(tenants[0], db).alert_channels.get(cid)
    assert record is not None and record.secret_fields == ()


def test_duplicate_name_in_tenant_is_an_integrity_error(db: Session, tenants: Any) -> None:
    a, b = tenants
    _create(db, a)
    _create(db, b)  # same name in another tenant is fine
    repo = repo_for(a, db).alert_channels
    assert repo.name_taken("ops") and repo.name_taken(" ops ")
    assert not repo.name_taken("other")
    with pytest.raises(IntegrityError):
        _create(db, a)
    db.rollback()


def test_update_changes_only_given_fields(db: Session, tenants: Any) -> None:
    a, _ = tenants
    cid = _create(db, a)
    repo = repo_for(a, db).alert_channels
    later = T0 + timedelta(hours=1)
    record = repo.update(cid, now=later, enabled=False)
    assert record is not None and record.enabled is False and record.name == "ops"
    assert record.updated_at == later and record.created_at == T0
    record = repo.update(cid, now=later, secret=("new-token", ["signing_secret", "url"]))
    assert record is not None and record.secret_fields == ("signing_secret", "url")
    assert repo.secret_token(cid) == "new-token"
    assert repo.name_taken("ops", exclude_id=cid) is False
    with pytest.raises(AlertChannelInvalid):
        repo.update(cid, now=later, name="")


def _alert_with_delivery(db: Session, ctx: TenantContext, channel_id: int, n: int) -> None:
    repos = repo_for(ctx, db)
    domain = repos.domains.get_by_name(f"d{ctx.tenant_id}.example") or repos.domains.create(
        f"d{ctx.tenant_id}.example"
    )
    alert = repos.alerts.insert_if_absent(
        domain.id,
        kind="new_listing",
        stream=HASH,
        fingerprint=HASH,
        state_hash=f"{n:064x}",
        code="ALERT_NEW_LISTING",
        params={},
        suppressed=False,
        created_at=T0,
    )
    assert alert is not None
    repos.alert_deliveries.add_pending(alert.id, [channel_id], T0)
    repos.alert_rules.add("new_listing", channel_id)
    db.commit()


def _count(db: Session, model: Any, tenant: int) -> int:
    return int(db.scalar(select(func.count()).where(model.tenant_id == tenant)) or 0)


def test_delete_removes_rules_and_deliveries_of_that_channel_only(
    db: Session, tenants: Any
) -> None:
    a, b = tenants
    gone, kept = _create(db, a), _create(db, a, name="kept")
    other = _create(db, b)
    _alert_with_delivery(db, a, gone, 1)
    _alert_with_delivery(db, a, kept, 2)
    # Tenant B uses the same channel id number in its own rows (no FK yet): untouched.
    _alert_with_delivery(db, b, gone, 3)
    _alert_with_delivery(db, b, other, 4)
    assert repo_for(a, db).alert_channels.delete(gone) is True
    db.commit()
    assert _count(db, AlertChannel, a.tenant_id) == 1
    assert _count(db, AlertRule, a.tenant_id) == 1
    assert _count(db, AlertDelivery, a.tenant_id) == 1
    assert _count(db, AlertRule, b.tenant_id) == 2
    assert _count(db, AlertDelivery, b.tenant_id) == 2


def test_tenants_with_due(db: Session, tenants: Any) -> None:
    a, b = tenants
    _alert_with_delivery(db, b, 1, 1)
    _alert_with_delivery(db, a, 1, 2)
    system = AlertDispatchRepository(db)
    assert system.tenants_with_due(T0, 10) == sorted([a.tenant_id, b.tenant_id])
    assert system.tenants_with_due(T0 - timedelta(seconds=1), 10) == []
    assert len(system.tenants_with_due(T0, 1)) == 1
    db.execute(AlertDelivery.__table__.update().values(status="sent"))
    db.commit()
    assert system.tenants_with_due(T0, 10) == []


@pytest.mark.parametrize(
    ("now", "limit"),
    [(datetime(2026, 1, 1), 1), (T0, 0), (T0, MAX_LIMIT + 1), (T0, True), (T0, "5")],
)
def test_tenants_with_due_rejects_malformed(db: Session, now: Any, limit: Any) -> None:
    with pytest.raises(AlertChannelInvalid):
        AlertDispatchRepository(db).tenants_with_due(now, limit)


def test_rotate_all_rewrites_every_token(db: Session, tenants: Any) -> None:
    a, b = tenants
    ca, cb = _create(db, a), _create(db, b)
    _create(db, a, name="mail", kind="email", config={}, secret_token=None, secret_fields=[])
    assert AlertChannelSecretRotation(db).rotate_all(lambda token: token + "-rotated") == 2
    db.commit()
    assert repo_for(a, db).alert_channels.secret_token(ca) == "token-ciphertext-rotated"
    assert repo_for(b, db).alert_channels.secret_token(cb) == "token-ciphertext-rotated"


def test_rotate_all_failure_changes_nothing_after_rollback(db: Session, tenants: Any) -> None:
    cid = _create(db, tenants[0])

    def broken(_token: str) -> str:
        raise ValueError("unreadable")

    with pytest.raises(ValueError):
        AlertChannelSecretRotation(db).rotate_all(broken)
    db.rollback()
    assert repo_for(tenants[0], db).alert_channels.secret_token(cid) == "token-ciphertext"
