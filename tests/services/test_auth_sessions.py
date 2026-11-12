"""R1-14 (AUTH-09): purge of expired and revoked session rows.

Every login and tenant switch inserts a `sessions` row and nothing deleted one, so the table grew
without bound. `purge_sessions` deletes rows that can never resolve again (past `expires_at`, idle
for longer than the idle timeout, or revoked) once they are older than `SESSION_PURGE_GRACE`.

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (`migrated_db_url`).
Time is always injected.
"""

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.security import hash_password
from app.main import purge_sessions_at_startup
from app.models import Tenant, User, UserSession
from app.services import auth
from app.services.auth import (
    SESSION_PURGE_GRACE,
    SessionPolicy,
    create_session,
    purge_sessions,
    resolve_session,
    revoke_session,
)

KEY = "k" * 40
SECRET = SecretStr("s" * 40)
T0 = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
POLICY = SessionPolicy(idle=timedelta(minutes=30), absolute=timedelta(hours=12))
EPS = timedelta(seconds=1)


@dataclass
class Env:
    db: Session
    alice: User
    tenant_id: int


@pytest.fixture
def env(migrated_db_url: str) -> Iterator[Env]:
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        tenant = Tenant(name="Agency", slug="agency")
        alice = User(email="alice@example.com", password_hash=hash_password("x" * 20))
        db.add_all([tenant, alice])
        db.commit()
        yield Env(db, alice, tenant.id)
    finally:
        db.close()
        engine.dispose()


def _issue(env: Env, now: datetime = T0) -> auth.IssuedSession:
    return create_session(
        env.db, env.alice, SECRET, active_tenant_id=env.tenant_id, policy=POLICY, now=now
    )


def _ids(env: Env) -> set[int]:
    env.db.expire_all()
    return set(env.db.scalars(select(UserSession.id)))


def _count(env: Env) -> int:
    return int(env.db.scalar(select(func.count()).select_from(UserSession)) or 0)


# Each case: how the session is left at T0, and when the purge runs (offset from T0).
# Margins: purge needs the dead state to be at least SESSION_PURGE_GRACE old.
IDLE_DEAD = POLICY.idle + SESSION_PURGE_GRACE
ABS_DEAD = POLICY.absolute + SESSION_PURGE_GRACE

CASES: list[tuple[str, str, timedelta, bool]] = [
    # (id, state, purge at T0 + offset, purged?)
    ("live-fresh", "live", timedelta(0), False),
    ("live-just-before-idle", "live", POLICY.idle - EPS, False),
    ("idle-expired-within-grace", "live", POLICY.idle + EPS, False),
    ("idle-expired-at-grace-edge", "live", IDLE_DEAD - EPS, False),
    ("idle-expired-past-grace", "live", IDLE_DEAD, True),
    ("revoked-just-now", "revoked", timedelta(0), False),
    ("revoked-within-grace", "revoked", SESSION_PURGE_GRACE - EPS, False),
    ("revoked-past-grace", "revoked", SESSION_PURGE_GRACE, True),
    ("revoked-long-ago", "revoked", timedelta(days=30), True),
    ("absolute-expired-past-grace", "active-until-end", ABS_DEAD, True),
    ("absolute-expired-within-grace", "active-until-end", POLICY.absolute + EPS, False),
]


@pytest.mark.parametrize(
    ("state", "offset", "purged"), [c[1:] for c in CASES], ids=[c[0] for c in CASES]
)
def test_purge_by_state(env: Env, state: str, offset: timedelta, purged: bool) -> None:
    issued = _issue(env)
    if state == "revoked":
        assert revoke_session(env.db, issued.session_id, now=T0)
    elif state == "active-until-end":
        # Kept alive by activity until just before the absolute expiry: only expires_at kills it.
        t = T0
        while t + POLICY.idle < T0 + POLICY.absolute:
            t += POLICY.idle - EPS
            assert resolve_session(env.db, issued.cookie_value, SECRET, policy=POLICY, now=t)
    env.db.commit()
    removed = purge_sessions(env.db, policy=POLICY, now=T0 + offset)
    env.db.commit()
    assert removed == (1 if purged else 0)
    assert (issued.session_id not in _ids(env)) is purged


def test_login_logout_switch_rows_are_purged_and_live_session_still_resolves(env: Env) -> None:
    """Reproduction of AUTH-09: logins, a logout and a tenant switch leave dead rows behind;
    the purge removes them and the live session keeps working."""
    first = _issue(env)  # login
    revoke_session(env.db, first.session_id, now=T0)  # logout
    second = _issue(env, T0 + timedelta(minutes=1))  # login again
    revoke_session(env.db, second.session_id, now=T0 + timedelta(minutes=2))  # tenant switch:
    switched = _issue(env, T0 + timedelta(minutes=2))  # the old session is replaced
    abandoned = _issue(env, T0 + timedelta(minutes=3))  # another login, never used again
    env.db.commit()
    assert _count(env) == 4

    active = T0 + timedelta(minutes=25)  # the user keeps working in the switched session
    assert resolve_session(env.db, switched.cookie_value, SECRET, policy=POLICY, now=active)
    later = T0 + timedelta(minutes=40)  # `abandoned` is idle past the grace, `switched` is not
    env.db.commit()
    assert purge_sessions(env.db, policy=POLICY, now=later) == 3
    env.db.commit()
    assert _ids(env) == {switched.session_id}
    assert abandoned.session_id not in _ids(env)
    resolved = resolve_session(
        env.db, switched.cookie_value, SECRET, policy=POLICY, now=later + timedelta(minutes=1)
    )
    assert resolved == auth.ResolvedSession(switched.session_id, env.alice.id, env.tenant_id)


def test_purge_without_policy_keeps_idle_expired_rows(env: Env) -> None:
    """Without a policy only `expires_at` and `revoked_at` are used (the idle rule needs it)."""
    issued = _issue(env)
    env.db.commit()
    assert purge_sessions(env.db, now=T0 + IDLE_DEAD + timedelta(hours=1)) == 0
    assert purge_sessions(env.db, now=T0 + ABS_DEAD) == 1
    env.db.commit()
    assert issued.session_id not in _ids(env)


def test_purge_empty_table_is_noop(env: Env) -> None:
    assert purge_sessions(env.db, policy=POLICY, now=T0) == 0
    assert _count(env) == 0


@pytest.mark.parametrize("batch_size", [1, 2, 3, 50])
def test_purge_in_bounded_batches(
    env: Env, batch_size: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    dead = [_issue(env, T0 + timedelta(seconds=i)) for i in range(5)]
    for s in dead:
        revoke_session(env.db, s.session_id, now=T0)
    live = _issue(env, T0 + timedelta(days=2))
    env.db.commit()

    seen: list[int] = []
    real = auth._purge_batch

    def spy(db: Session, where: Any, limit: int) -> int:
        n = real(db, where, limit)
        seen.append(n)
        return n

    monkeypatch.setattr(auth, "_purge_batch", spy)
    assert purge_sessions(env.db, policy=POLICY, now=T0 + timedelta(days=2), batch_size=batch_size)
    env.db.commit()
    assert sum(seen) == 5 and max(seen) <= batch_size
    assert _ids(env) == {live.session_id}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"now": datetime(2026, 11, 5, 12, 0)},  # naive
        {"now": T0, "batch_size": 0},
        {"now": T0, "batch_size": -1},
        {"now": T0, "batch_size": True},
        {"now": T0, "batch_size": 1.5},
    ],
)
def test_purge_rejects_bad_arguments(env: Env, kwargs: dict[str, Any]) -> None:
    _issue(env)
    env.db.commit()
    with pytest.raises(ValueError):
        purge_sessions(env.db, policy=POLICY, **kwargs)
    env.db.rollback()
    assert _count(env) == 1


def test_purge_non_utc_now_is_normalized(env: Env) -> None:
    """A `now` in another timezone means the same instant (SQLite stores naive UTC)."""
    from datetime import timezone

    issued = _issue(env)
    revoke_session(env.db, issued.session_id, now=T0)
    env.db.commit()
    plus2 = timezone(timedelta(hours=2))
    within = (T0 + SESSION_PURGE_GRACE - EPS).astimezone(plus2)
    assert purge_sessions(env.db, policy=POLICY, now=within) == 0
    assert purge_sessions(env.db, policy=POLICY, now=within + EPS) == 1


# --- startup hook ---------------------------------------------------------------------------------


def _app(factory: Any) -> FastAPI:
    app = FastAPI()
    app.state.session_factory = factory
    app.state.settings = SimpleNamespace(
        session_idle_timeout_minutes=30, session_absolute_timeout_minutes=720
    )
    return app


def test_startup_purge_commits(migrated_db_url: str, caplog: pytest.LogCaptureFixture) -> None:
    engine = create_db_engine(migrated_db_url)
    factory = create_session_factory(engine)
    try:
        with factory.begin() as db:
            alice = User(email="alice@example.com", password_hash=hash_password("x" * 20))
            db.add(alice)
            db.flush()
            old = datetime.now(UTC) - timedelta(days=2)
            create_session(db, alice, SECRET, policy=POLICY, now=old)
            create_session(db, alice, SECRET, policy=POLICY)
        with caplog.at_level(logging.INFO):
            purge_sessions_at_startup(_app(factory))
        with factory() as db:
            assert db.scalar(select(func.count()).select_from(UserSession)) == 1
        assert any(getattr(r, "event", None) == "session_purge.done" for r in caplog.records)
    finally:
        engine.dispose()


def test_startup_purge_failure_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    def broken() -> Any:
        raise RuntimeError("connection to secret-host failed")

    broken.begin = broken  # type: ignore[attr-defined]
    with caplog.at_level(logging.ERROR):
        purge_sessions_at_startup(_app(broken))  # must not raise
    [record] = [r for r in caplog.records if getattr(r, "event", None) == "session_purge.failed"]
    assert "RuntimeError" in record.getMessage()
    assert "secret-host" not in record.getMessage()
