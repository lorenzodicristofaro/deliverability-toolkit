"""Authentication service: password login and server-side sessions (M1-13, GM decision Q3).

Tables used: `users` and `sessions`. Both are user-owned, not tenant-owned (no `tenant_id`), so
they are queried here directly; tenant data is still reached only through
`app.repositories.repo_for`. `active_tenant_id` is stored as given: whether the user may enter
that tenant is checked when the TenantContext is built (UserMembershipsRepository, M1-15).

The functions flush but never commit: the caller owns the transaction. Nothing here logs, and no
exception carries a password, token or cookie value.

Expiry (SessionPolicy): absolute expiry is fixed at creation (`expires_at`); idle expiry is
`last_seen_at` + `idle`, and `last_seen_at` is refreshed by every successful resolve.
The policy comes from Settings (SESSION_IDLE_TIMEOUT_MINUTES, default 30;
SESSION_ABSOLUTE_TIMEOUT_MINUTES, default 720 = 12 h) via `SessionPolicy.from_settings`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from argon2 import PasswordHasher
from pydantic import SecretStr
from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import (
    DEFAULT_HASHER,
    dummy_verify,
    hash_password,
    hash_session_token,
    needs_rehash,
    new_session_token,
    sign_session_token,
    unsign_session_token,
    verify_password,
)
from app.models import User, UserSession
from app.models.user import normalize_email
from app.repositories.base import coerce_id


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    idle: timedelta
    absolute: timedelta

    def __post_init__(self) -> None:
        if self.idle <= timedelta(0) or self.absolute <= timedelta(0):
            raise ValueError("session timeouts must be positive")
        if self.idle > self.absolute:
            raise ValueError("idle timeout must not exceed the absolute timeout")

    @classmethod
    def from_settings(cls, settings: Settings) -> SessionPolicy:
        return cls(
            idle=timedelta(minutes=settings.session_idle_timeout_minutes),
            absolute=timedelta(minutes=settings.session_absolute_timeout_minutes),
        )


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """A new session. `cookie_value` is the only place the token exists; never log it."""

    session_id: int
    cookie_value: str
    expires_at: datetime

    def __repr__(self) -> str:
        return f"IssuedSession(session_id={self.session_id}, expires_at={self.expires_at!r})"


@dataclass(frozen=True, slots=True)
class ResolvedSession:
    session_id: int
    user_id: int
    active_tenant_id: int | None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _now(now: datetime | None) -> datetime:
    """`now`, or the current UTC time. A naive `now` is refused: it cannot be compared with the
    stored UTC timestamps without guessing its timezone."""
    if now is None:
        return _utcnow()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now


def _aware(value: datetime) -> datetime:
    # SQLite returns naive datetimes for DateTime(timezone=True); everything is stored in UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


# --- passwords ------------------------------------------------------------------------------------


def lookup_email(email: object) -> str | None:
    """The normalized email to query `users` with, or None when the input cannot be a stored
    address: not a str, or rejected by `normalize_email` (malformed, longer than
    MAX_EMAIL_LENGTH, control character or surrogate). Callers treat None like an unknown user."""
    if not isinstance(email, str):
        return None
    try:
        return normalize_email(email)  # the same rule the model validator applies on storage
    except ValueError:
        return None


def authenticate(
    db: Session, email: object, password: object, *, hasher: PasswordHasher = DEFAULT_HASHER
) -> User | None:
    """The active user with this email and password, or None. Unknown, malformed or password-less
    accounts still run one argon2 verification (dummy) so timing does not reveal them. On success
    the hash is upgraded when the hasher parameters changed (rehash-on-login). Input rejected by
    `lookup_email` (NUL/control characters, over-long) never reaches the database."""
    user: User | None = None
    normalized = lookup_email(email)
    if normalized is not None:
        user = db.scalars(select(User).where(User.email == normalized)).one_or_none()
    if user is None or user.password_hash is None or not isinstance(password, str):
        dummy_verify(password, hasher)
        return None
    if not verify_password(user.password_hash, password, hasher):
        return None
    if not user.is_active:
        return None
    if needs_rehash(user.password_hash, hasher):
        user.password_hash = hash_password(password, hasher)
        db.flush()
    return user


def change_password(
    db: Session,
    user_id: int,
    new_password: str,
    *,
    keep_session_id: int | None = None,
    hasher: PasswordHasher = DEFAULT_HASHER,
    now: datetime | None = None,
) -> bool:
    """Set a new password and revoke every other session of the user (the current one, if given,
    survives). False if the user does not exist. Password policy is enforced by the caller."""
    current = _now(now)  # validate before changing anything
    uid = coerce_id(user_id)
    user = None if uid is None else db.scalars(select(User).where(User.id == uid)).one_or_none()
    if user is None:
        return False
    user.password_hash = hash_password(new_password, hasher)
    db.flush()
    revoke_all_sessions(db, user.id, except_session_id=keep_session_id, now=current)
    return True


# --- sessions -------------------------------------------------------------------------------------


def create_session(
    db: Session,
    user: User,
    secret_key: SecretStr,
    *,
    active_tenant_id: int | None = None,
    policy: SessionPolicy,
    now: datetime | None = None,
) -> IssuedSession:
    """Store a new session for `user` (its token hash only) and return the signed cookie value."""
    if user.id is None or not user.is_active:
        raise ValueError("sessions can only be created for an active, persisted user")
    current = _now(now)
    token = new_session_token()
    row = UserSession(
        token_hash=hash_session_token(token),
        user_id=user.id,
        active_tenant_id=active_tenant_id,
        created_at=current,
        last_seen_at=current,
        expires_at=current + policy.absolute,
    )
    db.add(row)
    db.flush()
    return IssuedSession(
        session_id=row.id,
        cookie_value=sign_session_token(token, secret_key),
        expires_at=row.expires_at,
    )


def resolve_session(
    db: Session,
    cookie_value: object,
    secret_key: SecretStr,
    *,
    policy: SessionPolicy,
    now: datetime | None = None,
) -> ResolvedSession | None:
    """The live session for a cookie value, or None if the cookie is malformed or tampered, or
    the session is unknown, revoked, past its absolute or idle expiry, or its user is inactive.
    A successful resolve refreshes `last_seen_at`."""
    current = _now(now)
    token = unsign_session_token(cookie_value, secret_key)
    if token is None:
        return None
    stmt = (
        select(UserSession, User.is_active)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == hash_session_token(token))
    )
    found = db.execute(stmt).one_or_none()
    if found is None:
        return None
    row, user_active = found
    if not user_active or row.revoked_at is not None:
        return None
    if current >= _aware(row.expires_at) or current >= _aware(row.last_seen_at) + policy.idle:
        return None
    row.last_seen_at = current
    db.flush()
    return ResolvedSession(row.id, row.user_id, row.active_tenant_id)


def revoke_session(db: Session, session_id: object, *, now: datetime | None = None) -> bool:
    """Revoke one session; False if it does not exist or was already revoked."""
    sid = coerce_id(session_id)
    if sid is None:
        return False
    result = db.execute(
        update(UserSession)
        .where(UserSession.id == sid, UserSession.revoked_at.is_(None))
        .values(revoked_at=_now(now))
        .execution_options(synchronize_session="fetch")
    )
    return bool(cast(CursorResult[Any], result).rowcount)


def revoke_all_sessions(
    db: Session,
    user_id: object,
    *,
    except_session_id: object = None,
    now: datetime | None = None,
) -> int:
    """Revoke every live session of the user except `except_session_id`; returns how many.
    A malformed `except_session_id` keeps no session (fail closed: everything is revoked)."""
    uid = coerce_id(user_id)
    if uid is None:
        return 0
    stmt = update(UserSession).where(UserSession.user_id == uid, UserSession.revoked_at.is_(None))
    keep = coerce_id(except_session_id)
    if keep is not None:
        stmt = stmt.where(UserSession.id != keep)
    result = db.execute(
        stmt.values(revoked_at=_now(now)).execution_options(synchronize_session="fetch")
    )
    return int(cast(CursorResult[Any], result).rowcount)
