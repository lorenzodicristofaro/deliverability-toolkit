"""M1-13 auth service: login, sessions, revocation, rehash-on-login.

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url`
fixture); the schema is built by Alembic. A fast argon2 hasher keeps the suite quick; the default
parameters are pinned in tests/core/test_security.py.
"""

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher
from pydantic import SecretStr
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.security import hash_password, hash_session_token, unsign_session_token
from app.models import Tenant, User, UserSession
from app.models.user import MAX_EMAIL_LENGTH
from app.services import auth
from app.services.auth import (
    SessionPolicy,
    authenticate,
    change_password,
    create_session,
    resolve_session,
    revoke_all_sessions,
    revoke_session,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
SECRET = SecretStr("s" * 40)
PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
T0 = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
POLICY = SessionPolicy(idle=timedelta(minutes=30), absolute=timedelta(hours=12))


@dataclass
class Env:
    db: Session
    alice: User
    inactive: User
    no_password: User
    tenant_id: int


@pytest.fixture
def env(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    try:
        tenant = Tenant(name="Agency", slug="agency")
        alice = User(email="alice@example.com", password_hash=hash_password(PASSWORD, FAST))
        inactive = User(
            email="bob@example.com", password_hash=hash_password(PASSWORD, FAST), is_active=False
        )
        no_password = User(email="carol@example.com")
        db.add_all([tenant, alice, inactive, no_password])
        db.commit()
        yield Env(db, alice, inactive, no_password, tenant.id)
    finally:
        db.close()
        engine.dispose()


def _login(env: Env, email: Any, password: Any) -> User | None:
    return authenticate(env.db, email, password, hasher=FAST)


# --- authenticate ---------------------------------------------------------------------------------


@pytest.mark.parametrize("email", ["alice@example.com", "  ALICE@Example.com "])
def test_login_ok(env: Env, email: str) -> None:
    user = _login(env, email, PASSWORD)
    assert user is not None and user.id == env.alice.id


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("alice@example.com", "wrong"),  # wrong password
        ("alice@example.com", ""),
        ("alice@example.com", PASSWORD.upper()),
        ("alice@example.com", None),
        ("alice@example.com", PASSWORD.encode()),
        ("nobody@example.com", PASSWORD),  # unknown user
        ("bob@example.com", PASSWORD),  # inactive user, right password
        ("carol@example.com", ""),  # no password set
        ("carol@example.com", PASSWORD),
        ("not-an-email", PASSWORD),  # malformed
        ("", PASSWORD),
        (None, PASSWORD),
        (123, PASSWORD),
        ("alice@example.com' OR '1'='1", PASSWORD),
    ],
)
def test_login_rejected(env: Env, email: Any, password: Any) -> None:
    assert _login(env, email, password) is None


@pytest.mark.parametrize(
    "email", ["nobody@example.com", "carol@example.com", "not-an-email", None, ""]
)
def test_unknown_user_runs_dummy_verify(
    env: Env, email: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    real = security.verify_password

    def spy(stored: str, pw: str, hasher: PasswordHasher = FAST) -> bool:
        calls.append(stored)
        return real(stored, pw, hasher)

    monkeypatch.setattr(security, "verify_password", spy)
    assert _login(env, email, PASSWORD) is None
    assert len(calls) == 1  # same argon2 work as a real account


LONG_LOCAL = "a" * (MAX_EMAIL_LENGTH - len("@example.com"))
REJECTED_BEFORE_QUERY = [
    "alice@example.com\x00",  # NUL: PostgreSQL text raises DataError
    "\x00alice@example.com",
    "ali\x00ce@example.com",
    "alice@exa\x01mple.com",  # other C0 controls
    "alice@example.com\x1b",
    "alice@example.com\x7f",  # DEL
    "alice@exa\x85mple.com",  # C1 (NEL)
    "alice@example.com\ud800",  # lone surrogate: not encodable as UTF-8
    "a" + LONG_LOCAL + "@example.com",  # 255 chars: over the cap
    "a" * 5000 + "@example.com",
]


@pytest.mark.parametrize("email", REJECTED_BEFORE_QUERY)
def test_unusable_email_rejected_before_any_query(
    env: Env, email: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert auth.lookup_email(email) is None
    statements: list[str] = []
    calls: list[str] = []
    real = security.verify_password

    def spy(stored: str, pw: str, hasher: PasswordHasher = FAST) -> bool:
        calls.append(stored)
        return real(stored, pw, hasher)

    def record(*args: Any) -> None:
        statements.append(args[2])

    monkeypatch.setattr(security, "verify_password", spy)
    bind = env.db.get_bind()
    event.listen(bind, "before_cursor_execute", record)
    try:
        assert _login(env, email, PASSWORD) is None
    finally:
        event.remove(bind, "before_cursor_execute", record)
    assert statements == []  # never reaches the database
    assert len(calls) == 1  # timing: still one argon2 verification


@pytest.mark.parametrize(
    ("email", "expected"),
    [
        ("Alice@Example.com", "alice@example.com"),
        (" alice@example.com\t", "alice@example.com"),  # surrounding whitespace is stripped
        (LONG_LOCAL + "@example.com", LONG_LOCAL + "@example.com"),  # exactly 254: allowed
        ("x@ex\u00e4mple.com", "x@ex\u00e4mple.com"),  # non-ASCII is not a control character
        ("jos\u00e9@example.com", "jos\u00e9@example.com"),  # Unicode local part
        ("alice@example.com\x00", None),
        ("alice@example.com\x9f", None),
        ("a" + LONG_LOCAL + "@example.com", None),
        ("not-an-email", None),
        (None, None),
        (b"alice@example.com", None),
    ],
)
def test_lookup_email(email: Any, expected: str | None) -> None:
    assert auth.lookup_email(email) == expected


def test_rehash_on_login_when_parameters_change(env: Env) -> None:
    stronger = PasswordHasher(time_cost=2, memory_cost=16, parallelism=1)
    old_hash = env.alice.password_hash
    assert authenticate(env.db, "alice@example.com", PASSWORD, hasher=stronger) is not None
    env.db.commit()
    new_hash = env.db.scalar(select(User.password_hash).where(User.id == env.alice.id))
    assert new_hash is not None and new_hash != old_hash
    assert not stronger.check_needs_rehash(new_hash)
    assert authenticate(env.db, "alice@example.com", PASSWORD, hasher=stronger) is not None


def test_no_rehash_when_parameters_match(env: Env) -> None:
    old_hash = env.alice.password_hash
    assert _login(env, "alice@example.com", PASSWORD) is not None
    assert env.alice.password_hash == old_hash


def test_failed_login_does_not_rehash(env: Env) -> None:
    stronger = PasswordHasher(time_cost=2, memory_cost=16, parallelism=1)
    old_hash = env.alice.password_hash
    assert authenticate(env.db, "alice@example.com", "wrong", hasher=stronger) is None
    assert env.alice.password_hash == old_hash


# --- sessions -------------------------------------------------------------------------------------


def _issue(env: Env, now: datetime = T0, user: User | None = None) -> auth.IssuedSession:
    return create_session(
        env.db, user or env.alice, SECRET, active_tenant_id=env.tenant_id, policy=POLICY, now=now
    )


def _resolve(env: Env, cookie: Any, now: datetime = T0) -> auth.ResolvedSession | None:
    return resolve_session(env.db, cookie, SECRET, policy=POLICY, now=now)


def test_create_stores_only_token_hash(env: Env) -> None:
    issued = _issue(env)
    env.db.commit()
    token = unsign_session_token(issued.cookie_value, SECRET)
    assert token is not None
    row = env.db.scalars(select(UserSession).where(UserSession.id == issued.session_id)).one()
    assert row.token_hash == hash_session_token(token)
    with env.db.connection() as conn:
        dump = " ".join(str(v) for r in conn.execute(text("SELECT * FROM sessions")) for v in r)
    assert token not in dump and issued.cookie_value not in dump
    assert issued.expires_at == T0 + POLICY.absolute
    assert token not in repr(issued)


def test_resolve_ok_and_refreshes_last_seen(env: Env) -> None:
    issued = _issue(env)
    later = T0 + timedelta(minutes=20)
    resolved = _resolve(env, issued.cookie_value, later)
    assert resolved == auth.ResolvedSession(issued.session_id, env.alice.id, env.tenant_id)
    # Activity keeps the session alive past the first idle window.
    assert _resolve(env, issued.cookie_value, later + timedelta(minutes=20)) is not None


@pytest.mark.parametrize(
    ("offset", "alive"),
    [
        (timedelta(minutes=29, seconds=59), True),
        (timedelta(minutes=30), False),  # idle expiry
        (timedelta(hours=2), False),
    ],
)
def test_idle_expiry(env: Env, offset: timedelta, alive: bool) -> None:
    issued = _issue(env)
    env.db.commit()
    assert (_resolve(env, issued.cookie_value, T0 + offset) is not None) is alive


def test_absolute_expiry_despite_activity(env: Env) -> None:
    issued = _issue(env)
    now = T0
    while now + timedelta(minutes=20) < T0 + POLICY.absolute:
        now += timedelta(minutes=20)
        assert _resolve(env, issued.cookie_value, now) is not None
    assert _resolve(env, issued.cookie_value, T0 + POLICY.absolute) is None


def _tampered_cookies(cookie: str) -> list[Any]:
    tok, _, sig = cookie.partition(".")
    other = security.new_session_token()
    return [
        f"{tok}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}",
        f"{other}.{sig}",
        security.sign_session_token(tok, SecretStr("t" * 40)),
        security.sign_session_token(other, SECRET),  # valid signature, unknown token
        tok,
        cookie + "x",
        "",
        None,
        42,
    ]


def test_tampered_cookie_rejected(env: Env) -> None:
    issued = _issue(env)
    env.db.commit()
    for cookie in _tampered_cookies(issued.cookie_value):
        assert _resolve(env, cookie) is None, cookie
    assert _resolve(env, issued.cookie_value) is not None


def test_revoked_session_rejected(env: Env) -> None:
    issued = _issue(env)
    assert revoke_session(env.db, issued.session_id, now=T0) is True
    assert revoke_session(env.db, issued.session_id, now=T0) is False  # already revoked
    env.db.commit()
    assert _resolve(env, issued.cookie_value) is None


@pytest.mark.parametrize("session_id", [None, "1", 0, -1, True, 2**80, 999_999])
def test_revoke_malformed_or_missing(env: Env, session_id: Any) -> None:
    issued = _issue(env)
    assert revoke_session(env.db, session_id) is False
    assert _resolve(env, issued.cookie_value) is not None


def test_inactive_user_session_rejected(env: Env) -> None:
    issued = _issue(env)
    env.alice.is_active = False
    env.db.commit()
    assert _resolve(env, issued.cookie_value) is None


def test_cannot_create_session_for_inactive_user(env: Env) -> None:
    with pytest.raises(ValueError):
        _issue(env, user=env.inactive)


def test_revoke_all_for_user(env: Env) -> None:
    other_user = User(email="dave@example.com", password_hash=hash_password(PASSWORD, FAST))
    env.db.add(other_user)
    env.db.flush()
    mine = [_issue(env) for _ in range(3)]
    theirs = _issue(env, user=other_user)
    assert revoke_all_sessions(env.db, env.alice.id, now=T0) == 3
    env.db.commit()
    assert all(_resolve(env, s.cookie_value) is None for s in mine)
    assert _resolve(env, theirs.cookie_value) is not None
    assert revoke_all_sessions(env.db, env.alice.id, now=T0) == 0
    assert revoke_all_sessions(env.db, "1", now=T0) == 0


def test_password_change_revokes_other_sessions(env: Env) -> None:
    current, other1, other2 = (_issue(env) for _ in range(3))
    new_password = "a completely new passphrase"
    assert change_password(
        env.db, env.alice.id, new_password, keep_session_id=current.session_id, hasher=FAST, now=T0
    )
    env.db.commit()
    assert _resolve(env, current.cookie_value) is not None
    assert _resolve(env, other1.cookie_value) is None
    assert _resolve(env, other2.cookie_value) is None
    assert _login(env, "alice@example.com", PASSWORD) is None
    assert _login(env, "alice@example.com", new_password) is not None


NAIVE = datetime(2026, 11, 5, 12, 0)


@pytest.mark.parametrize(
    "call",
    [
        lambda env: _issue(env, now=NAIVE),
        lambda env: resolve_session(env.db, "x", SECRET, policy=POLICY, now=NAIVE),
        lambda env: revoke_session(env.db, 1, now=NAIVE),
        lambda env: revoke_all_sessions(env.db, env.alice.id, now=NAIVE),
        lambda env: change_password(env.db, env.alice.id, "new pw", hasher=FAST, now=NAIVE),
    ],
    ids=["create", "resolve", "revoke", "revoke_all", "change_password"],
)
def test_naive_now_rejected(env: Env, call: Any) -> None:
    old_hash = env.alice.password_hash
    live = _issue(env)
    with pytest.raises(ValueError, match="timezone-aware"):
        call(env)
    assert env.alice.password_hash == old_hash
    assert _resolve(env, live.cookie_value) is not None


@pytest.mark.parametrize("keep", ["1", 1.0, True, 0, -1, 2**80, [1]])
def test_revoke_all_malformed_except_revokes_everything(env: Env, keep: Any) -> None:
    sessions = [_issue(env) for _ in range(2)]
    assert revoke_all_sessions(env.db, env.alice.id, except_session_id=keep, now=T0) == 2
    assert all(_resolve(env, s.cookie_value) is None for s in sessions)


def test_password_change_unknown_user(env: Env) -> None:
    assert change_password(env.db, 999_999, "x", hasher=FAST) is False
    assert change_password(env.db, "1", "x", hasher=FAST) is False  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("idle", "absolute"),
    [
        (timedelta(0), timedelta(hours=1)),
        (timedelta(minutes=-1), timedelta(hours=1)),
        (timedelta(hours=2), timedelta(hours=1)),
        (timedelta(minutes=5), timedelta(0)),
    ],
)
def test_session_policy_rejects_unsafe_values(idle: timedelta, absolute: timedelta) -> None:
    with pytest.raises(ValueError):
        SessionPolicy(idle=idle, absolute=absolute)


def _settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    for name in ("SESSION_IDLE_TIMEOUT_MINUTES", "SESSION_ABSOLUTE_TIMEOUT_MINUTES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings()  # type: ignore[call-arg]


def test_policy_from_default_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = SessionPolicy.from_settings(_settings(monkeypatch))
    assert (policy.idle, policy.absolute) == (timedelta(minutes=30), timedelta(hours=12))


def test_policy_from_configured_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(
        monkeypatch, SESSION_IDLE_TIMEOUT_MINUTES="5", SESSION_ABSOLUTE_TIMEOUT_MINUTES="60"
    )
    policy = SessionPolicy.from_settings(settings)
    assert (policy.idle, policy.absolute) == (timedelta(minutes=5), timedelta(hours=1))


def test_no_secrets_in_logs(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)  # SQL + bound params
    try:
        assert _login(env, "alice@example.com", "wrong-password-xyz") is None
        assert _login(env, "nobody@example.com", PASSWORD) is None
        issued = _issue(env)
        token = unsign_session_token(issued.cookie_value, SECRET)
        assert _resolve(env, issued.cookie_value) is not None
        change_password(env.db, env.alice.id, "brand-new-secret-pw", hasher=FAST, now=T0)
    finally:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    assert token is not None
    for secret in (PASSWORD, "wrong-password-xyz", "brand-new-secret-pw", token, SECRET):
        value = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
        assert value not in caplog.text
