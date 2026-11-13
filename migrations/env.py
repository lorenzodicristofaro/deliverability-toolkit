"""Alembic environment. The URL comes from an injected connection (tests) or from Settings."""

import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import psycopg
from alembic import context
from sqlalchemy import exc as sa_exc
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

from app.core.config import Settings
from app.core.db import engine_from_settings
from app.models import Base

target_metadata = Base.metadata
logger = logging.getLogger(__name__)

# Arbitrary fixed 64-bit key ("dtkit-mg" as ASCII) shared by every process that migrates this
# database. Advisory locks are per database, so it cannot clash with another database.
MIGRATION_LOCK_KEY = 0x64746B69742D6D67

# Bounded wait for PostgreSQL at container start (R1-25b): compose cannot order the app after a
# profile-only service, and `docker compose up --wait` fails as soon as the app exits, so the
# first connection is retried here instead of relying on `restart: unless-stopped`.
DB_WAIT_TIMEOUT_S = 60.0
DB_WAIT_INITIAL_DELAY_S = 0.5
DB_WAIT_MAX_DELAY_S = 4.0

# psycopg 3 raises a plain psycopg.OperationalError for every connection-time failure, built
# from libpq's message (psycopg/generators.py `_connect`): no SQLSTATE and no subclass, so
# refused, starting-up, bad password and unknown database differ only by text. SQLAlchemy wraps
# it in sqlalchemy.exc.OperationalError (`.orig`). Only these transient causes are retried
# (lower-cased substrings -> reason logged); anything else fails at once.
_TRANSIENT_CONNECT_ERRORS = (
    # libpq, server not listening yet (ECONNREFUSED); during initdb the image's temporary
    # server listens on the Unix socket only, so TCP is refused.
    ("connection refused", "connection refused"),
    # PostgreSQL 57P03 cannot_connect_now, sent by the postmaster before it accepts sessions.
    ("the database system is starting up", "server starting up"),
    ("the database system is not yet accepting connections", "server starting up"),
)


def _transient_reason(error: BaseException) -> str | None:
    """Short operator-safe reason if `error` is a retryable first-connection failure, else None.

    Never returns the driver message: it names host and user."""
    if not isinstance(error, sa_exc.OperationalError):
        return None
    orig = error.orig
    # Should a future psycopg attach SQLSTATE 57P03 at connect, it maps to CannotConnectNow.
    if isinstance(orig, psycopg.errors.CannotConnectNow):
        return "server starting up"
    if not isinstance(orig, psycopg.OperationalError):
        return None
    message = str(orig).lower()
    for marker, reason in _TRANSIENT_CONNECT_ERRORS:
        if marker in message:
            return reason
    return None


def _wait_for_database(
    connect: Callable[[], Connection],
    *,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
    timeout: float = DB_WAIT_TIMEOUT_S,
) -> None:
    """Open and close one connection, retrying transient failures with capped exponential
    backoff for at most `timeout` seconds; after that, or on any other error, it propagates."""
    start = clock()
    delay = DB_WAIT_INITIAL_DELAY_S
    attempt = 1
    while True:
        try:
            connect().close()
        except sa_exc.OperationalError as error:
            reason = _transient_reason(error)
            if reason is None:
                raise
            waited = clock() - start
            remaining = timeout - waited
            if remaining <= 0:
                logger.error(
                    "database still not ready after %.0f s (%s, %d attempts); giving up",
                    waited,
                    reason,
                    attempt,
                )
                raise
            pause = min(delay, remaining)
            logger.warning(
                "database not ready (%s), attempt %d; retrying in %.1f s (%.0f s of %.0f s)",
                reason,
                attempt,
                pause,
                waited,
                timeout,
            )
            sleep(pause)
            delay = min(delay * 2, DB_WAIT_MAX_DELAY_S)
            attempt += 1
        else:
            if attempt > 1:
                logger.warning(
                    "database ready after %d attempts (%.0f s)", attempt, clock() - start
                )
            return


@contextmanager
def _migration_lock(engine: Engine) -> Iterator[None]:
    """Serialise migrations across replicas that start together (PostgreSQL only; SQLite no-op).

    A session-level pg_advisory_lock on a dedicated AUTOCOMMIT connection, not the xact-level
    variant: the migration runs in its own transaction(s) on another connection, and an xact
    lock would have to live inside that transaction and interfere with Alembic's transaction
    handling. The lock connection holds no transaction, so nothing is left open. It is released
    explicitly in `finally` (an unlock error is only logged); if the process dies, closing the
    connection releases it too.
    The second replica waits, then sees alembic_version already at head and does nothing."""
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as raw:
        lock_conn = raw.execution_options(isolation_level="AUTOCOMMIT")
        # No lock_timeout, intentionally: at container start a replica waits as long as the
        # first one takes to migrate, rather than failing and restarting mid-migration.
        lock_conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK_KEY})
        try:
            yield
        finally:
            # A failed unlock must not mask the migration's exception nor fail a migration that
            # committed: it only fails when the lock connection is gone, and then the server has
            # already released the session lock.
            try:
                lock_conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRATION_LOCK_KEY})
            except Exception:
                logger.warning("could not release the migration lock", exc_info=True)


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations() -> None:
    connection = context.config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = engine_from_settings(Settings())  # type: ignore[call-arg]
    try:
        if engine.dialect.name == "postgresql":
            # Before the R1-28 lock, whose connection would otherwise fail at once.
            _wait_for_database(engine.connect, sleep=time.sleep, clock=time.monotonic)
        with _migration_lock(engine), engine.connect() as conn:
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline migrations are not supported")
run_migrations()
