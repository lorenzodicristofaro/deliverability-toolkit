"""Alembic environment. The URL comes from an injected connection (tests) or from Settings."""

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from alembic import context
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
        with _migration_lock(engine), engine.connect() as conn:
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline migrations are not supported")
run_migrations()
