"""Alembic environment. The URL comes from an injected connection (tests) or from Settings."""

from alembic import context
from sqlalchemy.engine import Connection

from app.core.config import Settings
from app.core.db import engine_from_settings
from app.models import Base

target_metadata = Base.metadata


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
        with engine.connect() as conn:
            _run(conn)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline migrations are not supported")
run_migrations()
