"""Database engine and session factory (sync SQLAlchemy 2.x; SQLite and PostgreSQL).

Tenant data is accessed only through /repositories; this module only provides plumbing.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


def normalize_url(url: str) -> str:
    """Select the psycopg (v3) driver for bare postgresql:// URLs; other URLs are unchanged."""
    parsed = make_url(url)
    if parsed.drivername in ("postgresql", "postgres"):
        parsed = parsed.set(drivername="postgresql+psycopg")
    return parsed.render_as_string(hide_password=False)


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def create_db_engine(url: str) -> Engine:
    engine = create_engine(normalize_url(url))
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def engine_from_settings(settings: Settings) -> Engine:
    return create_db_engine(settings.database_url.get_secret_value())


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
