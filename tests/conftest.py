"""Shared fixtures. `db_url` is the single parametrisation point: every test that uses it runs on
SQLite and, when TEST_DATABASE_URL is set (CI, or a local throwaway container), on PostgreSQL."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.core.db import create_db_engine
from app.models import Base


def refusal_reason(test_url: str, app_url: str | None) -> str | None:
    """Why TEST_DATABASE_URL must not be used (None = safe). The reset drops tables, so it only
    ever runs on a database whose name contains "test" and that is not the app's DATABASE_URL.
    The reason never contains the URL or its password."""
    try:
        database = make_url(test_url).database or ""
    except ArgumentError:
        return "TEST_DATABASE_URL is not a valid database URL"
    if "test" not in database.lower():
        return 'TEST_DATABASE_URL database name must contain "test"'
    if app_url and test_url.strip() == app_url.strip():
        return "TEST_DATABASE_URL equals DATABASE_URL"
    return None


def _reset_postgres(url: str) -> None:
    """Drop only what this project creates, so a clean schema is guaranteed per test."""
    engine = create_db_engine(url)
    try:
        Base.metadata.drop_all(engine)
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
    finally:
        engine.dispose()


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgresql",
            marks=pytest.mark.skipif(
                not os.environ.get("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL not set"
            ),
        ),
    ]
)
def db_url(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[str]:
    if request.param == "sqlite":
        yield f"sqlite:///{tmp_path / 'test.db'}"
        return
    url = os.environ["TEST_DATABASE_URL"]
    reason = refusal_reason(url, os.environ.get("DATABASE_URL"))
    if reason:
        pytest.exit(f"Refusing to reset the test database: {reason}", returncode=2)
    _reset_postgres(url)
    yield url
    _reset_postgres(url)
