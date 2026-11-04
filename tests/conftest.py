"""Shared fixtures. `db_url` is the single parametrisation point: every test that uses it runs on
SQLite and, when TEST_DATABASE_URL is set (CI, or a local throwaway container), on PostgreSQL."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text

from app.core.db import create_db_engine
from app.models import Base


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
    _reset_postgres(url)
    yield url
    _reset_postgres(url)
