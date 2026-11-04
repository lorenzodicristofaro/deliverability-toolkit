"""Shared fixtures. The database URL fixture is the single parametrisation point: M1-07 adds a
PostgreSQL variant (TEST_DATABASE_URL) without touching the tests that use it."""

from pathlib import Path

import pytest


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'test.db'}"
