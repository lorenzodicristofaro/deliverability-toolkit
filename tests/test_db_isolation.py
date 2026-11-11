"""M5-15b: the shared migrated schema still isolates tests, on SQLite and on PostgreSQL."""

from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from app.core.db import create_db_engine, create_session_factory
from app.models import Base, Tenant
from tests import conftest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("run", [1, 2, 3])
def test_rows_and_sequences_do_not_leak_to_the_next_test(migrated_db_url: str, run: int) -> None:
    """Each run writes a row, so whichever runs second proves the first one's row and id are gone
    (it holds in any test order)."""
    engine = create_db_engine(migrated_db_url)
    try:
        with create_session_factory(engine)() as session:
            assert session.execute(text("SELECT COUNT(*) FROM tenants")).scalar_one() == 0
            tenant = Tenant(name=f"run{run}", slug=f"run{run}")
            session.add(tenant)
            session.commit()
            assert tenant.id == 1
    finally:
        engine.dispose()


def test_migrated_db_url_is_at_head_with_every_table(migrated_db_url: str) -> None:
    engine = create_db_engine(migrated_db_url)
    try:
        assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    finally:
        engine.dispose()
    assert (
        version == ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    )


def test_db_url_is_truly_empty(db_url: str) -> None:
    """Also on PostgreSQL right after tests that used the shared migrated schema."""
    project_tables = {*Base.metadata.tables, "alembic_version"}
    engine = create_db_engine(db_url)
    try:
        assert not project_tables & set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


@pytest.mark.parametrize("run", [1, 2])
def test_migrated_db_url_after_a_db_url_test_is_migrated_again(
    migrated_db_url: str, run: int
) -> None:
    engine = create_db_engine(migrated_db_url)
    try:
        assert "alembic_version" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("vetted", "url"),
    [
        (None, "postgresql://u:p@h/app_test"),  # nothing vetted: no TEST_DATABASE_URL at start
        ("postgresql://u:p@h/app_test", "postgresql://u:p@h/other_test"),  # another database
        ("postgresql://u:p@h/app_test", "postgresql://u:p@other/app_test"),  # another host
        ("postgresql://u:p@h/app_test", ""),
        ("postgresql://u:p@h/app_test", "not a url"),
    ],
)
@pytest.mark.parametrize(
    "reset",
    [
        conftest._reset_postgres,
        conftest._truncate_postgres,
        conftest._check_postgres_schema_unchanged,
    ],
    ids=["drop", "truncate", "schema_check"],
)
def test_every_postgres_reset_refuses_an_unvetted_url(
    monkeypatch: pytest.MonkeyPatch, vetted: str | None, url: str, reset: object
) -> None:
    """Raises before connecting, so no database or network is involved."""
    monkeypatch.setattr(conftest._pg, "vetted_url", vetted)
    with pytest.raises(RuntimeError, match="not vetted") as refused:
        reset(url)  # type: ignore[operator]
    if url:
        assert url not in str(refused.value)
