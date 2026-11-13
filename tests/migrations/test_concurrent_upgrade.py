"""Two replicas that start together must both reach head (PostgreSQL only; skipped without
TEST_DATABASE_URL, like the PostgreSQL parameters in tests/conftest.py)."""

import multiprocessing
import os
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.core.db import create_db_engine
from tests.conftest import PG_SKIP_REASON, _reset_postgres

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40


def _upgrade_worker(barrier: Any, errors: Any) -> None:
    """Runs in a spawned process: waits for its peer, then runs a real `upgrade head`."""
    import app.core.db as db

    original = db.engine_from_settings

    def synced(settings: Any) -> Any:
        engine = original(settings)
        barrier.wait(timeout=60)  # both processes enter the migration together
        return engine

    db.engine_from_settings = synced
    try:
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    except BaseException as exc:  # reported to the parent, which asserts on it
        errors.put(f"{type(exc).__name__}: {exc}")
        raise


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason=PG_SKIP_REASON)
def test_two_concurrent_upgrades_from_empty_both_reach_head(
    _postgres_session: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = _postgres_session
    _reset_postgres(url)
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    errors = ctx.Queue()
    procs = [ctx.Process(target=_upgrade_worker, args=(barrier, errors)) for _ in range(2)]
    try:
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=300)
        reported = []
        while not errors.empty():
            reported.append(errors.get())
        assert reported == []
        assert [p.exitcode for p in procs] == [0, 0]
        engine = create_db_engine(url)
        try:
            with engine.connect() as conn:
                rows = conn.execute(text("SELECT version_num FROM alembic_version")).all()
        finally:
            engine.dispose()
        head = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
        assert [r[0] for r in rows] == [head]
    finally:
        for p in procs:
            if p.is_alive():
                p.kill()
        _reset_postgres(url)
