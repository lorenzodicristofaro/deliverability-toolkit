"""R1-25b: bounded wait for PostgreSQL before migrations (no network, no database, no wall clock).

`alembic upgrade head` runs the real migrations/env.py. app.core.db.engine_from_settings is
replaced by a postgresql+psycopg engine whose `creator` is a fake connect function, and
time.sleep / time.monotonic by a fake clock. The fake raises the scripted errors, then a
sentinel: reaching the sentinel proves the error before it was retried."""

import logging
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy import exc as sa_exc

import app.core.db as db

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
PASSWORD = "throwaway-pw-r125b"
HOST = "db-r125b.invalid"
URL = f"postgresql+psycopg://deliverability:{PASSWORD}@{HOST}:5432/deliverability"

REFUSED = (
    f'connection failed: connection to server at "{HOST}" (10.0.0.9), port 5432 failed: '
    "Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?"
)
STARTING = (
    f'connection failed: connection to server at "{HOST}" (10.0.0.9), port 5432 failed: '
    "FATAL:  the database system is starting up"
)
RECOVERING = (
    f'connection failed: connection to server at "{HOST}" (10.0.0.9), port 5432 failed: '
    "FATAL:  the database system is not yet accepting connections"
)
BAD_PASSWORD = (
    f'connection failed: connection to server at "{HOST}" (10.0.0.9), port 5432 failed: '
    'FATAL:  password authentication failed for user "deliverability"'
)
NO_DATABASE = (
    f'connection failed: connection to server at "{HOST}" (10.0.0.9), port 5432 failed: '
    'FATAL:  database "deliverability" does not exist'
)
NO_HOST = f"failed to resolve host '{HOST}': [Errno -2] Name or service not known"


class Reached(Exception):
    """Raised by the fake once the scripted errors are used up."""


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _install(
    monkeypatch: pytest.MonkeyPatch, errors: list[BaseException], *, repeat_last: bool = False
) -> tuple[list[int], FakeClock]:
    """Wire the fake connect function and clock; returns the call log and the clock."""
    calls: list[int] = []

    def fake_connect() -> Any:
        calls.append(1)
        if len(calls) <= len(errors):
            raise errors[len(calls) - 1]
        if repeat_last:
            raise errors[-1]
        raise Reached()

    clock = FakeClock()
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    monkeypatch.setattr("time.sleep", clock.sleep)
    monkeypatch.setattr(
        db, "engine_from_settings", lambda _s: create_engine(URL, creator=fake_connect)
    )
    monkeypatch.setenv("DATABASE_URL", URL)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    return calls, clock


def _upgrade() -> None:
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")


op_error = psycopg.OperationalError


@pytest.mark.parametrize(
    ("errors", "expected", "attempts", "sleeps"),
    [
        # Reproduction (fails before R1-25b): one refused connection aborted the migration.
        pytest.param([op_error(REFUSED)], Reached, 2, [0.5], id="refused-once"),
        pytest.param([op_error(STARTING)] * 3, Reached, 4, [0.5, 1.0, 2.0], id="starting-up-3x"),
        pytest.param([op_error(RECOVERING)], Reached, 2, [0.5], id="not-yet-accepting"),
        pytest.param(
            [op_error(REFUSED), op_error(STARTING)],
            Reached,
            3,
            [0.5, 1.0],
            id="refused-then-starting",
        ),
        # 57P03 class, should psycopg ever attach the SQLSTATE at connect.
        pytest.param(
            [psycopg.errors.CannotConnectNow("x")], Reached, 2, [0.5], id="cannot-connect-now-class"
        ),
        # Not retried: fail at once with the driver error, wrapped by SQLAlchemy.
        pytest.param([op_error(BAD_PASSWORD)], sa_exc.OperationalError, 1, [], id="bad-password"),
        pytest.param([op_error(NO_DATABASE)], sa_exc.OperationalError, 1, [], id="unknown-db"),
        pytest.param([op_error(NO_HOST)], sa_exc.OperationalError, 1, [], id="unresolvable-host"),
        pytest.param([op_error("")], sa_exc.OperationalError, 1, [], id="empty-message"),
        pytest.param([op_error()], sa_exc.OperationalError, 1, [], id="no-args"),
        pytest.param(
            [psycopg.errors.InvalidPassword("x")], sa_exc.OperationalError, 1, [], id="28P01-class"
        ),
        # Not an OperationalError even though the text matches.
        pytest.param(
            [psycopg.InterfaceError("Connection refused")],
            sa_exc.InterfaceError,
            1,
            [],
            id="interface-error",
        ),
        pytest.param(
            [psycopg.ProgrammingError("the database system is starting up")],
            sa_exc.ProgrammingError,
            1,
            [],
            id="programming-error",
        ),
        # Not a DBAPI error at all: SQLAlchemy re-raises it unwrapped.
        pytest.param([OSError("Connection refused")], OSError, 1, [], id="raw-oserror"),
        # Transient first, then a non-transient error stops the wait.
        pytest.param(
            [op_error(REFUSED), op_error(BAD_PASSWORD)],
            sa_exc.OperationalError,
            2,
            [0.5],
            id="refused-then-bad-password",
        ),
    ],
)
def test_first_connection_retry(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    errors: list[BaseException],
    expected: type[BaseException],
    attempts: int,
    sleeps: list[float],
) -> None:
    calls, clock = _install(monkeypatch, errors)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(expected) as info:
        _upgrade()
    assert len(calls) == attempts
    assert clock.sleeps == sleeps
    if expected is sa_exc.OperationalError:
        assert getattr(info.value, "orig", None) is errors[attempts - 1]
    retry_lines = [r.getMessage() for r in caplog.records if "retrying in" in r.getMessage()]
    assert len(retry_lines) == len(sleeps)
    for record in caplog.records:
        assert PASSWORD not in record.getMessage()
        assert HOST not in record.getMessage()


def test_gives_up_after_bound_and_propagates_original(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    error = op_error(REFUSED)
    calls, clock = _install(monkeypatch, [error], repeat_last=True)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(sa_exc.OperationalError) as info:
        _upgrade()
    assert info.value.orig is error
    # 0.5, 1, 2, then capped at 4 s, last pause trimmed so the total is exactly the bound.
    assert clock.sleeps[:4] == [0.5, 1.0, 2.0, 4.0]
    assert max(clock.sleeps) == 4.0
    assert sum(clock.sleeps) == pytest.approx(60.0)
    assert len(calls) == len(clock.sleeps) + 1
    messages = [r.getMessage() for r in caplog.records]
    assert any("giving up" in m for m in messages)
    assert all(PASSWORD not in m and HOST not in m for m in messages)


def test_sqlite_engine_path_does_not_wait(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    clock = FakeClock()
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    monkeypatch.setattr("time.sleep", clock.sleep)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'app.db'}")
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    _upgrade()
    assert clock.sleeps == []
    assert (tmp_path / "app.db").exists()
