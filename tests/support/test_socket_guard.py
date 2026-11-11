"""Unit tests of the offline socket guard (no real database, no network)."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from tests.support import socket_guard
from tests.support.socket_guard import db_endpoint, install


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("postgresql://u:p@localhost:5432/x_test", ("localhost", 5432)),
        ("postgresql://u:p@DB.example:6543/x_test", ("db.example", 6543)),
        ("postgresql://u:p@127.0.0.1/x_test", ("127.0.0.1", 5432)),
        ("", None),
        ("not a url", None),
        ("sqlite:///x.db", None),
    ],
)
def test_db_endpoint(url: str, expected: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    assert db_endpoint(url) == expected


def test_db_endpoint_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    assert db_endpoint() is None


def _run(monkeypatch: pytest.MonkeyPatch, endpoint: Any) -> list[Any]:
    calls: list[Any] = []

    def fake_connect(self: Any, address: Any) -> int:
        calls.append(address)
        return 0

    monkeypatch.setattr(socket.socket, "connect", fake_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", fake_connect)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    install(monkeypatch, "guard test", endpoint)
    return calls


def test_allowed_db_endpoint_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _run(monkeypatch, ("127.0.0.1", 5432))
    s = socket.socket()
    try:
        assert s.connect(("127.0.0.1", 5432)) == 0
        assert s.connect_ex(("127.0.0.1", 5432)) == 0
        assert socket.getaddrinfo("127.0.0.1", 5432) == []
    finally:
        s.close()
    assert len(calls) == 2


@pytest.mark.parametrize(
    "address",
    [("127.0.0.1", 53), ("127.0.0.1", 5433), ("10.0.0.1", 5432), ("localhost", 5432), "/tmp/x"],
)
def test_other_connects_fail(monkeypatch: pytest.MonkeyPatch, address: Any) -> None:
    calls = _run(monkeypatch, ("127.0.0.1", 5432))
    s = socket.socket()
    try:
        with pytest.raises(AssertionError, match="network access"):
            s.connect(address)
        with pytest.raises(AssertionError, match="network access"):
            s.connect_ex(address)
    finally:
        s.close()
    assert calls == []


def test_everything_fails_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, None)
    s = socket.socket()
    try:
        with pytest.raises(AssertionError):
            s.connect(("127.0.0.1", 5432))
        with pytest.raises(AssertionError):
            s.sendto(b"x", ("127.0.0.1", 53))
        with pytest.raises(AssertionError):
            socket.getaddrinfo("127.0.0.1", 5432)
        with pytest.raises(AssertionError):
            socket.gethostbyname("localhost")
    finally:
        s.close()


def test_getaddrinfo_only_for_db_host_and_port(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, ("db.test", 5432))
    assert socket.getaddrinfo("db.test", 5432) == []
    for host, port in (("db.test", 53), ("other.test", 5432), ("db.test", None)):
        with pytest.raises(AssertionError):
            socket.getaddrinfo(host, port)
    assert socket_guard.resolved_addresses(None) == set()
