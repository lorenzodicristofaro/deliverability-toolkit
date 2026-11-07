"""Socket guard for suites that must stay offline but may reach the test database.

Everything is refused except an exact host:port match on the endpoint parsed from
TEST_DATABASE_URL (only when that variable is set). Loopback in general is NOT allowed, so a DNS
query to 127.0.0.1:53 or another port on the DB host still fails."""

from __future__ import annotations

import os
import socket
from typing import Any

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

Endpoint = tuple[str, int]


def db_endpoint(url: str | None = None) -> Endpoint | None:
    """host:port of TEST_DATABASE_URL (or `url`); None when unset or without a host."""
    url = os.environ.get("TEST_DATABASE_URL") if url is None else url
    if not url:
        return None
    try:
        parsed = make_url(url)
    except ArgumentError:
        return None
    if not parsed.host:
        return None
    return parsed.host.lower(), parsed.port or 5432


def resolved_addresses(endpoint: Endpoint | None) -> set[Endpoint]:
    """The endpoint plus the IPs its host name resolves to (a connect uses the resolved IP)."""
    if endpoint is None:
        return set()
    host, port = endpoint
    allowed = {endpoint}
    try:
        for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            allowed.add((str(info[4][0]).lower(), port))
    except OSError:
        pass
    return allowed


def install(monkeypatch: pytest.MonkeyPatch, label: str, endpoint: Endpoint | None) -> None:
    allowed = resolved_addresses(endpoint)
    real_getaddrinfo = socket.getaddrinfo

    def blocked(*_a: Any, **_k: Any) -> Any:
        raise AssertionError(f"network access in {label}")

    def guarded_connect(original: Any) -> Any:
        def wrapper(self: Any, address: Any, *args: Any, **kwargs: Any) -> Any:
            if (
                isinstance(address, tuple)
                and len(address) >= 2
                and (str(address[0]).lower(), address[1]) in allowed
            ):
                return original(self, address, *args, **kwargs)
            raise AssertionError(f"network access in {label}")

        return wrapper

    def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if (
            endpoint is not None
            and isinstance(host, str)
            and host.lower() == endpoint[0]
            and port in (endpoint[1], str(endpoint[1]))
        ):
            return real_getaddrinfo(host, port, *args, **kwargs)
        raise AssertionError(f"network access in {label}")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, guarded_connect(getattr(socket.socket, name)))
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
