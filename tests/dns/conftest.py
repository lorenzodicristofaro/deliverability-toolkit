"""No test under tests/dns may open a connection (M2-15): the DNS unit tests run against recorded
zones and injected transports only. Creating a socket object stays possible (the event loop owns
a self-pipe socketpair); connecting, sending and resolving names do not."""

from __future__ import annotations

import socket
from typing import Any

import pytest

_SOCKET = socket.socket  # the class, captured before any test replaces the module attribute


@pytest.fixture(autouse=True)
def _no_network_in_dns_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("network access attempted in a DNS unit test")

    for name in ("connect", "connect_ex", "sendto", "sendmsg"):
        monkeypatch.setattr(_SOCKET, name, boom)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, boom)
