"""No test under tests/dns may reach the network (M2-15): the DNS unit tests run against recorded
zones and injected transports only. Creating a socket object stays possible (the event loop owns
a self-pipe socketpair), and loopback / unix sockets stay allowed (the CI database is reached via
`localhost`); connecting, sending and resolving anything else fails."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any

import pytest

_SOCKET = socket.socket  # the class, captured before any test replaces the module attribute
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain"}


def _blocked() -> AssertionError:
    return AssertionError("network access attempted in a DNS unit test")


def is_loopback(host: object) -> bool:
    if host is None or host == "":  # wildcard/local lookups
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host.lower().rstrip(".") in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def _address_host(address: object) -> object:
    return address[0] if isinstance(address, tuple) and address else address


def _guard_address(original: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(self: Any, address: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(address, (str, bytes)) or is_loopback(_address_host(address)):
            return original(self, address, *args, **kwargs)  # unix path or loopback
        raise _blocked()

    return wrapper


def _no_call(*_a: Any, **_k: Any) -> Any:
    raise _blocked()


@pytest.fixture(autouse=True)
def _no_network_in_dns_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(_SOCKET, name, _guard_address(getattr(_SOCKET, name)))
    for name in ("sendto", "sendmsg"):
        monkeypatch.setattr(_SOCKET, name, _no_call)

    real_getaddrinfo = socket.getaddrinfo
    real_create_connection = socket.create_connection

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if is_loopback(host):
            return real_getaddrinfo(host, *args, **kwargs)
        raise _blocked()

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        if not is_loopback(_address_host(address)):
            raise _blocked()
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    for name in ("gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, _no_call)
