"""tests/net never reaches the network: name resolution goes through ScriptedResolver, requests
through an in-process httpx2.MockTransport, and the end-to-end tests use a server bound to
127.0.0.1 inside the test. Connecting anywhere but loopback, sending datagrams and OS name
resolution of anything but loopback fail the test."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Sequence
from typing import Any

import pytest

from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState

_SOCKET = socket.socket


def is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def _blocked(*_a: Any, **_k: Any) -> Any:
    raise AssertionError("network access attempted in a tests/net unit test")


def _guard(original: Any) -> Any:
    def wrapper(self: Any, address: Any, *args: Any, **kwargs: Any) -> Any:
        host = address[0] if isinstance(address, tuple) and address else address
        if isinstance(address, str | bytes) or is_loopback(host):
            return original(self, address, *args, **kwargs)
        raise AssertionError(f"network access attempted in tests/net: {address!r}")

    return wrapper


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(_SOCKET, name, _guard(getattr(_SOCKET, name)))
    for name in ("sendto", "sendmsg"):
        monkeypatch.setattr(_SOCKET, name, _blocked)
    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if is_loopback(host):
            return real_getaddrinfo(host, *args, **kwargs)
        raise AssertionError(f"OS resolver used in tests/net: {host!r}")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


Answer = ResultState | Sequence[str]


class ScriptedResolver:
    """Resolver protocol fake. ``answers[(name, rdtype)]`` is a list of answers consumed one per
    lookup (the last one repeats); an answer is a ResultState or a list of rdata strings.
    Unlisted names answer nxdomain. ``questions`` records every lookup."""

    identity = "scripted"

    def __init__(self, answers: dict[tuple[str, str], list[Answer]] | None = None) -> None:
        self.answers = answers or {}
        self.questions: list[DnsQuestion] = []

    def count(self, name: str, rdtype: str) -> int:
        return sum(1 for q in self.questions if (q.name, q.rdtype) == (name, rdtype))

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        n = self.count(question.name, question.rdtype)
        self.questions.append(question)
        script = self.answers.get((question.name, question.rdtype))
        if not script:
            return DnsResult(question, ResultState.nxdomain)
        answer = script[min(n, len(script) - 1)]
        if isinstance(answer, ResultState):
            return DnsResult(question, answer)
        records = tuple(DnsRecord(question.name, question.rdtype, 300, text) for text in answer)
        return DnsResult(question, ResultState.ok, records=records, ttl_min=300)


def hosts(**names: str | Sequence[str]) -> ScriptedResolver:
    """hosts(**{"www.example.com": "93.184.216.34"}): A/AAAA answers split by family; a family
    without addresses answers nodata."""
    answers: dict[tuple[str, str], list[Answer]] = {}
    for name, value in names.items():
        values = [value] if isinstance(value, str) else list(value)
        v4 = [v for v in values if ":" not in v]
        v6 = [v for v in values if ":" in v]
        answers[(name, "A")] = [v4] if v4 else [ResultState.nodata]
        answers[(name, "AAAA")] = [v6] if v6 else [ResultState.nodata]
    return ScriptedResolver(answers)
