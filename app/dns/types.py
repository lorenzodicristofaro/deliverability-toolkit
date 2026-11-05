"""Library-independent DNS result types and the Resolver protocol."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

ALLOWED_RDTYPES: frozenset[str] = frozenset(
    {
        "A",
        "AAAA",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "CNAME",
        "PTR",
        "SRV",
        "CAA",
        "DS",
        "DNSKEY",
        "TLSA",
        "NAPTR",
        "SPF",
    }
)  # ANY is deliberately not allowed.

_MAX_NAME = 253
_MAX_LABEL = 63


class ResultState(StrEnum):
    """Outcome of one DNS query. Callers must handle every state.

    ok: answer with at least one record.
    nxdomain: authoritative "name does not exist" (definitive absence).
    nodata: name exists but has no record of this type (definitive absence).
    servfail: server failed to answer (incl. DNSSEC validation failure); NOT absence.
    refused: server refused the query; NOT absence.
    timeout: no answer in time; NOT absence.
    truncated: response too large and the TC fallback could not be completed.
    malformed: response unparseable or over the size cap.
    network_error: server unreachable, connection refused, etc.
    blocked: target rejected by the egress policy (M2-03); the query never ran,
        so this is never "missing".
    error: any other failure to evaluate.
    """

    ok = "ok"
    nxdomain = "nxdomain"
    nodata = "nodata"
    servfail = "servfail"
    refused = "refused"
    timeout = "timeout"
    truncated = "truncated"
    malformed = "malformed"
    network_error = "network_error"
    blocked = "blocked"
    error = "error"

    @property
    def is_ok(self) -> bool:
        return self is ResultState.ok

    @property
    def is_definitive_absence(self) -> bool:
        return self in (ResultState.nxdomain, ResultState.nodata)

    @property
    def is_failure(self) -> bool:
        return not self.is_ok and not self.is_definitive_absence


def join_txt_strings(strings: Iterable[bytes]) -> str:
    """Canonical TXT rdata_text: concatenate the character-strings (no separator)
    and decode the raw bytes as latin-1, so every byte maps to exactly one char
    and decoding never fails."""
    return b"".join(strings).decode("latin-1")


def _validate_name(name: str) -> None:
    if not name or len(name) > _MAX_NAME or not name.isascii() or name != name.lower():
        raise ValueError(f"invalid DNS name: {name!r}")
    if name.endswith("."):
        raise ValueError("DNS name must not have a trailing dot")
    for label in name.split("."):
        if not label or len(label) > _MAX_LABEL or not label.isprintable() or " " in label:
            raise ValueError(f"invalid DNS label in {name!r}")


def _validate_rdtype(rdtype: str) -> None:
    if rdtype not in ALLOWED_RDTYPES:
        raise ValueError(f"rdtype not allowed: {rdtype!r}")


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    name: str
    rdtype: str

    def __post_init__(self) -> None:
        _validate_name(self.name)
        _validate_rdtype(self.rdtype)


@dataclass(frozen=True, slots=True)
class DnsRecord:
    """rdata_text is the canonical presentation text (see join_txt_strings for TXT)."""

    name: str
    rdtype: str
    ttl: int
    rdata_text: str

    def __post_init__(self) -> None:
        _validate_name(self.name)
        _validate_rdtype(self.rdtype)
        if self.ttl < 0:
            raise ValueError("ttl must be >= 0")


@dataclass(frozen=True, slots=True)
class DnsResult:
    question: DnsQuestion
    state: ResultState
    records: tuple[DnsRecord, ...] = ()
    ttl_min: int | None = None
    authenticated_data: bool = False
    rcode: int | None = None
    server: str | None = None
    elapsed_ms: float = 0.0
    detail_code: str | None = None

    def __post_init__(self) -> None:
        if self.state is ResultState.ok and not self.records:
            raise ValueError("ok result requires records")
        if self.state is not ResultState.ok and self.records:
            raise ValueError("records are only allowed for ok results")
        if self.elapsed_ms < 0:
            raise ValueError("elapsed_ms must be >= 0")


@runtime_checkable
class Resolver(Protocol):
    """Async resolver. `resolve` never raises for network/DNS conditions: it
    returns a DnsResult whose state says what happened. Callers must handle
    every ResultState. `identity` is a stable id used as cache key and in reports.
    """

    identity: str

    async def resolve(self, question: DnsQuestion) -> DnsResult: ...
