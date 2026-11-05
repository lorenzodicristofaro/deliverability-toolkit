import dataclasses
from typing import Any

import pytest

from app.dns.types import (
    ALLOWED_RDTYPES,
    DnsQuestion,
    DnsRecord,
    DnsResult,
    Resolver,
    ResultState,
    join_txt_strings,
)

Q = DnsQuestion("example.com", "A")
R = DnsRecord("example.com", "A", 300, "192.0.2.1")


@pytest.mark.parametrize("state", list(ResultState))
def test_exactly_one_class(state: ResultState) -> None:
    assert [state.is_ok, state.is_definitive_absence, state.is_failure].count(True) == 1


@pytest.mark.parametrize(
    ("state", "absence"),
    [(s, s in (ResultState.nxdomain, ResultState.nodata)) for s in ResultState],
)
def test_definitive_absence_only_nx_nodata(state: ResultState, absence: bool) -> None:
    assert state.is_definitive_absence is absence


@pytest.mark.parametrize("state", [ResultState.servfail, ResultState.timeout])
def test_servfail_timeout_never_absence(state: ResultState) -> None:
    assert not state.is_definitive_absence
    assert state.is_failure


def test_blocked_exists_and_is_failure() -> None:
    assert ResultState("blocked").is_failure


@pytest.mark.parametrize(
    "name",
    [
        "",
        "Example.com",
        "example.com.",
        "a..b",
        "exämple.com",
        "a b.com",
        "a" * 64 + ".com",
        ("a." * 130) + "com",
    ],
)
def test_bad_names(name: str) -> None:
    with pytest.raises(ValueError):
        DnsQuestion(name, "A")


@pytest.mark.parametrize("rdtype", ["ANY", "any", "a", "", "BOGUS", "AXFR"])
def test_bad_rdtypes(rdtype: str) -> None:
    with pytest.raises(ValueError):
        DnsQuestion("example.com", rdtype)


@pytest.mark.parametrize("rdtype", sorted(ALLOWED_RDTYPES))
def test_allowed_rdtypes(rdtype: str) -> None:
    assert DnsQuestion("example.com", rdtype).rdtype == rdtype


def test_record_negative_ttl() -> None:
    with pytest.raises(ValueError):
        DnsRecord("example.com", "A", -1, "x")


@pytest.mark.parametrize("state", [s for s in ResultState if s is not ResultState.ok])
def test_records_with_non_ok_rejected(state: ResultState) -> None:
    with pytest.raises(ValueError):
        DnsResult(Q, state, records=(R,))
    assert DnsResult(Q, state).records == ()


def test_ok_requires_records() -> None:
    with pytest.raises(ValueError):
        DnsResult(Q, ResultState.ok)
    assert DnsResult(Q, ResultState.ok, records=(R,), ttl_min=300).state.is_ok


def test_negative_elapsed_rejected() -> None:
    with pytest.raises(ValueError):
        DnsResult(Q, ResultState.timeout, elapsed_ms=-1)


@pytest.mark.parametrize("obj", [Q, R, DnsResult(Q, ResultState.nxdomain)])
def test_immutable(obj: Any) -> None:
    field = dataclasses.fields(obj)[0].name
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(obj, field, "x")


@pytest.mark.parametrize(
    ("strings", "expected"),
    [
        ([b"v=spf1 ", b"-all"], "v=spf1 -all"),
        ([], ""),
        ([b"\xe9"], "\xe9"),
        ([b"\x00\xff"], "\x00\xff"),
    ],
)
def test_txt_join(strings: list[bytes], expected: str) -> None:
    assert join_txt_strings(strings) == expected


def test_resolver_protocol() -> None:
    class Fake:
        identity = "fake"

        async def resolve(self, question: DnsQuestion) -> DnsResult:
            return DnsResult(question, ResultState.timeout)

    assert isinstance(Fake(), Resolver)
    assert not isinstance(object(), Resolver)


def test_root_name_accepted() -> None:
    assert DnsQuestion(".", "NS").name == "."


@pytest.mark.parametrize("name", ["..", ".a", "a..", ".."])
def test_root_lookalikes_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        DnsQuestion(name, "NS")


@pytest.mark.parametrize(
    ("state", "rcode"),
    [
        (ResultState.nxdomain, 2),
        (ResultState.nxdomain, 0),
        (ResultState.nodata, 3),
        (ResultState.nodata, 2),
    ],
)
def test_inconsistent_rcode_rejected(state: ResultState, rcode: int) -> None:
    with pytest.raises(ValueError):
        DnsResult(Q, state, rcode=rcode)


def test_ok_rcode_must_be_zero() -> None:
    with pytest.raises(ValueError):
        DnsResult(Q, ResultState.ok, records=(R,), rcode=3)
    assert DnsResult(Q, ResultState.ok, records=(R,), rcode=0).rcode == 0
    assert DnsResult(Q, ResultState.nxdomain, rcode=3).rcode == 3
    assert DnsResult(Q, ResultState.nodata, rcode=0).rcode == 0
    assert DnsResult(Q, ResultState.servfail, rcode=2).rcode == 2


def test_negative_ttl_min_rejected() -> None:
    with pytest.raises(ValueError):
        DnsResult(Q, ResultState.ok, records=(R,), ttl_min=-1)


def test_explicit_failure_set() -> None:
    expected = {
        ResultState.servfail,
        ResultState.refused,
        ResultState.timeout,
        ResultState.truncated,
        ResultState.malformed,
        ResultState.network_error,
        ResultState.blocked,
        ResultState.error,
    }
    assert {s for s in ResultState if s.is_failure} == expected
