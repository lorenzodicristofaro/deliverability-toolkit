from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.checks.dnsutil import fetch_cname, fetch_txt
from app.core.domain_names import InvalidDomainName
from app.dns.types import DnsQuestion, DnsRecord, DnsResult, ResultState
from tests.support.dns_zones import FakeResolver, load_zones, parse_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"
_ABSENT = {ResultState.nxdomain, ResultState.nodata}


def _fake(entries: list[dict[str, Any]]) -> FakeResolver:
    return parse_zones({"zones": {"default": entries}}).resolver()


class _Fixed:
    """Resolver returning a canned result for any question."""

    identity = "fixed"

    def __init__(self, state: ResultState, records: tuple[DnsRecord, ...] = ()) -> None:
        self.state, self.records = state, records

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        return DnsResult(question, self.state, self.records)


@pytest.mark.parametrize("state", list(ResultState))
async def test_every_state_txt(state: ResultState) -> None:
    recs = (DnsRecord("example.com", "TXT", 60, "v=spf1 -all"),) if state.is_ok else ()
    out = await fetch_txt(_Fixed(state, recs), "example.com")
    assert out.state is state
    if state.is_ok:
        assert out.evaluated and out.records == ("v=spf1 -all",) and out.ttl == 60
    elif state in _ABSENT:
        assert out.evaluated and out.records == () and out.ttl is None
    else:
        assert not out.evaluated and out.records == ()


@pytest.mark.parametrize("state", list(ResultState))
async def test_every_state_cname(state: ResultState) -> None:
    recs = (DnsRecord("a.example.com", "CNAME", 60, "t.example.net"),) if state.is_ok else ()
    out = await fetch_cname(_Fixed(state, recs), "a.example.com")
    assert out.state is state
    assert out.evaluated == (state.is_ok or state in _ABSENT)
    assert out.target == ("t.example.net" if state.is_ok else None)


@pytest.mark.parametrize(
    ("zone", "name", "state", "evaluated"),
    [
        ("healthy", "example.com", ResultState.ok, True),
        ("healthy", "_dmarc.example.com", ResultState.ok, True),
        ("healthy", "s1._domainkey.example.com", ResultState.ok, True),
        ("healthy", "missing.example.com", ResultState.nxdomain, True),
        ("failures", "nodata.example.com", ResultState.nodata, True),
        ("failures", "truncated.example.com", ResultState.truncated, False),
    ],
)
async def test_recorded_zones_txt(
    zone: str, name: str, state: ResultState, evaluated: bool
) -> None:
    resolver = load_zones(ZONES / f"{zone}.yaml").resolver()
    out = await fetch_txt(resolver, name)
    assert (out.state, out.evaluated) == (state, evaluated)


async def test_multi_string_and_record_order_not_merged() -> None:
    r = load_zones(ZONES / "healthy.yaml").resolver()
    out = await fetch_txt(r, "example.com")
    assert out.records == ("v=spf1 ip4:192.0.2.0/24 -all", "v=DKIM1; k=rsa; p=AAAABBBB")
    assert out.ttl == 300


async def test_non_ascii_latin1_lossless() -> None:
    r = _fake([{"name": "x.example.com", "type": "TXT", "ttl": 5, "rdata": [["caf\xe9 ", "\xff"]]}])
    out = await fetch_txt(r, "x.example.com")
    assert out.records == ("caf\xe9 \xff",)


async def test_ok_without_requested_type_is_not_evaluated() -> None:
    wrong = (DnsRecord("example.com", "A", 60, "192.0.2.1"),)
    out = await fetch_txt(_Fixed(ResultState.ok, wrong), "example.com")
    assert not out.evaluated and out.records == ()


async def test_cname_target_and_absent() -> None:
    r = _fake([{"name": "a.example.com", "type": "CNAME", "ttl": 30, "rdata": ["t.example.net"]}])
    got = await fetch_cname(r, "a.example.com")
    assert (got.target, got.evaluated, got.ttl) == ("t.example.net", True, 30)
    none = await fetch_cname(r, "b.example.com")
    assert (none.target, none.evaluated, none.state) == (None, True, ResultState.nxdomain)


async def test_name_normalised() -> None:
    r = _fake([{"name": "x.example.com", "type": "TXT", "ttl": 5, "rdata": ["a"]}])
    assert (await fetch_txt(r, " X.Example.com. ")).records == ("a",)


@pytest.mark.parametrize("bad", ["", "a b.example.com", "192.0.2.1", "a..example.com", "x\x00.com"])
async def test_invalid_name_raises(bad: str) -> None:
    with pytest.raises(InvalidDomainName):
        await fetch_txt(_Fixed(ResultState.nxdomain), bad)
    with pytest.raises(InvalidDomainName):
        await fetch_cname(_Fixed(ResultState.nxdomain), bad)


def _cnames(*targets: str) -> _Fixed:
    return _Fixed(
        ResultState.ok, tuple(DnsRecord("a.example.com", "CNAME", 60, t) for t in targets)
    )


async def test_cname_multiple_distinct_targets_not_evaluated() -> None:
    out = await fetch_cname(_cnames("t1.example.net", "t2.example.net"), "a.example.com")
    assert (out.state, out.evaluated, out.target, out.ttl) == (ResultState.error, False, None, None)


async def test_cname_identical_duplicates_collapse() -> None:
    out = await fetch_cname(_cnames("T.Example.net.", "t.example.net"), "a.example.com")
    assert (out.state, out.evaluated, out.target) == (ResultState.ok, True, "t.example.net")
