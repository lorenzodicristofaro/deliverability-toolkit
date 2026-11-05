import ipaddress
import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.dns.types import DnsQuestion, Resolver, ResultState
from tests.support.dns_zones import (
    FakeResolver,
    ZoneData,
    ZoneFixtureError,
    is_reserved_addr,
    is_reserved_name,
    load_zones,
    parse_zones,
)

ZONES_DIR = Path(__file__).parent.parent / "fixtures" / "zones"


def q(name: str, rdtype: str = "A") -> DnsQuestion:
    return DnsQuestion(name, rdtype)


async def test_no_socket_is_created(fake_dns: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("socket created")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    servers = fake_dns("healthy")
    assert (await servers.resolver().resolve(q("example.com"))).state is ResultState.ok
    assert (await fake_dns("delegation").query_server("192.0.2.1", q("example.com"))).referral


def test_implements_resolver_protocol(fake_dns: Any) -> None:
    assert isinstance(fake_dns("healthy").resolver(), Resolver)


@pytest.mark.parametrize(
    ("fixture", "name", "rdtype", "state"),
    [
        ("healthy", "example.com", "A", ResultState.ok),
        ("healthy", "example.com", "AAAA", ResultState.ok),
        ("healthy", "example.com", "MX", ResultState.ok),
        ("healthy", "example.com", "NS", ResultState.ok),
        ("healthy", "example.com", "SOA", ResultState.ok),
        ("healthy", "example.com", "CAA", ResultState.ok),
        ("healthy", "_dmarc.example.com", "TXT", ResultState.ok),
        ("healthy", "s1._domainkey.example.com", "TXT", ResultState.ok),
        ("healthy", "example.com", "SRV", ResultState.nodata),
        ("healthy", "_domainkey.example.com", "TXT", ResultState.nodata),  # empty non-terminal
        ("healthy", "missing.example.com", "A", ResultState.nxdomain),
        ("failures", "nodata.example.com", "AAAA", ResultState.nodata),
        ("failures", "leaf.example.com", "A", ResultState.nodata),  # ENT
        ("failures", "servfail.example.com", "A", ResultState.servfail),
        ("failures", "refused.example.com", "A", ResultState.refused),
        ("failures", "timeout.example.com", "A", ResultState.timeout),
        ("failures", "truncated.example.com", "TXT", ResultState.truncated),
        ("failures", "malformed.example.com", "A", ResultState.malformed),
        ("failures", "down.example.com", "A", ResultState.network_error),
        ("failures", "nothing.example.com", "A", ResultState.nxdomain),
    ],
)
async def test_resolution_states(
    fake_dns: Any, fixture: str, name: str, rdtype: str, state: ResultState
) -> None:
    res = await fake_dns(fixture).resolver().resolve(q(name, rdtype))
    assert res.state is state
    assert res.server == "fake:default"


async def test_ok_details(fake_dns: Any) -> None:
    r = fake_dns("healthy").resolver()
    mx = await r.resolve(q("example.com", "MX"))
    assert [x.rdata_text for x in mx.records] == ["10 mx1.example.com", "20 mx2.example.com"]
    assert mx.ttl_min == 3600
    assert not mx.authenticated_data
    txt = await r.resolve(q("example.com", "TXT"))
    assert [x.rdata_text for x in txt.records][1] == "v=DKIM1; k=rsa; p=AAAABBBB"  # joined
    assert (await r.resolve(q("signed.example.com"))).authenticated_data


async def test_rcode_and_no_sleep(fake_dns: Any) -> None:
    r = FakeResolver(fake_dns("failures").resolver().zones, latency_ms=25.0)
    res = await r.resolve(q("servfail.example.com"))
    assert res.rcode == 2
    assert (await r.resolve(q("timeout.example.com"))).state is ResultState.timeout
    assert r.virtual_elapsed_ms == 50.0
    assert res.elapsed_ms == 25.0


async def test_records_questions(fake_dns: Any) -> None:
    servers = fake_dns("healthy")
    r = servers.resolver()
    await r.resolve(q("example.com"))
    await r.resolve(q("example.com", "MX"))
    assert r.questions == [q("example.com"), q("example.com", "MX")]
    assert servers.all_questions == r.questions


async def test_servers_disagree(fake_dns: Any) -> None:
    s = fake_dns("disagree")
    answers = {
        addr: (await s.query_server(addr, q("example.com"))).result
        for addr in ("192.0.2.53", "198.51.100.53", "203.0.113.53", "192.0.2.200")
    }
    assert answers["192.0.2.53"].records[0].rdata_text == "192.0.2.99"
    assert answers["198.51.100.53"].records[0].rdata_text == "192.0.2.10"
    assert answers["203.0.113.53"].state is ResultState.servfail
    assert answers["192.0.2.200"].state is ResultState.network_error


async def test_delegation_chain(fake_dns: Any) -> None:
    s = fake_dns("delegation")
    root = await s.query_server("192.0.2.1", q("example.com", "A"))
    assert root.referral is not None and root.referral.zone == "com"
    tld = await s.query_server(root.referral.ns[0].addr, q("example.com", "A"))
    assert tld.referral is not None and tld.referral.zone == "example.com"
    auth = await s.query_server(tld.referral.ns[0].addr, q("example.com", "A"))
    assert auth.referral is None and auth.result.state is ResultState.ok
    private = await s.query_server("192.0.2.2", q("www.example.net", "A"))
    assert private.referral is not None
    assert ipaddress.ip_address(private.referral.ns[0].addr).is_private


def good() -> dict[str, Any]:
    return {
        "zones": {
            "default": [{"name": "example.com", "type": "A", "ttl": 1, "rdata": ["192.0.2.1"]}]
        }
    }


def entry(**kw: Any) -> dict[str, Any]:
    return {"zones": {"default": [kw]}}


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (None, "non-empty mapping"),
        ({}, "non-empty mapping"),
        ({"zones": {}}, "non-empty mapping"),
        ({"zones": {"not-an-ip": []}}, "`default` or an IP"),
        ({"zones": {"default": {}}}, "list of entries"),
        ({"zones": {"default": ["x"]}}, "must be a mapping"),
        (entry(type="A", ttl=1, rdata=["192.0.2.1"]), "`name`"),
        (entry(name="example.com", ttl=1, rdata=["192.0.2.1"]), "`type`"),
        (entry(name="example.com", type="ANY", ttl=1, rdata=["x"]), "not allowed"),
        (entry(name="Example.COM", type="A", ttl=1, rdata=["192.0.2.1"]), "invalid DNS name"),
        (
            entry(name="example.com", type="A", ttl=1, rdata=["192.0.2.1"], state="servfail"),
            "xor|exactly one",
        ),
        (entry(name="example.com", type="A"), "exactly one"),
        (entry(name="example.com", type="A", state="bogus"), "unknown state"),
        (entry(name="example.com", type="A", state="ok"), "not allowed in a failure"),
        (entry(name="example.com", type="A", state="servfail", rcode=99), "rcode"),
        (entry(name="example.com", type="A", state="servfail", rcode=True), "rcode"),
        (entry(name="example.com", type="A", ttl=-1, rdata=["192.0.2.1"]), "ttl"),
        (entry(name="example.com", type="A", ttl="5", rdata=["192.0.2.1"]), "ttl"),
        (entry(name="example.com", type="A", ttl=True, rdata=["192.0.2.1"]), "ttl"),
        (entry(name="example.com", type="A", rdata=["192.0.2.1"]), "ttl"),
        (entry(name="example.com", type="A", ttl=1, rdata=[5]), "must be a string"),
        (entry(name="example.com", type="TXT", ttl=1, rdata=[[1, 2]]), "must be a string"),
        (entry(name="example.com", type="A", ttl=1, rdata=[["a"]]), "must be a string"),
        (entry(name="example.com", type="A", ttl=1, rdata="192.0.2.1"), "non-empty list"),
        (entry(name="example.com", type="A", ttl=1, rdata=[]), "non-empty list"),
        (entry(name="example.com", type="A", ttl=1, rdata=["nope"]), "invalid address"),
        (entry(name="example.com", type="A", ttl=1, rdata=["192.0.2.1"], ad="yes"), "`ad`"),
        (entry(referral={"zone": "com"}), "ns"),
        (
            entry(referral={"zone": "com", "ns": [{"name": "a.example.net", "addr": "zz"}]}),
            "not an IP",
        ),
        (entry(referral={"zone": "com", "ns": [{"name": 1, "addr": "192.0.2.1"}]}), "string"),
        (entry(referral="com"), "zone"),
    ],
)
def test_malformed_fixtures(data: Any, message: str) -> None:
    with pytest.raises(ZoneFixtureError, match=message):
        parse_zones(data, "t.yaml")


def test_duplicate_entries() -> None:
    data = good()
    data["zones"]["default"].append(dict(data["zones"]["default"][0]))
    with pytest.raises(ZoneFixtureError, match="duplicate"):
        parse_zones(data)


def test_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("zones: [unclosed")
    with pytest.raises(ZoneFixtureError, match="invalid YAML"):
        load_zones(p)


def test_zone_data_default_is_empty() -> None:
    assert ZoneData().names() == set()


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("example.com", True),
        ("a.b.example.net", True),
        ("host.test", True),
        ("x.invalid", True),
        ("com", True),
        (".", True),
        ("google.com", False),
        ("notexample.com", False),
        ("example.com.evil.io", False),
    ],
)
def test_reserved_name_helper(name: str, ok: bool) -> None:
    assert is_reserved_name(name) is ok


def _hostnames(rdtype: str, text: str) -> list[str]:
    if rdtype in ("MX", "NS", "CNAME", "PTR"):
        return [text.split()[-1].rstrip(".")]
    if rdtype == "SOA":
        return [t.rstrip(".") for t in text.split()[:2]]
    return []


def test_all_fixtures_use_reserved_names_only() -> None:
    files = sorted(ZONES_DIR.glob("*.yaml"))
    assert files
    for path in files:
        data = yaml.safe_load(path.read_text())
        parse_zones(data, str(path))  # also validates the schema
        for server, entries in data["zones"].items():
            if server != "default":
                assert is_reserved_addr(server), (path, server)
            for e in entries:
                if "referral" in e:
                    ref = e["referral"]
                    assert is_reserved_name(ref["zone"]), (path, ref["zone"])
                    for ns in ref["ns"]:
                        assert is_reserved_name(ns["name"]), (path, ns)
                        assert is_reserved_addr(ns["addr"]), (path, ns)
                    continue
                assert is_reserved_name(e["name"]), (path, e["name"])
                for item in e.get("rdata", []):
                    text = item if isinstance(item, str) else "".join(item)
                    if e["type"] in ("A", "AAAA"):
                        assert is_reserved_addr(text), (path, text)
                    for host in _hostnames(e["type"], text.replace("@", ".")):
                        assert is_reserved_name(host), (path, host)
