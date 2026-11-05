import socket
from typing import Any

import pytest

from app.dns.knowledge import PublicResolver
from app.dns.types import DnsQuestion, DnsResult, ResultState
from app.services.dns_tools import (
    COMMON_RDTYPES,
    MAX_CONCURRENCY,
    FcrdnsState,
    InvalidLookupInput,
    LookupResolvers,
    lookup,
    parse_ip,
    reverse,
)
from tests.support.dns_zones import FakeResolver, parse_zones

DEFAULT = "default"


def make(entries: list[dict[str, Any]]) -> FakeResolver:
    return parse_zones({"zones": {DEFAULT: entries}}).resolver()


def rs(fake: Any) -> LookupResolvers:
    return LookupResolvers(default=fake, public_factory=lambda e: fake)


def rec(name: str, typ: str, rdata: list[str], ttl: int = 300, **kw: Any) -> dict[str, Any]:
    return {"name": name, "type": typ, "ttl": ttl, "rdata": rdata, **kw}


def fail(name: str, typ: str, state: str) -> dict[str, Any]:
    return {"name": name, "type": typ, "state": state}


ZONE = [
    rec("example.com", "A", ["192.0.2.10"]),
    rec("example.com", "AAAA", ["2001:db8::10"]),
    rec("example.com", "MX", ["10 mx.example.com"]),
    rec("example.com", "TXT", ["v=spf1 -all"]),
    rec("example.com", "NS", ["ns1.example.net"]),
    rec("example.com", "SOA", ["ns1.example.net h.example.com 1 2 3 4 5"]),
    rec("_dmarc.example.com", "TXT", ["v=DMARC1; p=none"]),
]


async def test_all_types_distinct_states() -> None:
    fake = make(
        [
            *ZONE,
            fail("example.com", "CAA", "servfail"),
            fail("example.com", "CNAME", "nodata"),
        ]
    )
    rep = await lookup("example.com", "all", DEFAULT, resolvers=rs(fake))
    by = {r.rdtype: r.state for r in rep.results}
    assert tuple(by) == COMMON_RDTYPES
    assert by["A"] is ResultState.ok and by["CAA"] is ResultState.servfail
    assert by["CNAME"] is ResultState.nodata
    assert rep.summary.evaluated is False
    assert rep.summary.failed == ("CAA",)
    assert "CAA" not in rep.summary.absent and "CAA" not in rep.summary.found
    assert "CNAME" in rep.summary.absent
    assert rep.resolver_identity == "fake:default"
    assert not any(q.rdtype == "ANY" for q in fake.questions)


@pytest.mark.parametrize(
    "state",
    ["servfail", "refused", "timeout", "truncated", "malformed", "network_error"],
)
async def test_failure_states_never_missing(state: str) -> None:
    fake = make([*ZONE, fail("bad.example.com", "A", state)])
    rep = await lookup("bad.example.com", "A", DEFAULT, resolvers=rs(fake))
    (r,) = rep.results
    assert r.state.value == state
    assert r.evaluated is False
    assert rep.summary.evaluated is False
    assert rep.summary.absent == () and rep.summary.failed == ("A",)


@pytest.mark.parametrize(
    ("name", "state"),
    [("missing.example.com", ResultState.nxdomain), ("example.com", ResultState.nodata)],
)
async def test_absence_is_evaluated(name: str, state: ResultState) -> None:
    rep = await lookup(name, "SRV", DEFAULT, resolvers=rs(make(ZONE)))
    assert rep.results[0].state is state
    assert rep.summary.evaluated is True and rep.summary.absent == ("SRV",)


async def test_timeout_does_not_hide_other_types() -> None:
    fake = make([e for e in ZONE if e["type"] != "MX"] + [fail("example.com", "MX", "timeout")])
    rep = await lookup("example.com", "ALL", DEFAULT, resolvers=rs(fake))
    by = {r.rdtype: r for r in rep.results}
    assert by["MX"].state is ResultState.timeout
    assert by["A"].records[0].rdata_text == "192.0.2.10"
    assert by["TXT"].state is ResultState.ok
    assert rep.summary.found == ("A", "AAAA", "TXT", "NS", "SOA")


@pytest.mark.parametrize(
    "name",
    [
        "_dmarc.example.com",
        "_DMARC.Example.COM.",
        "  _dmarc.example.com \n",
    ],
)
async def test_name_forms(name: str) -> None:
    rep = await lookup(name, "TXT", DEFAULT, resolvers=rs(make(ZONE)))
    assert rep.name == "_dmarc.example.com"
    assert rep.results[0].state is ResultState.ok


async def test_unicode_name_idna() -> None:
    fake = make([])
    rep = await lookup("bücher.example.com", "A", DEFAULT, resolvers=rs(fake))
    assert rep.name == "xn--bcher-kva.example.com"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "a\x00b.example.com",
        "example.com\x00",
        ("a" * 64) + ".example.com",
        ".".join(["a" * 60] * 5) + ".com",
        "-bad-.example.com",
        "a_b.example.com",
        "exa mple.com",
        "single",
        "192.0.2.1",
        "x" * 2000,
        None,
        123,
        b"example.com",
    ],
)
async def test_malformed_names_rejected(bad: Any) -> None:
    fake = make(ZONE)
    with pytest.raises(InvalidLookupInput) as e:
        await lookup(bad, "A", DEFAULT, resolvers=rs(fake))
    assert e.value.field == "name"
    assert fake.questions == []


@pytest.mark.parametrize("bad", ["ANY", "any", "", "BOGUS", "A;B", None, 1])
async def test_rdtype_validation(bad: Any) -> None:
    with pytest.raises(InvalidLookupInput) as e:
        await lookup("example.com", bad, DEFAULT, resolvers=rs(make(ZONE)))
    assert e.value.field == "rdtype"


@pytest.mark.parametrize(
    "bad",
    ["", "Default", "public:", "public:nope", "8.8.8.8", "8.8.8.8:53", "public", "x:google", None],
)
async def test_selector_validation(bad: Any) -> None:
    with pytest.raises(InvalidLookupInput) as e:
        await lookup("example.com", "A", bad, resolvers=rs(make(ZONE)))
    assert e.value.field == "resolver"


async def test_public_selector_uses_factory_with_known_entry() -> None:
    seen: list[PublicResolver] = []
    fake = make(ZONE)

    def factory(entry: PublicResolver) -> FakeResolver:
        seen.append(entry)
        return fake

    rep = await lookup(
        "example.com", "A", "public:google", resolvers=LookupResolvers(fake, factory)
    )
    assert [e.id for e in seen] == ["google"]
    assert rep.resolver_selector == "public:google"


async def test_default_public_factory_goes_through_egress_policy() -> None:
    # Real factory, but resolution is never reached for a blocked target; here the entry is
    # public so we only check an unsent build: identity names the target, no query is issued.
    from app.services.dns_tools import _build_public

    r = _build_public(PublicResolver("t", "t", "t", ("10.0.0.1",), 53, None, (), "unverified"))
    res = await r.resolve(DnsQuestion("example.com", "A"))
    assert res.state is ResultState.blocked


async def test_concurrency_cap_and_exception_is_error() -> None:
    import asyncio

    active = peak = 0

    class Slow:
        identity = "slow"

        async def resolve(self, q: DnsQuestion) -> DnsResult:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
            if q.rdtype == "MX":
                raise RuntimeError("boom")
            return DnsResult(q, ResultState.nodata)

    rep = await lookup("example.com", "ALL", DEFAULT, resolvers=LookupResolvers(Slow()))
    assert peak <= MAX_CONCURRENCY
    mx = next(r for r in rep.results if r.rdtype == "MX")
    assert mx.state is ResultState.error and mx.detail_code == "resolver_exception"
    assert rep.summary.evaluated is False


# ---- reverse ----


@pytest.mark.parametrize(
    ("text", "ptr"),
    [
        ("192.0.2.10", "10.2.0.192.in-addr.arpa"),
        (" 192.0.2.10\n", "10.2.0.192.in-addr.arpa"),
        (
            "2001:db8::1",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ),
        (
            "2001:DB8:0:0:0:0:0:1",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        ),
        (
            "::ffff:192.0.2.1",
            "1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        ),
        ("10.0.0.1", "1.0.0.10.in-addr.arpa"),  # private accepted as input
    ],
)
async def test_reverse_names(text: str, ptr: str) -> None:
    fake = make([])
    rep = await reverse(text, DEFAULT, resolvers=rs(fake))
    assert rep.ptr_name == ptr
    assert [(q.name, q.rdtype) for q in fake.questions] == [(ptr, "PTR")]


@pytest.mark.parametrize(
    ("bad", "reason"),
    [
        ("", "empty"),
        ("example.com", "malformed"),
        ("192.0.2.0/24", "range"),
        ("fe80::1%eth0", "zone_id"),
        ("192.0.2", "malformed"),
        ("192.0.2.256", "malformed"),
        ("192.000.2.1", "malformed"),
        ("1.2.3.4 5.6.7.8", "malformed"),
        ("1.2.3.4\x00", "malformed"),
        ("２００１:db8::1", "malformed"),
        ("2001:db8::g", "malformed"),
        ("[2001:db8::1]", "malformed"),
        ("1" * 100, "malformed"),
        (None, "not_a_string"),
        (3232235777, "not_a_string"),
    ],
)
def test_parse_ip_rejects(bad: Any, reason: str) -> None:
    with pytest.raises(InvalidLookupInput) as e:
        parse_ip(bad)
    assert (e.value.field, e.value.reason) == ("ip", reason)


async def test_private_ip_input_makes_no_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    fake = make([])
    rep = await reverse("192.168.1.1", DEFAULT, resolvers=rs(fake))
    assert rep.ptr.state is ResultState.nxdomain
    assert [q.name for q in fake.questions] == ["1.1.168.192.in-addr.arpa"]


PTR = "10.2.0.192.in-addr.arpa"


def fz(*extra: dict[str, Any], ptr: list[str] | None = None) -> FakeResolver:
    return make([rec(PTR, "PTR", ptr or ["mail.example.com."]), *extra])


async def fc(fake: FakeResolver) -> Any:
    return await reverse("192.0.2.10", DEFAULT, resolvers=rs(fake), forward_confirm=True)


async def test_fcrdns_confirmed() -> None:
    rep = await fc(fz(rec("mail.example.com", "A", ["192.0.2.10"])))
    assert rep.fcrdns is FcrdnsState.confirmed and rep.evaluated is True
    assert rep.forward[0].matches is True


async def test_fcrdns_confirmed_via_v6_ptr_target_ipv6() -> None:
    ip6 = "2001:db8::1"
    name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    fake = make([rec(name, "PTR", ["Mail.Example.com"]), rec("mail.example.com", "AAAA", [ip6])])
    rep = await reverse(ip6, DEFAULT, resolvers=rs(fake), forward_confirm=True)
    assert rep.fcrdns is FcrdnsState.confirmed


async def test_fcrdns_mismatch_only_when_fully_evaluated() -> None:
    rep = await fc(fz(rec("mail.example.com", "A", ["192.0.2.99"])))
    assert rep.fcrdns is FcrdnsState.mismatch and rep.evaluated is True
    rep = await fc(fz())  # forward name has no A/AAAA: nxdomain, still definitive
    assert rep.fcrdns is FcrdnsState.mismatch


@pytest.mark.parametrize("state", ["servfail", "timeout", "refused", "network_error", "truncated"])
@pytest.mark.parametrize("which", ["A", "AAAA"])
async def test_fcrdns_forward_failure_is_could_not_verify(state: str, which: str) -> None:
    other = "AAAA" if which == "A" else "A"
    addr = "192.0.2.99" if other == "A" else "2001:db8::99"
    rep = await fc(
        fz(fail("mail.example.com", which, state), rec("mail.example.com", other, [addr]))
    )
    assert rep.fcrdns is FcrdnsState.could_not_verify
    assert rep.fcrdns is not FcrdnsState.mismatch
    assert rep.evaluated is False and rep.detail_code == "forward_not_evaluated"


@pytest.mark.parametrize(
    ("extra", "ptr", "expected", "detail", "matches"),
    [
        # match + failure elsewhere -> pass, failure recorded
        (
            [rec("a.example.com", "A", ["192.0.2.10"]), fail("b.example.com", "A", "timeout")],
            ["a.example.com.", "b.example.com."],
            FcrdnsState.confirmed,
            "forward_not_evaluated",
            [True, None],
        ),
        # match on A, AAAA of same name failed -> still pass
        (
            [rec("a.example.com", "A", ["192.0.2.10"]), fail("a.example.com", "AAAA", "servfail")],
            ["a.example.com."],
            FcrdnsState.confirmed,
            None,
            [True],
        ),
        # match + invalid PTR name -> pass, recorded
        (
            [rec("a.example.com", "A", ["192.0.2.10"])],
            ["a.example.com.", "bad name.example.com"],
            FcrdnsState.confirmed,
            "invalid_ptr_name",
            [True],
        ),
        # no match + failure -> could not verify
        (
            [rec("a.example.com", "A", ["192.0.2.99"]), fail("b.example.com", "A", "timeout")],
            ["a.example.com.", "b.example.com."],
            FcrdnsState.could_not_verify,
            "forward_not_evaluated",
            [False, None],
        ),
        # all ok, no match -> mismatch
        (
            [rec("a.example.com", "A", ["192.0.2.99"]), rec("b.example.com", "A", ["192.0.2.98"])],
            ["a.example.com.", "b.example.com."],
            FcrdnsState.mismatch,
            None,
            [False, False],
        ),
    ],
)
async def test_fcrdns_match_wins(
    extra: list[dict[str, Any]],
    ptr: list[str],
    expected: FcrdnsState,
    detail: str | None,
    matches: list[bool | None],
) -> None:
    rep = await fc(fz(*extra, ptr=ptr))
    assert rep.fcrdns is expected
    assert rep.detail_code == detail
    assert [f.matches for f in rep.forward][: len(matches)] == matches
    if expected is FcrdnsState.confirmed:
        assert rep.evaluated is True


@pytest.mark.parametrize("state", ["servfail", "timeout", "refused", "malformed"])
async def test_fcrdns_ptr_failure(state: str) -> None:
    rep = await fc(make([fail(PTR, "PTR", state)]))
    assert rep.fcrdns is FcrdnsState.could_not_verify
    assert rep.ptr.state.value == state and rep.evaluated is False
    assert rep.detail_code == "ptr_not_evaluated"


async def test_fcrdns_no_ptr_is_evaluated() -> None:
    rep = await fc(make([]))
    assert rep.ptr.state is ResultState.nxdomain
    assert rep.fcrdns is FcrdnsState.no_ptr and rep.evaluated is True


@pytest.mark.parametrize("bad_target", ["bad name.example.com", "a" * 64 + ".example.com", ""])
async def test_fcrdns_unusable_ptr_rdata(bad_target: str) -> None:
    rep = await fc(fz(ptr=[bad_target]))
    assert rep.fcrdns is FcrdnsState.could_not_verify
    assert rep.detail_code == "invalid_ptr_name"


async def test_fcrdns_too_many_ptr_names() -> None:
    names = [f"h{i}.example.com." for i in range(12)]
    rep = await fc(fz(ptr=names))
    assert rep.fcrdns is FcrdnsState.could_not_verify
    assert rep.detail_code == "too_many_ptr_names" and len(rep.forward) == 8


async def test_not_requested_makes_no_forward_queries() -> None:
    fake = fz()
    rep = await reverse("192.0.2.10", DEFAULT, resolvers=rs(fake))
    assert rep.fcrdns is FcrdnsState.not_requested and rep.forward == ()
    assert len(fake.questions) == 1


async def test_reverse_selector_validation() -> None:
    with pytest.raises(InvalidLookupInput) as e:
        await reverse("192.0.2.10", "1.1.1.1", resolvers=rs(make([])))
    assert e.value.field == "resolver"
