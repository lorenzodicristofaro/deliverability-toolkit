from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.checks.spf_tree import (
    LOOKUP_LIMIT,
    MAX_DEPTH,
    MAX_NODES,
    MAX_QUERIES,
    MX_ADDRESS_LIMIT,
    VOID_LOOKUP_LIMIT,
    SpfNode,
    SpfTree,
    resolve_spf,
)
from app.core.domain_names import InvalidDomainName
from app.dns.types import DnsQuestion, DnsResult, ResultState
from tests.dns.conftest import _no_network_in_dns_tests  # noqa: F401  (autouse socket guard)
from tests.support.dns_zones import FakeResolver, load_zones, parse_zones

ZONES = Path(__file__).parent.parent / "fixtures" / "zones"


def _zone(name: str) -> FakeResolver:
    return load_zones(ZONES / f"spf_{name}.yaml").resolver()


def _find(tree: SpfTree, domain: str) -> SpfNode:
    return next(n for n in tree.nodes() if n.domain == domain)


def test_limits_are_rfc_values() -> None:
    assert (LOOKUP_LIMIT, VOID_LOOKUP_LIMIT, MX_ADDRESS_LIMIT) == (10, 2, 10)


@pytest.mark.parametrize(
    ("zone", "domain", "lookups", "voids", "evaluated", "truncated", "n_nodes"),
    [
        ("counts", "simple.example.com", 1, 0, True, False, 2),
        ("counts", "ten.example.com", 10, 0, True, False, 4),
        ("counts", "eleven.example.com", 11, 0, True, False, 4),
        ("counts", "voids2.example.com", 2, 2, True, False, 1),
        ("counts", "voids3.example.com", 3, 3, True, False, 2),
        ("counts", "v6only.example.com", 1, 1, True, False, 1),
        ("counts", "mxten.example.com", 1, 0, True, False, 1),
        ("counts", "mxmany.example.com", 1, 0, True, False, 1),
        ("counts", "inclplain.example.com", 1, 0, True, False, 2),
        ("counts", "dup.example.com", 4, 0, True, False, 3),
        ("counts", "macro.example.com", 3, 0, True, False, 1),
        ("loops", "loopa.example.com", 2, 0, True, False, 3),
        ("loops", "self.example.com", 1, 0, True, False, 2),
        ("loops", "selfredir.example.com", 1, 0, True, False, 2),
        ("loops", "r1.example.com", 2, 0, True, False, 3),
        ("loops", "rall.example.com", 0, 0, True, False, 1),
        ("loops", "d0.example.com", MAX_DEPTH + 1, 0, True, True, MAX_DEPTH + 2),
        ("failures", "sf.example.com", 1, 0, False, False, 2),
        ("failures", "to.example.com", 1, 0, False, False, 1),
        ("failures", "trunc.example.com", 1, 0, False, False, 2),
        ("failures", "rootfail.example.com", 0, 0, False, False, 1),
        ("failures", "mal.example.com", 1, 0, True, False, 2),
        ("failures", "synroot.example.com", 0, 0, True, False, 1),
        ("failures", "multi.example.com", 0, 0, True, False, 1),
        ("failures", "incmulti.example.com", 1, 0, True, False, 2),
        ("failures", "nospf.example.com", 0, 0, True, False, 1),
        ("failures", "nothing.example.com", 0, 0, True, False, 1),
        ("failures", "incmissing.example.com", 1, 1, True, False, 2),
        ("failures", "redirmissing.example.com", 1, 1, True, False, 2),
    ],
)
async def test_tree_counters(
    zone: str,
    domain: str,
    lookups: int,
    voids: int,
    evaluated: bool,
    truncated: bool,
    n_nodes: int,
) -> None:
    tree = await resolve_spf(_zone(zone), domain)
    assert tree.domain == domain
    assert (tree.lookup_count, tree.void_count) == (lookups, voids)
    assert (tree.evaluated, tree.truncated) == (evaluated, truncated)
    assert len(tree.nodes()) == n_nodes
    assert tree.lookup_limit_exceeded == (lookups > LOOKUP_LIMIT)
    assert tree.void_limit_exceeded == (voids > VOID_LOOKUP_LIMIT)
    assert tree.evaluated == (tree.errors == ())


async def test_node_fields_recorded() -> None:
    tree = await resolve_spf(_zone("counts"), "Simple.Example.com.")
    root = tree.root
    assert (root.domain, root.via, root.depth, root.dns_state) == (
        "simple.example.com",
        "root",
        0,
        ResultState.ok,
    )
    assert root.records == ("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all",)
    assert [t.name for t in root.terms] == ["ip4", "include", "all"]
    (child,) = root.children
    assert (child.domain, child.via, child.depth) == ("_spf.example.net", "include", 1)
    assert child.record is not None and child.record.is_valid
    assert child.lookups == () and child.children == ()


async def test_ip_all_exp_not_counted_ptr_counted_unresolved() -> None:
    tree = await resolve_spf(_zone("counts"), "ten.example.com")
    n2 = _find(tree, "n2.example.net")
    ptr = next(lk for lk in n2.lookups if lk.term.name == "ptr")
    assert (ptr.resolved, ptr.target, ptr.states) == (False, None, ())
    n3 = _find(tree, "n3.example.net")
    assert [lk.term.name for lk in n3.lookups] == ["a", "mx"]  # exp is not a lookup term


async def test_voids_and_nodata_vs_nxdomain() -> None:
    tree = await resolve_spf(_zone("counts"), "voids3.example.com")
    by = {lk.term.name: lk for lk in tree.root.lookups}
    assert by["a"].void and dict(by["a"].states) == {
        "A": ResultState.nxdomain,
        "AAAA": ResultState.nxdomain,
    }
    assert by["mx"].void and dict(by["mx"].states) == {"MX": ResultState.nodata}
    assert by["include"].void and by["include"].child is not None
    assert by["include"].child.missing_target and by["include"].child.error is None


async def test_a_void_decided_by_a_query_aaaa_recorded() -> None:
    tree = await resolve_spf(_zone("counts"), "v6only.example.com")
    (lk,) = tree.root.lookups
    assert lk.void and lk.error is None
    assert dict(lk.states) == {"A": ResultState.nodata, "AAAA": ResultState.ok}


@pytest.mark.parametrize(
    ("a_entry", "aaaa_state", "error"),
    [
        ({"rdata": ["192.0.2.1"], "ttl": 60}, "servfail", ResultState.servfail),
        ({"state": "nxdomain"}, "timeout", ResultState.timeout),
        ({"state": "servfail"}, "nxdomain", ResultState.servfail),
    ],
)
async def test_a_failure_on_either_family_is_error_not_void(
    a_entry: dict[str, Any], aaaa_state: str, error: ResultState
) -> None:
    resolver = _fake(
        [
            _txt("fam.test", "v=spf1 a:h.fam.test -all"),
            {"name": "h.fam.test", "type": "A", **a_entry},
            {"name": "h.fam.test", "type": "AAAA", "state": aaaa_state},
        ]
    )
    tree = await resolve_spf(resolver, "fam.test")
    (lk,) = tree.root.lookups
    assert lk.error is error and not lk.void
    assert tree.void_count == 0 and not tree.evaluated


@pytest.mark.parametrize(
    ("domain", "hosts", "exceeded"),
    [("mxten.example.com", 10, False), ("mxmany.example.com", 11, True)],
)
async def test_mx_address_lookups(domain: str, hosts: int, exceeded: bool) -> None:
    tree = await resolve_spf(_zone("counts"), domain)
    assert tree.mx_address_lookups == ((domain, hosts),)
    assert tree.mx_limit_exceeded is exceeded
    (lk,) = tree.root.lookups
    assert (lk.mx_hosts, lk.mx_limit_exceeded) == (hosts, exceeded)


async def test_include_without_spf_is_missing_not_void_not_error() -> None:
    tree = await resolve_spf(_zone("counts"), "inclplain.example.com")
    (child,) = tree.root.children
    assert child.no_record and child.missing_target and child.error is None
    assert child.dns_state is ResultState.ok and tree.void_count == 0


async def test_same_name_fetched_once() -> None:
    resolver = _zone("counts")
    tree = await resolve_spf(resolver, "dup.example.com")
    asked = [(q.name, q.rdtype) for q in resolver.questions]
    assert asked.count(("shared.example.net", "TXT")) == 1
    assert asked.count(("host.example.net", "A")) == 1
    assert len(asked) == len(set(asked)) == tree.query_count
    assert [c.domain for c in tree.root.children] == ["shared.example.net"] * 2
    assert not tree.has_loop


async def test_macro_terms_not_queried() -> None:
    resolver = _zone("counts")
    tree = await resolve_spf(resolver, "macro.example.com")
    assert all(not lk.resolved for lk in tree.root.lookups)
    assert [q.name for q in resolver.questions] == ["macro.example.com"]


@pytest.mark.parametrize(
    ("domain", "loop_domain", "via"),
    [
        ("loopa.example.com", "loopa.example.com", "include"),
        ("self.example.com", "self.example.com", "include"),
        ("selfredir.example.com", "selfredir.example.com", "redirect"),
    ],
)
async def test_loop_detection(domain: str, loop_domain: str, via: str) -> None:
    resolver = _zone("loops")
    tree = await resolve_spf(resolver, domain)
    loops = [n for n in tree.nodes() if n.loop]
    assert len(loops) == 1 and loops[0].domain == loop_domain and loops[0].via == via
    assert loops[0].dns_state is None and loops[0].children == ()
    assert tree.has_loop and tree.evaluated
    txt = [q.name for q in resolver.questions if q.rdtype == "TXT"]
    assert len(txt) == len(set(txt))


async def test_redirect_chain_and_redirect_ignored_with_all() -> None:
    tree = await resolve_spf(_zone("loops"), "r1.example.com")
    assert [(n.domain, n.via, n.depth) for n in tree.nodes()] == [
        ("r1.example.com", "root", 0),
        ("r2.example.com", "redirect", 1),
        ("r3.example.com", "redirect", 2),
    ]
    rall = await resolve_spf(_zone("loops"), "rall.example.com")
    assert rall.root.children == () and rall.lookup_count == 0


async def test_deep_chain_truncated_at_depth_cap() -> None:
    tree = await resolve_spf(_zone("loops"), "d0.example.com")
    last = tree.nodes()[-1]
    assert last.truncated and last.depth == MAX_DEPTH + 1 and last.dns_state is None
    assert max(n.depth for n in tree.nodes() if not n.truncated) == MAX_DEPTH
    assert tree.lookup_count > LOOKUP_LIMIT and tree.evaluated


@pytest.mark.parametrize(
    ("domain", "failed", "state"),
    [
        ("sf.example.com", "broken.example.net", ResultState.servfail),
        ("trunc.example.com", "big.example.net", ResultState.truncated),
        ("rootfail.example.com", "rootfail.example.com", ResultState.servfail),
    ],
)
async def test_txt_failure_is_error_not_missing(
    domain: str, failed: str, state: ResultState
) -> None:
    tree = await resolve_spf(_zone("failures"), domain)
    node = _find(tree, failed)
    assert node.error is state and not node.no_record and not node.missing_target
    assert not tree.evaluated and tree.void_count == 0
    assert (failed, "TXT", state) in tree.errors


async def test_a_timeout_is_error_not_void() -> None:
    tree = await resolve_spf(_zone("failures"), "to.example.com")
    (lk,) = tree.root.lookups
    assert lk.error is ResultState.timeout and not lk.void
    assert ("slow.example.net", "A", ResultState.timeout) in tree.errors


class _Blocking:
    """Wraps a fake resolver and answers ``blocked`` for one name (egress policy)."""

    identity = "blocking"

    def __init__(self, inner: FakeResolver, name: str) -> None:
        self.inner, self.name = inner, name

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        if question.name == self.name:
            return DnsResult(question, ResultState.blocked)
        return await self.inner.resolve(question)


async def test_blocked_is_error() -> None:
    resolver = _Blocking(_zone("failures"), "blocked.example.net")
    tree = await resolve_spf(resolver, "blk.example.com")
    (child,) = tree.root.children
    assert child.error is ResultState.blocked and not child.no_record
    assert not tree.evaluated and tree.void_count == 0


async def test_malformed_record_inside_include() -> None:
    tree = await resolve_spf(_zone("failures"), "mal.example.com")
    bad = _find(tree, "badrec.example.net")
    assert bad.syntax_error and bad.record is not None and not bad.record.is_valid
    assert {"unknown_mechanism", "bad_ip", "empty_value"} <= set(bad.record.issue_codes())
    assert bad.lookups == () and bad.children == ()
    assert tree.lookup_count == 1 and tree.evaluated


async def test_malformed_root_record_not_evaluated() -> None:
    resolver = _zone("failures")
    tree = await resolve_spf(resolver, "synroot.example.com")
    assert tree.root.syntax_error and tree.root.records and tree.root.lookups == ()
    assert tree.root.record is not None
    assert "unknown_mechanism" in tree.root.record.issue_codes()
    assert [q.name for q in resolver.questions] == ["synroot.example.com"]


async def test_multiple_records_kept_and_not_followed() -> None:
    tree = await resolve_spf(_zone("failures"), "incmulti.example.com")
    (child,) = tree.root.children
    assert child.multiple_records and len(child.records) == 2
    assert child.record is None and child.lookups == ()


@pytest.mark.parametrize(
    ("domain", "state"),
    [("nospf.example.com", ResultState.ok), ("nothing.example.com", ResultState.nxdomain)],
)
async def test_root_without_spf(domain: str, state: ResultState) -> None:
    tree = await resolve_spf(_zone("failures"), domain)
    assert tree.root.no_record and not tree.root.missing_target
    assert tree.root.dns_state is state and tree.evaluated


async def test_redirect_to_missing_is_recorded() -> None:
    tree = await resolve_spf(_zone("failures"), "redirmissing.example.com")
    (child,) = tree.root.children
    assert child.via == "redirect" and child.missing_target
    (lk,) = tree.root.lookups
    assert lk.void and tree.void_count == 1


def _fake(entries: list[dict[str, Any]]) -> FakeResolver:
    return parse_zones({"zones": {"default": entries}}).resolver()


def _txt(name: str, text: str) -> dict[str, Any]:
    return {"name": name, "type": "TXT", "ttl": 60, "rdata": [text]}


async def test_node_cap_bounds_wide_tree() -> None:
    entries = [_txt("wide.test", "v=spf1 " + " ".join(f"include:w{i}.test" for i in range(20)))]
    for i in range(20):
        inc = " ".join(f"include:x{i}-{j}.test" for j in range(10))
        entries.append(_txt(f"w{i}.test", f"v=spf1 {inc} -all"))
    resolver = _fake(entries)
    tree = await resolve_spf(resolver, "wide.test")
    fetched = [n for n in tree.nodes() if not n.truncated]
    assert len(fetched) == MAX_NODES and tree.truncated
    assert tree.lookup_count > LOOKUP_LIMIT and tree.evaluated
    assert len(resolver.questions) == tree.query_count == MAX_NODES


async def test_query_cap_bounds_hostile_record() -> None:
    terms = " ".join(f"a:h{i}.test" for i in range(190))
    resolver = _fake([_txt("hostile.test", f"v=spf1 {terms} -all")])
    tree = await resolve_spf(resolver, "hostile.test")
    assert tree.truncated and tree.query_count == MAX_QUERIES == len(resolver.questions)
    assert tree.lookup_count > LOOKUP_LIMIT and tree.evaluated


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 include:bad_label.example.com -all",
        "v=spf1 a:" + "x" * 64 + ".example.com -all",
    ],
)
async def test_invalid_target_not_queried(record: str) -> None:
    resolver = _fake([_txt("inv.test", record)])
    tree = await resolve_spf(resolver, "inv.test")
    assert [q.name for q in resolver.questions] == ["inv.test"]
    assert all(lk.invalid_target for lk in tree.root.lookups)


@pytest.mark.parametrize("bad", ["", "a b.example.com", "192.0.2.1", "x\x00.com"])
async def test_invalid_root_raises(bad: str) -> None:
    with pytest.raises(InvalidDomainName):
        await resolve_spf(_fake([_txt("x.test", "v=spf1 -all")]), bad)


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1",
        "v=spf1 include",
        "v=spf1 redirect=",
        "v=spf1 \x00",
        "garbage",
        "v=spf1 " + "a " * 300,
    ],
)
async def test_malformed_root_records_never_raise(record: str) -> None:
    resolver = _fake(
        [_txt("m.test", record), {"name": "m.test", "type": "A", "ttl": 60, "rdata": ["192.0.2.1"]}]
    )
    tree = await resolve_spf(resolver, "m.test")
    assert tree.query_count <= MAX_QUERIES
