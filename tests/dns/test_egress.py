import ast
import ipaddress
from pathlib import Path

import pytest

from app.core.config import ResolverAddr
from app.dns.egress import (
    BLOCKED_IPV4,
    BLOCKED_IPV6,
    BlockReason,
    TargetPolicy,
    is_allowed_untrusted_target,
    parse_target,
    untrusted_target_reason,
)
from app.dns.types import ResultState

POLICY = TargetPolicy()
R = BlockReason

# (target, expected reason) for UNTRUSTED targets; port defaults to 53.
BLOCKED_V4 = [
    ("0.0.0.0", R.unspecified),
    ("0.1.2.3", R.this_network),
    ("10.0.0.1", R.private),
    ("10.255.255.255", R.private),
    ("172.16.0.1", R.private),
    ("172.31.255.254", R.private),
    ("172.28.53.2", R.private),  # bundled Unbound address as UNTRUSTED
    ("192.168.1.1", R.private),
    ("100.64.0.1", R.shared_address_space),
    ("100.127.255.254", R.shared_address_space),
    ("127.0.0.1", R.loopback),
    ("127.255.255.254", R.loopback),
    ("169.254.0.1", R.link_local),
    ("169.254.169.254", R.link_local),  # cloud metadata
    ("192.0.0.1", R.protocol_assignment),
    ("192.0.0.9", R.protocol_assignment),
    ("192.0.0.170", R.protocol_assignment),
    ("192.0.2.1", R.documentation),
    ("198.51.100.7", R.documentation),
    ("203.0.113.9", R.documentation),
    ("198.18.0.1", R.benchmarking),
    ("198.19.255.254", R.benchmarking),
    ("192.88.99.1", R.reserved),
    ("192.88.99.2", R.reserved),
    ("224.0.0.1", R.multicast),
    ("239.255.255.255", R.multicast),
    ("240.0.0.1", R.reserved),
    ("255.255.255.254", R.reserved),
    ("255.255.255.255", R.broadcast),
]

BLOCKED_V6 = [
    ("[::]", R.unspecified),
    ("[::1]", R.loopback),
    ("[fc00::1]", R.private),
    ("[fd12:3456::1]", R.private),
    ("[fe80::1]", R.link_local),
    ("[febf::1]", R.link_local),
    ("[ff02::1]", R.multicast),
    ("[ff0e::fb]", R.multicast),
    ("[2001:db8::53]", R.documentation),
    ("[3fff::1]", R.documentation),
    ("[2001:2::1]", R.benchmarking),
    ("[2001:10::1]", R.protocol_assignment),
    ("[2001:1::1]", R.protocol_assignment),
    ("[100::1]", R.discard),
    ("[100:0:0:1::1]", R.reserved),
    ("[5f00::1]", R.reserved),
    ("[64:ff9b:1::808:808]", R.translation_local),
    ("[fec0::1]", R.not_global_unicast),  # deprecated site-local
    ("[4000::1]", R.not_global_unicast),
    ("[::808:808]", R.not_global_unicast),  # deprecated IPv4-compatible
    ("[1::1]", R.not_global_unicast),
]

# IPv6 forms that embed an IPv4 address.
BLOCKED_EMBEDDED = [
    # IPv4-mapped: blocked as a whole (IANA: not globally reachable), even with a public IPv4.
    ("[::ffff:127.0.0.1]", R.ipv4_mapped),
    ("[::ffff:10.0.0.1]", R.ipv4_mapped),
    ("[::ffff:169.254.169.254]", R.ipv4_mapped),
    ("[::ffff:8.8.8.8]", R.ipv4_mapped),
    # NAT64 well-known prefix (RFC 6052): blocked when the embedded IPv4 is blocked.
    ("[64:ff9b::7f00:1]", R.embedded_ipv4_blocked),  # 127.0.0.1
    ("[64:ff9b::10.0.0.1]", R.embedded_ipv4_blocked),
    ("[64:ff9b::a9fe:a9fe]", R.embedded_ipv4_blocked),  # 169.254.169.254
    ("[64:ff9b::100.64.0.1]", R.embedded_ipv4_blocked),
    # 6to4 (RFC 3056): bits 16-47 carry the IPv4.
    ("[2002:7f00:1::1]", R.embedded_ipv4_blocked),  # 127.0.0.1
    ("[2002:c0a8:101::1]", R.embedded_ipv4_blocked),  # 192.168.1.1
    ("[2002:a9fe:a9fe::1]", R.embedded_ipv4_blocked),  # 169.254.169.254
    ("[2002:a00:1::]", R.embedded_ipv4_blocked),  # 10.0.0.1
    # Teredo (RFC 4380): blocked as a whole, whatever the server/client IPv4.
    ("[2001:0:7f00:1::1]", R.teredo),
    ("[2001:0:808:808:8000:f227:f7f7:f7f7]", R.teredo),
]

ALLOWED = [
    "1.1.1.1",
    "8.8.8.8",
    "8.8.8.8:53",
    "9.9.9.9:053",
    "223.255.255.254",
    "100.63.255.255",  # just below 100.64/10
    "100.128.0.0",  # just above 100.64/10
    "172.15.255.255",
    "172.32.0.0",
    "192.31.196.1",  # AS112-v4, globally reachable
    "[2606:4700:4700::1111]",
    "[2001:4860:4860::8888]:53",
    "[2620:4f:8000::1]",  # Direct Delegation AS112, globally reachable
    "[64:ff9b::808:808]",  # NAT64 of 8.8.8.8
    "[2002:808:808::1]",  # 6to4 of 8.8.8.8
]

MALFORMED = [
    "",
    " ",
    "example.com",
    "example.com:53",
    "localhost",
    "1.2.3.4:99999",
    "1.2.3.4:0",
    "1.2.3.4:",
    "1.2.3.4:abc",
    "[::1",
    "::1",  # unbracketed IPv6
    "[fe80::1%eth0]",
    "256.1.1.1",
    "01.2.3.4",
    "1.2.3",
    "1.1.1.1,8.8.8.8",
    "1.1.1.1,",
    "[]",
    "http://1.1.1.1/",
]


@pytest.mark.parametrize(("target", "reason"), BLOCKED_V4 + BLOCKED_V6 + BLOCKED_EMBEDDED)
def test_blocked_untrusted(target: str, reason: BlockReason) -> None:
    assert untrusted_target_reason(target) is reason
    assert not is_allowed_untrusted_target(target)


@pytest.mark.parametrize(("target", "reason"), BLOCKED_V4)
def test_blocked_ipv4_also_blocked_in_mapped_and_nat64_forms(
    target: str, reason: BlockReason
) -> None:
    v4 = int(ipaddress.IPv4Address(target))
    for prefix in ("::ffff:0:0", "64:ff9b::"):
        v6 = ipaddress.IPv6Address(int(ipaddress.IPv6Address(prefix)) | v4)
        assert not is_allowed_untrusted_target(f"[{v6}]")
    sixtofour = ipaddress.IPv6Address((0x2002 << 112) | (v4 << 80) | 1)
    assert untrusted_target_reason(f"[{sixtofour}]") is R.embedded_ipv4_blocked


@pytest.mark.parametrize("target", ALLOWED)
def test_allowed_untrusted(target: str) -> None:
    assert untrusted_target_reason(target) is None
    assert is_allowed_untrusted_target(target)


@pytest.mark.parametrize("target", MALFORMED)
def test_malformed_untrusted(target: str) -> None:
    assert untrusted_target_reason(target) is R.malformed
    assert not is_allowed_untrusted_target(target)


@pytest.mark.parametrize("value", [None, 53, b"1.1.1.1"])
def test_non_string_target_is_malformed(value: object) -> None:
    assert untrusted_target_reason(value) is R.malformed  # type: ignore[arg-type]
    assert parse_target(value) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("8.8.8.8:5353", R.port_not_allowed),
        ("8.8.8.8:853", R.port_not_allowed),
        ("8.8.8.8:1", R.port_not_allowed),
        ("8.8.8.8:65535", R.port_not_allowed),
        ("[2606:4700:4700::1111]:443", R.port_not_allowed),
        ("10.0.0.1:5353", R.port_not_allowed),  # port is checked before range
    ],
)
def test_untrusted_port_must_be_53(target: str, reason: BlockReason) -> None:
    assert untrusted_target_reason(target) is reason


@pytest.mark.parametrize(
    "addr",
    [
        ResolverAddr("172.28.53.2", 5353),  # bundled Unbound
        ResolverAddr("127.0.0.1", 53),
        ResolverAddr("10.0.0.2", 53),
        ResolverAddr("::1", 5353),
        ResolverAddr("fd00::53", 53),
        ResolverAddr("169.254.169.254", 53),
        ResolverAddr("8.8.8.8", 853),
    ],
)
def test_trusted_any_address_and_port_allowed_but_untrusted_blocked(addr: ResolverAddr) -> None:
    assert POLICY.check(addr, trusted=True) is None
    reason = POLICY.check(addr, trusted=False)
    assert reason is not None
    assert reason.result_state is ResultState.blocked


@pytest.mark.parametrize(
    "addr",
    [
        ResolverAddr("", 53),
        ResolverAddr("example.com", 53),
        ResolverAddr("[::1]", 53),
        ResolverAddr("fe80::1%eth0", 53),
        ResolverAddr(" 1.1.1.1", 53),
        ResolverAddr("1.1.1.1", 0),
        ResolverAddr("1.1.1.1", 65536),
        ResolverAddr("1.1.1.1", -1),
        ResolverAddr("1.1.1.1", True),  # bool is not a port
        ResolverAddr("1.1.1.1", "53"),  # type: ignore[arg-type]
        ResolverAddr(None, 53),  # type: ignore[arg-type]
    ],
)
@pytest.mark.parametrize("trusted", [True, False])
def test_check_malformed_resolver_addr(addr: ResolverAddr, trusted: bool) -> None:
    assert POLICY.check(addr, trusted=trusted) is R.malformed


def test_parse_target_returns_normalised_addr() -> None:
    assert parse_target("8.8.8.8") == ResolverAddr("8.8.8.8", 53)
    assert parse_target("[2001:4860:4860:0::8888]:53") == ResolverAddr("2001:4860:4860::8888", 53)


@pytest.mark.parametrize("reason", list(BlockReason))
def test_every_reason_maps_to_blocked_never_absence(reason: BlockReason) -> None:
    assert reason.result_state is ResultState.blocked
    assert not reason.result_state.is_definitive_absence


@pytest.mark.parametrize(("net", "_reason"), BLOCKED_IPV4 + BLOCKED_IPV6)
def test_every_listed_network_blocks_its_first_and_last_address(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network, _reason: BlockReason
) -> None:
    for ip in (net.network_address, net.broadcast_address):
        host = f"[{ip}]" if ip.version == 6 else str(ip)
        assert not is_allowed_untrusted_target(host), host


def test_module_is_pure() -> None:
    """No DNS library, sockets or HTTP clients in the egress policy module."""
    source = Path(__file__).resolve().parents[2] / "app" / "dns" / "egress.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint({"dns", "socket", "asyncio", "httpx", "requests", "ssl", "urllib"})
