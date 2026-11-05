"""DNS egress policy before the M7 guarded client (ARCHITECTURE section 7, M2-03).

Two address classes:

- TRUSTED: operator-configured resolvers (``RESOLVER_ADDRS``). Any well-formed IP literal and
  port, private/Docker addresses included. In ``system`` mode the nameservers come from the
  container's resolv.conf and are not seen by this module (not policy-checkable).
- UNTRUSTED: every target derived from request input or DNS data (public-resolver list entries,
  trace referral/glue/NS addresses). It must be a globally routable unicast IP literal on
  port 53.

A blocked target maps to ``ResultState.blocked`` in callers, never to "missing". Pure functions:
no DNS library, no sockets, no network access.

Address ranges below are taken from the IANA registries, retrieved 2026-11-05:

- IPv4 Special-Purpose Address Registry
  https://www.iana.org/assignments/iana-ipv4-special-registry/
- IPv6 Special-Purpose Address Registry
  https://www.iana.org/assignments/iana-ipv6-special-registry/
- IPv4 Address Space Registry (224/8-239/8 Multicast)
  https://www.iana.org/assignments/ipv4-address-space/
- IPv6 Address Space Registry (2000::/3 Global Unicast, ff00::/8 Multicast)
  https://www.iana.org/assignments/ipv6-address-space/

Every special-purpose entry whose "Globally Reachable" column is False, N/A or empty is blocked.
Covering blocks (192.0.0.0/24, 2001::/23 "IETF Protocol Assignments") are blocked whole: the
globally reachable more-specific entries inside them (PCP/TURN anycast, AMT, AS112-v6, ORCHIDv2,
DETs) are not carved out, since none is a resolver an untrusted target should point at.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from app.core.config import ConfigError, ResolverAddr, parse_resolver_addrs
from app.dns.types import ResultState

UNTRUSTED_DNS_PORT = 53

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class BlockReason(StrEnum):
    """Why a target was rejected. Reason codes only; UI i18n keys come with M2-13."""

    malformed = "malformed"
    port_not_allowed = "port_not_allowed"
    unspecified = "unspecified"
    this_network = "this_network"
    loopback = "loopback"
    private = "private"
    shared_address_space = "shared_address_space"
    link_local = "link_local"
    protocol_assignment = "protocol_assignment"
    documentation = "documentation"
    benchmarking = "benchmarking"
    reserved = "reserved"
    broadcast = "broadcast"
    multicast = "multicast"
    discard = "discard"
    ipv4_mapped = "ipv4_mapped"
    embedded_ipv4_blocked = "embedded_ipv4_blocked"
    translation_local = "translation_local"
    teredo = "teredo"
    not_global_unicast = "not_global_unicast"

    @property
    def result_state(self) -> ResultState:
        """Every block is ResultState.blocked: the query never ran, so it is never absence."""
        return ResultState.blocked


def _v4(net: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(net)


def _v6(net: str) -> ipaddress.IPv6Network:
    return ipaddress.IPv6Network(net)


# IPv4 Special-Purpose Address Registry entries that are not globally reachable, plus multicast
# from the IPv4 Address Space Registry. Order: first match wins.
BLOCKED_IPV4: tuple[tuple[ipaddress.IPv4Network, BlockReason], ...] = (
    (_v4("0.0.0.0/32"), BlockReason.unspecified),  # "This host on this network", RFC 1122
    (_v4("0.0.0.0/8"), BlockReason.this_network),  # "This network", RFC 791
    (_v4("10.0.0.0/8"), BlockReason.private),  # Private-Use, RFC 1918
    (_v4("100.64.0.0/10"), BlockReason.shared_address_space),  # CGNAT, RFC 6598
    (_v4("127.0.0.0/8"), BlockReason.loopback),  # Loopback, RFC 1122
    # Link Local, RFC 3927; includes the cloud metadata address 169.254.169.254.
    (_v4("169.254.0.0/16"), BlockReason.link_local),
    (_v4("172.16.0.0/12"), BlockReason.private),  # Private-Use, RFC 1918
    # IETF Protocol Assignments, RFC 6890 (covers 192.0.0.0/29, .8, .9, .10, .170, .171).
    (_v4("192.0.0.0/24"), BlockReason.protocol_assignment),
    (_v4("192.0.2.0/24"), BlockReason.documentation),  # TEST-NET-1, RFC 5737
    # Deprecated 6to4 Relay Anycast, RFC 7526 (incl. 192.88.99.2/32 6a44-relay, RFC 6751).
    (_v4("192.88.99.0/24"), BlockReason.reserved),
    (_v4("192.168.0.0/16"), BlockReason.private),  # Private-Use, RFC 1918
    (_v4("198.18.0.0/15"), BlockReason.benchmarking),  # Benchmarking, RFC 2544
    (_v4("198.51.100.0/24"), BlockReason.documentation),  # TEST-NET-2, RFC 5737
    (_v4("203.0.113.0/24"), BlockReason.documentation),  # TEST-NET-3, RFC 5737
    (_v4("224.0.0.0/4"), BlockReason.multicast),  # IPv4 Address Space: 224/8-239/8 Multicast
    (_v4("255.255.255.255/32"), BlockReason.broadcast),  # Limited Broadcast, RFC 919/8190
    (_v4("240.0.0.0/4"), BlockReason.reserved),  # Reserved, RFC 1112
)

# IPv6 Address Space Registry: IANA unicast assignments are limited to 2000::/3.
GLOBAL_UNICAST_IPV6 = _v6("2000::/3")
IPV4_MAPPED = _v6("::ffff:0:0/96")  # IPv4-mapped Address, RFC 4291 (not globally reachable)
NAT64_WELL_KNOWN = _v6("64:ff9b::/96")  # IPv4-IPv6 Translat., RFC 6052 (globally reachable)
SIX_TO_FOUR = _v6("2002::/16")  # 6to4, RFC 3056 (Globally Reachable N/A)

# IPv6 Special-Purpose Address Registry entries that are not globally reachable, plus multicast
# from the IPv6 Address Space Registry. Order: first match wins. Anything outside 2000::/3 that
# is not listed here is blocked as not_global_unicast.
BLOCKED_IPV6: tuple[tuple[ipaddress.IPv6Network, BlockReason], ...] = (
    (_v6("::/128"), BlockReason.unspecified),  # Unspecified Address, RFC 4291
    (_v6("::1/128"), BlockReason.loopback),  # Loopback Address, RFC 4291
    (IPV4_MAPPED, BlockReason.ipv4_mapped),
    (_v6("64:ff9b:1::/48"), BlockReason.translation_local),  # Local-use NAT64, RFC 8215
    (_v6("100::/64"), BlockReason.discard),  # Discard-Only Address Block, RFC 6666
    (_v6("100:0:0:1::/64"), BlockReason.reserved),  # Dummy IPv6 Prefix, RFC 9780
    (_v6("2001::/32"), BlockReason.teredo),  # TEREDO, RFC 4380 (Globally Reachable N/A)
    (_v6("2001:2::/48"), BlockReason.benchmarking),  # Benchmarking, RFC 5180
    (_v6("2001::/23"), BlockReason.protocol_assignment),  # IETF Protocol Assignments, RFC 2928
    (_v6("2001:db8::/32"), BlockReason.documentation),  # Documentation, RFC 3849
    (_v6("3fff::/20"), BlockReason.documentation),  # Documentation, RFC 9637
    (_v6("5f00::/16"), BlockReason.reserved),  # Segment Routing (SRv6) SIDs, RFC 9602
    (_v6("fc00::/7"), BlockReason.private),  # Unique-Local, RFC 4193
    (_v6("fe80::/10"), BlockReason.link_local),  # Link-Local Unicast, RFC 4291
    (_v6("ff00::/8"), BlockReason.multicast),  # IPv6 Address Space: Multicast, RFC 4291
)


def _ipv4_reason(ip: ipaddress.IPv4Address) -> BlockReason | None:
    for net, reason in BLOCKED_IPV4:
        if ip in net:
            return reason
    return None


def _ipv6_reason(ip: ipaddress.IPv6Address) -> BlockReason | None:
    if ip in NAT64_WELL_KNOWN:
        # RFC 6052: the IPv4 address is the last 32 bits.
        embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        return BlockReason.embedded_ipv4_blocked if _ipv4_reason(embedded) else None
    for net, reason in BLOCKED_IPV6:
        if ip in net:
            return reason
    if ip not in GLOBAL_UNICAST_IPV6:
        return BlockReason.not_global_unicast
    if ip in SIX_TO_FOUR:
        sixtofour = ip.sixtofour  # RFC 3056: bits 16-47 carry the IPv4 address
        if sixtofour is None or _ipv4_reason(sixtofour):
            return BlockReason.embedded_ipv4_blocked
        return None
    return None


def _parse_host(host: object) -> IPAddress | None:
    """Strict IP literal: no hostnames, brackets, zone ids or surrounding whitespace."""
    if not isinstance(host, str) or not host or host != host.strip():
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id is not None:
        return None
    return ip


def _valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def address_reason(ip: IPAddress) -> BlockReason | None:
    """Range check only (no port): None if the address is globally routable unicast."""
    if isinstance(ip, ipaddress.IPv4Address):
        return _ipv4_reason(ip)
    return _ipv6_reason(ip)


@dataclass(frozen=True, slots=True)
class TargetPolicy:
    """Decides whether the DNS engine may send packets to a target.

    ``check`` returns None when allowed, else the BlockReason; callers turn a reason into
    ``ResultState.blocked`` (``reason.result_state``).
    """

    untrusted_port: int = UNTRUSTED_DNS_PORT

    def check(self, addr: ResolverAddr, trusted: bool) -> BlockReason | None:
        ip = _parse_host(addr.host)
        if ip is None or not _valid_port(addr.port):
            return BlockReason.malformed
        if trusted:
            # Operator-configured: private/Docker addresses and any port are allowed.
            return None
        if addr.port != self.untrusted_port:
            return BlockReason.port_not_allowed
        return address_reason(ip)


DEFAULT_POLICY = TargetPolicy()


def parse_target(target: str) -> ResolverAddr | None:
    """Parse one ``host[:port]`` target with the RESOLVER_ADDRS syntax; None if malformed."""
    if not isinstance(target, str) or "," in target:
        return None
    try:
        addrs = parse_resolver_addrs(target)
    except ConfigError:
        return None
    return addrs[0] if len(addrs) == 1 else None


def untrusted_target_reason(target: str) -> BlockReason | None:
    """Policy decision for an UNTRUSTED ``host[:port]`` string (port defaults to 53)."""
    addr = parse_target(target)
    if addr is None:
        return BlockReason.malformed
    return DEFAULT_POLICY.check(addr, trusted=False)


def is_allowed_untrusted_target(target: str) -> bool:
    """True only for a globally routable unicast IP literal on port 53."""
    return untrusted_target_reason(target) is None
