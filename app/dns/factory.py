"""Build resolvers from Settings (M2-05).

- ``system``: nameservers read from resolv.conf by dnspython. Trusted. The container's resolv.conf
  is not operator input we can validate, so these addresses are NOT policy-checked beyond being
  well-formed IP literals (ARCHITECTURE section 7).
- ``custom``: RESOLVER_ADDRS, trusted.
- ``unbound``: RESOLVER_ADDRS (the bundled profile uses 172.28.53.2:5353), trusted; sets the EDNS
  DO bit and reports the AD flag.

``build_resolver_for_target`` is for UNTRUSTED targets (public-resolver list entries, trace
addresses): the egress policy runs before any packet and a rejected target gives a resolver that
only ever answers ``blocked``.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.resolver

from app.core.config import ResolverAddr, Settings
from app.dns.backends import BlockedResolver, DnsPythonResolver, Transport, format_addr
from app.dns.egress import DEFAULT_POLICY, BlockReason, TargetPolicy, parse_target

logger = logging.getLogger(__name__)

RESOLV_CONF = "/etc/resolv.conf"


def system_nameservers(resolv_conf: str = RESOLV_CONF) -> list[ResolverAddr]:
    """Nameservers from resolv.conf via dnspython. Empty list if it cannot be read: the
    resolver then answers ``error`` (``no_nameservers``) for every query, never "missing"."""
    try:
        conf = dns.resolver.Resolver(filename=resolv_conf, configure=True)
    except (dns.exception.DNSException, OSError, ValueError) as exc:
        logger.warning(
            "resolv.conf unusable: %s",
            type(exc).__name__,
            extra={"event": "dns.resolv_conf_error"},
        )
        return []
    addrs: list[ResolverAddr] = []
    for ns in conf.nameservers:
        if isinstance(ns, str):
            addrs.append(ResolverAddr(ns, conf.nameserver_ports.get(ns, conf.port)))
    return addrs


def build_resolver(
    settings: Settings,
    *,
    transport: Transport | None = None,
    resolv_conf: str = RESOLV_CONF,
) -> DnsPythonResolver:
    mode = settings.resolver_mode
    if mode == "system":
        return DnsPythonResolver(
            system_nameservers(resolv_conf), trusted=True, identity="system", transport=transport
        )
    addrs = settings.parsed_resolver_addrs()
    return DnsPythonResolver(
        addrs,
        trusted=True,
        identity=f"{mode}:{','.join(format_addr(a) for a in addrs)}",
        dnssec_ok=mode == "unbound",
        transport=transport,
    )


def build_resolver_for_target(
    addr: str | ResolverAddr,
    policy: TargetPolicy = DEFAULT_POLICY,
    *,
    transport: Transport | None = None,
) -> DnsPythonResolver | BlockedResolver:
    """UNTRUSTED target (``host[:port]`` string or ResolverAddr). Policy is checked here,
    before any packet, and again by the resolver before every send."""
    target = parse_target(addr) if isinstance(addr, str) else addr
    if target is None:
        return BlockedResolver(str(addr), BlockReason.malformed)
    reason = policy.check(target, trusted=False)
    if reason is not None:
        return BlockedResolver(format_addr(target), reason)
    return DnsPythonResolver(
        [target],
        trusted=False,
        identity=f"target:{format_addr(target)}",
        policy=policy,
        transport=transport,
    )
