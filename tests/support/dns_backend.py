"""A fake `DnsBackend` for the DNS tools API tests (M2-12): fixtures only, no network."""

from __future__ import annotations

from typing import Any

from app.api.v1.dns_tools import DnsBackend
from app.core.config import ResolverAddr
from app.dns.egress import DEFAULT_POLICY, BlockReason
from app.dns.knowledge import RootServer
from app.services.dns_tools import LookupResolvers
from tests.support.dns_zones import FakeResolver, FakeServerSet, parse_zones

ROOTS = (RootServer("a.root-servers.net", "192.0.2.1", "2001:db8::1"),)

ZONES: dict[str, list[dict[str, Any]]] = {
    "default": [
        {"name": "example.com", "type": "A", "ttl": 300, "rdata": ["192.0.2.10"]},
        {"name": "example.com", "type": "TXT", "ttl": 300, "rdata": ["v=spf1 -all"]},
        {"name": "servfail.example.com", "type": "A", "state": "servfail", "rcode": 2},
        {"name": "mail.example.com", "type": "A", "ttl": 300, "rdata": ["192.0.2.10"]},
        {
            "name": "10.2.0.192.in-addr.arpa",
            "type": "PTR",
            "ttl": 300,
            "rdata": ["mail.example.com"],
        },
    ],
    "192.0.2.1": [
        {"referral": {"zone": "com", "ns": [{"name": "a.gtld.example.net", "addr": "192.0.2.2"}]}}
    ],
    "192.0.2.2": [
        {
            "referral": {
                "zone": "example.com",
                "ns": [{"name": "ns1.example.net", "addr": "192.0.2.3"}],
            }
        }
    ],
    "192.0.2.3": [{"name": "example.com", "type": "A", "ttl": 300, "rdata": ["192.0.2.10"]}],
}


class FixturePolicy:
    """The production policy, except that documentation ranges (the fixture addresses) pass."""

    def check(self, addr: ResolverAddr, trusted: bool) -> BlockReason | None:
        reason = DEFAULT_POLICY.check(addr, trusted)
        return None if reason is BlockReason.documentation else reason


def fake_backend(
    zones: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[DnsBackend, FakeServerSet]:
    """Backend whose default resolver and public resolvers are fixtures. Any public address
    without its own fixture answers like the default resolver."""
    servers = parse_zones({"zones": zones if zones is not None else ZONES})
    default = servers.resolver("default")

    def address_factory(_entry: Any, address: str) -> FakeResolver:
        return servers.servers.get(address, default)

    backend = DnsBackend(
        lookup=LookupResolvers(default, lambda _e: default),
        address_factory=address_factory,
        query_server=servers.query_server,
        root_hints=ROOTS,
        policy=FixturePolicy(),
    )
    return backend, servers
