"""Configuration helpers (ARCHITECTURE section 11)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

DEFAULT_RESOLVER_PORT = 53

RESOLVER_ADDR_INVALID_KEY = "config.resolver_addr.invalid"


class ConfigError(ValueError):
    """Invalid operator configuration, raised at startup.

    Carries an i18n key (locales/*.json) plus its parameters. The message is for the operator's
    log and is not translated; there is no end-user UI path for it.
    """

    def __init__(self, key: str, **params: str) -> None:
        super().__init__(f"{key} {params}")
        self.key = key
        self.params = params


@dataclass(frozen=True)
class ResolverAddr:
    host: str  # normalised IP literal, no brackets
    port: int


def _invalid(entry: str) -> ConfigError:
    return ConfigError(RESOLVER_ADDR_INVALID_KEY, entry=entry)


def _parse_port(text: str, entry: str) -> int:
    if not (text.isascii() and text.isdigit()):
        raise _invalid(entry)
    port = int(text)
    if not 1 <= port <= 65535:
        raise _invalid(entry)
    return port


def _parse_entry(entry: str) -> ResolverAddr:
    if entry.startswith("["):
        # Bracketed IPv6: "[addr]" or "[addr]:port".
        host, sep, rest = entry[1:].partition("]")
        if not sep:
            raise _invalid(entry)
        if rest == "":
            port = DEFAULT_RESOLVER_PORT
        elif rest.startswith(":"):
            port = _parse_port(rest[1:], entry)
        else:
            raise _invalid(entry)
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError:
            raise _invalid(entry) from None
        if ip6.scope_id is not None:
            raise _invalid(entry)
        return ResolverAddr(str(ip6), port)

    if entry.count(":") > 1:
        # Unbracketed IPv6 is ambiguous with host:port and is rejected.
        raise _invalid(entry)
    host, sep, port_text = entry.partition(":")
    port = _parse_port(port_text, entry) if sep else DEFAULT_RESOLVER_PORT
    try:
        ip4 = ipaddress.IPv4Address(host)
    except ValueError:
        # Hostnames are not accepted: they would need a resolver to resolve the resolver.
        raise _invalid(entry) from None
    return ResolverAddr(str(ip4), port)


def parse_resolver_addrs(value: str) -> list[ResolverAddr]:
    """Parse RESOLVER_ADDRS: comma-separated ``host:port`` entries.

    - ``host`` is an IPv4 literal or a bracketed IPv6 literal (``[::1]:5353``). Hostnames,
      unbracketed IPv6 and IPv6 zone ids are rejected.
    - A missing port means the default port, 53 (DEFAULT_RESOLVER_PORT). The bundled Unbound
      listens on 5353, so configure ``172.28.53.2:5353`` explicitly for it.
    - Whitespace around entries is ignored. An empty or whitespace-only string yields an empty
      list; an empty entry inside a list ("a,,b", trailing comma) is an error.
    - Raises ConfigError(``config.resolver_addr.invalid``) naming the offending entry.
    No DNS or network access.
    """
    if value.strip() == "":
        return []
    return [_parse_entry(raw.strip()) for raw in value.split(",")]
