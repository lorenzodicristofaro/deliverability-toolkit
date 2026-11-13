"""Configuration helpers (ARCHITECTURE section 11)."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field, PrivateAttr, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_RESOLVER_PORT = 53
MIN_SECRET_LENGTH = 32
# Session expiry defaults (M1-13): project choice, not taken from an external source.
DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES = 30
DEFAULT_SESSION_ABSOLUTE_TIMEOUT_MINUTES = 12 * 60

RESOLVER_ADDR_INVALID_KEY = "config.resolver_addr.invalid"

config_logger = logging.getLogger("app.config")
# i18n keys; the locale files are created by M1-09, until then these are constants only.
CONFIG_MISSING_KEY = "config.missing"
CONFIG_INVALID_VALUE_KEY = "config.invalid_value"
CONFIG_RESOLVER_ADDRS_REQUIRED_KEY = "config.resolver_addrs_required"


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
    - Leading zeros in a port are accepted (``:053`` is 53). An IPv4-mapped IPv6 address
      (``[::ffff:1.2.3.4]``) is accepted as IPv6 and kept as such (not converted to IPv4).
      Duplicate entries are kept as given, in order; they are not de-duplicated.
    - Raises ConfigError(``config.resolver_addr.invalid``) naming the offending entry.
    No DNS or network access.
    """
    if value.strip() == "":
        return []
    return [_parse_entry(raw.strip()) for raw in value.split(",")]


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_trusted_proxies(value: str) -> tuple[IPNetwork, ...]:
    """Parse TRUSTED_PROXIES (R1-30): comma-separated IPv4/IPv6 addresses or CIDR networks.

    - A bare address is a single-host network (``10.0.0.5`` is ``10.0.0.5/32``, ``::1`` is
      ``::1/128``). A network must have no host bits set (``10.0.0.0/8``, not ``10.0.0.1/8``).
    - An empty or whitespace-only string yields an empty tuple: no proxy is trusted.
    - Whitespace around entries is ignored; an empty entry ("a,,b", trailing comma), a hostname,
      ``*``, a port, a bracketed IPv6 or an IPv6 zone id is an error.
    - An IPv4-mapped IPv6 network (``::ffff:10.0.0.0/104``) is kept as given; client addresses
      are unmapped before matching (app.web.auth), so list IPv4 proxies as IPv4.
    - Raises ConfigError(``config.invalid_value``, name="TRUSTED_PROXIES", entry=...).
    No DNS or network access.
    """
    if value.strip() == "":
        return ()
    networks: list[IPNetwork] = []
    for raw in value.split(","):
        entry = raw.strip()
        try:
            if entry == "" or "%" in entry:
                raise ValueError(entry)
            networks.append(ipaddress.ip_network(entry, strict=True))
        except ValueError:
            raise ConfigError(
                CONFIG_INVALID_VALUE_KEY, name="TRUSTED_PROXIES", entry=entry
            ) from None
    return tuple(networks)


_SECRET_FIELDS = ("secret_key", "encryption_key")


class Settings(BaseSettings):
    """Operator configuration from the environment (ARCHITECTURE section 11).

    Construction validates everything and raises ConfigError (never pydantic's ValidationError,
    whose messages echo input values). ConfigError params carry variable names, never secret
    values; secrets are SecretStr so repr/str mask them. SMTP_* is out of scope until M7.
    """

    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    # SecretStr: a PostgreSQL URL carries the password; repr/str mask it.
    database_url: SecretStr = SecretStr("sqlite:////data/app.db")
    secret_key: SecretStr
    encryption_key: SecretStr
    resolver_mode: Literal["system", "custom", "unbound"] = "system"
    resolver_addrs: str = ""
    role: Literal["web", "worker", "all"] = "all"
    allow_smtp_checks: bool = False
    allow_registration: bool = False
    base_url: str = "http://localhost:8000"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    # Login sessions: idle timeout (since last request) and absolute lifetime, in minutes.
    # Both must be > 0 and idle <= absolute.
    session_idle_timeout_minutes: int = Field(default=DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES, gt=0)
    session_absolute_timeout_minutes: int = Field(
        default=DEFAULT_SESSION_ABSOLUTE_TIMEOUT_MINUTES, gt=0
    )
    # Reverse proxies whose X-Forwarded-For is trusted for the client IP (R1-30), parsed by
    # parse_trusted_proxies. Default empty: the client IP is the direct peer, headers ignored.
    trusted_proxies: str = ""
    _trusted_networks: tuple[IPNetwork, ...] = PrivateAttr(default=())

    @field_validator("secret_key", "encryption_key", mode="after")
    @classmethod
    def _not_blank(cls, value: SecretStr) -> SecretStr:
        if value.get_secret_value().strip() == "":
            raise ValueError("blank")
        return value

    @field_validator("secret_key", "encryption_key", mode="after")
    @classmethod
    def _min_length(cls, value: SecretStr) -> SecretStr:
        # Very short secrets would make log value-masking match arbitrary text.
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError("too short")
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("resolver_mode", "role", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    def __init__(self, **values: Any) -> None:
        try:
            super().__init__(**values)
        except ValidationError as exc:
            err = exc.errors(include_input=False, include_url=False)[0]
            name = str(err["loc"][0]) if err["loc"] else "settings"
            # Drop the pydantic exception: its repr would include input values (secrets).
            if name in _SECRET_FIELDS and "too short" not in err["msg"]:
                raise ConfigError(CONFIG_MISSING_KEY, name=name.upper()) from None
            raise ConfigError(CONFIG_INVALID_VALUE_KEY, name=name.upper()) from None
        if not self.base_url.startswith(("http://", "https://")):
            raise ConfigError(CONFIG_INVALID_VALUE_KEY, name="BASE_URL")
        if self.session_idle_timeout_minutes > self.session_absolute_timeout_minutes:
            raise ConfigError(CONFIG_INVALID_VALUE_KEY, name="SESSION_IDLE_TIMEOUT_MINUTES")
        if not self.parsed_resolver_addrs() and self.resolver_mode in ("custom", "unbound"):
            raise ConfigError(CONFIG_RESOLVER_ADDRS_REQUIRED_KEY, mode=self.resolver_mode)
        # Parsed once here: an invalid entry fails at startup, requests reuse the result.
        self._trusted_networks = parse_trusted_proxies(self.trusted_proxies)

    def trusted_proxy_networks(self) -> tuple[IPNetwork, ...]:
        """TRUSTED_PROXIES as parsed at construction (empty: no proxy is trusted)."""
        return self._trusted_networks

    def parsed_resolver_addrs(self) -> list[ResolverAddr]:
        return parse_resolver_addrs(self.resolver_addrs)

    def log_resolver_config(self, logger: logging.Logger | None = None) -> None:
        """Log the resolver mode and the parsed (trusted) addresses at INFO for startup.

        Call after logging is configured. Addresses are operator config, not secrets. In
        ``system`` mode the resolv.conf nameservers are used and cannot be policy-checked
        (ARCHITECTURE section 7); RESOLVER_ADDRS is still parsed, so a malformed value fails.
        """
        addrs = self.parsed_resolver_addrs()
        rendered = ",".join(
            f"[{a.host}]:{a.port}" if ":" in a.host else f"{a.host}:{a.port}" for a in addrs
        )
        (logger or config_logger).info(
            "resolver mode=%s addrs=%s",
            self.resolver_mode,
            rendered or "-",
            extra={"event": "config.resolver"},
        )
