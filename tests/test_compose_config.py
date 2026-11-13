"""Static checks of compose.yaml (no Docker needed)."""

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

from app.core.config import Settings

ROOT = Path(__file__).resolve().parent.parent
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "compose.yaml").read_text())
UNBOUND_CONF = (ROOT / "docker/unbound/unbound.conf").read_text()


def test_app_joins_default_and_dns() -> None:
    assert set(COMPOSE["services"]["app"]["networks"]) == {"default", "dns"}


def test_app_resolver_env_defaults() -> None:
    env = COMPOSE["services"]["app"]["environment"]
    assert env["RESOLVER_MODE"] == "${RESOLVER_MODE:-system}"
    assert env["RESOLVER_ADDRS"] == "${RESOLVER_ADDRS:-}"


def test_dns_network_internal_with_gateway() -> None:
    dns = COMPOSE["networks"]["dns"]
    assert dns["internal"] is True
    cfg = dns["ipam"]["config"][0]
    assert cfg["subnet"] == "172.28.53.0/24"
    assert cfg["gateway"] == "172.28.53.1"
    assert f"access-control: {cfg['gateway']}/32 refuse" in UNBOUND_CONF


def test_static_addresses_outside_ip_range() -> None:
    cfg = COMPOSE["networks"]["dns"]["ipam"]["config"][0]
    subnet = ipaddress.ip_network(cfg["subnet"])
    ip_range = ipaddress.ip_network(cfg["ip_range"])
    assert ip_range.subnet_of(subnet)
    unbound_ip = ipaddress.ip_address(
        COMPOSE["services"]["unbound"]["networks"]["dns"]["ipv4_address"]
    )
    gateway = ipaddress.ip_address(cfg["gateway"])
    for addr in (unbound_ip, gateway):
        assert addr in subnet
        assert addr not in ip_range


def test_unbound_ip_matches_conf() -> None:
    ip = COMPOSE["services"]["unbound"]["networks"]["dns"]["ipv4_address"]
    assert ip == "172.28.53.2"
    assert f"interface: {ip}" in UNBOUND_CONF


def test_unbound_publishes_no_ports() -> None:
    assert "ports" not in COMPOSE["services"]["unbound"]


def test_unbound_only_in_profile() -> None:
    assert COMPOSE["services"]["unbound"]["profiles"] == ["unbound"]


# --- R1-04: every Settings field documented in .env.example reaches the app container ---

# SECRET_KEY / ENCRYPTION_KEY are required and have no Settings default; compose keeps its
# empty `:-` so the app itself refuses to start, exactly as before.
_REQUIRED_NO_DEFAULT = {"SECRET_KEY", "ENCRYPTION_KEY"}


def _documented_settings() -> set[str]:
    """Names in .env.example (active or commented `#NAME=`) that are Settings fields."""
    fields = {name.upper() for name in Settings.model_fields}
    text = (ROOT / ".env.example").read_text()
    names = set(re.findall(r"^#?([A-Z][A-Z0-9_]*)=", text, flags=re.MULTILINE))
    return names & fields


def _default_text(value: Any) -> str:
    if hasattr(value, "get_secret_value"):
        value = value.get_secret_value()
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def test_documented_settings_found() -> None:
    # Guard against the regex silently matching nothing.
    assert {"BASE_URL", "LOG_LEVEL", "ROLE", "SESSION_IDLE_TIMEOUT_MINUTES"} <= (
        _documented_settings()
    )


def test_app_forwards_every_documented_setting() -> None:
    env = COMPOSE["services"]["app"]["environment"]
    missing = sorted(_documented_settings() - set(env))
    assert not missing, f"documented in .env.example but not forwarded by compose.yaml: {missing}"


def test_forwarded_defaults_match_settings_defaults() -> None:
    env = COMPOSE["services"]["app"]["environment"]
    for name in sorted(_documented_settings() - _REQUIRED_NO_DEFAULT):
        expected = _default_text(Settings.model_fields[name.lower()].default)
        assert env[name] == f"${{{name}:-{expected}}}", name
    for name in sorted(_REQUIRED_NO_DEFAULT):
        assert env[name] == f"${{{name}:-}}", name


def test_app_container_hardening() -> None:
    app = COMPOSE["services"]["app"]
    assert app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert app["init"] is True
