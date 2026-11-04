"""Static checks of compose.yaml (no Docker needed)."""

from pathlib import Path
from typing import Any

import yaml

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


def test_unbound_ip_matches_conf() -> None:
    ip = COMPOSE["services"]["unbound"]["networks"]["dns"]["ipv4_address"]
    assert ip == "172.28.53.2"
    assert f"interface: {ip}" in UNBOUND_CONF


def test_unbound_publishes_no_ports() -> None:
    assert "ports" not in COMPOSE["services"]["unbound"]


def test_unbound_only_in_profile() -> None:
    assert COMPOSE["services"]["unbound"]["profiles"] == ["unbound"]
