"""R1-30 (AUTH-04): TRUSTED_PROXIES parsing and the client-IP rule (no network, no app)."""

from __future__ import annotations

import ipaddress

import pytest

from app.core.config import ConfigError, Settings, parse_trusted_proxies
from app.web.auth import resolve_client_ip

KEY = "k" * 40
PROXY = "10.0.0.5"
TRUSTED = parse_trusted_proxies("10.0.0.0/8, 2001:db8:f::/48, 192.0.2.1")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", []),
        ("   ", []),
        ("10.0.0.5", ["10.0.0.5/32"]),
        (" 10.0.0.0/8 ,172.16.0.0/12 ", ["10.0.0.0/8", "172.16.0.0/12"]),
        ("::1", ["::1/128"]),
        ("2001:DB8::/32", ["2001:db8::/32"]),
        ("10.0.0.0/255.0.0.0", ["10.0.0.0/8"]),
        ("0.0.0.0/0", ["0.0.0.0/0"]),  # trusts every IPv4 peer: allowed, operator's choice
    ],
)
def test_parse_trusted_proxies_valid(value: str, expected: list[str]) -> None:
    assert [str(n) for n in parse_trusted_proxies(value)] == expected


@pytest.mark.parametrize(
    "value",
    [
        "*",
        "proxy.example.com",
        "localhost",
        "10.0.0.1/8",  # host bits set
        "10.0.0.0/33",
        "10.0.0.256",
        "10.0.0.5:8080",
        "[::1]",
        "fe80::1%eth0",
        "10.0.0.5,",
        "10.0.0.5,,10.0.0.6",
        "10.0.0.5 10.0.0.6",
        "10.0.0.5;10.0.0.6",
        "\x00",
    ],
)
def test_parse_trusted_proxies_invalid_names_the_setting_and_entry(value: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_trusted_proxies(value)
    assert exc.value.key == "config.invalid_value"
    assert exc.value.params["name"] == "TRUSTED_PROXIES"
    assert "entry" in exc.value.params


def test_settings_default_trusts_no_proxy_and_invalid_value_fails_at_startup() -> None:
    settings = Settings(secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    assert settings.trusted_proxies == ""
    assert settings.trusted_proxy_networks() == ()
    configured = Settings(  # type: ignore[call-arg]
        secret_key=KEY, encryption_key=KEY, trusted_proxies="10.0.0.0/8,::1"
    )
    assert configured.trusted_proxy_networks() == (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("::1"),
    )
    with pytest.raises(ConfigError) as exc:
        Settings(secret_key=KEY, encryption_key=KEY, trusted_proxies="10.0.0.0/8,nope")  # type: ignore[call-arg]
    assert exc.value.params == {"name": "TRUSTED_PROXIES", "entry": "nope"}


def test_settings_reads_trusted_proxies_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setenv("TRUSTED_PROXIES", "172.16.0.0/12")
    assert [str(n) for n in Settings().trusted_proxy_networks()] == ["172.16.0.0/12"]
    monkeypatch.setenv("TRUSTED_PROXIES", "172.16.0.1/12")
    with pytest.raises(ConfigError):
        Settings()


@pytest.mark.parametrize(
    ("peer", "headers", "expected"),
    [
        # Untrusted or non-IP peer: the header is ignored, the peer is returned unchanged.
        ("198.51.100.9", ["203.0.113.1"], "198.51.100.9"),
        ("testclient", ["203.0.113.1"], "testclient"),
        ("", ["203.0.113.1"], ""),
        ("10.0.0.5:80", ["203.0.113.1"], "10.0.0.5:80"),
        ("2001:db8::99", ["203.0.113.1"], "2001:db8::99"),
        # Trusted peer: the rightmost hop that is not a trusted proxy.
        (PROXY, ["203.0.113.1"], "203.0.113.1"),
        (PROXY, [" 203.0.113.1 "], "203.0.113.1"),
        (PROXY, ["203.0.113.1, 10.1.1.1, 10.2.2.2"], "203.0.113.1"),
        (PROXY, ["203.0.113.1, 192.0.2.1"], "203.0.113.1"),
        # Spoofed leftmost entries never change the result.
        (PROXY, ["1.1.1.1, 203.0.113.1"], "203.0.113.1"),
        (PROXY, ["garbage, , unknown, 203.0.113.1"], "203.0.113.1"),
        (PROXY, ["10.9.9.9, 203.0.113.1"], "203.0.113.1"),
        # Several header lines are one list, in order.
        (PROXY, ["1.1.1.1", "203.0.113.1, 10.1.1.1"], "203.0.113.1"),
        # IPv6: peer, hops and normalisation; IPv4-mapped addresses are unmapped.
        ("2001:db8:f::1", ["2001:DB8:0::a"], "2001:db8::a"),
        (PROXY, ["2001:db8::a, 2001:db8:f::2"], "2001:db8::a"),
        ("::ffff:10.0.0.5", ["203.0.113.1"], "203.0.113.1"),
        (PROXY, ["::ffff:203.0.113.1"], "203.0.113.1"),
        (PROXY, ["203.0.113.1, ::ffff:10.1.1.1"], "203.0.113.1"),
        # Fallback to the peer: no/empty header, all hops trusted, malformed rightmost client.
        (PROXY, [], PROXY),
        (PROXY, [""], PROXY),
        (PROXY, [" , "], PROXY),
        (PROXY, ["10.1.1.1, 10.2.2.2"], PROXY),
        (PROXY, ["203.0.113.1, unknown"], PROXY),
        (PROXY, ["203.0.113.1:4711"], PROXY),
        (PROXY, ["[2001:db8::a]"], PROXY),
        (PROXY, ["[2001:db8::a]:443"], PROXY),
        (PROXY, ["fe80::1%eth0"], PROXY),
        (PROXY, ["203.0.113.1,"], PROXY),
        (PROXY, ["_hidden"], PROXY),
        (PROXY, ["203.0.113.1 203.0.113.2"], PROXY),
        (PROXY, ["203.0.113.256"], PROXY),
        (PROXY, ["\x00"], PROXY),
        (PROXY, ["1" * 10_000], PROXY),
        (PROXY, ["for=203.0.113.1"], PROXY),
        # More trusted hops than are read: the client beyond them is not reached.
        (PROXY, ["203.0.113.1, " + ", ".join(["10.1.1.1"] * 40)], PROXY),
    ],
)
def test_resolve_client_ip(peer: str, headers: list[str], expected: str) -> None:
    assert resolve_client_ip(peer, headers, TRUSTED) == expected


@pytest.mark.parametrize("peer", [PROXY, "198.51.100.9", "testclient"])
def test_no_trusted_proxy_always_returns_the_peer(peer: str) -> None:
    assert resolve_client_ip(peer, ["203.0.113.1"], ()) == peer


@pytest.mark.parametrize(
    "spoofed", ["", "6.6.6.6, ", "6.6.6.6, 7.7.7.7, ", "x, 10.0.0.1, ", "2001:db8::1, "]
)
def test_spoofed_leftmost_entries_do_not_change_the_key(spoofed: str) -> None:
    assert resolve_client_ip(PROXY, [f"{spoofed}203.0.113.1"], TRUSTED) == "203.0.113.1"


def test_two_clients_behind_one_trusted_proxy_get_separate_keys() -> None:
    a = resolve_client_ip(PROXY, ["203.0.113.1"], TRUSTED)
    b = resolve_client_ip(PROXY, ["203.0.113.2"], TRUSTED)
    assert a != b and PROXY not in (a, b)
