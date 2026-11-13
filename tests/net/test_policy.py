"""URL/address policy of the guarded HTTP client (M7-01): table-driven, pure, no network."""

from __future__ import annotations

import ipaddress

import pytest

from app.core.config import ConfigError, Settings, parse_port_list
from app.net.guarded_http import limits_from_settings
from app.net.policy import FetchError, FetchErrorKind, FetchLimits, Target, parse_url

PORTS = (80, 443)


def _err(url: object, ports: tuple[int, ...] = PORTS) -> FetchError:
    result = parse_url(url, ports)
    assert isinstance(result, FetchError), result
    return result


@pytest.mark.parametrize(
    ("url", "host", "port", "path", "is_ip"),
    [
        ("https://www.example.com", "www.example.com", 443, "/", False),
        ("https://WWW.Example.COM/A?b=1#frag", "www.example.com", 443, "/A?b=1", False),
        ("http://www.example.com./x", "www.example.com", 80, "/x", False),  # trailing dot
        ("HTTP://www.example.com:443/", "www.example.com", 443, "/", False),
        ("https://bücher.example/", "xn--bcher-kva.example", 443, "/", False),  # IDNA
        ("https://93.184.216.34/", "93.184.216.34", 443, "/", True),
        ("https://[2606:2800:220:1::1]/", "2606:2800:220:1::1", 443, "/", True),
        ("https://[2606:2800:0220:0001:0:0:0:1]:443/", "2606:2800:220:1::1", 443, "/", True),
    ],
)
def test_accepted_urls(url: str, host: str, port: int, path: str, is_ip: bool) -> None:
    target = parse_url(url, PORTS)
    assert isinstance(target, Target)
    assert (target.host, target.port, target.path, target.ip is not None) == (
        host,
        port,
        path,
        is_ip,
    )


@pytest.mark.parametrize(
    ("url", "kind", "detail"),
    [
        # scheme allowlist
        ("ftp://www.example.com/", FetchErrorKind.scheme_not_allowed, "ftp"),
        ("file:///etc/passwd", FetchErrorKind.scheme_not_allowed, "file"),
        ("https:/www.example.com/", FetchErrorKind.blocked, "malformed"),  # no authority
        ("gopher://www.example.com/", FetchErrorKind.scheme_not_allowed, "gopher"),
        ("//www.example.com/", FetchErrorKind.scheme_not_allowed, "missing"),
        # port allowlist
        ("https://www.example.com:8443/", FetchErrorKind.port_not_allowed, "8443"),
        ("http://www.example.com:22/", FetchErrorKind.port_not_allowed, "22"),
        ("http://www.example.com:99999/", FetchErrorKind.blocked, "malformed"),
        ("http://www.example.com:-1/", FetchErrorKind.blocked, "malformed"),
        ("http://www.example.com:8o/", FetchErrorKind.blocked, "malformed"),
        # userinfo and @ tricks
        ("https://user:pw@www.example.com/", FetchErrorKind.blocked, "userinfo"),
        ("https://www.example.com@127.0.0.1/", FetchErrorKind.blocked, "userinfo"),
        ("https://@www.example.com/", FetchErrorKind.blocked, "userinfo"),
        ("https://www.example.com\\@127.0.0.1/", FetchErrorKind.blocked, "malformed"),
        # malformed / control characters
        ("", FetchErrorKind.blocked, "malformed"),
        (None, FetchErrorKind.blocked, "malformed"),
        (b"https://www.example.com/", FetchErrorKind.blocked, "malformed"),
        ("https://www.example.com/a b", FetchErrorKind.blocked, "malformed"),
        ("https://www.example.com/\r\nX: y", FetchErrorKind.blocked, "malformed"),
        ("https://www.exa\x00mple.com/", FetchErrorKind.blocked, "malformed"),
        ("https:///path", FetchErrorKind.blocked, "malformed"),
        ("https://" + "a" * 2050, FetchErrorKind.blocked, "malformed"),
        ("https://[::1/", FetchErrorKind.blocked, "malformed"),
        ("https://::1/", FetchErrorKind.blocked, "malformed"),
        # host names that are not acceptable
        ("http://localhost/", FetchErrorKind.blocked, "host_single_label"),
        ("http://under_score.example.com/", FetchErrorKind.blocked, "host_idna"),
        ("http://" + "a" * 64 + ".example.com/", FetchErrorKind.blocked, "host_idna"),
        # decimal / octal / hex / short IPv4 spellings never reach a resolver
        ("http://2130706433/", FetchErrorKind.blocked, "host_single_label"),
        ("http://0x7f000001/", FetchErrorKind.blocked, "host_single_label"),
        ("http://017700000001/", FetchErrorKind.blocked, "host_single_label"),
        ("http://0x7f.0.0.1/", FetchErrorKind.blocked, "host_ip_address"),
        ("http://0177.0.0.1/", FetchErrorKind.blocked, "host_ip_address"),
        ("http://127.1/", FetchErrorKind.blocked, "host_ip_address"),
        ("http://169.254.43518/", FetchErrorKind.blocked, "host_ip_address"),
        # IPv6 zone ids
        ("http://[fe80::1%25eth0]/", FetchErrorKind.blocked, "zone_id"),
        ("http://[fe80::1%eth0]/", FetchErrorKind.blocked, "zone_id"),
        # percent-encoded host names
        ("http://www%2eexample.com/", FetchErrorKind.blocked, "malformed"),
        ("http://%31%32%37.0.0.1/", FetchErrorKind.blocked, "malformed"),
    ],
)
def test_rejected_urls(url: object, kind: FetchErrorKind, detail: str) -> None:
    err = _err(url)
    assert (err.kind, err.detail) == (kind, detail)


# One representative per blocked range class (app.dns.egress.address_reason).
BLOCKED_LITERALS = [
    ("http://0.0.0.0/", "unspecified"),
    ("http://0.1.2.3/", "this_network"),
    ("http://127.0.0.1/", "loopback"),
    ("http://10.1.2.3/", "private"),
    ("http://172.16.0.1/", "private"),
    ("http://192.168.1.1/", "private"),
    ("http://100.64.0.1/", "shared_address_space"),  # CGNAT
    ("http://169.254.169.254/latest/meta-data/", "link_local"),  # cloud metadata
    ("http://192.0.0.170/", "protocol_assignment"),
    ("http://192.0.2.1/", "documentation"),
    ("http://198.18.0.1/", "benchmarking"),
    ("http://224.0.0.1/", "multicast"),
    ("http://240.0.0.1/", "reserved"),
    ("http://255.255.255.255/", "broadcast"),
    ("http://[::]/", "unspecified"),
    ("http://[::1]/", "loopback"),
    ("http://[fe80::1]/", "link_local"),
    ("http://[fd00:ec2::254]/", "private"),  # ULA
    ("http://[fc00::1]/", "private"),
    ("http://[ff02::1]/", "multicast"),
    ("http://[::ffff:127.0.0.1]/", "ipv4_mapped"),
    ("http://[::ffff:169.254.169.254]/", "ipv4_mapped"),
    ("http://[2002:7f00:1::1]/", "embedded_ipv4_blocked"),  # 6to4 of 127.0.0.1
    ("http://[2002:a9fe:a9fe::1]/", "embedded_ipv4_blocked"),  # 6to4 of 169.254.169.254
    ("http://[64:ff9b::a9fe:a9fe]/", "embedded_ipv4_blocked"),  # NAT64 of metadata
    ("http://[64:ff9b:1::1]/", "translation_local"),
    ("http://[2001:db8::1]/", "documentation"),
    ("http://[::127.0.0.1]/", "not_global_unicast"),  # IPv4-compatible (deprecated)
]


@pytest.mark.parametrize(("url", "reason"), BLOCKED_LITERALS)
def test_ip_literals_are_classified_directly(url: str, reason: str) -> None:
    err = _err(url)
    assert (err.kind, err.detail) == (FetchErrorKind.blocked, reason)


def test_allowed_ports_are_configurable() -> None:
    target = parse_url("https://www.example.com:8443/", (443, 8443))
    assert isinstance(target, Target) and target.port == 8443
    assert target.host_header == "www.example.com:8443"
    assert _err("https://www.example.com/", (8443,)).kind is FetchErrorKind.port_not_allowed


def test_connect_url_pins_ip_and_keeps_path() -> None:
    target = parse_url("https://www.example.com/a?b", PORTS)
    assert isinstance(target, Target)
    assert target.connect_url(ipaddress.ip_address("93.184.216.34")) == (
        "https://93.184.216.34:443/a?b"
    )
    assert target.connect_url(ipaddress.ip_address("2606:2800:220:1::1")) == (
        "https://[2606:2800:220:1::1]:443/a?b"
    )
    assert target.host_header == "www.example.com"


def test_hop_is_carried_in_errors() -> None:
    err = parse_url("http://127.0.0.1/", PORTS, hop=2)
    assert isinstance(err, FetchError) and err.hop == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_ports": ()},
        {"allowed_ports": (0,)},
        {"allowed_ports": (65536,)},
        {"allowed_ports": (True,)},
        {"max_redirects": -1},
        {"max_redirects": 6},
        {"connect_timeout": 0},
        {"total_timeout": -1.0},
        {"max_body_bytes": 0},
        {"max_header_count": 0},
    ],
)
def test_invalid_limits_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        FetchLimits(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("80,443", (80, 443)),
        (" 443 ", (443,)),
        ("443,443,80", (443, 80)),
        ("8443", (8443,)),
    ],
)
def test_parse_port_list(value: str, expected: tuple[int, ...]) -> None:
    assert parse_port_list(value, "X") == expected


@pytest.mark.parametrize("value", ["", " ", "80,", "0", "65536", "-1", "+80", "http", "8٠"])
def test_parse_port_list_rejects(value: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_port_list(value, "OUTBOUND_HTTP_ALLOWED_PORTS")
    assert exc.value.params["name"] == "OUTBOUND_HTTP_ALLOWED_PORTS"


_SECRETS = {"secret_key": "s" * 40, "encryption_key": "e" * 40}


def test_settings_defaults_and_limits() -> None:
    settings = Settings(**_SECRETS)
    assert settings.outbound_http_ports() == (80, 443)
    assert settings.outbound_http_max_redirects == 3
    limits = limits_from_settings(settings, max_body_bytes=10)
    assert (limits.allowed_ports, limits.max_redirects, limits.max_body_bytes) == (
        (80, 443),
        3,
        10,
    )


@pytest.mark.parametrize(
    ("field", "value", "name"),
    [
        ("outbound_http_allowed_ports", "80,abc", "OUTBOUND_HTTP_ALLOWED_PORTS"),
        ("outbound_http_allowed_ports", "", "OUTBOUND_HTTP_ALLOWED_PORTS"),
        ("outbound_http_max_redirects", 6, "OUTBOUND_HTTP_MAX_REDIRECTS"),
        ("outbound_http_max_redirects", -1, "OUTBOUND_HTTP_MAX_REDIRECTS"),
    ],
)
def test_settings_reject_invalid_values(field: str, value: object, name: str) -> None:
    with pytest.raises(ConfigError) as exc:
        Settings(**_SECRETS, **{field: value})
    assert exc.value.params["name"] == name


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTBOUND_HTTP_ALLOWED_PORTS", "443,8443")
    monkeypatch.setenv("OUTBOUND_HTTP_MAX_REDIRECTS", "5")
    settings = Settings(**_SECRETS)
    assert settings.outbound_http_ports() == (443, 8443)
    assert settings.outbound_http_max_redirects == 5
