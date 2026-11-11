import json
import logging
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from app.core.config import (
    RESOLVER_ADDR_INVALID_KEY,
    ConfigError,
    ResolverAddr,
    Settings,
    parse_resolver_addrs,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", []),
        ("   ", []),
        ("1.1.1.1", [ResolverAddr("1.1.1.1", 53)]),
        ("1.1.1.1:5353", [ResolverAddr("1.1.1.1", 5353)]),
        ("[::1]", [ResolverAddr("::1", 53)]),
        ("[::1]:5353", [ResolverAddr("::1", 5353)]),
        ("[2001:DB8::1]:53", [ResolverAddr("2001:db8::1", 53)]),
        (
            " 172.28.53.2:5353 , [::1] ",
            [ResolverAddr("172.28.53.2", 5353), ResolverAddr("::1", 53)],
        ),
        ("1.1.1.1:1", [ResolverAddr("1.1.1.1", 1)]),
        ("1.1.1.1:65535", [ResolverAddr("1.1.1.1", 65535)]),
        ("1.1.1.1:053", [ResolverAddr("1.1.1.1", 53)]),
        ("[::ffff:1.2.3.4]:53", [ResolverAddr(str(IPv6Address("::ffff:1.2.3.4")), 53)]),
        ("1.1.1.1,1.1.1.1", [ResolverAddr("1.1.1.1", 53), ResolverAddr("1.1.1.1", 53)]),
    ],
)
def test_parse_valid(value: str, expected: list[ResolverAddr]) -> None:
    assert parse_resolver_addrs(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "1.1.1.1:0",
        "1.1.1.1:65536",
        "1.1.1.1:-1",
        "1.1.1.1:abc",
        "1.1.1.1:",
        "1.1.1.1:٥",  # non-ASCII digit
        "[::1]:0",
        "[::1]:65536",
        "[::1]:x",
        "[::1]:",
        "::1",  # unbracketed IPv6
        "2001:db8::1:53",
        "[::1",
        "[::1]x",
        "[::1]5353",
        "[1.1.1.1]:53",  # IPv4 in brackets
        "[fe80::1%eth0]:53",  # zone id
        "[]",
        "[]:53",
        "1.1.1.1,,8.8.8.8",
        "1.1.1.1,",
        ",1.1.1.1",
        ",",
        "1.1.1.1 8.8.8.8",
        "example.com",  # hostname
        "example.com:53",
        "localhost:5353",
        "256.1.1.1",
        "1.1.1",
        ":53",
    ],
)
def test_parse_invalid(value: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        parse_resolver_addrs(value)
    assert excinfo.value.key == RESOLVER_ADDR_INVALID_KEY
    assert "entry" in excinfo.value.params


def test_error_names_offending_entry() -> None:
    with pytest.raises(ConfigError) as excinfo:
        parse_resolver_addrs("1.1.1.1, nope:53")
    assert excinfo.value.params["entry"] == "nope:53"


def test_i18n_keys_present_in_en_and_it() -> None:
    locales = Path(__file__).resolve().parent.parent / "locales"
    for lang in ("en", "it"):
        messages = json.loads((locales / f"{lang}.json").read_text(encoding="utf-8"))
        assert RESOLVER_ADDR_INVALID_KEY in messages
        assert "{entry}" in messages[RESOLVER_ADDR_INVALID_KEY]


# M2-03: startup INFO log of the resolver mode and the trusted addresses.
@pytest.mark.parametrize(
    ("mode", "addrs", "expected"),
    [
        ("system", "", "resolver mode=system addrs=-"),
        (
            "custom",
            "1.1.1.1, [2606:4700::1111]:53",
            "resolver mode=custom addrs=1.1.1.1:53,[2606:4700::1111]:53",
        ),
        ("unbound", "172.28.53.2:5353", "resolver mode=unbound addrs=172.28.53.2:5353"),
    ],
)
def test_log_resolver_config(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    mode: str,
    addrs: str,
    expected: str,
) -> None:
    for name in ("DATABASE_URL", "RESOLVER_MODE", "RESOLVER_ADDRS", "LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    monkeypatch.setenv("ENCRYPTION_KEY", "e" * 40)
    monkeypatch.setenv("RESOLVER_MODE", mode)
    monkeypatch.setenv("RESOLVER_ADDRS", addrs)
    settings = Settings()  # type: ignore[call-arg]
    with caplog.at_level(logging.INFO, logger="app.config"):
        settings.log_resolver_config()
    records = [r for r in caplog.records if r.name == "app.config"]
    assert [r.levelno for r in records] == [logging.INFO]
    assert records[0].getMessage() == expected
    assert records[0].__dict__["event"] == "config.resolver"
