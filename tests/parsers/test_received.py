"""Table-driven tests for the Received chain parser (RFC 5321 4.4, RFC 5322 3.3/4.3). No network.

All fixtures are synthetic: example.com hosts, 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24 and 2001:db8::/32 addresses.
"""

from __future__ import annotations

import socket
import time
from datetime import UTC, datetime
from typing import Any

import pytest

from app.parsers import received as r
from app.parsers.message import parse_header_block
from app.parsers.received import (
    MAX_HOP_BYTES,
    MAX_HOPS,
    ReceivedHop,
    parse_received_chain,
    parse_received_values,
)

DATE = "Tue, 1 Jul 2025 10:00:00 +0000"
TS = datetime(2025, 7, 1, 10, 0, 0, tzinfo=UTC)


def hop(value: str) -> ReceivedHop:
    chain = parse_received_values([value])
    assert len(chain.hops) == 1
    return chain.hops[0]


def codes(h: ReceivedHop) -> list[str]:
    return [w.code for w in h.warnings]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access attempted")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyaddr", "create_connection"):
        monkeypatch.setattr(socket, name, boom)


# --- clause extraction -------------------------------------------------------------------

CLAUSE_CASES = [
    pytest.param(
        f"from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.com "
        f"(Postfix) with ESMTPS id 4AbC123 for <user@example.com>; {DATE}",
        {
            "from_host": "mail.example.com",
            "from_ip": "192.0.2.1",
            "from_ip_reserved": True,
            "by_host": "mx.example.com",
            "with_protocol": "ESMTPS",
            "id": "4AbC123",
            "has_for": True,
            "via": None,
        },
        [],
        id="typical",
    ),
    pytest.param(
        f"from [198.51.100.7] (helo=client.example.com) by mx.example.com with SMTP; {DATE}",
        {"from_host": None, "from_ip": "198.51.100.7", "by_host": "mx.example.com"},
        [],
        id="from-address-literal",
    ),
    pytest.param(
        f"from client.example.com ([IPv6:2001:db8::25]) by mx.example.com with ESMTP; {DATE}",
        {"from_host": "client.example.com", "from_ip": "2001:db8::25", "from_ip_reserved": True},
        [],
        id="ipv6-literal",
    ),
    pytest.param(
        f"from client.example.com ([2001:db8:0:0::1]) by mx.example.com; {DATE}",
        {"from_ip": "2001:db8::1"},
        [],
        id="bare-ipv6-in-brackets-normalised",
    ),
    pytest.param(
        f"FROM Client.Example.COM by MX.example.com WITH esmtp ID x1; {DATE}",
        {"from_host": "Client.Example.COM", "by_host": "MX.example.com", "with_protocol": "esmtp"},
        [],
        id="keywords-case-insensitive",
    ),
    pytest.param(
        f"by mx.example.com (Postfix, from userid 1000) id 7F2; {DATE}",
        {"from_host": None, "from_ip": None, "by_host": "mx.example.com", "id": "7F2"},
        [],
        id="local-hop-no-from",
    ),
    pytest.param(
        f"from a.example.com by b.example.com via TCP with SMTP; {DATE}",
        {"via": "TCP", "with_protocol": "SMTP"},
        [],
        id="via-clause",
    ),
    pytest.param(
        f"from a.example.com (10.0.0.1) by b.example.com; {DATE}",
        {"from_ip": None, "from_ip_reserved": None},
        [],
        id="unbracketed-ip-not-extracted",
    ),
    pytest.param(
        f"from a.example.com ([203.0.113.9]) by b.example.com with Example SMTP Server "
        f"(version=TLS1_2) id 15.20; {DATE}",
        {"from_ip": "203.0.113.9", "with_protocol": "Example", "id": "15.20"},
        ["unexpected_token"],
        id="multi-word-protocol",
    ),
    pytest.param(
        f"from a.example.com ([192.0.2.300]) by b.example.com; {DATE}",
        {"from_ip": None, "from_ip_reserved": None},
        ["invalid_ip_literal"],
        id="invalid-ipv4-literal",
    ),
    pytest.param(
        f"from a.example.com ([999.1.1.1] [192.0.2.4]) by b.example.com; {DATE}",
        {"from_ip": "192.0.2.4"},
        ["invalid_ip_literal"],
        id="second-literal-used",
    ),
    pytest.param(
        f"from a.example.com ([IPv6:192.0.2.1]) by b.example.com; {DATE}",
        {"from_ip": None},
        ["invalid_ip_literal"],
        id="ipv6-tag-on-ipv4",
    ),
    pytest.param(
        f"from a.example.com by b.example.com for <secret@example.com>; {DATE}",
        {"has_for": True},
        [],
        id="for-presence-only",
    ),
    pytest.param(
        f'from a.example.com by b.example.com id "quoted ; id (x)"; {DATE}',
        {"id": '"quoted ; id (x)"'},
        [],
        id="quoted-string-with-specials",
    ),
    pytest.param(
        f"from a.example.com (comment; with semicolon) by b.example.com; {DATE}",
        {"by_host": "b.example.com", "timestamp": TS},
        [],
        id="semicolon-inside-comment",
    ),
]


@pytest.mark.parametrize(("value", "expected", "warning_codes"), CLAUSE_CASES)
def test_clause_extraction(value: str, expected: dict[str, object], warning_codes: list[str]):
    h = hop(value)
    assert h.parsed is True
    assert h.raw == value
    for name, want in expected.items():
        assert getattr(h, name) == want, name
    assert codes(h) == warning_codes


# --- from_ip source: TCP-info comment over HELO literal (RFC 5321 4.4, PARSE-05) ---------

FROM_IP_SOURCE_CASES = [
    pytest.param(
        "from [8.8.8.8] (unknown [10.1.2.3]) by mx.example.org with ESMTP id 1; "
        "Tue, 10 Nov 2026 10:00:00 +0000",
        "10.1.2.3",
        True,
        [],
        id="helo-literal-vs-comment-literal",
    ),
    pytest.param(
        f"from [198.51.100.7] (unknown [192.0.2.9]) by mx.example.com; {DATE}",
        "192.0.2.9",
        True,
        [],
        id="comment-wins-both-documentation",
    ),
    pytest.param(
        f"from [198.51.100.7] (helo=client.example.com) by mx.example.com; {DATE}",
        "198.51.100.7",
        True,
        [],
        id="comment-without-literal-helo-used",
    ),
    pytest.param(
        f"from client.example.com (client.example.com [203.0.113.5]) by mx.example.com; {DATE}",
        "203.0.113.5",
        True,
        [],
        id="hostname-plus-comment-literal",
    ),
    pytest.param(
        f"from [IPv6:2001:db8::1] (unknown [IPv6:2001:db8::2]) by mx.example.com; {DATE}",
        "2001:db8::2",
        True,
        [],
        id="ipv6-both-positions",
    ),
    pytest.param(
        f"from [192.0.2.1] (unknown [IPv6:2001:db8::2]) by mx.example.com; {DATE}",
        "2001:db8::2",
        True,
        [],
        id="ipv4-helo-ipv6-comment",
    ),
    pytest.param(
        f"from [IPv6:2001:db8::1] (unknown [8.8.4.4]) by mx.example.com; {DATE}",
        "8.8.4.4",
        False,
        [],
        id="ipv6-helo-ipv4-comment-reserved-from-comment",
    ),
    pytest.param(
        f"from [8.8.8.8] (unknown [192.0.2.300]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        ["invalid_ip_literal"],
        id="invalid-comment-literal-falls-back-to-helo",
    ),
    pytest.param(
        f"from [8.8.8.8] (unknown [IPv6:192.0.2.1]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        ["invalid_ip_literal"],
        id="bad-ipv6-tag-in-comment-falls-back",
    ),
    pytest.param(
        f"from [999.1.1.1] (unknown [192.0.2.4]) by mx.example.com; {DATE}",
        "192.0.2.4",
        True,
        ["invalid_ip_literal"],
        id="invalid-helo-valid-comment",
    ),
    pytest.param(
        f"from [8.8.8.8] (helo=x.example.com) (unknown [192.0.2.4]) (z [198.51.100.1]) "
        f"by mx.example.com; {DATE}",
        "192.0.2.4",
        True,
        [],
        id="multiple-comments-first-literal",
    ),
    pytest.param(
        f"from [8.8.8.8] (unknown [192.0.2.4] [198.51.100.1]) by mx.example.com; {DATE}",
        "192.0.2.4",
        True,
        [],
        id="multiple-addresses-in-one-comment",
    ),
    pytest.param(
        f"from [8.8.8.8] (unknown [192.0.2.4] port 25 helo x) by mx.example.com; {DATE}",
        "192.0.2.4",
        True,
        [],
        id="comment-literal-with-trailing-text",
    ),
    pytest.param(
        f"from [8.8.8.8] ({'x' * 7000}) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="over-long-comment-no-literal",
    ),
    pytest.param(
        f"from [8.8.8.8] (helo=[10.1.2.3]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="helo-labelled-comment-literal-not-tcp-info",
    ),
    pytest.param(
        f"from h.example.com (helo=[10.1.2.3] [8.8.8.8]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="helo-labelled-then-tcp-info-same-comment",
    ),
    pytest.param(
        f"from h.example.com (helo=[10.1.2.3]) (unknown [8.8.8.8]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="helo-labelled-comment-then-tcp-info-comment",
    ),
    pytest.param(
        f"from h.example.com ([8.8.8.8] helo=[10.1.2.3]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="tcp-info-then-helo-labelled-same-comment",
    ),
    pytest.param(
        f"from [8.8.8.8] (HELO=[10.1.2.3]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="helo-label-upper-case",
    ),
    pytest.param(
        f"from [8.8.8.8] (ehlo=[10.1.2.3]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="ehlo-label",
    ),
    pytest.param(
        f"from h.example.com (EHLO=[10.1.2.3] [8.8.8.8]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="ehlo-label-upper-case-then-tcp-info",
    ),
    pytest.param(
        f"from [8.8.8.8] (helo=[bad]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        ["invalid_ip_literal"],
        id="helo-labelled-invalid-falls-back-to-value",
    ),
    pytest.param(
        f"from h.example.com (helo=[bad] [192.0.2.4]) by mx.example.com; {DATE}",
        "192.0.2.4",
        True,
        ["invalid_ip_literal"],
        id="helo-labelled-invalid-then-tcp-info",
    ),
    pytest.param(
        f"from h.example.com (helo=[10.1.2.3]) by mx.example.com; {DATE}",
        "10.1.2.3",
        True,
        [],
        id="helo-labelled-only-literal-used-as-fallback",
    ),
    pytest.param(
        f"from [8.8.8.8] (helo=[10.1.2.3]) (unknown) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        [],
        id="value-literal-before-helo-labelled-fallback",
    ),
    pytest.param(
        f"from [8.8.8.8] ({'[x] ' * 1500}[192.0.2.4]) by mx.example.com; {DATE}",
        "8.8.8.8",
        False,
        ["invalid_ip_literal"],
        id="many-bad-literals-capped-helo-kept",
    ),
]


@pytest.mark.parametrize(("value", "from_ip", "reserved", "warning_codes"), FROM_IP_SOURCE_CASES)
def test_from_ip_prefers_tcp_info_comment(
    value: str, from_ip: str, reserved: bool, warning_codes: list[str]
):
    h = hop(value)
    assert h.parsed is True
    assert (h.from_ip, h.from_ip_reserved) == (from_ip, reserved)
    assert codes(h) == warning_codes


def test_for_address_not_retained_in_fields():
    h = hop(f"from a.example.com by b.example.com for <secret@example.com>; {DATE}")
    for name in ("from_host", "by_host", "via", "with_protocol", "id"):
        assert "secret" not in str(getattr(h, name))
    assert all(w.term == "" for w in h.warnings)


# --- malformed and hostile input -----------------------------------------------------------

DEEP = 10_000
HOSTILE_CASES = [
    pytest.param("", False, ["empty_received", "date_missing"], id="empty"),
    pytest.param("   \t ", False, ["empty_received", "date_missing"], id="whitespace-only"),
    pytest.param(
        f"from a.example.com\x00 by b.example.com; {DATE}", True, [], id="nul-passed-anyway"
    ),
    pytest.param(f"garbage text here; {DATE}", False, ["unparsed_hop"], id="no-keyword"),
    pytest.param(
        f"qmail 1234 invoked by uid 0; {DATE}", False, ["unparsed_hop"], id="leading-words"
    ),
    pytest.param(
        f"from a.example.com from b.example.com by c.example.com; {DATE}",
        True,
        ["duplicate_clause"],
        id="from-repeated",
    ),
    pytest.param(
        "from a.example.com " * 300 + f"; {DATE}",
        True,
        ["duplicate_clause"],
        id="from-repeated-many-one-warning",
    ),
    pytest.param(
        f"from a.example.com ([[[192.0.2.1]]]) by b.example.com; {DATE}",
        True,
        ["invalid_ip_literal"],
        id="bracket-garbage",
    ),
    pytest.param(
        f"from a.example.com (] [ ][) by b.example.com; {DATE}",
        True,
        ["invalid_ip_literal"],
        id="bracket-garbage-empty",
    ),
    pytest.param(
        f"from a.example.com ([IPv6:{'1:' * 2000}1]) by b.example.com; {DATE}",
        True,
        ["invalid_ip_literal"],
        id="huge-ipv6",
    ),
    pytest.param(
        f"from a.example.com ([2001:db8::1:2:3:4:5:6:7:8]) by b.example.com; {DATE}",
        True,
        ["invalid_ip_literal"],
        id="ipv6-too-many-groups",
    ),
    pytest.param(
        f"from a.example.com (unclosed by b.example.com; {DATE}",
        True,
        ["unbalanced_comment", "date_missing"],
        id="unclosed-comment-swallows-rest",
    ),
    pytest.param(
        f"from a.example.com) by b.example.com; {DATE}",
        True,
        ["unbalanced_comment"],
        id="stray-close-paren",
    ),
    pytest.param(
        f'from a.example.com by b.example.com id "unterminated; {DATE}',
        True,
        ["unterminated_quote", "date_missing"],
        id="unterminated-quote",
    ),
    pytest.param(
        f"from mäil.exämple.com by mx.example.com; {DATE}",
        True,
        ["non_ascii_host"],
        id="non-ascii-host",
    ),
    pytest.param(
        f"from by b.example.com; {DATE}", True, ["missing_clause_value"], id="from-no-value"
    ),
    pytest.param(
        "(" * 3000 + ")" * 3000 + f" from a.example.com by b.example.com; {DATE}",
        True,
        [],
        id="nested-comments-3000-deep",
    ),
    pytest.param("from a.example.com by b.example.com", True, ["date_missing"], id="no-semi"),
]


@pytest.mark.parametrize(("value", "parsed", "warning_codes"), HOSTILE_CASES)
def test_hostile_input(value: str, parsed: bool, warning_codes: list[str]):
    h = hop(value)
    assert h.parsed is parsed
    assert h.raw == value
    assert codes(h) == warning_codes
    if not parsed:
        assert (h.from_host, h.from_ip, h.by_host, h.with_protocol, h.id) == (None,) * 5


def test_unparsed_hop_keeps_timestamp():
    h = hop(f"something odd; {DATE}")
    assert h.parsed is False
    assert h.timestamp == TS


def test_unparsed_hop_does_not_abort_chain():
    chain = parse_received_values(
        [
            f"by c.example.com; {DATE}",
            "\x00\x01 junk",
            f"from a.example.com by b.example.com; {DATE}",
        ]
    )
    assert [h.parsed for h in chain.hops] == [True, False, True]


# --- caps ---------------------------------------------------------------------------------


def _value_of_bytes(size: int, char: str = "a") -> str:
    head = "by mx.example.com id "
    tail = f"; {DATE}"
    width = len(char.encode())
    pad = size - len(head) - len(tail)
    assert pad % width == 0
    value = head + char * (pad // width) + tail
    assert len(value.encode()) == size
    return value


@pytest.mark.parametrize(
    ("value", "too_long"),
    [
        pytest.param(_value_of_bytes(MAX_HOP_BYTES), False, id="ascii-at-cap"),
        pytest.param(_value_of_bytes(MAX_HOP_BYTES + 1), True, id="ascii-over-cap"),
        pytest.param(_value_of_bytes(MAX_HOP_BYTES - 1, "é"), False, id="utf8-below-cap"),
        pytest.param("a" * (1024 * 1024), True, id="1mb-single-token"),
    ],
)
def test_hop_byte_cap(value: str, too_long: bool):
    h = hop(value)
    if too_long:
        assert codes(h) == ["hop_too_long"]
        assert h.parsed is False
        assert h.timestamp is None
        assert len(h.raw.encode()) <= MAX_HOP_BYTES
    else:
        assert h.parsed is True
        assert h.timestamp == TS
        assert h.raw == value


def test_hop_byte_cap_counts_utf8_bytes():
    # Fewer characters than the cap, more bytes than the cap.
    value = "by mx.example.com id " + "é" * (MAX_HOP_BYTES // 2) + f"; {DATE}"
    assert len(value) < MAX_HOP_BYTES < len(value.encode())
    h = hop(value)
    assert codes(h) == ["hop_too_long"]
    h.raw.encode("utf-8")  # cut on a character boundary


@pytest.mark.parametrize(
    ("count", "truncated"),
    [(0, False), (1, False), (MAX_HOPS - 1, False), (MAX_HOPS, False), (MAX_HOPS + 1, True)],
)
def test_hop_count_cap(count: int, truncated: bool):
    values = [f"by h{i}.example.com; {DATE}" for i in range(count)]  # h0 is the newest
    chain = parse_received_values(values)
    assert chain.truncated is truncated
    assert chain.received_count == count
    assert len(chain.hops) == min(count, MAX_HOPS)
    if count:
        assert chain.hops[-1].by_host == "h0.example.com"  # newest kept
        assert [h.index for h in chain.hops] == list(range(len(chain.hops)))


# --- linear time guards -------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("(" * DEEP + ")" * DEEP, id="nested-10k"),
        pytest.param("(" * DEEP, id="unclosed-10k"),
        pytest.param("\\(" * DEEP, id="quoted-pairs"),
        pytest.param("[" * DEEP + "]" * DEEP, id="brackets"),
        pytest.param('"' * DEEP, id="quotes"),
        pytest.param("from " * DEEP, id="keywords"),
    ],
)
def test_scanners_linear(value: str):
    start = time.perf_counter()
    r._tokenize(value, r._Warnings())
    r._strip_comments(value)
    r._address_literals(value)
    assert time.perf_counter() - start < 1.0


def test_nested_10k_through_public_api_hits_cap():
    h = hop("from a.example.com " + "(" * DEEP + ")" * DEEP + f" by b.example.com; {DATE}")
    assert codes(h) == ["hop_too_long"]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("(" * (MAX_HOP_BYTES // 2) + ")" * (MAX_HOP_BYTES // 2), id="nested-at-cap"),
        pytest.param("from (" + "[" * (MAX_HOP_BYTES - 6), id="brackets-at-cap"),
        pytest.param("; " + "(" * (MAX_HOP_BYTES - 2), id="date-comments-at-cap"),
    ],
)
def test_public_api_bounded_time(value: str):
    start = time.perf_counter()
    parse_received_values([value] * MAX_HOPS)
    assert time.perf_counter() - start < 2.0


# --- dates --------------------------------------------------------------------------------

DATE_CASES = [
    pytest.param(DATE, TS, [], id="rfc5322"),
    pytest.param("1 Jul 2025 10:00:00 +0000", TS, [], id="no-day-of-week"),
    pytest.param("Tue,1 Jul 2025 10:00:00 +0000", TS, [], id="no-space-after-comma"),
    pytest.param("Tue, 1 Jul 2025 12:00:00 +0200", TS, [], id="positive-offset"),
    pytest.param("Tue, 1 Jul 2025 05:30:00 -0430", TS, [], id="negative-offset-minutes"),
    pytest.param("Tue, 1 Jul 2025 10:00:00 -0000", TS, [], id="minus-zero-is-utc"),
    pytest.param("Tue, 1 Jul 2025 10:00 +0000", TS, [], id="no-seconds"),
    pytest.param("Tue, 1 Jul 2025 10:00:00 +0000 (UTC)", TS, [], id="trailing-comment"),
    pytest.param(
        "(c) Tue, (x (nested)) 1 Jul 2025 (y) 10:00:00 (z) +0000", TS, [], id="comments-anywhere"
    ),
    pytest.param("\r\n\tTue, 1 Jul 2025 10:00:00 +0000", TS, [], id="folding-whitespace"),
    pytest.param("Tue, 1 Jul 2025 10:00:00 GMT", TS, [], id="obs-gmt"),
    pytest.param("Tue, 1 Jul 2025 10:00:00 UT", TS, [], id="obs-ut"),
    pytest.param("Tue, 1 Jul 2025 06:00:00 EDT", TS, [], id="obs-edt"),
    pytest.param("Tue, 1 Jul 2025 02:00:00 pst", TS, [], id="obs-pst-lowercase"),
    pytest.param("Tue, 1 Jul 2025 04:00:00 CST", TS, [], id="obs-cst"),
    pytest.param("Tue, 1 Jul 2025 03:00:00 MST", TS, [], id="obs-mst"),
    pytest.param(
        "Tue, 1 Jul 2025 10:00:00 Z", TS, ["date_zone_unknown"], id="military-as-minus-zero"
    ),
    pytest.param(
        "Tue, 1 Jul 2025 10:00:00 CEST", TS, ["date_zone_unknown"], id="unknown-alpha-zone"
    ),
    pytest.param("Tue, 1 Jul 25 10:00:00 +0000", TS, [], id="obs-2-digit-year"),
    pytest.param(
        "1 Jul 99 10:00:00 +0000",
        datetime(1999, 7, 1, 10, tzinfo=UTC),
        [],
        id="obs-2-digit-year-1900s",
    ),
    pytest.param("1 Jul 125 10:00:00 +0000", TS, [], id="obs-3-digit-year"),
    pytest.param(
        "31 Dec 2016 23:59:60 +0000",
        datetime(2017, 1, 1, tzinfo=UTC),
        [],
        id="leap-second",
    ),
    pytest.param("Tue, 1 Jul 2025 10:00:00", None, ["date_no_timezone"], id="no-zone"),
    pytest.param("1 Jul 2025 10:00:00 (UTC)", None, ["date_no_timezone"], id="zone-only-comment"),
    pytest.param("30 Feb 2025 10:00:00 +0000", None, ["date_invalid"], id="feb-30"),
    pytest.param("1 Jul 2025 25:00:00 +0000", None, ["date_invalid"], id="hour-25"),
    pytest.param("1 Jul 2025 10:61:00 +0000", None, ["date_invalid"], id="minute-61"),
    pytest.param("1 Jul 2025 10:00:61 +0000", None, ["date_invalid"], id="second-61"),
    pytest.param("1 Foo 2025 10:00:00 +0000", None, ["date_invalid"], id="bad-month"),
    pytest.param("1 Jul 2025 10:00:00 +2400", None, ["date_invalid"], id="offset-hours-24"),
    pytest.param("1 Jul 2025 10:00:00 +0060", None, ["date_invalid"], id="offset-minutes-60"),
    pytest.param("1 Jul 2025 10:00:00 +00", None, ["date_invalid"], id="short-offset"),
    pytest.param("1 Jul 2025 10:00:00 +0000 extra", None, ["date_invalid"], id="extra-token"),
    pytest.param("1 Jul 0 10:00:00 +0000", None, ["date_invalid"], id="1-digit-year"),
    pytest.param("1 Jul 0000 10:00:00 +0000", None, ["date_invalid"], id="year-zero"),
    pytest.param("1 Jul 99999 10:00:00 +0000", None, ["date_invalid"], id="year-5-digits"),
    pytest.param("1 Jan 0001 00:00:00 +0100", None, ["date_invalid"], id="underflow"),
    pytest.param("31 Dec 9999 23:59:60 +0000", None, ["date_invalid"], id="leap-overflow"),
    pytest.param("1 Jul 2025 ١٠:00:00 +0000", None, ["date_invalid"], id="non-ascii-digits"),
    pytest.param(
        "1 Jul 2025 10:00:00 +0000 (open",
        None,
        ["unbalanced_comment", "date_invalid"],
        id="unclosed",
    ),
    pytest.param(
        "1 Jul 2025 10:00:00 +0000)", None, ["unbalanced_comment", "date_invalid"], id="stray-paren"
    ),
    pytest.param("1 Jul 2025 10::00 +0000", None, ["date_invalid"], id="empty-time-part"),
    pytest.param("1 Jul 2025 10:00:00 +00.0", None, ["date_invalid"], id="garbage-zone"),
    pytest.param("", None, ["date_missing"], id="empty-after-semicolon"),
    pytest.param(" (only a comment) ", None, ["date_missing"], id="comment-only"),
]


@pytest.mark.parametrize(("date", "expected", "warning_codes"), DATE_CASES)
def test_dates(date: str, expected: datetime | None, warning_codes: list[str]):
    h = hop(f"from a.example.com by b.example.com;{date}")
    assert h.timestamp == expected
    if expected is not None:
        assert h.timestamp is not None and h.timestamp.tzinfo is UTC
    assert codes(h) == warning_codes


def test_last_top_level_semicolon_starts_date():
    h = hop(f"from a.example.com; by b.example.com; {DATE}")
    assert h.timestamp == TS
    assert codes(h) == ["unexpected_token"]


# --- order, delays, transit ---------------------------------------------------------------


def _v(host: str, clock: str) -> str:
    return f"from {host}.example.com by mx.example.com; Tue, 1 Jul 2025 {clock} +0000"


@pytest.mark.parametrize(
    ("values", "delays", "total", "skew"),
    [
        pytest.param(
            [_v("c", "10:00:30"), _v("b", "10:00:10"), _v("a", "10:00:00")],
            [None, 10, 20],
            30,
            [False, False, False],
            id="ordered",
        ),
        pytest.param(
            [_v("c", "10:00:05"), _v("b", "10:00:10"), _v("a", "10:00:00")],
            [None, 10, -5],
            5,
            [False, False, True],
            id="negative-kept-and-flagged",
        ),
        pytest.param(
            [_v("c", "09:59:00"), _v("a", "10:00:00")],
            [None, -60],
            -60,
            [False, True],
            id="negative-total",
        ),
        pytest.param(
            [_v("c", "10:00:30"), "by b.example.com; no date", _v("a", "10:00:00")],
            [None, None, None],
            30,
            [False, False, False],
            id="gap-no-delay-across-missing",
        ),
        pytest.param(
            ["by c.example.com", _v("b", "10:00:10"), _v("a", "10:00:00")],
            [None, 10, None],
            None,
            [False, False, False],
            id="last-missing-no-total",
        ),
        pytest.param([_v("a", "10:00:00")], [None], 0, [False], id="single-hop-total-zero"),
        pytest.param([], [], None, [], id="no-hops"),
    ],
)
def test_delays(values: list[str], delays: list[int | None], total: int | None, skew: list[bool]):
    chain = parse_received_values(values)
    assert [h.delay_seconds for h in chain.hops] == delays
    assert chain.total_transit_seconds == total
    assert [("clock_skew" in codes(h)) for h in chain.hops] == skew


def test_order_oldest_first():
    chain = parse_received_values([_v("newest", "10:00:02"), _v("oldest", "10:00:00")])
    assert [h.from_host for h in chain.hops] == ["oldest.example.com", "newest.example.com"]
    assert [h.index for h in chain.hops] == [0, 1]


def test_from_header_block():
    raw = (
        b"Received: from relay.example.com (relay.example.com [203.0.113.5])\r\n"
        b"\tby mx.example.com with ESMTPS id ABC;\r\n"
        b"\tTue, 1 Jul 2025 10:00:07 +0000\r\n"
        b"Subject: hi\r\n"
        b"received: from origin.example.com ([2001:db8::7]) by relay.example.com\r\n"
        b" with ESMTP; Tue, 1 Jul 2025 10:00:00 +0000\r\n"
        b"\r\nbody"
    )
    chain = parse_received_chain(parse_header_block(raw))
    assert [h.from_ip for h in chain.hops] == ["2001:db8::7", "203.0.113.5"]
    assert [h.by_host for h in chain.hops] == ["relay.example.com", "mx.example.com"]
    assert chain.hops[1].delay_seconds == 7
    assert chain.total_transit_seconds == 7
    assert chain.received_count == 2


def test_string_input_rejected():
    with pytest.raises(TypeError):
        parse_received_values("by mx.example.com; " + DATE)  # type: ignore[arg-type]
