"""Table-driven tests for static link analysis (M5-09). No network, no DNS."""

from __future__ import annotations

import socket
from typing import Any

import dns.query
import dns.resolver
import pytest

from app.parsers.content_html import parse_content
from app.parsers.content_links import LinkInfo, LinkLimits, analyze_links
from app.parsers.url_shorteners import Shortener

SHORTENERS = (
    Shortener("bit.ly", "bitly", "n", "verified", ("https://dev.bitly.com/api-reference/",)),
    Shortener("ow.ly", None, "n", "unverified", ()),
)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access attempted")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyaddr", "create_connection"):
        monkeypatch.setattr(socket, name, boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", boom)
    monkeypatch.setattr(dns.resolver, "resolve", boom)
    for name in ("udp", "tcp", "https"):
        monkeypatch.setattr(dns.query, name, boom)


def one(href: str | None, text: str = "click here", **kw: Any) -> LinkInfo:
    kw.setdefault("sender_domains", ["example.com"])
    kw.setdefault("shorteners", SHORTENERS)
    return analyze_links([(text, href)], **kw).links[0]


@pytest.mark.parametrize(
    ("href", "expected"),
    [
        # plain and uppercase schemes
        (
            "https://www.example.com/a",
            {"kind": "web", "scheme": "https", "host": "www.example.com"},
        ),
        ("HTTPS://WWW.EXAMPLE.COM", {"scheme": "https", "host": "www.example.com"}),
        ("http://example.org/", {"non_https": True, "registrable_domain": "example.org"}),
        ("HtTp://example.org", {"scheme": "http", "non_https": True}),
        # userinfo trick: host is after the LAST @
        ("http://bank.example@evil.example/", {"host": "evil.example", "has_userinfo": True}),
        ("https://a@b@evil.example", {"host": "evil.example", "has_userinfo": True}),
        ("https://user:pw@example.com:8443/x", {"host": "example.com", "has_userinfo": True}),
        # IP literals in every form
        ("http://192.0.2.1/", {"host": "192.0.2.1", "ip_literal": True}),
        ("http://3221225985", {"host": "192.0.2.1", "ip_literal": True}),
        ("http://0xC0.0x00.0x02.0x01", {"host": "192.0.2.1", "ip_literal": True}),
        ("http://0300.0.02.01", {"host": "192.0.2.1", "ip_literal": True}),
        ("http://0x7f.1", {"host": "127.0.0.1", "ip_literal": True}),
        ("http://192.0.2.1./", {"host": "192.0.2.1", "ip_literal": True}),
        ("http://[2001:db8::1]:8080/", {"host": "[2001:db8::1]", "ip_literal": True}),
        ("http://[2001:DB8:0:0::1]", {"host": "[2001:db8::1]", "ip_literal": True}),
        ("http://１９２.０.２.１", {"host": "192.0.2.1", "ip_literal": True}),
        # protocol-relative and backslash forms
        ("//cdn.example.net/a", {"kind": "web", "protocol_relative": True, "scheme": None}),
        ("\\\\evil.example\\x", {"protocol_relative": True, "host": "evil.example"}),
        ("http:\\\\evil.example", {"host": "evil.example"}),
        ("http:///evil.example", {"host": "evil.example"}),
        ("https://example.com?q=@evil.example", {"host": "example.com", "has_userinfo": False}),
        ("https://example.com#@evil.example", {"host": "example.com", "has_userinfo": False}),
        # percent-encoding in the host
        ("http://%65vil.example", {"host": "evil.example", "percent_encoded_host": True}),
        ("http://ex%ffample.com", {"malformed": "host_percent_encoding", "host": None}),
        ("http://ex%2Fample.com", {"malformed": "host_idna"}),
        # IDN / punycode / mixed script
        ("https://bücher.example", {"host": "xn--bcher-kva.example", "idn": True}),
        ("https://xn--bcher-kva.example", {"host_unicode": "bücher.example"}),
        ("http://аpple.com", {"idn": True, "mixed_script": True, "homograph_suspect": True}),
        ("https://例え.jp", {"idn": True, "mixed_script": False}),
        # dangerous and ignored schemes
        ("javascript:alert(1)", {"kind": "javascript", "dangerous_scheme": True, "host": None}),
        ("JAVASCRIPT:alert(1)", {"kind": "javascript", "dangerous_scheme": True}),
        (" java\tscr\nipt:alert(1)", {"kind": "javascript", "dangerous_scheme": True}),
        ("\x01javascript:x", {"kind": "javascript"}),
        ("data:text/html;base64,PHA+", {"kind": "data", "dangerous_scheme": True}),
        ("vbscript:msgbox", {"kind": "vbscript", "dangerous_scheme": True}),
        ("mailto:a@evil.example", {"kind": "mailto", "host": None, "aligned": None}),
        ("tel:+390000000", {"kind": "tel", "aligned": None}),
        ("ftp://example.com/f", {"kind": "other", "host": None}),
        # relative, empty, missing
        ("/path?x=1", {"kind": "relative", "host": None, "aligned": None}),
        ("page.html", {"kind": "relative"}),
        ("#top", {"kind": "relative"}),
        ("", {"kind": "empty"}),
        ("  \t ", {"kind": "empty"}),
        (None, {"kind": "no_href"}),
        # whitespace/control characters
        ("  https://example.com  ", {"host": "example.com", "has_control_chars": False}),
        ("https://exa\nmple.com", {"host": "example.com"}),
        (
            "https://exa\x00mple.com",
            {"has_control_chars": True, "malformed": "host_forbidden_character"},
        ),
        ("https://exa mple.com", {"malformed": "host_forbidden_character"}),
        # malformed hosts
        ("http://", {"kind": "web", "malformed": "empty_host"}),
        ("https://?x", {"malformed": "empty_host"}),
        ("http://999.1.1.1", {"malformed": "invalid_ipv4"}),
        ("http://1.2.3.4.5", {"malformed": "invalid_ipv4"}),
        ("http://08.1.1.1", {"malformed": "invalid_ipv4"}),
        ("http://[::1", {"malformed": "invalid_ipv6"}),
        ("http://[zz::1]", {"malformed": "invalid_ipv6"}),
        ("http://[fe80::1%25eth0]", {"malformed": "invalid_ipv6"}),
        ("http://[::1]x", {"malformed": "port"}),
        ("http://example.com:abc", {"malformed": "port"}),
        ("http://example.com:99999", {"malformed": "port"}),
        ("http://localhost/", {"malformed": "host_single_label"}),
        ("http://exa_mple.com", {"malformed": "host_idna"}),
        ("http://" + "a" * 64 + ".com", {"malformed": "host_idna"}),
    ],
)
def test_link_facts(href: str | None, expected: dict[str, object]) -> None:
    info = one(href)
    for key, value in expected.items():
        assert getattr(info, key) == value, (href, key, getattr(info, key))


@pytest.mark.parametrize(
    ("text", "href", "text_host", "masked"),
    [
        ("https://www.paypal.com/login", "https://evil.example/x", "www.paypal.com", True),
        ("www.paypal.com", "https://evil.example", "www.paypal.com", True),
        ("Visit paypal.com today", "https://evil.example", "paypal.com", True),
        ("paypal.com", "https://www.paypal.com/x", "paypal.com", False),
        ("PAYPAL.COM", "https://login.paypal.com", "paypal.com", False),
        ("support@paypal.com", "https://evil.example", "paypal.com", True),
        ("https://192.0.2.1", "https://example.com", "192.0.2.1", True),
        ("https://www.example.com", "http://3232235777", "www.example.com", True),
        ("https://www.example.com", "javascript:void(0)", "www.example.com", True),
        ("Click here", "https://evil.example", None, False),
        ("Mr.Smith", "https://evil.example", None, False),
        ("readme.txt", "https://evil.example", None, False),
        ("", "https://evil.example", None, False),
        ("www.example.com", "mailto:a@evil.example", None, False),
        (
            "(https://bücher.example)",
            "https://xn--bcher-kva.example",
            "xn--bcher-kva.example",
            False,
        ),
        ("https://apple.com", "https://xn--pple-43d.com", "apple.com", True),
    ],
)
def test_masked_links(text: str, href: str, text_host: str | None, masked: bool) -> None:
    info = one(href, text)
    assert (info.text_host, info.masked) == (text_host, masked)


def test_homograph_flag_needs_mismatch_or_mixed_script() -> None:
    assert one("https://xn--pple-43d.com", "https://apple.com").homograph_suspect is True
    assert one("https://xn--bcher-kva.example", "bücher.example").homograph_suspect is False


@pytest.mark.parametrize(
    ("href", "shortener", "verified"),
    [
        ("https://bit.ly/abc", "bit.ly", True),
        ("https://BIT.LY/abc", "bit.ly", True),
        ("https://www.bit.ly/abc", "bit.ly", True),
        ("http://ow.ly/x", "ow.ly", False),
        ("https://notbit.ly/abc", None, None),
        ("https://bit.ly.evil.example/abc", None, None),
        ("https://192.0.2.1/bit.ly", None, None),
    ],
)
def test_shortener_match(href: str, shortener: str | None, verified: bool | None) -> None:
    info = one(href)
    assert (info.shortener, info.shortener_verified) == (shortener, verified)


@pytest.mark.parametrize(
    ("senders", "href", "aligned"),
    [
        (["example.com"], "https://example.com/", True),
        (["mail.example.com"], "https://track.example.com/", True),
        (["example.com"], "https://example.co.uk/", False),
        (["example.co.uk"], "https://news.example.co.uk/", True),
        (["foo.github.io"], "https://bar.github.io/", False),
        (["example.com"], "http://192.0.2.1/", False),
        (["EXAMPLE.COM."], "https://www.example.com", True),
        (["bücher.example"], "https://xn--bcher-kva.example/", True),
        ([], "https://example.com/", None),
        ([None, "", "not a domain", "localhost"], "https://example.com/", None),
        (["example.com"], "/relative", None),
        (["example.com"], "http://localhost/", None),
    ],
)
def test_alignment(senders: list[str | None], href: str, aligned: bool | None) -> None:
    assert one(href, sender_domains=senders).aligned is aligned


def test_message_level_alignment_and_tracking_domains() -> None:
    anchors = [
        ("a", "https://www.example.com/"),
        ("b", "https://click.tracker.example/1"),
        ("c", "https://click.tracker.example/2"),
        ("d", "https://links.tracker.example/3"),
        ("e", "https://other.example/"),
        ("f", "https://a.zzz.example/"),
        ("g", "mailto:x@outside.example"),
        ("h", "/rel"),
    ]
    result = analyze_links(anchors, sender_domains=["example.com"], shorteners=())
    assert result.sender_domains == ("example.com",)
    assert result.all_aligned is False
    assert result.unaligned_count == 5
    assert result.other_domains == ("tracker.example", "other.example", "zzz.example")
    assert result.dominant_domain == "tracker.example"
    assert result.outlier_domains == ("other.example", "zzz.example")
    assert not result.capped


def test_no_sender_alignment_fields_are_none() -> None:
    result = analyze_links(
        [("a", "https://t.example/1"), ("b", "https://t.example/2")],
        sender_domains=[],
        shorteners=(),
    )
    assert result.all_aligned is None and result.unaligned_count is None
    assert all(link.aligned is None for link in result.links)
    assert result.dominant_domain == "t.example" and result.outlier_domains == ()


def test_all_aligned_and_no_links() -> None:
    ok = analyze_links(
        [("a", "https://example.com")], sender_domains=["example.com"], shorteners=()
    )
    assert (ok.all_aligned, ok.unaligned_count, ok.dominant_domain) == (True, 0, None)
    empty = analyze_links([], sender_domains=["example.com"], shorteners=())
    assert (empty.all_aligned, empty.total_anchors, empty.capped) == (None, 0, False)
    only_mailto = analyze_links(
        [("a", "mailto:a@b.example")], sender_domains=["x.com"], shorteners=()
    )
    assert only_mailto.all_aligned is None


@pytest.mark.parametrize(
    ("count", "limit", "capped", "analyzed"),
    [(3, 5, False, 3), (5, 5, False, 5), (6, 5, True, 5), (10_000, 500, True, 500)],
)
def test_link_count_cap(count: int, limit: int, capped: bool, analyzed: int) -> None:
    anchors = [("x", f"https://h{i}.example/") for i in range(count)]
    result = analyze_links(
        anchors, sender_domains=[], shorteners=(), limits=LinkLimits(max_links=limit)
    )
    assert (result.capped, len(result.links), result.total_anchors) == (capped, analyzed, count)
    assert result.cap_reason == ("link_count" if capped else None)


@pytest.mark.parametrize(
    ("length", "kind", "capped"),
    [(4096, "web", False), (4097, "too_long", True), (1_000_000, "too_long", True)],
)
def test_url_length_cap(length: int, kind: str, capped: bool) -> None:
    prefix = "https://example.com/"
    href = prefix + "a" * (length - len(prefix))
    result = analyze_links([("x", href)], sender_domains=["example.com"], shorteners=())
    assert result.links[0].kind == kind
    assert (result.capped, result.cap_reason) == (capped, "url_length" if capped else None)
    if capped:
        assert result.links[0].host is None and result.links[0].aligned is None


def test_link_count_cap_reason_wins() -> None:
    anchors = [("x", "https://example.com/" + "a" * 50)] * 3
    result = analyze_links(
        anchors,
        sender_domains=[],
        shorteners=(),
        limits=LinkLimits(max_links=2, max_url_length=10),
    )
    assert (result.capped, result.cap_reason) == (True, "link_count")


def test_huge_visible_text_is_bounded() -> None:
    text = "word " * 200_000 + "https://paypal.com"
    info = one("https://evil.example", text)
    assert (info.text_host, info.masked) == (None, False)


@pytest.mark.parametrize(
    "href",
    [
        "http://" + "a." * 600 + "com",
        "http://[" + ":" * 3000 + "]",
        "http://" + "1." * 2000 + "1",
        "http://0x" + "f" * 3000,
        "http://" + "%" * 3000,
        "\x00" * 100,
        "https://\udcff.example",
        "https://example.com:" + "9" * 3000,
        "‮https://example.com",
    ],
)
def test_hostile_inputs_do_not_raise(href: str) -> None:
    info = one(href)
    assert info.kind in {"web", "relative", "empty", "too_long"}


def test_consumes_content_html_anchors() -> None:
    html = (
        '<a href="https://www.example.com/a">ok</a>'
        '<a href="http://bank.example@evil.example">https://bank.example</a>'
        "<a>no href</a>"
        '<a href="https://bit.ly/x"><a href="javascript:alert(1)">nested</a>'
    )
    anchors = parse_content(html, None).anchors
    result = analyze_links(anchors, sender_domains=["example.com"], shorteners=SHORTENERS)
    kinds = [link.kind for link in result.links]
    assert "no_href" in kinds and "javascript" in kinds
    trick = next(link for link in result.links if link.has_userinfo)
    assert (trick.host, trick.masked, trick.text_host) == ("evil.example", True, "bank.example")
    assert any(link.shortener == "bit.ly" for link in result.links)
