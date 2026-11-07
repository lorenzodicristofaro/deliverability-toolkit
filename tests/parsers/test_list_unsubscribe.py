"""Table-driven tests for List-Unsubscribe / One-Click header facts (M5-10). No network."""

from __future__ import annotations

import socket
import time
from typing import Any

import dns.query
import dns.resolver
import pytest

from app.parsers.list_unsubscribe import (
    MAX_FIELDS,
    MAX_POST_ECHO,
    MAX_URI_LENGTH,
    MAX_URIS,
    MAX_VALUE_LENGTH,
    ListUnsubscribeFacts,
    analyze_list_unsubscribe,
)
from app.parsers.message import HeaderField, parse_header_block


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


def facts(raw: bytes, **kw: Any) -> ListUnsubscribeFacts:
    return analyze_list_unsubscribe(parse_header_block(raw + b"\r\n\r\nbody"), **kw)


def lu(value: bytes, post: bytes | None = b"List-Unsubscribe=One-Click") -> bytes:
    raw = b"From: a@example.com\r\nList-Unsubscribe: " + value
    if post is not None:
        raw += b"\r\nList-Unsubscribe-Post: " + post
    return raw


def field(value: str, name: str = "List-Unsubscribe") -> HeaderField:
    return HeaderField(name, value, value, 0)


# --- URI list syntax (RFC 2369 section 2) --------------------------------------------------

URI_CASES = [
    # (id, value, expected kinds, syntax_error, extra field attrs)
    ("rfc8058_8_1", b"<https://example.com/unsubscribe/opaquepart>", ["https"], None, {}),
    (
        "rfc8058_8_2_folded",
        b"\r\n    <mailto:listrequest@example.com?subject=unsubscribe>,\r\n"
        b"    <https://example.com/unsubscribe.html?opaque=123456789>",
        ["mailto", "https"],
        None,
        {},
    ),
    (
        "rfc2369_comment_first",
        b"(Use this command to get off the list)\r\n"
        b"     <mailto:list-manager@host.com?body=unsubscribe%20list>",
        ["mailto"],
        None,
        {"comments": True},
    ),
    ("http_only", b"<http://www.host.com/list.cgi?cmd=unsub&lst=list>", ["http"], None, {}),
    ("uppercase_scheme", b"<HTTPS://EXAMPLE.COM/u>", ["https"], None, {}),
    ("mailto_uppercase", b"<MAILTO:off@Example.COM>", ["mailto"], None, {}),
    (
        "no_space_after_comma",
        b"<https://a.example/u>,<mailto:x@a.example>",
        ["https", "mailto"],
        None,
        {},
    ),
    (
        "comment_between",
        b"<https://a.example/u> (web) , (mail) <mailto:x@a.example>",
        ["https", "mailto"],
        None,
        {"comments": True},
    ),
    ("nested_comment", b"(a (b) \\) c) <https://a.example/u>", ["https"], None, {"comments": True}),
    (
        "trailing_comment",
        b"<https://a.example/u> (List Instructions)",
        ["https"],
        None,
        {"comments": True},
    ),
    ("ftp_other", b"<ftp://ftp.host.com/list.txt>", ["other"], None, {}),
    # malformed
    ("empty", b"", [], "empty_value", {}),
    ("only_comment", b"(nothing here)", [], "empty_value", {"comments": True}),
    ("bare_url", b"https://example.com/u", [], "not_bracketed", {}),
    ("bare_mailto", b"mailto:off@example.com", [], "not_bracketed", {}),
    ("unterminated_bracket", b"<https://example.com/u", [], "unterminated_bracket", {}),
    (
        "second_unterminated",
        b"<https://a.example/u>, <mailto:x@a.example",
        ["https"],
        "unterminated_bracket",
        {},
    ),
    ("unterminated_comment", b"(oops <https://a.example/u>", [], "unterminated_comment", {}),
    (
        "trailing_text_ignored",
        b"<mailto:x@a.example> junk <https://a.example/u>",
        ["mailto"],
        "trailing_text",
        {},
    ),
    (
        "non_uri_item_rule3",
        b"<mailto:x@a.example>, https://a.example/u, <https://b.example/>",
        ["mailto"],
        "non_uri_item",
        {},
    ),
    ("trailing_comma", b"<mailto:x@a.example>,", ["mailto"], "non_uri_item", {}),
    (
        "double_comma",
        b"<mailto:x@a.example>,,<https://a.example/u>",
        ["mailto"],
        "non_uri_item",
        {},
    ),
    ("empty_brackets", b"<>", ["empty"], None, {}),
    ("double_brackets", b"<<https://a.example/u>>", ["relative"], "trailing_text", {}),
    ("relative", b"</unsubscribe>", ["relative"], None, {}),
    ("protocol_relative", b"<//a.example/u>", ["relative"], None, {}),
    (
        "semicolon_separator",
        b"<mailto:x@a.example>; <https://a.example/u>",
        ["mailto"],
        "trailing_text",
        {},
    ),
]


@pytest.mark.parametrize(
    ("value", "kinds", "error", "extra"),
    [c[1:] for c in URI_CASES],
    ids=[c[0] for c in URI_CASES],
)
def test_uri_list_syntax(
    value: bytes, kinds: list[str], error: str | None, extra: dict[str, Any]
) -> None:
    result = facts(lu(value))
    assert result.present and result.field_count == 1
    f = result.fields[0]
    assert [u.kind for u in f.uris] == kinds
    assert f.syntax_error == error
    assert f.evaluated
    for key, want in extra.items():
        assert getattr(f, key) == want


# --- per-URI facts --------------------------------------------------------------------------

URI_FACT_CASES = [
    ("https://example.com/u", {"kind": "https", "scheme": "https", "host": "example.com"}),
    ("http://example.com/u", {"kind": "http", "host": "example.com", "malformed": None}),
    ("hTtPs://Example.COM/u", {"kind": "https", "host": "example.com"}),
    ("https://bank.example@evil.example/u", {"host": "evil.example", "has_userinfo": True}),
    ("https://192.0.2.1/u", {"host": "192.0.2.1", "ip_literal": True}),
    ("https://0xC0.0.2.1/u", {"host": "192.0.2.1", "ip_literal": True}),
    ("https://bücher.example/u", {"host": "xn--bcher-kva.example"}),
    ("https:///u", {"kind": "https", "malformed": "host_single_label"}),
    ("https://ex ample.com/u", {"host": "example.com", "whitespace_removed": True}),
    ("https://\texample.com/u", {"host": "example.com", "whitespace_removed": True}),
    ("https://example.com:99999/u", {"kind": "https", "malformed": "port", "host": None}),
    ("https://example.com/\x01u", {"kind": "https", "malformed": "control_character"}),
    (
        "mailto:list@host.com?subject=unsubscribe",
        {"kind": "mailto", "mailto_domain": "host.com", "mailto_has_query": True},
    ),
    (
        "mailto:list-manager@host.com?body=unsubscribe%20list",
        {"mailto_domain": "host.com", "mailto_has_query": True},
    ),
    ("mailto:off@host.com", {"mailto_domain": "host.com", "mailto_has_query": False}),
    ("mailto:a@one.example,b@two.example", {"mailto_domain": "one.example"}),
    ("mailto:off%40host.com", {"mailto_domain": "host.com", "malformed": None}),
    ("mailto:?subject=unsubscribe", {"kind": "mailto", "malformed": "mailto_no_address"}),
    ("mailto:host.com", {"malformed": "mailto_no_address"}),
    ("mailto:@host.com", {"malformed": "mailto_no_address"}),
    ("mailto:off@", {"malformed": "mailto_domain_empty"}),
    ("mailto:off@ex%ffample.com", {"malformed": "mailto_percent_encoding"}),
    ("mailto:off@[192.0.2.1]", {"mailto_domain": None}),
    ("javascript:alert(1)", {"kind": "other", "scheme": "javascript"}),
    ("=?utf-8?q?https=3A//a.example/u?=", {"kind": "relative"}),
]


@pytest.mark.parametrize(("uri", "expected"), URI_FACT_CASES)
def test_uri_facts(uri: str, expected: dict[str, Any]) -> None:
    result = analyze_list_unsubscribe([field(f"<{uri}>")])
    (u,) = result.fields[0].uris
    for key, want in expected.items():
        assert getattr(u, key) == want, key


def test_mailto_domain_literal_is_malformed() -> None:
    (u,) = analyze_list_unsubscribe([field("<mailto:off@[192.0.2.1]>")]).fields[0].uris
    assert u.malformed is not None and u.malformed.startswith("mailto_domain_")


# --- message-level presence -----------------------------------------------------------------

PRESENCE_CASES = [
    # (id, value, https, http, mailto)
    ("https_only", b"<https://a.example/u>", True, False, False),
    ("http_and_mailto", b"<http://a.example/u>, <mailto:x@a.example>", False, True, True),
    (
        "all_three",
        b"<mailto:x@a.example>, <http://a.example/u>, <https://a.example/u>",
        True,
        True,
        True,
    ),
    ("malformed_https_not_counted", b"<https://a.example:x/u>", False, False, False),
    (
        "https_after_rule2_ignored",
        b"<mailto:x@a.example> x <https://a.example/u>",
        False,
        False,
        True,
    ),
    ("not_bracketed", b"https://a.example/u", False, False, False),
]


@pytest.mark.parametrize(
    ("value", "https", "http", "mailto"),
    [c[1:] for c in PRESENCE_CASES],
    ids=[c[0] for c in PRESENCE_CASES],
)
def test_presence(value: bytes, https: bool, http: bool, mailto: bool) -> None:
    result = facts(lu(value))
    assert (result.https_uri_present, result.http_uri_present, result.mailto_uri_present) == (
        https,
        http,
        mailto,
    )


def test_absent_header() -> None:
    result = facts(b"From: a@example.com\r\nSubject: hi")
    assert result == ListUnsubscribeFacts()
    assert result.one_click_eligible is False
    assert result.post_value_exact is None


# --- List-Unsubscribe-Post value (RFC 8058 section 5, RFC 5234 section 2.3) -----------------

POST_CASES = [
    # (id, post value, exact, abnf, eligible)
    ("exact", b"List-Unsubscribe=One-Click", True, True, True),
    ("lowercase", b"list-unsubscribe=one-click", False, True, True),
    ("uppercase", b"LIST-UNSUBSCRIBE=ONE-CLICK", False, True, True),
    ("no_space_after_colon", None, True, True, True),
    ("folded", b"\r\n List-Unsubscribe=One-Click", True, True, True),
    ("spaces_around_equals", b"List-Unsubscribe = One-Click", False, False, False),
    ("tab_inside", b"List-Unsubscribe=\tOne-Click", False, False, False),
    ("trailing_semicolon", b"List-Unsubscribe=One-Click;", False, False, False),
    ("extra_pair", b"List-Unsubscribe=One-Click&x=1", False, False, False),
    ("quoted", b'"List-Unsubscribe=One-Click"', False, False, False),
    ("one_click_only", b"One-Click", False, False, False),
    ("empty", b"", False, False, False),
    ("encoded_word", b"=?utf-8?q?List-Unsubscribe=3DOne-Click?=", False, False, False),
    ("non_ascii_kelvin", "List-Unsubscribe=One-Kick".encode(), False, False, False),
    ("dotless_i_lookalike", "Lıst-Unsubscribe=One-Click".encode(), False, False, False),
]


@pytest.mark.parametrize(
    ("post", "exact", "abnf", "eligible"),
    [c[1:] for c in POST_CASES],
    ids=[c[0] for c in POST_CASES],
)
def test_post_value(post: bytes | None, exact: bool, abnf: bool, eligible: bool) -> None:
    if post is None:
        raw = b"List-Unsubscribe: <https://a.example/u>\r\nList-Unsubscribe-Post:List-Unsubscribe=One-Click"
    else:
        raw = lu(b"<https://a.example/u>", post)
    result = facts(raw)
    assert result.post_present and result.post_count == 1
    assert result.post_value_exact is exact
    assert result.post_value_matches_abnf is abnf
    assert result.one_click_eligible is eligible


def test_post_header_name_case() -> None:
    result = facts(
        b"list-unsubscribe: <https://a.example/u>\r\nLIST-UNSUBSCRIBE-POST: "
        b"List-Unsubscribe=One-Click"
    )
    assert result.present and result.post_present and result.one_click_eligible


def test_post_value_echo_capped_and_controls_replaced() -> None:
    long_value = "List-Unsubscribe=One-Click" + "x" * 1000
    result = analyze_list_unsubscribe(
        [field("<https://a.example/u>"), field("a\x00b", "List-Unsubscribe-Post")]
    )
    assert result.post_values == ("a�b",)
    assert result.post_value_exact is False
    result = analyze_list_unsubscribe([field(long_value, "List-Unsubscribe-Post")])
    assert len(result.post_values[0]) == MAX_POST_ECHO


# --- One-Click eligibility ------------------------------------------------------------------

ELIGIBLE_CASES = [
    # (id, raw headers, eligible)
    ("simple", lu(b"<https://a.example/u>"), True),
    ("mailto_then_https", lu(b"<mailto:x@a.example>, <https://a.example/u>"), True),
    ("no_post", lu(b"<https://a.example/u>", None), False),
    ("http_only", lu(b"<http://a.example/u>"), False),
    ("mailto_only", lu(b"<mailto:x@a.example>"), False),
    ("malformed_https", lu(b"<https://a.example:x/u>"), False),
    ("not_bracketed", lu(b"https://a.example/u"), False),
    ("post_without_list_unsubscribe", b"List-Unsubscribe-Post: List-Unsubscribe=One-Click", False),
    (
        "duplicate_post",
        lu(b"<https://a.example/u>") + b"\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click",
        False,
    ),
    (
        "duplicate_list_unsubscribe",
        lu(b"<https://a.example/u>") + b"\r\nList-Unsubscribe: <https://b.example/u>",
        False,
    ),
]


@pytest.mark.parametrize(
    ("raw", "eligible"), [c[1:] for c in ELIGIBLE_CASES], ids=[c[0] for c in ELIGIBLE_CASES]
)
def test_one_click_eligible(raw: bytes, eligible: bool) -> None:
    assert facts(raw).one_click_eligible is eligible


def test_duplicates_reported() -> None:
    raw = (
        lu(b"<https://a.example/u>")
        + b"\r\nList-Unsubscribe: <http://b.example/u>"
        + b"\r\nlist-unsubscribe-post: list-unsubscribe=one-click"
    )
    result = facts(raw)
    assert result.field_count == 2 and result.duplicated
    assert result.post_count == 2 and result.post_duplicated
    assert result.post_values == ("List-Unsubscribe=One-Click", "list-unsubscribe=one-click")
    assert result.post_value_exact is False and result.post_value_matches_abnf is True
    assert result.https_uri_present is True and result.http_uri_present is True
    assert [f.uris[0].host for f in result.fields] == ["a.example", "b.example"]


# --- DKIM coverage (RFC 8058 sections 3.1 and 4) --------------------------------------------

DKIM_CASES = [
    # (id, raw, h= lists, lu_signed, post_signed, both)
    ("unknown", lu(b"<https://a.example/u>"), None, None, None, None),
    ("no_valid_signature", lu(b"<https://a.example/u>"), [], False, False, False),
    (
        "both_one_sig",
        lu(b"<https://a.example/u>"),
        [["from", "subject", "list-unsubscribe", "list-unsubscribe-post"]],
        True,
        True,
        True,
    ),
    (
        "mixed_case_and_spaces",
        lu(b"<https://a.example/u>"),
        [[" From", "List-Unsubscribe ", "LIST-UNSUBSCRIBE-POST"]],
        True,
        True,
        True,
    ),
    ("only_lu", lu(b"<https://a.example/u>"), [["from", "list-unsubscribe"]], True, False, False),
    (
        "split_across_sigs",
        lu(b"<https://a.example/u>"),
        [["list-unsubscribe"], ["list-unsubscribe-post"]],
        True,
        True,
        False,
    ),
    ("no_post_field", lu(b"<https://a.example/u>", None), [["list-unsubscribe"]], True, None, None),
    (
        "absent_fields",
        b"From: a@example.com",
        [["list-unsubscribe", "list-unsubscribe-post"]],
        None,
        None,
        None,
    ),
    (
        "prefix_not_match",
        lu(b"<https://a.example/u>"),
        [["list-unsubscribe-postx", "list"]],
        False,
        False,
        False,
    ),
    (
        "tuple_input",
        lu(b"<https://a.example/u>"),
        (("list-unsubscribe", "list-unsubscribe-post"),),
        True,
        True,
        True,
    ),
]


@pytest.mark.parametrize(
    ("raw", "h_lists", "lu_signed", "post_signed", "both"),
    [c[1:] for c in DKIM_CASES],
    ids=[c[0] for c in DKIM_CASES],
)
def test_dkim_coverage(
    raw: bytes,
    h_lists: Any,
    lu_signed: bool | None,
    post_signed: bool | None,
    both: bool | None,
) -> None:
    result = facts(raw, dkim_signed_headers=h_lists)
    assert result.list_unsubscribe_signed is lu_signed
    assert result.post_signed is post_signed
    assert result.one_click_signed is both


def test_dkim_flat_string_list_rejected() -> None:
    with pytest.raises(TypeError):
        facts(lu(b"<https://a.example/u>"), dkim_signed_headers=["list-unsubscribe"])


# --- hostile input --------------------------------------------------------------------------


def test_nul_byte_not_evaluated() -> None:
    result = analyze_list_unsubscribe([field("<https://a.example/u\x00>")])
    f = result.fields[0]
    assert f.syntax_error == "nul_byte" and not f.evaluated and f.uris == ()
    assert result.https_uri_present is None
    assert result.http_uri_present is None
    assert result.one_click_eligible is False


def test_nul_in_message_rejected_by_header_parser() -> None:
    from app.parsers.message import InvalidMessage

    with pytest.raises(InvalidMessage):
        facts(lu(b"<https://a.example/u\x00>"))


def test_value_too_long_not_evaluated() -> None:
    value = "<https://a.example/u>, <" + "m" * MAX_VALUE_LENGTH + ">"
    result = analyze_list_unsubscribe([field(value)])
    f = result.fields[0]
    assert f.syntax_error == "value_too_long" and not f.evaluated
    assert result.https_uri_present is None


def test_value_at_cap_evaluated() -> None:
    head = "<https://a.example/u>"
    value = head + " " * (MAX_VALUE_LENGTH - len(head))
    result = analyze_list_unsubscribe([field(value)])
    assert result.fields[0].evaluated and result.https_uri_present is True


def test_uri_too_long() -> None:
    long_uri = "https://a.example/" + "a" * MAX_URI_LENGTH
    result = analyze_list_unsubscribe([field(f"<{long_uri}>, <mailto:x@a.example>")])
    kinds = [u.kind for u in result.fields[0].uris]
    assert kinds == ["too_long", "mailto"]
    assert result.fields[0].uris[0].uri is None
    assert result.https_uri_present is None  # cannot tell
    assert result.mailto_uri_present is True


def test_many_uris_capped() -> None:
    value = ", ".join(f"<mailto:x{i}@a.example>" for i in range(150)) + ", <https://a.example/u>"
    result = analyze_list_unsubscribe([field(value)])
    f = result.fields[0]
    assert f.capped and len(f.uris) == MAX_URIS
    assert result.mailto_uri_present is True
    assert result.https_uri_present is None  # beyond the cap: unknown, not False


def test_many_fields_capped() -> None:
    fields = [field("<mailto:x@a.example>") for _ in range(MAX_FIELDS + 5)]
    fields.append(field("<https://a.example/u>"))
    result = analyze_list_unsubscribe(fields)
    assert result.field_count == MAX_FIELDS + 6 and len(result.fields) == MAX_FIELDS
    assert result.https_uri_present is None
    assert result.one_click_eligible is False


def test_encoded_word_value_not_decoded_into_uri() -> None:
    raw = lu(b"=?utf-8?q?=3Chttps=3A//a.example/u=3E?=")
    result = facts(raw)
    f = result.fields[0]
    assert f.encoded_word is True
    assert f.syntax_error == "not_bracketed" and f.uris == ()
    assert result.https_uri_present is False


def test_encoded_word_inside_brackets_flagged() -> None:
    result = facts(lu(b"<https://a.example/u> (=?utf-8?q?caf=C3=A9?=)"))
    f = result.fields[0]
    assert f.encoded_word is True and f.comments
    assert result.https_uri_present is True


def test_plain_header_list_input() -> None:
    block = parse_header_block(lu(b"<https://a.example/u>") + b"\r\n\r\n")
    assert analyze_list_unsubscribe(block.fields) == analyze_list_unsubscribe(block)


def test_ignores_nameless_fields() -> None:
    result = analyze_list_unsubscribe([HeaderField("", "<https://a.example/u>", "", 0)])
    assert not result.present


@pytest.mark.parametrize(
    "value",
    [
        "(" * 20000,
        "(" * 5000 + ")" * 5000 + "<https://a.example/u>",
        "<" * 8000,
        "<a>," * 2000,
        "\\" * 8000,
        "<https://a.example/u>" + " ," * 3000,
    ],
    ids=["open_parens", "deep_nesting", "open_brackets", "many_items", "backslashes", "commas"],
)
def test_pathological_values_are_fast(value: str) -> None:
    start = time.perf_counter()
    analyze_list_unsubscribe([field(value)])
    assert time.perf_counter() - start < 1.0
