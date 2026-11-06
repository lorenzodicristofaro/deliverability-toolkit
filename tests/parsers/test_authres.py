"""Table-driven tests for the Authentication-Results parser (RFC 8601). No network.

Fixtures marked "RFC 8601 B.x" are the header fields of RFC 8601 appendix B (read-only, from
tests/fixtures/messages/ or copied from the RFC text). All other values are synthetic and use
example.com / example.net / example.org only.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path

import pytest

from app.parsers import authres as ar
from app.parsers.authres import (
    MAX_AUTHRES_LENGTH,
    MAX_ISSUES,
    MAX_RESINFO,
    AuthResHeader,
    AuthResParseError,
    AuthResTooLarge,
    InvalidAuthenticationResults,
    parse_all_authentication_results,
    parse_authentication_results,
)
from app.parsers.message import parse_header_block

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "messages"


def codes(header: AuthResHeader) -> list[str]:
    return [i.code for i in header.issues]


def summary(header: AuthResHeader) -> list[tuple[str, str]]:
    return [(r.method, r.result) for r in header.resinfo]


def parse(value: str) -> AuthResHeader:
    return parse_authentication_results(value)


# --- valid forms ------------------------------------------------------------------------

VALID_CASES: list[tuple[str, str, str | None, int | None, list[tuple[str, str]]]] = [
    # RFC 8601 B.2
    ("rfc8601_b2_none", "example.org 1; none", "example.org", 1, []),
    # RFC 8601 B.3
    (
        "rfc8601_b3",
        "example.com;\n          spf=pass smtp.mailfrom=example.net",
        "example.com",
        None,
        [("spf", "pass")],
    ),
    # RFC 8601 B.4 (first field)
    (
        "rfc8601_b4_auth_spf",
        "example.com;\n auth=pass (cram-md5) smtp.auth=sender@example.net;\n"
        " spf=pass smtp.mailfrom=example.net",
        "example.com",
        None,
        [("auth", "pass"), ("spf", "pass")],
    ),
    # RFC 8601 B.4 (second field)
    (
        "rfc8601_b4_iprev",
        "example.com; iprev=pass\n policy.iprev=192.0.2.200",
        "example.com",
        None,
        [("iprev", "pass")],
    ),
    # RFC 8601 B.5
    (
        "rfc8601_b5_dkim_comment",
        "example.com;\n dkim=pass (good signature) header.d=example.com",
        "example.com",
        None,
        [("dkim", "pass")],
    ),
    # RFC 8601 B.6
    (
        "rfc8601_b6_two_dkim",
        'example.com;\n dkim=pass reason="good signature"\n header.i=@mail-router.example.net;\n'
        ' dkim=fail reason="bad signature"\n header.i=@newyork.example.com',
        "example.com",
        None,
        [("dkim", "pass"), ("dkim", "fail")],
    ),
    # RFC 8601 B.7 (comment-heavy)
    (
        "rfc8601_b7_comment_heavy",
        "foo.example.net (foobar) 1 (baz);\n"
        "    dkim (Because I like it) / 1 (One yay) = (wait for it) fail\n"
        "      policy (A dot can go here) . (like that) expired\n"
        "      (this surprised me) = (as I wasn't expecting it) 1362471462",
        "foo.example.net",
        1,
        [("dkim", "fail")],
    ),
    # RFC 8601 section 2.7.4 resinfo example
    (
        "rfc8601_274_auth",
        "example.com; auth=pass smtp.auth=client@c.example smtp.mailfrom=bob@b.example",
        "example.com",
        None,
        [("auth", "pass")],
    ),
    (
        "quoted_authserv_id",
        '"mx.example.com"; spf=none',
        "mx.example.com",
        None,
        [("spf", "none")],
    ),
    (
        "all_typed",
        "mx.example.com; spf=softfail smtp.mailfrom=example.net smtp.helo=mx.example.net;"
        " dkim=pass header.d=example.net header.s=sel header.a=rsa-sha256 header.b=AbC/+dEf;"
        " dmarc=fail header.from=example.net policy.dmarc=reject;"
        " arc=none",
        "mx.example.com",
        None,
        [("spf", "softfail"), ("dkim", "pass"), ("dmarc", "fail"), ("arc", "none")],
    ),
]


@pytest.mark.parametrize(
    ("value", "authserv_id", "version", "expected"),
    [c[1:] for c in VALID_CASES],
    ids=[c[0] for c in VALID_CASES],
)
def test_valid_forms(
    value: str, authserv_id: str, version: int | None, expected: list[tuple[str, str]]
) -> None:
    header = parse(value)
    assert header.authserv_id == authserv_id
    assert header.version == version
    assert summary(header) == expected
    assert codes(header) == []
    assert header.raw == value
    assert not header.truncated
    assert not any(r.unknown_value for r in header.resinfo)


def test_none_form() -> None:
    header = parse("example.org 1; none")
    assert header.no_result is True
    assert header.resinfo == ()


def test_b6_reason_and_properties() -> None:
    header = parse(VALID_CASES[5][1])
    first, second = header.dkim
    assert first.reason == "good signature"
    assert first.header_i == "@mail-router.example.net"
    assert second.reason == "bad signature"
    assert second.header_i == "@newyork.example.com"
    # Different properties: two dkim results are normal, not a conflict.
    assert ar.CONFLICTING_RESULTS not in codes(header)


def test_b7_cfws_around_slash_dot_equals() -> None:
    info = parse(VALID_CASES[6][1]).resinfo[0]
    assert info.method_version == 1
    assert info.policy == (
        ar.AuthResProperty("policy", "expired", "1362471462", info.policy[0].position),
    )
    assert "Because I like it" in info.raw  # raw keeps the source text


def test_typed_accessors() -> None:
    header = parse(VALID_CASES[9][1])
    (spf,) = header.spf
    assert (spf.smtp_mailfrom, spf.smtp_helo) == ("example.net", "mx.example.net")
    (dkim,) = header.dkim
    assert (dkim.header_d, dkim.header_s, dkim.header_a, dkim.header_b) == (
        "example.net",
        "sel",
        "rsa-sha256",
        "AbC/+dEf",
    )
    assert dkim.header_i is None
    (dmarc,) = header.dmarc
    assert dmarc.header_from == "example.net"
    assert dmarc.get("POLICY", "Dmarc") == "reject"
    assert [r.result for r in header.arc] == ["none"]
    assert header.other == ()


def test_by_method_preserves_order_and_duplicates() -> None:
    header = parse(
        "mx.example.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com;"
        " dkim=fail header.d=example.net; iprev=pass policy.iprev=192.0.2.1; foo=bar"
    )
    grouped = header.by_method()
    assert list(grouped) == ["dkim", "spf", "iprev", "foo"]
    assert [r.header_d for r in grouped["dkim"]] == ["example.com", "example.net"]
    assert [r.method for r in header.other] == ["iprev", "foo"]


# --- multiple header fields from a message ---------------------------------------------


def _fixture_block(name: str) -> tuple[AuthResHeader, ...]:
    return parse_all_authentication_results(parse_header_block((FIXTURES / name).read_bytes()))


def test_fixture_rfc8601_b3() -> None:
    # tests/fixtures/messages/plain-rfc8601-b3.eml (RFC 8601 B.3)
    (header,) = _fixture_block("plain-rfc8601-b3.eml")
    assert header.authserv_id == "example.com"
    assert header.spf[0].smtp_mailfrom == "example.net"
    assert (header.index, header.position) == (0, 0)


def test_fixture_rfc8601_b4_two_fields_in_order() -> None:
    # tests/fixtures/messages/plain-rfc8601-b4.eml (RFC 8601 B.4)
    raw = (FIXTURES / "plain-rfc8601-b4.eml").read_bytes()
    headers = parse_all_authentication_results(parse_header_block(raw))
    assert [h.index for h in headers] == [0, 1]
    assert [summary(h) for h in headers] == [
        [("auth", "pass"), ("spf", "pass")],
        [("iprev", "pass")],
    ]
    assert headers[0].position == 0
    assert raw[headers[1].position :].startswith(b"Authentication-Results: example.com; iprev")
    assert [h.authserv_id for h in headers] == ["example.com", "example.com"]


def test_fixture_rfc8617_arc_message() -> None:
    # tests/fixtures/messages/arc-rfc8617-appendix-b.eml (RFC 8617 appendix B): only the
    # Authentication-Results field is parsed, ARC-Authentication-Results is not.
    (header,) = _fixture_block("arc-rfc8617-appendix-b.eml")
    assert header.authserv_id == "clochette.example.org"
    assert summary(header) == [
        ("spf", "fail"),
        ("dkim", "fail"),
        ("dmarc", "fail"),
        ("arc", "pass"),
    ]
    # smtp.from is not a registered SPF property but it is kept as written.
    assert header.spf[0].get("smtp", "from") == "jqd@d1.example.net"
    assert codes(header) == []


def test_no_header_fields() -> None:
    block = parse_header_block(b"From: a@example.com\r\nSubject: x\r\n\r\n")
    assert parse_all_authentication_results(block) == ()


def test_header_name_case_insensitive() -> None:
    block = parse_header_block(b"authentication-results: example.com; spf=pass\r\n\r\n")
    (header,) = parse_all_authentication_results(block)
    assert summary(header) == [("spf", "pass")]


# --- malformed input --------------------------------------------------------------------

MALFORMED: list[tuple[str, str, list[str], str | None, list[tuple[str, str]]]] = [
    ("empty", "", [ar.MISSING_AUTHSERV_ID, ar.NO_RESINFO], None, []),
    ("whitespace_only", "  \t ", [ar.MISSING_AUTHSERV_ID, ar.NO_RESINFO], None, []),
    ("only_comment", "(nothing)", [ar.MISSING_AUTHSERV_ID, ar.NO_RESINFO], None, []),
    (
        "missing_authserv_id_semicolon",
        "; spf=pass smtp.mailfrom=example.com",
        [ar.MISSING_AUTHSERV_ID],
        None,
        [("spf", "pass")],
    ),
    (
        "missing_authserv_id_no_semicolon",
        "spf=pass smtp.mailfrom=example.com",
        [ar.MISSING_AUTHSERV_ID],
        None,
        [("spf", "pass")],
    ),
    ("empty_quoted_authserv_id", '""; spf=pass', [ar.MISSING_AUTHSERV_ID], None, [("spf", "pass")]),
    ("authserv_only", "example.com", [ar.NO_RESINFO], "example.com", []),
    (
        "authserv_tspecials",
        "ex@mple.com; spf=pass",
        [ar.INVALID_AUTHSERV_ID],
        "ex@mple.com",
        [("spf", "pass")],
    ),
    (
        "version_not_digit",
        "example.com v1; spf=pass",
        [ar.INVALID_VERSION],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "version_extra_tokens",
        "example.com 1 2; spf=pass",
        [ar.INVALID_VERSION],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "version_2",
        "example.com 2; spf=pass",
        [ar.UNSUPPORTED_VERSION],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "version_huge",
        "example.com " + "9" * 5000 + "; spf=pass",
        [ar.INVALID_VERSION],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "unterminated_quote",
        'example.com; dkim=pass reason="never closed header.d=example.com',
        [ar.UNTERMINATED_QUOTE],
        "example.com",
        [("dkim", "pass")],
    ),
    (
        "unterminated_quote_authserv",
        '"example.com; spf=pass',
        [ar.UNTERMINATED_QUOTE, ar.NO_RESINFO],
        "example.com; spf=pass",
        [],
    ),
    (
        "unterminated_comment",
        "example.com; spf=pass (open (nested) smtp.mailfrom=example.com",
        [ar.UNTERMINATED_COMMENT],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "comment_hides_semicolon",
        "example.com; spf=pass (a; b=c) smtp.mailfrom=example.com",
        [],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "escaped_paren_in_comment",
        r"example.com; spf=pass (a \) b) smtp.mailfrom=example.com",
        [],
        "example.com",
        [("spf", "pass")],
    ),
    ("missing_equals", "example.com; spf pass", [ar.MISSING_EQUALS], "example.com", []),
    (
        "missing_equals_keeps_others",
        "example.com; spf pass; dkim=pass",
        [ar.MISSING_EQUALS],
        "example.com",
        [("dkim", "pass")],
    ),
    ("empty_result_end", "example.com; spf=", [ar.EMPTY_RESULT], "example.com", []),
    (
        "empty_result_before_prop",
        "example.com; spf= smtp.mailfrom=example.com",
        [ar.EMPTY_RESULT],
        "example.com",
        [],
    ),
    (
        "empty_result_semicolon",
        "example.com; spf=; dkim=pass",
        [ar.EMPTY_RESULT],
        "example.com",
        [("dkim", "pass")],
    ),
    ("method_starts_with_equals", "example.com; =pass", [ar.INVALID_RESINFO], "example.com", []),
    ("method_quoted", 'example.com; "spf"=pass', [ar.INVALID_RESINFO], "example.com", []),
    (
        "semicolon_garbage",
        "example.com;;; spf=pass;;",
        [ar.EMPTY_RESINFO, ar.EMPTY_RESINFO, ar.EMPTY_RESINFO, ar.EMPTY_RESINFO],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "only_semicolons",
        "example.com;;",
        [ar.EMPTY_RESINFO, ar.EMPTY_RESINFO, ar.NO_RESINFO],
        "example.com",
        [],
    ),
    (
        "none_with_results",
        "example.com; none; spf=pass",
        [ar.UNEXPECTED_NONE],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "uppercase",
        "EXAMPLE.COM; SPF=PASS SMTP.MAILFROM=Example.COM",
        [],
        "EXAMPLE.COM",
        [("spf", "pass")],
    ),
    ("mixed_case_none", "example.com; NoNe", [], "example.com", []),
    (
        "unknown_method",
        "example.com; x-foo=pass",
        [ar.UNKNOWN_VALUE],
        "example.com",
        [("x-foo", "pass")],
    ),
    (
        "unknown_result",
        "example.com; spf=hardfail",
        [ar.UNKNOWN_VALUE],
        "example.com",
        [("spf", "hardfail")],
    ),
    (
        "iprev_none_unknown",
        "example.com; iprev=none",
        [ar.UNKNOWN_VALUE],
        "example.com",
        [("iprev", "none")],
    ),
    (
        "arc_neutral_unknown",
        "example.com; arc=neutral",
        [ar.UNKNOWN_VALUE],
        "example.com",
        [("arc", "neutral")],
    ),
    (
        "registered_method",
        "example.com; dkim-adsp=discard",
        [],
        "example.com",
        [("dkim-adsp", "discard")],
    ),
    (
        "invalid_keyword_result",
        "example.com; spf=pa_ss",
        [ar.INVALID_KEYWORD, ar.UNKNOWN_VALUE],
        "example.com",
        [("spf", "pa_ss")],
    ),
    (
        "quoted_result",
        'example.com; spf="pass"',
        [ar.INVALID_KEYWORD],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "invalid_method_version",
        "example.com; dkim/x=pass",
        [ar.INVALID_METHOD_VERSION],
        "example.com",
        [("dkim", "pass")],
    ),
    (
        "unknown_ptype",
        "example.com; spf=pass envelope.from=example.com",
        [ar.UNKNOWN_PTYPE],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "property_no_dot",
        "example.com; spf=pass mailfrom=example.com",
        [ar.INVALID_PROPERTY],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "property_empty_part",
        "example.com; spf=pass smtp.=example.com",
        [ar.INVALID_PROPERTY],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "property_missing_equals",
        "example.com; spf=pass smtp.mailfrom",
        [ar.MISSING_EQUALS],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "property_empty_value",
        "example.com; dkim=pass header.d= header.s=sel",
        [ar.EMPTY_PROPERTY_VALUE],
        "example.com",
        [("dkim", "pass")],
    ),
    (
        "property_value_end_empty",
        "example.com; dkim=pass header.d=",
        [ar.EMPTY_PROPERTY_VALUE],
        "example.com",
        [("dkim", "pass")],
    ),
    (
        "stray_equals",
        "example.com; dkim=pass = header.d=example.com",
        [ar.UNEXPECTED_TOKEN],
        "example.com",
        [("dkim", "pass")],
    ),
    (
        "stray_quoted",
        'example.com; dkim=pass "x" header.d=example.com',
        [ar.UNEXPECTED_TOKEN],
        "example.com",
        [("dkim", "pass")],
    ),
    (
        "duplicate_reason",
        'example.com; dkim=fail reason="a" reason="b"',
        [ar.DUPLICATE_REASON],
        "example.com",
        [("dkim", "fail")],
    ),
    (
        "conflicting_same_props",
        "example.com; spf=pass smtp.mailfrom=example.com; spf=fail smtp.mailfrom=EXAMPLE.com",
        [ar.CONFLICTING_RESULTS],
        "example.com",
        [("spf", "pass"), ("spf", "fail")],
    ),
    (
        "conflicting_no_props",
        "example.com; dmarc=pass; dmarc=fail; dmarc=none",
        [ar.CONFLICTING_RESULTS],
        "example.com",
        [("dmarc", "pass"), ("dmarc", "fail"), ("dmarc", "none")],
    ),
    (
        "duplicate_same_result_ok",
        "example.com; spf=pass smtp.mailfrom=example.com; spf=pass smtp.mailfrom=example.com",
        [],
        "example.com",
        [("spf", "pass"), ("spf", "pass")],
    ),
    (
        "rfc2047_authserv",
        "=?utf-8?q?example.com?=; spf=pass",
        [ar.ENCODED_WORD, ar.MISSING_AUTHSERV_ID, ar.INVALID_RESINFO],
        None,
        [("spf", "pass")],
    ),
    (
        "rfc2047_value",
        "example.com; spf=pass smtp.mailfrom=?utf-8?b?ZXhhbXBsZS5jb20=?=",
        [ar.ENCODED_WORD, ar.UNEXPECTED_TOKEN, ar.EMPTY_PROPERTY_VALUE, ar.INVALID_PROPERTY],
        "example.com",
        [("spf", "pass")],
    ),
    (
        "control_char_authserv",
        "exa\x01mple.com; spf=pass",
        [ar.INVALID_AUTHSERV_ID],
        "exa\x01mple.com",
        [("spf", "pass")],
    ),
    ("non_ascii_authserv", "exämple.com; spf=pass", [], "exämple.com", [("spf", "pass")]),
]


@pytest.mark.parametrize(
    ("value", "expected_codes", "authserv_id", "expected"),
    [c[1:] for c in MALFORMED],
    ids=[c[0] for c in MALFORMED],
)
def test_malformed(
    value: str,
    expected_codes: list[str],
    authserv_id: str | None,
    expected: list[tuple[str, str]],
) -> None:
    header = parse(value)
    assert codes(header) == expected_codes
    assert header.authserv_id == authserv_id
    assert summary(header) == expected
    assert header.raw == value
    for issue in header.issues:
        assert issue.term == ""  # never echo input
        assert 0 <= issue.position <= len(value)


def test_unknown_values_kept_and_flagged() -> None:
    header = parse("example.com; x-foo=pass; spf=hardfail; spf=pass")
    assert [r.unknown_value for r in header.resinfo] == [True, True, False]
    assert header.by_method()["spf"][0].result == "hardfail"


def test_uppercase_raw_kept() -> None:
    info = parse("example.com; SPF=PASS SMTP.MAILFROM=Example.COM").resinfo[0]
    assert (info.method, info.result) == ("spf", "pass")
    assert info.smtp_mailfrom == "Example.COM"
    assert info.raw == "SPF=PASS SMTP.MAILFROM=Example.COM"


def test_severities() -> None:
    header = parse('; spf pass; dkim=; x=y "open')
    severity = {i.code: i.severity for i in header.issues}
    assert severity[ar.MISSING_AUTHSERV_ID] == "error"
    assert severity[ar.MISSING_EQUALS] == "error"
    assert severity[ar.EMPTY_RESULT] == "error"
    assert severity[ar.UNTERMINATED_QUOTE] == "error"
    assert severity[ar.UNKNOWN_VALUE] == "warning"


# --- caps and hard errors ---------------------------------------------------------------


def _many_resinfo(count: int) -> str:
    return "example.com;" + ";".join(["spf=pass"] * count)


@pytest.mark.parametrize(
    ("count", "truncated"),
    [(MAX_RESINFO, False), (MAX_RESINFO + 1, True), (5_000, True)],
)
def test_max_resinfo_boundary(count: int, truncated: bool) -> None:
    header = parse(_many_resinfo(count))
    assert len(header.resinfo) == MAX_RESINFO
    assert header.truncated is truncated
    assert (ar.TOO_MANY_RESINFO in codes(header)) is truncated


def test_10k_resinfo_is_linear() -> None:
    value = "x;" + "a=b;" * 10_000
    started = time.perf_counter()
    header = parse(value)
    assert time.perf_counter() - started < 2.0
    assert header.truncated
    assert len(header.resinfo) == MAX_RESINFO
    # Every "a=b" is an unknown method: the issue cap is reached first and still reported.
    assert header.issues[-1].code == ar.TOO_MANY_ISSUES


@pytest.mark.parametrize(("extra", "capped"), [(0, False), (1, True)])
def test_max_issues_boundary(extra: int, capped: bool) -> None:
    # Each empty segment adds exactly one issue.
    header = parse("example.com; spf=pass" + ";" * (MAX_ISSUES + extra))
    assert len(header.issues) == MAX_ISSUES + extra
    assert (header.issues[-1].code == ar.TOO_MANY_ISSUES) is capped


@pytest.mark.parametrize(
    ("size", "raises"), [(MAX_AUTHRES_LENGTH, False), (MAX_AUTHRES_LENGTH + 1, True)]
)
def test_max_length_boundary(size: int, raises: bool) -> None:
    head = "example.com; spf=pass reason="
    value = head + "a" * (size - len(head))
    assert len(value) == size
    if raises:
        with pytest.raises(AuthResTooLarge) as exc:
            parse(value)
        assert exc.value.code == ar.AUTHRES_TOO_LARGE
        assert str(exc.value) == ar.AUTHRES_TOO_LARGE
    else:
        assert summary(parse(value)) == [("spf", "pass")]


@pytest.mark.parametrize(
    "value", ["example.com;\x00 spf=pass", "\x00", "example.com; spf=pass\x00"]
)
def test_nul_rejected_without_echo(value: str) -> None:
    with pytest.raises(InvalidAuthenticationResults) as exc:
        parse(value)
    assert isinstance(exc.value, AuthResParseError)
    assert exc.value.code == ar.NUL_BYTE
    assert "example" not in str(exc.value)


def test_non_str_rejected() -> None:
    with pytest.raises(TypeError):
        parse_authentication_results(b"example.com; spf=pass")  # type: ignore[arg-type]


def test_results_are_frozen() -> None:
    header = parse("example.com; spf=pass smtp.mailfrom=example.com")
    with pytest.raises(dataclasses.FrozenInstanceError):
        header.authserv_id = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        header.resinfo[0].result = "fail"  # type: ignore[misc]
