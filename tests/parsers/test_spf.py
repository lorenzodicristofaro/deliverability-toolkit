"""Table-driven tests for the SPF parser (RFC 7208). Pure: no DNS, no network."""

from __future__ import annotations

import ipaddress
import random
import time

import pytest

from app.parsers import spf
from app.parsers.spf import (
    MAX_RECORD_LENGTH,
    MAX_TERMS,
    ParseIssue,
    is_spf_record,
    parse_spf,
)

# --- is_spf_record -------------------------------------------------------------------

IS_SPF_CASES: list[tuple[str, bool]] = [
    ("v=spf1", True),
    ("v=spf1 -all", True),
    ("V=SPF1 -all", True),
    ("v=SpF1 include:example.com ~all", True),
    ("v=spf1 ", True),
    ("v=spf10 -all", False),
    ("v=spf1-all", False),
    ("v=spf1\t-all", False),
    (" v=spf1 -all", False),
    ("v=spf2.0/pra -all", False),
    ("spf1 -all", False),
    ("v=DMARC1; p=none", False),
    ('"v=spf1 -all"', False),
    ("", False),
    ("v=spf", False),
    ("v =spf1 -all", False),
]


@pytest.mark.parametrize(("text", "expected"), IS_SPF_CASES)
def test_is_spf_record(text: str, expected: bool) -> None:
    assert is_spf_record(text) is expected


# --- valid real-world shaped records ---------------------------------------------------

VALID_CASES: list[tuple[str, list[tuple[str, str | None]]]] = [
    ("v=spf1 -all", [("all", "-")]),
    ("v=spf1", []),
    ("v=spf1 ", []),
    (
        "v=spf1 include:_spf.example.com include:mail.example.net ~all",
        [("include", "+"), ("include", "+"), ("all", "~")],
    ),
    (
        "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.7 ip6:2001:db8::/32 ip6:2001:db8::1 ?all",
        [("ip4", "+"), ("ip4", "+"), ("ip6", "+"), ("ip6", "+"), ("all", "?")],
    ),
    ("v=spf1 a mx -all", [("a", "+"), ("mx", "+"), ("all", "-")]),
    ("v=spf1 +a +mx ~all", [("a", "+"), ("mx", "+"), ("all", "~")]),
    (
        "v=spf1 a:mail.example.com/28 mx:example.com//64 a/24//64 -all",
        [("a", "+"), ("mx", "+"), ("a", "+"), ("all", "-")],
    ),
    ("v=spf1 ptr -all", [("ptr", "+"), ("all", "-")]),
    ("v=spf1 ptr:example.com -all", [("ptr", "+"), ("all", "-")]),
    ("v=spf1 redirect=_spf.example.com", [("redirect", None)]),
    ("v=spf1 mx -all exp=explain._spf.example.com", [("mx", "+"), ("all", "-"), ("exp", None)]),
    ("v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all", [("exists", "+"), ("all", "-")]),
    ("v=spf1 include:%{d}.spf.example.com -all", [("include", "+"), ("all", "-")]),
    ("v=spf1 a:example.com. -all", [("a", "+"), ("all", "-")]),
    ("v=spf1 ip4:0.0.0.0/0 -all", [("ip4", "+"), ("all", "-")]),
    ("v=spf1 ip6:::/0 ip6:::ffff:192.0.2.1 -all", [("ip6", "+"), ("ip6", "+"), ("all", "-")]),
    ("v=spf1 a:xn--bcher-kva.example -all", [("a", "+"), ("all", "-")]),
    ("v=spf1 a:host.example.co-uk -all", [("a", "+"), ("all", "-")]),
    ("v=spf1 exists:%{i}._spf.example.com -all", [("exists", "+"), ("all", "-")]),
    ("v=spf1 exists:%{I}._spf.example.com -all", [("exists", "+"), ("all", "-")]),
    ("v=spf1 exists:%{d127r.-}.example.com -all", [("exists", "+"), ("all", "-")]),
    ("v=spf1 exists:a%%b%_c%-d.example.com -all", [("exists", "+"), ("all", "-")]),
    ("v=spf1 a:example.com/32//128 -all", [("a", "+"), ("all", "-")]),
    ("v=spf1 a:example.com/0//0 -all", [("a", "+"), ("all", "-")]),
    ("v=spf1 mx:%{d}", [("mx", "+")]),
]


@pytest.mark.parametrize(("text", "expected"), VALID_CASES)
def test_valid_records(text: str, expected: list[tuple[str, str | None]]) -> None:
    rec = parse_spf(text)
    errors = [i for i in rec.issues if i.severity == "error"]
    assert errors == []
    assert rec.is_valid
    assert rec.version == "v=spf1"
    assert [(t.name, t.qualifier) for t in rec.terms] == expected
    assert all(t.valid for t in rec.terms)


def test_term_details() -> None:
    rec = parse_spf(
        "v=spf1 ip4:192.0.2.5/24 ip6:2001:db8::1 a:example.com/24//64 mx//48 "
        "include:_spf.example.com -all redirect=other.example.com"
    )
    ip4, ip6, a, mx, inc, all_, redir = rec.terms
    assert ip4.network == ipaddress.ip_network("192.0.2.0/24")
    assert (ip4.value, ip4.cidr4) == ("192.0.2.5/24", 24)
    assert ip6.network == ipaddress.ip_network("2001:db8::1/128")
    assert ip6.cidr6 is None
    assert (a.value, a.cidr4, a.cidr6) == ("example.com", 24, 64)
    assert (mx.value, mx.cidr4, mx.cidr6) == (None, None, 48)
    assert (inc.kind, inc.value, inc.position) == ("mechanism", "_spf.example.com", 68)
    assert (all_.qualifier, all_.kind) == ("-", "mechanism")
    assert (redir.kind, redir.name, redir.qualifier) == ("modifier", "redirect", None)
    assert rec.redirect is redir
    assert rec.exp is None
    assert len(rec.mechanisms) == 6 and len(rec.modifiers) == 1
    assert not rec.has_macro


@pytest.mark.parametrize(
    ("text", "has_macro"),
    [
        ("v=spf1 include:example.com -all", False),
        ("v=spf1 exists:%{i}.example.com -all", True),
        ("v=spf1 a:%{d} -all", True),
        ("v=spf1 redirect=%{d}.spf.example.com", True),
        ("v=spf1 foo=%{s}", True),
        ("v=spf1 exists:x%%y.example.com", True),
    ],
)
def test_has_macro(text: str, has_macro: bool) -> None:
    rec = parse_spf(text)
    assert rec.has_macro is has_macro
    # macros are recognised but never expanded
    assert all("%" in (t.value or "") for t in rec.terms if t.has_macro)


def test_parse_issue_shape_is_generic() -> None:
    issue = ParseIssue("bad_ip", "ip4:x", 7)
    assert (issue.code, issue.term, issue.position, issue.severity) == (
        "bad_ip",
        "ip4:x",
        7,
        "error",
    )


# --- malformed input -------------------------------------------------------------------

# (record, expected issue code, expected severity)
MALFORMED_CASES: list[tuple[str, str, str]] = [
    # empty / version
    ("", spf.EMPTY_RECORD, "error"),
    ("   ", spf.EMPTY_RECORD, "error"),
    ("include:example.com -all", spf.MISSING_VERSION, "error"),
    ("spf1 -all", spf.MISSING_VERSION, "error"),
    ('"v=spf1 -all"', spf.MISSING_VERSION, "error"),
    ("v=spf10 -all", spf.BAD_VERSION, "error"),
    ("v=spf1-all", spf.BAD_VERSION, "error"),
    ("v=spf2.0/pra -all", spf.BAD_VERSION, "error"),
    ("v=spf1.0 -all", spf.BAD_VERSION, "error"),
    ("V=SPF1 -all", spf.VERSION_CASE, "warning"),
    (" v=spf1 -all", spf.LEADING_WHITESPACE, "error"),
    ("v=spf1 a v=spf1 -all", spf.DUPLICATE_VERSION, "warning"),
    # whitespace and characters
    ("v=spf1  -all", spf.EXTRA_WHITESPACE, "warning"),
    ("v=spf1\t-all", spf.INVALID_WHITESPACE, "error"),
    ("v=spf1 a\r\n-all", spf.INVALID_WHITESPACE, "error"),
    ("v=spf1 -all", spf.NON_ASCII, "error"),
    ("v=spf1 include:exämple.com -all", spf.NON_ASCII, "error"),
    ("v=spf1 a:example.com –all", spf.NON_ASCII, "error"),
    ("v=spf1 a\x00 -all", spf.CONTROL_CHARACTER, "error"),
    ("v=spf1 a\x7f -all", spf.CONTROL_CHARACTER, "error"),
    # mechanisms
    ("v=spf1 allow", spf.UNKNOWN_MECHANISM, "error"),
    ("v=spf1 ip:192.0.2.1 -all", spf.UNKNOWN_MECHANISM, "error"),
    ("v=spf1 include_spf.example.com -all", spf.TRAILING_GARBAGE, "error"),
    ("v=spf1 redirect:example.com", spf.UNKNOWN_MECHANISM, "error"),
    ("v=spf1 -all.", spf.TRAILING_GARBAGE, "error"),
    ("v=spf1 -all;", spf.TRAILING_GARBAGE, "error"),
    ('v=spf1 -all"', spf.TRAILING_GARBAGE, "error"),
    ("v=spf1 mx, -all", spf.TRAILING_GARBAGE, "error"),
    ("v=spf1 --all", spf.INVALID_TERM, "error"),
    ("v=spf1 + -all", spf.INVALID_TERM, "error"),
    ("v=spf1 =foo -all", spf.INVALID_TERM, "error"),
    ("v=spf1 all:example.com", spf.UNEXPECTED_ARGUMENT, "error"),
    ("v=spf1 include/24 -all", spf.UNEXPECTED_ARGUMENT, "error"),
    ("v=spf1 ptr/24 -all", spf.UNEXPECTED_ARGUMENT, "error"),
    ("v=spf1 INCLUDE:example.com -all", spf.UPPERCASE_NAME, "warning"),
    ("v=spf1 -All", spf.UPPERCASE_NAME, "warning"),
    # empty values
    ("v=spf1 include -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 include: -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 exists: -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 a: -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 ptr: -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 ip4 -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 ip6: -all", spf.EMPTY_VALUE, "error"),
    ("v=spf1 redirect=", spf.EMPTY_VALUE, "error"),
    ("v=spf1 -all exp=", spf.EMPTY_VALUE, "error"),
    # IPs
    ("v=spf1 ip4:192.0.2 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip4:192.0.2.256 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip4:192.0.2.01 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip4:2001:db8::1 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip4:example.com -all", spf.BAD_IP, "error"),
    ("v=spf1 ip4:１.2.3.4 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip6:192.0.2.1 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip6:2001:db8:::1 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip6:fe80::1%eth0 -all", spf.BAD_IP, "error"),
    ("v=spf1 ip4/24 -all", spf.BAD_IP, "error"),
    # CIDR
    ("v=spf1 ip4:192.0.2.0/33 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip4:192.0.2.0/ -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip4:192.0.2.0/024 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip4:192.0.2.0/-1 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip4:192.0.2.0/24/8 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip4:192.0.2.0/2² -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip6:2001:db8::/129 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 ip6:2001:db8::/0128 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 a/33 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 a//129 -all", spf.BAD_CIDR, "error"),
    ("v=spf1 mx:example.com/24//abc -all", spf.BAD_CIDR, "error"),
    ("v=spf1 a:example.com/ -all", spf.BAD_CIDR, "error"),
    ("v=spf1 a:example.com///64 -all", spf.BAD_CIDR, "error"),
    # macros
    ("v=spf1 exists:%(ir).sbl.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{ir.sbl.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{x}.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{}.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{d0}.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{d2rr}.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{d2;}.example.org -all", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:example.org% -all", spf.BAD_MACRO, "error"),
    ("v=spf1 redirect=%x.example.com", spf.BAD_MACRO, "error"),
    ("v=spf1 foo=%{z}", spf.BAD_MACRO, "error"),
    ("v=spf1 exists:%{c}.example.org -all", spf.MACRO_EXP_ONLY, "error"),
    ("v=spf1 -all exp=%{t}.example.org", spf.MACRO_EXP_ONLY, "error"),
    # domain-spec
    ("v=spf1 include:example -all", spf.INVALID_DOMAIN, "error"),
    ("v=spf1 include:example.123 -all", spf.INVALID_DOMAIN, "error"),
    ("v=spf1 include:example.com- -all", spf.INVALID_DOMAIN, "error"),
    ("v=spf1 a:example.c_m -all", spf.INVALID_DOMAIN, "error"),
    ("v=spf1 redirect=example.com..", spf.INVALID_DOMAIN, "error"),
    ("v=spf1 include:example.com/24 -all", spf.INVALID_DOMAIN, "error"),
    # modifiers
    ("v=spf1 redirect=a.example.com redirect=b.example.com", spf.DUPLICATE_MODIFIER, "error"),
    ("v=spf1 -all exp=a.example.com exp=b.example.com", spf.DUPLICATE_MODIFIER, "error"),
    ("v=spf1 -all REDIRECT=a.example.com", spf.REDIRECT_WITH_ALL, "warning"),
    ("v=spf1 redirect=a.example.com ~all", spf.REDIRECT_WITH_ALL, "warning"),
    ("v=spf1 redirct=example.com", spf.UNKNOWN_MODIFIER, "warning"),
    ("v=spf1 ip4=192.0.2.1 -all", spf.MECHANISM_AS_MODIFIER, "warning"),
    ("v=spf1 Exp=x.example.com -all", spf.UPPERCASE_NAME, "warning"),
    # ordering
    ("v=spf1 -all include:example.com", spf.TERM_AFTER_ALL, "warning"),
    ("v=spf1 ~all -all", spf.TERM_AFTER_ALL, "warning"),
]


@pytest.mark.parametrize(("text", "code", "severity"), MALFORMED_CASES)
def test_malformed(text: str, code: str, severity: str) -> None:
    rec = parse_spf(text)
    matches = [i for i in rec.issues if i.code == code]
    assert matches, f"{code} not in {rec.issue_codes()}"
    assert all(i.severity == severity for i in matches)
    for i in rec.issues:
        assert i.code == i.code.lower()
        assert 0 <= i.position <= len(text)
    if severity == "error":
        assert not rec.is_valid


def test_malformed_table_is_large_enough() -> None:
    assert len([c for c in MALFORMED_CASES if c[2] == "error"]) >= 30


@pytest.mark.parametrize(
    ("text", "code", "position"),
    [
        ("v=spf1 a ipv4:192.0.2.1", spf.UNKNOWN_MECHANISM, 9),
        ("v=spf1 a\t-all", spf.INVALID_WHITESPACE, 8),
        ("v=spf1 a:exämple.com", spf.NON_ASCII, 11),
        ("v=spf1 exists:a.%(ir).example.org", spf.BAD_MACRO, 16),
        ("v=spf1 -all exp=x.example.com exp=y.example.com", spf.DUPLICATE_MODIFIER, 30),
    ],
)
def test_issue_positions(text: str, code: str, position: int) -> None:
    rec = parse_spf(text)
    assert [i.position for i in rec.issues if i.code == code] == [position]


def test_invalid_term_marked_but_others_kept() -> None:
    rec = parse_spf("v=spf1 include:example.com ip4:999.0.0.1 -all")
    assert [t.valid for t in rec.terms] == [True, False, True]
    assert [t.name for t in rec.terms] == ["include", "ip4", "all"]


def test_duplicate_modifier_marks_second_term_invalid() -> None:
    rec = parse_spf("v=spf1 redirect=a.example.com redirect=b.example.com")
    assert [t.valid for t in rec.terms] == [True, False]
    assert rec.redirect is not None and rec.redirect.value == "a.example.com"


def test_unknown_modifier_kept_and_record_valid() -> None:
    rec = parse_spf("v=spf1 -all foo.bar=baz x-y_z=")
    assert rec.is_valid
    assert [(t.kind, t.name, t.value) for t in rec.modifiers] == [
        ("modifier", "foo.bar", "baz"),
        ("modifier", "x-y_z", ""),
    ]


def test_mixed_case_accepted() -> None:
    rec = parse_spf("V=Spf1 +MX Ip4:192.0.2.0/24 Include:Example.COM ReDiReCt=Example.Org")
    assert rec.is_valid
    assert [t.name for t in rec.terms] == ["mx", "ip4", "include", "redirect"]
    assert rec.version == "V=Spf1"


# --- resource bounds ---------------------------------------------------------------------


def test_oversized_input_is_truncated() -> None:
    text = "v=spf1 " + "a:" + "x" * 10_000 + ".example.com -all"
    rec = parse_spf(text)
    assert rec.truncated
    assert spf.RECORD_TOO_LONG in rec.issue_codes()
    assert rec.raw == text
    assert sum(len(t.raw) for t in rec.terms) <= MAX_RECORD_LENGTH


def test_too_many_terms_is_truncated() -> None:
    text = "v=spf1 " + " ".join(["a"] * (MAX_TERMS + 50)) + " -all"
    rec = parse_spf(text)
    assert rec.truncated
    assert len(rec.terms) == MAX_TERMS
    assert spf.TOO_MANY_TERMS in rec.issue_codes()
    assert not rec.is_valid


def test_exactly_max_terms_is_not_truncated() -> None:
    rec = parse_spf("v=spf1 " + " ".join(["a"] * MAX_TERMS))
    assert not rec.truncated
    assert rec.is_valid


def test_non_str_input_does_not_raise() -> None:
    rec = parse_spf(b"v=spf1 -all")  # type: ignore[arg-type]
    assert not rec.is_valid
    assert is_spf_record(None) is False  # type: ignore[arg-type]


_ADVERSARIAL = [
    "v=spf1 " + "%" * 4000,
    "v=spf1 exists:" + "%{" * 2000,
    "v=spf1 a:" + "/" * 4000,
    "v=spf1 a" + "/1" * 2000,
    "v=spf1 " + "a=" * 2000,
    "v=spf1 " + " " * 4000,
    "v=spf1 " + "\t" * 4000,
    "v=spf1 ip6:" + ":" * 4000,
    "v=spf1 ip4:" + "1" * 4000,
    "v=spf1 exists:" + "%{d" + "1" * 4000 + "}",
    "v=spf1 " + "-" * 4000,
    "v=spf1 " + "é" * 4000,
    "v=spf1 " + "a " * 50_000,
]


@pytest.mark.parametrize("text", _ADVERSARIAL, ids=range(len(_ADVERSARIAL)))
def test_adversarial_inputs_are_fast(text: str) -> None:
    start = time.perf_counter()
    rec = parse_spf(text)
    assert time.perf_counter() - start < 0.5
    assert isinstance(rec.issues, tuple)


def test_fuzz_random_inputs_never_raise() -> None:
    rng = random.Random(7208)
    alphabet = "v=spf1 aimxptr46:/.%{}+-~?_=,\t\x00é" + "0123456789"
    start = time.perf_counter()
    for _ in range(2000):
        n = rng.randint(0, 300)
        if rng.random() < 0.5:
            text = "".join(rng.choice(alphabet) for _ in range(n))
        else:
            text = rng.randbytes(n).decode("latin-1")
        rec = parse_spf(text)
        assert all(isinstance(i, ParseIssue) for i in rec.issues)
        assert len(rec.terms) <= MAX_TERMS
        is_spf_record(text)
    long_text = "".join(rng.choice(alphabet) for _ in range(200_000))
    parse_spf(long_text)
    assert time.perf_counter() - start < 5.0
