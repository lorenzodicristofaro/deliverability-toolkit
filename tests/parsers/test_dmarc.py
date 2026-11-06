"""Table-driven tests for the DMARC parser (RFC 7489 sections 6.3, 6.4). No DNS, no network."""

from __future__ import annotations

import random
import time

import pytest

from app.parsers import dmarc, spf
from app.parsers.dmarc import (
    MAX_RECORD_LENGTH,
    MAX_TAGS,
    MAX_URIS,
    is_dmarc_record,
    parse_dmarc,
)

# --- is_dmarc_record -----------------------------------------------------------------

IS_DMARC_CASES: list[tuple[str, bool]] = [
    ("v=DMARC1; p=none", True),
    ("v=DMARC1;p=reject", True),
    ("v=DMARC1", True),  # section 7.1 authorization record
    ("v = DMARC1 ; p=none", True),
    ("v\t=\tDMARC1\t;", True),
    ("V=DMARC1; p=none", True),  # ABNF quoted "v" is case-insensitive
    ("v=dmarc1; p=none", False),  # %x literal, MUST match precisely
    ("v=DMARC2; p=none", False),
    ("v=DMARC10; p=none", False),
    ("v=DMARC1 p=none", False),
    (" v=DMARC1; p=none", False),
    ("p=none; v=DMARC1", False),
    ("v=spf1 -all", False),
    ("", False),
    ("v=", False),
    ("v", False),
    ('"v=DMARC1; p=none"', False),
]


@pytest.mark.parametrize(("text", "expected"), IS_DMARC_CASES)
def test_is_dmarc_record(text: str, expected: bool) -> None:
    assert is_dmarc_record(text) is expected


# --- valid real-world shaped records ---------------------------------------------------

VALID_CASES: list[tuple[str, dict[str, object]]] = [
    ("v=DMARC1; p=none", {"p": "none"}),
    ("v=DMARC1; p=none;", {"p": "none"}),
    ("v=DMARC1; p=none; ", {"p": "none"}),
    ("v=DMARC1;p=reject;sp=quarantine", {"p": "reject", "sp": "quarantine"}),
    (
        "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com",
        {"p": "none", "rua_domains": ("example.com",)},
    ),
    (
        "v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,"
        "mailto:tld-test@thirdparty.example.net!10m;"
        " ruf=mailto:auth-reports@thirdparty.example.net;"
        " pct=25",
        {
            "p": "quarantine",
            "pct": 25,
            "rua_domains": ("example.com", "thirdparty.example.net"),
            "ruf_domains": ("thirdparty.example.net",),
        },
    ),
    (
        "v=DMARC1; p=reject; aspf=r; rua=mailto:dmarc-feedback@example.com",
        {"p": "reject", "aspf": "r"},
    ),
    (
        "v=DMARC1; p=reject; adkim=s; aspf=s; fo=1:d:s; rf=afrf; ri=3600; pct=100",
        {"adkim": "s", "aspf": "s", "fo": ("1", "d", "s"), "rf": ("afrf",), "ri": 3600, "pct": 100},
    ),
    ("v = DMARC1 ; p = none ; pct = 0", {"p": "none", "pct": 0}),
    ("v=DMARC1;\tp=none;\tfo=0 : 1", {"fo": ("0", "1")}),
    (
        "v=DMARC1; p=none; rua=mailto:a@example.com , mailto:b@Example.ORG",
        {"rua_domains": ("example.com", "example.org")},
    ),
    ("v=DMARC1; p=none; rua=MAILTO:a@example.com", {"rua_domains": ("example.com",)}),
    (
        "v=DMARC1; p=none; rua=mailto:a@xn--bcher-kva.example",
        {"rua_domains": ("xn--bcher-kva.example",)},
    ),
    (
        "v=DMARC1; p=none; rua=mailto:a%2Bdmarc@example.com?subject=dmarc",
        {"rua_domains": ("example.com",)},
    ),
    ("v=DMARC1; p=none; ri=4294967295", {"ri": 4294967295}),
    ("v=DMARC1; p=none; pct=007", {"pct": 7}),
]


@pytest.mark.parametrize(("text", "expected"), VALID_CASES)
def test_valid_records(text: str, expected: dict[str, object]) -> None:
    rec = parse_dmarc(text)
    assert rec.is_valid, rec.issues
    assert rec.issues == ()
    assert rec.version == "DMARC1"
    for key, want in expected.items():
        if key == "rua_domains":
            assert tuple(u.domain for u in rec.rua) == want
        elif key == "ruf_domains":
            assert tuple(u.domain for u in rec.ruf) == want
        else:
            assert getattr(rec, key) == want, key


def test_defaults_are_none_when_absent() -> None:
    rec = parse_dmarc("v=DMARC1; p=none")
    assert (rec.sp, rec.pct, rec.adkim, rec.aspf, rec.ri) == (None, None, None, None, None)
    assert rec.fo == () and rec.rf == () and rec.rua == () and rec.ruf == ()


# --- size suffix ---------------------------------------------------------------------

SIZE_CASES: list[tuple[str, int]] = [
    ("mailto:a@example.com!0", 0),
    ("mailto:a@example.com!500", 500),
    ("mailto:a@example.com!10k", 10 * 2**10),
    ("mailto:a@example.com!10m", 10 * 2**20),
    ("mailto:a@example.com!1g", 2**30),
    ("mailto:a@example.com!2t", 2 * 2**40),
    ("mailto:a@example.com!50M", 50 * 2**20),
    ("mailto:a@example.com!18446744073709551615", 2**64 - 1),
]


@pytest.mark.parametrize(("uri", "size"), SIZE_CASES)
def test_size_suffix(uri: str, size: int) -> None:
    rec = parse_dmarc(f"v=DMARC1; p=none; rua={uri}")
    assert rec.is_valid, rec.issues
    assert rec.rua[0].size_limit == size
    assert rec.rua[0].uri == uri.partition("!")[0]


# --- malformed records ------------------------------------------------------------------

MALFORMED_CASES: list[tuple[str, str, str]] = [
    # empty / bounds / characters
    ("", "empty_record", "error"),
    ("   ", "empty_record", "error"),
    ("\t", "empty_record", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@exämple.com", "non_ascii", "error"),
    ("v=DMARC1; p=nöne", "non_ascii", "error"),
    ("v=DMARC1; p=none\x00", "control_character", "error"),
    ("v=DMARC1;\np=none", "control_character", "error"),
    (" v=DMARC1; p=none", "leading_whitespace", "error"),
    # version
    ("p=none", "missing_version", "error"),
    ("p=none; rua=mailto:a@example.com", "missing_version", "error"),
    ("p=none; v=DMARC1", "version_not_first", "error"),
    ("v=dmarc1; p=none", "version_case", "error"),
    ("v=Dmarc1; p=none", "version_case", "error"),
    ("v=DMARC2; p=none", "bad_version", "error"),
    ("v=DMARC; p=none", "bad_version", "error"),
    ("v=; p=none", "bad_version", "error"),
    ("v=DMARC1 p=none", "bad_version", "error"),
    ("v=spf1 -all", "bad_version", "error"),
    ("v=DMARC1; v=DMARC1; p=none", "duplicate_tag", "error"),
    # policy
    ("v=DMARC1", "missing_policy", "error"),
    ("v=DMARC1; rua=mailto:a@example.com", "missing_policy", "error"),
    ("v=DMARC1; p=", "empty_value", "error"),
    ("v=DMARC1; p=block", "invalid_policy", "error"),
    ("v=DMARC1; p=none reject", "invalid_policy", "error"),
    ('v=DMARC1; p="none"', "invalid_policy", "error"),
    ("v=DMARC1; p=REJECT", "uppercase_value", "warning"),
    ("v=DMARC1; p=none; sp=allow", "invalid_policy", "error"),
    ("v=DMARC1; p=none; sp=Quarantine", "uppercase_value", "warning"),
    ("v=DMARC1; rua=mailto:a@example.com; p=none", "policy_not_second", "warning"),
    ("v=DMARC1; p=none; p=reject", "duplicate_tag", "error"),
    ("v=DMARC1; p=none; P=reject", "duplicate_tag", "error"),
    # pct
    ("v=DMARC1; p=none; pct=101", "pct_out_of_range", "error"),
    ("v=DMARC1; p=none; pct=1000", "pct_out_of_range", "error"),
    ("v=DMARC1; p=none; pct=-1", "invalid_pct", "error"),
    ("v=DMARC1; p=none; pct=50%", "invalid_pct", "error"),
    ("v=DMARC1; p=none; pct=abc", "invalid_pct", "error"),
    ("v=DMARC1; p=none; pct=5.5", "invalid_pct", "error"),
    ("v=DMARC1; p=none; pct=", "empty_value", "error"),
    ("v=DMARC1; p=none; pct=١٠", "invalid_pct", "error"),  # Arabic-Indic digits
    # alignment, fo, rf, ri
    ("v=DMARC1; p=none; adkim=strict", "invalid_alignment", "error"),
    ("v=DMARC1; p=none; aspf=x", "invalid_alignment", "error"),
    ("v=DMARC1; p=none; adkim=S", "uppercase_value", "warning"),
    ("v=DMARC1; p=none; fo=2", "invalid_fo", "error"),
    ("v=DMARC1; p=none; fo=0:", "invalid_fo", "error"),
    ("v=DMARC1; p=none; fo=0,1", "invalid_fo", "error"),
    ("v=DMARC1; p=none; fo=D", "uppercase_value", "warning"),
    ("v=DMARC1; p=none; rf=iodef", "unknown_report_format", "warning"),
    ("v=DMARC1; p=none; rf=afrf:", "invalid_rf", "error"),
    ("v=DMARC1; p=none; rf=af_rf", "invalid_rf", "error"),
    ("v=DMARC1; p=none; rf=afrf-", "invalid_rf", "error"),
    ("v=DMARC1; p=none; ri=1h", "invalid_interval", "error"),
    ("v=DMARC1; p=none; ri=4294967296", "interval_out_of_range", "error"),
    ("v=DMARC1; p=none; ri=99999999999999999999999", "interval_out_of_range", "error"),
    # URIs
    ("v=DMARC1; p=none; rua=", "empty_value", "error"),
    ("v=DMARC1; p=none; rua=dmarc@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=https://example.com/dmarc", "unsupported_uri_scheme", "warning"),
    ("v=DMARC1; p=none; rua=http://example.com/report", "unsupported_uri_scheme", "warning"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com,", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=,mailto:a@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:a b@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:<a@example.com>", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:a%2@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:a%FF@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=1mailto:a@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=:a@example.com", "invalid_uri", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@", "invalid_uri_domain", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@localhost", "invalid_uri_domain", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@[192.0.2.1]", "invalid_uri_domain", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@exa_mple.com", "invalid_uri_domain", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@-example.com", "invalid_uri_domain", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@xn--zz.example", "invalid_uri_domain", "error"),
    (
        "v=DMARC1; p=none; ruf=mailto:a@example.com%2Cb@example.org",
        "multiple_mailto_addresses",
        "warning",
    ),
    # size suffix
    ("v=DMARC1; p=none; rua=mailto:a@example.com!", "bad_size_suffix", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com!m", "bad_size_suffix", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com!10x", "bad_size_suffix", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com!10mb", "bad_size_suffix", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com!-5", "bad_size_suffix", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com!1!2", "bad_size_suffix", "error"),
    ("v=DMARC1; p=none; rua=mailto:a@example.com!18446744073709551616", "bad_size_suffix", "error"),
    # tag syntax
    ("v=DMARC1;; p=none", "empty_tag", "error"),
    ("v=DMARC1; p=none;;", "empty_tag", "error"),
    ("v=DMARC1; p=none; ;", "empty_tag", "error"),
    (";v=DMARC1; p=none", "empty_tag", "error"),
    ("v=DMARC1; p=none; pct", "invalid_tag", "error"),
    ("v=DMARC1; p=none; =none", "invalid_tag", "error"),
    ("v=DMARC1; p=none; 1x=y", "invalid_tag", "error"),
    ("v=DMARC1; p=none; p-x=y", "invalid_tag", "error"),
    ("v=DMARC1; p=none; foo=bar", "unknown_tag", "warning"),
    ("v=DMARC1; p=none; np=reject", "unknown_tag", "warning"),  # DMARCbis, unverified
    ("v=DMARC1; P=none", "uppercase_tag_name", "warning"),
    ("v=DMARC1; p=none; RUA=mailto:a@example.com", "uppercase_tag_name", "warning"),
]


@pytest.mark.parametrize(("text", "code", "severity"), MALFORMED_CASES)
def test_malformed(text: str, code: str, severity: str) -> None:
    rec = parse_dmarc(text)
    matches = [i for i in rec.issues if i.code == code]
    assert matches, rec.issues
    assert matches[0].severity == severity
    if severity == "error":
        assert not rec.is_valid


def test_malformed_table_is_large_enough() -> None:
    assert len(MALFORMED_CASES) >= 30


def test_issue_shape_is_shared_with_spf() -> None:
    assert dmarc.ParseIssue is spf.ParseIssue
    issue = parse_dmarc("v=DMARC1; p=bad").issues[0]
    assert (issue.code, issue.term, issue.position, issue.severity) == (
        "invalid_policy",
        "p=bad",
        10,
        "error",
    )


POSITION_CASES: list[tuple[str, str, int]] = [
    ("v=DMARC1;; p=none", "empty_tag", 9),
    ("v=DMARC1; p=none; pct=200", "pct_out_of_range", 18),
    ("v=DMARC1;   p=x", "invalid_policy", 12),
    ("v=DMARC1; p=none; rua=mailto:a@example.com, ftp://x", "unsupported_uri_scheme", 44),
    ("v=DMARC1; p=nöne", "non_ascii", 13),
    ("p=none; v=DMARC1", "version_not_first", 8),
]


@pytest.mark.parametrize(("text", "code", "position"), POSITION_CASES)
def test_issue_positions(text: str, code: str, position: int) -> None:
    rec = parse_dmarc(text)
    assert [i.position for i in rec.issues if i.code == code][0] == position


# --- whitespace variants ----------------------------------------------------------------

WHITESPACE_VARIANTS = [
    "v=DMARC1;p=reject;pct=50",
    "v=DMARC1; p=reject; pct=50",
    "v=DMARC1 ; p=reject ; pct=50",
    "v = DMARC1 ; p = reject ; pct = 50 ;",
    "v=DMARC1;\tp=reject;\tpct=50\t",
    "v=DMARC1;  p=reject  ;  pct=50  ;  ",
]


@pytest.mark.parametrize("text", WHITESPACE_VARIANTS)
def test_whitespace_variants(text: str) -> None:
    rec = parse_dmarc(text)
    assert rec.is_valid and rec.issues == ()
    assert (rec.p, rec.pct) == ("reject", 50)


# --- semantics ------------------------------------------------------------------------


def test_unknown_tags_kept_and_record_valid() -> None:
    rec = parse_dmarc("v=DMARC1; p=none; psd=y; t=n; x_custom=some value")
    assert rec.is_valid
    names = [(t.name, t.known) for t in rec.tags]
    assert names == [("v", True), ("p", True), ("psd", False), ("t", False), ("x_custom", False)]
    tag = rec.tag("x_custom")
    assert tag is not None and tag.value == "some value"


def test_duplicate_keeps_first_and_marks_second_invalid() -> None:
    rec = parse_dmarc("v=DMARC1; p=none; p=reject")
    assert rec.p == "none"
    assert [t.valid for t in rec.tags if t.name == "p"] == [True, False]


def test_duplicate_rua_does_not_add_uris() -> None:
    rec = parse_dmarc("v=DMARC1; p=none; rua=mailto:a@example.com; rua=mailto:b@example.org")
    assert [u.domain for u in rec.rua] == ["example.com"]


def test_invalid_values_read_as_none() -> None:
    rec = parse_dmarc("v=DMARC1; p=block; pct=200; adkim=x; fo=9; ri=z")
    assert (rec.p, rec.pct, rec.adkim, rec.fo, rec.ri) == (None, None, None, (), None)


def test_uppercase_values_normalised() -> None:
    rec = parse_dmarc("v=DMARC1; P=REJECT; ADKIM=S; fo=D:S")
    assert (rec.p, rec.adkim, rec.fo) == ("reject", "s", ("d", "s"))
    assert all(i.severity == "warning" for i in rec.issues)
    assert rec.is_valid


def test_mixed_uri_list_keeps_valid_entries() -> None:
    rec = parse_dmarc("v=DMARC1; p=none; rua=mailto:a@example.com,bogus,https://r.example/x")
    assert [(u.scheme, u.valid, u.domain) for u in rec.rua] == [
        ("mailto", True, "example.com"),
        ("", False, None),
        ("https", True, None),
    ]


def test_version_none_when_not_first() -> None:
    assert parse_dmarc("p=none; v=DMARC1").version is None
    assert parse_dmarc("v=dmarc1; p=none").version is None


def test_policy_not_second_still_parses_policy() -> None:
    rec = parse_dmarc("v=DMARC1; pct=50; p=quarantine")
    assert rec.p == "quarantine"
    assert rec.is_valid


# --- bounds -----------------------------------------------------------------------------


def test_oversized_input_is_truncated() -> None:
    text = "v=DMARC1; p=none; x=" + "a" * (MAX_RECORD_LENGTH * 2)
    rec = parse_dmarc(text)
    assert rec.truncated
    assert rec.raw == text
    assert "record_too_long" in rec.issue_codes()
    assert not rec.is_valid


def test_too_many_tags_is_truncated() -> None:
    text = "v=DMARC1; p=none" + "".join(f"; x{i}=y" for i in range(MAX_TAGS))
    rec = parse_dmarc(text)
    assert rec.truncated
    assert len(rec.tags) == MAX_TAGS
    assert "too_many_tags" in rec.issue_codes()


def test_exactly_max_tags_is_not_truncated() -> None:
    text = "v=DMARC1; p=none" + "".join(f"; x{i}=y" for i in range(MAX_TAGS - 2))
    rec = parse_dmarc(text)
    assert not rec.truncated
    assert len(rec.tags) == MAX_TAGS


def test_too_many_uris_is_truncated() -> None:
    uris = ",".join(f"mailto:r{i}@example.com" for i in range(MAX_URIS))
    text = f"v=DMARC1; p=none; rua={uris}; ruf=mailto:extra@example.com"
    rec = parse_dmarc(text)
    assert rec.truncated
    assert len(rec.rua) == MAX_URIS and rec.ruf == ()
    assert rec.issue_codes().count("too_many_uris") == 1


def test_exactly_max_uris_is_not_truncated() -> None:
    uris = ",".join(f"mailto:r{i}@example.com" for i in range(MAX_URIS))
    rec = parse_dmarc(f"v=DMARC1; p=none; rua={uris}")
    assert not rec.truncated and rec.is_valid
    assert len(rec.rua) == MAX_URIS


def test_non_str_input_does_not_raise() -> None:
    for value in (None, 42, b"v=DMARC1; p=none", ["v=DMARC1"]):
        rec = parse_dmarc(value)  # type: ignore[arg-type]
        assert rec.issue_codes() == ("empty_record",)
        assert is_dmarc_record(value) is False  # type: ignore[arg-type]


ADVERSARIAL = [
    ";" * 10_000,
    "v=DMARC1; p=none; rua=" + "mailto:a@example.com," * 2_000,
    "v=DMARC1; p=none; rua=mailto:" + "%41" * 3_000 + "@example.com",
    "v=DMARC1; p=none; rua=mailto:a@example.com!" + "9" * 5_000,
    "v=DMARC1; p=none; ri=" + "9" * 5_000,
    "v=DMARC1; p=none; fo=" + "0:" * 2_000,
    "v" + " " * 10_000 + "=",
    "é" * 10_000,
]


@pytest.mark.parametrize("text", ADVERSARIAL)
def test_adversarial_inputs_are_fast(text: str) -> None:
    start = time.perf_counter()
    parse_dmarc(text)
    is_dmarc_record(text)
    assert time.perf_counter() - start < 0.5


def test_fuzz_random_inputs_never_raise() -> None:
    rng = random.Random(7489)
    alphabet = "v=DMARC1;p nonequarantinerejectsp:pct,rua!mailto@x.com%2C\t\x00é0123456789kmgt"
    start = time.perf_counter()
    for _ in range(3_000):
        n = rng.randint(0, 80)
        text = "".join(rng.choice(alphabet) for _ in range(n))
        if rng.random() < 0.5:
            text = "v=DMARC1;" + text
        rec = parse_dmarc(text)
        assert isinstance(rec.issues, tuple)
        is_dmarc_record(text)
    assert time.perf_counter() - start < 5.0
