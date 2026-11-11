"""Table-driven tests for the ARC chain parser (RFC 8617, structure only). No network.

The "RFC 8617 B" fixture is tests/fixtures/messages/arc-rfc8617-appendix-b.eml, the example
of RFC 8617 appendix B (https://www.rfc-editor.org/rfc/rfc8617.txt) with hosts mapped to
example.com/.net/.org (see MANIFEST.yaml). Everything else is synthetic on example.com.
"""

from __future__ import annotations

import random
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.parsers import arc
from app.parsers.arc import (
    AAR_NAME,
    AMS_NAME,
    AS_NAME,
    MAX_ARC_FIELDS,
    MAX_ARC_HEADER_LENGTH,
    MAX_ISSUES,
    MAX_TAG_VALUE,
    ArcChain,
    ArcSignature,
    parse_arc_chain,
    parse_arc_values,
)
from app.parsers.message import parse_header_block

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "messages" / "arc-rfc8617-appendix-b.eml"
)

B = "dGVzdHNpZ25hdHVyZQ=="
BH = "Ym9keWhhc2g="


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network access attempted")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyaddr", "create_connection"):
        monkeypatch.setattr(socket, name, boom)


def seal(i: str, cv: str = "pass", extra: str = "") -> tuple[str, str]:
    return (
        AS_NAME,
        f"i={i}; a=rsa-sha256; cv={cv}; d=example.com; s=sel{i}; t=1700000000; b={B}{extra}",
    )


def ams(i: str, extra: str = "") -> tuple[str, str]:
    return (
        AMS_NAME,
        f"i={i}; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel{i}; "
        f"h=from:to:subject; bh={BH}; b={B}{extra}",
    )


def aar(
    i: str, payload: str = "mx.example.com; spf=pass smtp.mailfrom=example.com"
) -> tuple[str, str]:
    return (AAR_NAME, f"i={i}; {payload}")


def arc_set(i: int, cv: str | None = None) -> list[tuple[str, str]]:
    status = cv if cv is not None else ("none" if i == 1 else "pass")
    return [seal(str(i), status), ams(str(i)), aar(str(i))]


def chain_of(n: int) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    for i in range(n, 0, -1):  # newest (highest) first, as in a message
        fields += arc_set(i)
    return fields


def chain_codes(chain: ArcChain) -> list[str]:
    return [i.code for i in chain.issues]


def field_codes(chain: ArcChain) -> list[str]:
    out: list[str] = []
    for item in (*chain.signatures, *chain.results):
        out += [i.code for i in item.issues]
    return out


def sig(value: str, kind: str = AS_NAME) -> ArcSignature:
    chain = parse_arc_values([(kind, value)])
    (only,) = chain.signatures
    return only


# --- RFC 8617 appendix B ----------------------------------------------------------------


def test_rfc8617_appendix_b() -> None:
    chain = parse_arc_chain(parse_header_block(FIXTURE.read_bytes()))
    assert chain.status == "structurally_valid"
    assert chain.verified is None
    assert chain.crypto_checked is False
    assert chain.issues == ()
    assert field_codes(chain) == []
    assert [s.instance for s in chain.sets] == [1, 2, 3]
    assert [s.cv for s in chain.sets] == ["none", "pass", "pass"]
    assert [s.domain for s in chain.sets] == [
        "lists.example.org",
        "gmail.example.com",
        "clochette.example.org",
    ]
    assert [s.selector for s in chain.sets] == ["dk-lists", "20120806", "clochette"]
    assert all(s.timestamp == datetime(1970, 1, 1, 3, 25, 45, tzinfo=UTC) for s in chain.sets)
    first = chain.sets[0]
    assert first.results is not None
    assert first.results.authserv_id == "lists.example.org"
    assert [(r.method, r.result) for r in first.results.resinfo] == [
        ("spf", "pass"),
        ("dkim", "pass"),
        ("dmarc", "pass"),
    ]
    newest = chain.highest
    assert newest is not None and newest.results is not None
    assert [r.result for r in newest.results.arc] == ["pass"]
    ms = newest.message_signature
    assert ms is not None
    assert ms.signed_headers == ("message-id", "date", "from", "to", "subject")
    assert ms.canonicalization == "relaxed/relaxed"
    # b= and bh= folded across lines: presence and whitespace-free length only.
    assert ms.has_signature and ms.signature_length == 88
    assert ms.has_body_hash and ms.body_hash_length == 44


def test_signature_values_not_retained() -> None:
    chain = parse_arc_values(chain_of(1))
    for item in chain.signatures:
        assert B not in repr(item)
        assert BH not in repr(item)


def test_no_arc_fields() -> None:
    chain = parse_arc_values([("Subject", "hi"), ("Authentication-Results", "x; none")])
    assert chain.status == "none"
    assert chain.sets == () and chain.field_count == 0
    assert chain.verified is None and chain.crypto_checked is False


def test_header_names_case_insensitive() -> None:
    fields = [(n.upper(), v) for n, v in chain_of(2)]
    assert parse_arc_values(fields).status == "structurally_valid"


# --- chain structure ----------------------------------------------------------------------

STRUCTURE_CASES = [
    pytest.param(chain_of(1), "structurally_valid", [], id="one_set"),
    pytest.param(chain_of(3), "structurally_valid", [], id="three_sets"),
    pytest.param(chain_of(50), "structurally_valid", [], id="fifty_sets"),
    pytest.param(list(reversed(chain_of(3))), "structurally_valid", [], id="any_order"),
    pytest.param(arc_set(1) + arc_set(3), "invalid", [arc.INSTANCE_GAP], id="gap"),
    pytest.param(arc_set(2), "invalid", [arc.INSTANCE_GAP], id="not_starting_at_1"),
    pytest.param(
        chain_of(2) + [seal("2")],
        "invalid",
        [arc.DUPLICATE_INSTANCE],
        id="duplicate_seal",
    ),
    pytest.param(
        chain_of(2) + [ams("1")],
        "invalid",
        [arc.DUPLICATE_INSTANCE],
        id="duplicate_ams",
    ),
    pytest.param(
        chain_of(2) + [aar("2")],
        "invalid",
        [arc.DUPLICATE_INSTANCE],
        id="duplicate_aar",
    ),
    pytest.param([seal("1", "none"), ams("1")], "invalid", [arc.MISSING_MEMBER], id="missing_aar"),
    pytest.param([seal("1", "none"), aar("1")], "invalid", [arc.MISSING_MEMBER], id="missing_ams"),
    pytest.param([ams("1"), aar("1")], "invalid", [arc.MISSING_MEMBER], id="missing_seal"),
    pytest.param([ams("1")], "invalid", [arc.MISSING_MEMBER, arc.MISSING_MEMBER], id="only_ams"),
    pytest.param(arc_set(1, "pass"), "invalid", [arc.CV_NOT_NONE_AT_FIRST], id="cv_pass_at_1"),
    pytest.param(
        arc_set(2, "none") + arc_set(1), "invalid", [arc.CV_NONE_AFTER_FIRST], id="cv_none_at_2"
    ),
    pytest.param(
        arc_set(1, "fail"), "cv_fail", [arc.CV_NOT_NONE_AT_FIRST, arc.CV_FAIL], id="cv_fail_1"
    ),
    pytest.param(arc_set(2, "fail") + arc_set(1), "cv_fail", [arc.CV_FAIL], id="cv_fail_top"),
    pytest.param(
        arc_set(3) + arc_set(2, "fail") + arc_set(1), "cv_fail", [arc.CV_FAIL], id="cv_fail_middle"
    ),
    pytest.param(
        arc_set(3, "fail") + arc_set(1),
        "cv_fail",
        [arc.INSTANCE_GAP, arc.CV_FAIL],
        id="cv_fail_wins",
    ),
    pytest.param(
        [(AS_NAME, f"i=1; a=rsa-sha256; cv=none; d=x; s=s; h=from; b={B}"), ams("1"), aar("1")],
        "cv_fail",
        [arc.CV_FAIL],
        id="h_on_seal_fails_chain",
    ),
    pytest.param(
        arc_set(2)
        + [(AS_NAME, f"i=2; a=rsa-sha256; cv=pass; d=x; s=s; h=from; b={B}")]
        + arc_set(1),
        "cv_fail",
        [arc.DUPLICATE_INSTANCE, arc.CV_FAIL],
        id="h_on_duplicate_seal",
    ),
    pytest.param(
        chain_of(2) + [(AS_NAME, f"i=abc; a=rsa-sha256; cv=fail; d=x; s=s; b={B}")],
        "invalid",
        [arc.UNGROUPED_FIELD],
        id="ungrouped_cv_fail_ignored",
    ),
    pytest.param(
        arc_set(1) + [(AS_NAME, f"i=51; a=rsa-sha256; cv=pass; d=x; s=s; h=from; b={B}")],
        "invalid",
        [arc.UNGROUPED_FIELD],
        id="ungrouped_h_ignored",
    ),
    pytest.param(
        arc_set(1) + [seal("001", "fail")],
        "invalid",
        [arc.UNGROUPED_FIELD],
        id="three_digit_instance_cv_fail_ignored",
    ),
]


@pytest.mark.parametrize(("fields", "status", "expected"), STRUCTURE_CASES)
def test_chain_structure(fields: list[tuple[str, str]], status: str, expected: list[str]) -> None:
    chain = parse_arc_values(fields)
    assert chain.status == status
    assert chain_codes(chain) == expected
    assert chain.verified is None and chain.crypto_checked is False


def test_gap_term_names_missing_instance() -> None:
    chain = parse_arc_values(arc_set(1) + arc_set(4))
    assert [(i.code, i.term) for i in chain.issues] == [
        (arc.INSTANCE_GAP, "2"),
        (arc.INSTANCE_GAP, "3"),
    ]


def test_duplicate_keeps_first() -> None:
    first = (AS_NAME, f"i=1; a=rsa-sha256; cv=none; d=first.example.com; s=a; b={B}")
    second = (AS_NAME, f"i=1; a=rsa-sha256; cv=none; d=second.example.com; s=a; b={B}")
    chain = parse_arc_values([first, second, ams("1"), aar("1")])
    assert chain.sets[0].domain == "first.example.com"
    assert len(chain.signatures) == 3
    assert [(i.code, i.term) for i in chain.issues] == [(arc.DUPLICATE_INSTANCE, AS_NAME)]


# --- instance numbers ---------------------------------------------------------------------

INSTANCE_CASES = [
    pytest.param("1", 1, [], id="one"),
    pytest.param("50", 50, [], id="fifty"),
    pytest.param("07", 7, [], id="two_digit_leading_zero"),
    pytest.param("01", 1, [], id="zero_one"),
    pytest.param("007", None, [arc.INVALID_INSTANCE], id="leading_zeros"),
    pytest.param("001", None, [arc.INVALID_INSTANCE], id="three_digit_one"),
    pytest.param("050", None, [arc.INVALID_INSTANCE], id="three_digit_fifty"),
    pytest.param("0", None, [arc.INVALID_INSTANCE], id="zero"),
    pytest.param("00", None, [arc.INVALID_INSTANCE], id="zeros"),
    pytest.param("-1", None, [arc.INVALID_INSTANCE], id="negative"),
    pytest.param("abc", None, [arc.INVALID_INSTANCE], id="alpha"),
    pytest.param("1.5", None, [arc.INVALID_INSTANCE], id="decimal"),
    pytest.param("\u0661", None, [arc.INVALID_TAG_VALUE, arc.MISSING_INSTANCE], id="arabic_digit"),
    pytest.param("1 2", None, [arc.INVALID_INSTANCE], id="two_numbers"),
    pytest.param("51", None, [arc.INSTANCE_TOO_HIGH], id="fifty_one"),
    pytest.param("100", None, [arc.INSTANCE_TOO_HIGH], id="hundred"),
    pytest.param("9" * 100, None, [arc.INSTANCE_TOO_HIGH], id="huge_number"),
    pytest.param(
        "9" * (MAX_TAG_VALUE + 1), None, [arc.TAG_TOO_LONG, arc.MISSING_INSTANCE], id="oversized_i"
    ),
]


@pytest.mark.parametrize(("text", "instance", "expected"), INSTANCE_CASES)
def test_instance_values(text: str, instance: int | None, expected: list[str]) -> None:
    item = sig(f"i={text}; a=rsa-sha256; cv=none; d=example.com; s=s; b={B}")
    assert item.instance == instance
    assert [i.code for i in item.issues] == expected
    if expected:
        chain = parse_arc_values([(AS_NAME, f"i={text}; a=rsa-sha256; cv=none; d=x; s=s; b={B}")])
        assert chain.status == "invalid"
        assert arc.UNGROUPED_FIELD in chain_codes(chain)
        assert chain.sets == ()


def test_missing_and_duplicate_i() -> None:
    assert [i.code for i in sig(f"a=rsa-sha256; cv=none; d=x; s=s; b={B}").issues] == [
        arc.MISSING_INSTANCE
    ]
    item = sig(f"i=1; i=2; a=rsa-sha256; cv=none; d=x; s=s; b={B}")
    assert item.instance == 1
    assert [(i.code, i.term) for i in item.issues] == [(arc.DUPLICATE_TAG, "i")]


# --- tag parsing --------------------------------------------------------------------------

SEAL_TAG_CASES = [
    pytest.param(f"i=1; a=rsa-sha256; cv=none; d=example.com; s=s; b={B}", [], id="minimal_seal"),
    pytest.param(f"i=1;a=rsa-sha256;cv=none;d=x;s=s;b={B};", [], id="no_spaces_trailing_semi"),
    pytest.param(f"i = 1 ;\r\n a = rsa-sha256 ; cv\t= none; d=x; s=s; b={B}", [], id="fws_around"),
    pytest.param(f"i=1; a=rsa-sha256; cv=none; d=x; s=s; b={B}; zz=ignored", [], id="unknown_tag"),
    pytest.param(f"i=1; a=rsa-sha256; cv=none; d=x; b={B}", [arc.MISSING_TAG], id="no_s"),
    pytest.param(f"i=1; a=rsa-sha256; cv=none; s=s; b={B}", [arc.MISSING_TAG], id="no_d"),
    pytest.param("i=1; a=rsa-sha256; cv=none; d=x; s=s", [arc.MISSING_TAG], id="no_b"),
    pytest.param(f"i=1; cv=none; d=x; s=s; b={B}", [arc.MISSING_TAG], id="no_a"),
    pytest.param(f"i=1; a=rsa-sha256; d=x; s=s; b={B}", [arc.MISSING_CV], id="no_cv"),
    pytest.param(f"i=1; a=rsa-sha256; cv=maybe; d=x; s=s; b={B}", [arc.INVALID_CV], id="bad_cv"),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=; d=x; s=s; b={B}",
        [arc.EMPTY_TAG_VALUE, arc.MISSING_CV],
        id="empty_cv",
    ),
    pytest.param(
        f"i=1; a=rsa-sha1; cv=none; d=x; s=s; b={B}", [arc.UNKNOWN_ALGORITHM], id="rsa_sha1"
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; t=soon; b={B}",
        [arc.INVALID_TIMESTAMP],
        id="bad_timestamp",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; t=9999999999999; b={B}",
        [arc.INVALID_TIMESTAMP],
        id="timestamp_13_digits",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; t=999999999999; b={B}",
        [arc.INVALID_TIMESTAMP],
        id="timestamp_out_of_range",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; h=from; b={B}",
        [arc.SEAL_H_TAG],
        id="h_on_seal",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; bh={BH}; b={B}",
        [arc.UNEXPECTED_TAG],
        id="bh_on_seal",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; d=y; s=s; b={B}", [arc.DUPLICATE_TAG], id="dup_d"
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; junk; b={B}", [arc.INVALID_TAG], id="no_equals"
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; 9x=1; b={B}",
        [arc.INVALID_TAG_NAME],
        id="bad_tag_name",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; =x; d=x; s=s; b={B}", [arc.INVALID_TAG_NAME], id="empty_name"
    ),
    pytest.param(f"i=1;; a=rsa-sha256; cv=none; d=x; s=s; b={B}", [arc.EMPTY_TAG], id="empty_spec"),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=exa\u00e9mple.com; s=s; b={B}",
        [arc.INVALID_TAG_VALUE, arc.MISSING_TAG],
        id="non_ascii_value",
    ),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d={'a' * (MAX_TAG_VALUE + 1)}; s=s; b={B}",
        [arc.TAG_TOO_LONG, arc.MISSING_TAG],
        id="oversized_d",
    ),
    pytest.param(
        "i=1; a=rsa-sha256; cv=none; d=x; s=s; b=",
        [arc.EMPTY_TAG_VALUE, arc.MISSING_TAG],
        id="truncated_b",
    ),
    pytest.param(
        "i=1; a=rsa-sha256; cv=no",
        [arc.MISSING_TAG, arc.MISSING_TAG, arc.MISSING_TAG, arc.INVALID_CV],
        id="truncated",
    ),
    pytest.param(
        "",
        [arc.MISSING_INSTANCE, *[arc.MISSING_TAG] * 2, arc.MISSING_CV, *[arc.MISSING_TAG] * 2],
        id="empty",
    ),
]


@pytest.mark.parametrize(("value", "expected"), SEAL_TAG_CASES)
def test_seal_tags(value: str, expected: list[str]) -> None:
    assert [i.code for i in sig(value).issues] == expected


def test_seal_fields() -> None:
    item = sig(f"i=1; a=RSA-SHA256; cv=NONE; d=Example.COM; s=sel; t=1700000000; b={B}")
    assert item.kind == "seal"
    assert (item.instance, item.algorithm, item.cv) == (1, "rsa-sha256", "none")
    assert (item.domain, item.selector) == ("Example.COM", "sel")
    assert item.timestamp == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert item.has_signature and item.signature_length == len(B)
    assert not item.has_body_hash and item.signed_headers == ()
    assert not item.unknown_algorithm


def test_unknown_algorithm_kept() -> None:
    item = sig(f"i=1; a=x-new-alg; cv=none; d=x; s=s; b={B}")
    assert item.algorithm == "x-new-alg" and item.unknown_algorithm
    assert item.issues[0].severity == "warning"
    chain = parse_arc_values(
        [(AS_NAME, f"i=1; a=x-new-alg; cv=none; d=x; s=s; b={B}"), ams("1"), aar("1")]
    )
    assert chain.status == "structurally_valid"


def test_invalid_timestamp_is_warning_only() -> None:
    fields = [(AS_NAME, f"i=1; a=rsa-sha256; cv=none; d=x; s=s; t=-5; b={B}"), ams("1"), aar("1")]
    chain = parse_arc_values(fields)
    assert chain.status == "structurally_valid"
    assert chain.sets[0].timestamp is None


AMS_TAG_CASES = [
    pytest.param(ams("1")[1], [], id="full"),
    pytest.param(f"i=1; a=rsa-sha256; d=x; s=s; h=from; b={B}", [arc.MISSING_TAG], id="no_bh"),
    pytest.param(f"i=1; a=rsa-sha256; d=x; s=s; bh={BH}; b={B}", [arc.MISSING_TAG], id="no_h"),
    pytest.param(
        f"i=1; a=rsa-sha256; cv=none; d=x; s=s; h=from; bh={BH}; b={B}",
        [arc.UNEXPECTED_TAG],
        id="cv_on_ams",
    ),
]


@pytest.mark.parametrize(("value", "expected"), AMS_TAG_CASES)
def test_ams_tags(value: str, expected: list[str]) -> None:
    assert [i.code for i in sig(value, AMS_NAME).issues] == expected


def test_ams_fields_with_folding() -> None:
    value = (
        "i=2; a=rsa-sha256; c=relaxed/simple; d=example.com; s=sel;\r\n"
        " h=From : To:\r\n\tSubject:; bh=Ym9k\r\n eWhh c2g=; b=dGVz\r\n\tdA=="
    )
    item = sig(value, AMS_NAME)
    assert item.issues == ()
    assert item.kind == "message_signature"
    assert item.signed_headers == ("from", "to", "subject")
    assert item.canonicalization == "relaxed/simple"
    assert item.body_hash_length == len("Ym9keWhhc2g=")
    assert item.signature_length == len("dGVzdA==")
    assert item.cv is None


# --- ARC-Authentication-Results ------------------------------------------------------------

AAR_CASES = [
    pytest.param("i=1; mx.example.com; spf=pass", 1, "mx.example.com", [], id="ok"),
    pytest.param(" i = 2 ;mx.example.com; none", 2, "mx.example.com", [], id="spaces"),
    pytest.param(
        "mx.example.com; spf=pass",
        None,
        None,
        [arc.INVALID_TAG, arc.MISSING_INSTANCE],
        id="no_i",
    ),
    pytest.param("i=1", None, None, [arc.INVALID_AAR], id="no_semicolon"),
    pytest.param("i=1; ", 1, None, [], id="empty_payload"),
    pytest.param(
        "i=0; mx.example.com; spf=pass", None, "mx.example.com", [arc.INVALID_INSTANCE], id="i0"
    ),
    pytest.param(
        "i=51; mx.example.com; spf=pass", None, "mx.example.com", [arc.INSTANCE_TOO_HIGH], id="i51"
    ),
    pytest.param(
        "i=1 a=2; mx.example.com; spf=pass",
        None,
        "mx.example.com",
        [arc.INVALID_INSTANCE],
        id="junk_i",
    ),
    pytest.param("i=1 ; a=rsa; mx.example.com", 1, None, [], id="extra_tag_goes_to_payload"),
]


@pytest.mark.parametrize(("value", "instance", "authserv", "expected"), AAR_CASES)
def test_aar(value: str, instance: int | None, authserv: str | None, expected: list[str]) -> None:
    chain = parse_arc_values([(AAR_NAME, value)])
    (item,) = chain.results
    assert item.instance == instance
    assert [i.code for i in item.issues] == expected
    if authserv is not None:
        assert item.results is not None
        assert item.results.authserv_id == authserv


def test_aar_results_visible_per_hop() -> None:
    fields = arc_set(2) + [
        seal("1", "none"),
        ams("1"),
        aar("1", "mx1.example.com; dkim=fail; dmarc=fail"),
    ]
    chain = parse_arc_values(fields)
    assert chain.status == "structurally_valid"
    first = chain.sets[0].results
    assert first is not None and [r.result for r in first.dkim] == ["fail"]
    second = chain.sets[1].results
    assert second is not None and [r.result for r in second.spf] == ["pass"]


# --- caps and hard errors -----------------------------------------------------------------

LIMIT_CASES = [
    pytest.param(
        (AS_NAME, seal("1", "none")[1] + " " * MAX_ARC_HEADER_LENGTH),
        arc.HEADER_TOO_LARGE,
        id="seal_too_large",
    ),
    pytest.param((AMS_NAME, ams("1")[1] + "\x00"), arc.NUL_BYTE, id="ams_nul"),
    pytest.param((AAR_NAME, "i=1; mx.example.com\x00; spf=pass"), arc.NUL_BYTE, id="aar_nul"),
    pytest.param(
        (AAR_NAME, "i=1; x; spf=pass" + "a" * MAX_ARC_HEADER_LENGTH),
        arc.HEADER_TOO_LARGE,
        id="aar_too_large",
    ),
]


@pytest.mark.parametrize(("field", "code"), LIMIT_CASES)
def test_field_limits(field: tuple[str, str], code: str) -> None:
    chain = parse_arc_values([field])
    (item,) = (*chain.signatures, *chain.results)
    assert [i.code for i in item.issues] == [code]
    assert item.instance is None
    assert chain.status == "invalid"


def test_oversized_b_within_header_cap_is_fine() -> None:
    big = "A" * (MAX_TAG_VALUE * 4)
    item = sig(f"i=1; a=rsa-sha256; cv=none; d=x; s=s; b={big}")
    assert item.issues == () and item.signature_length == len(big)


def test_too_many_fields() -> None:
    fields = [aar("1")] * (MAX_ARC_FIELDS + 10)
    chain = parse_arc_values(fields)
    assert chain.truncated
    assert chain.field_count == MAX_ARC_FIELDS
    assert arc.TOO_MANY_FIELDS in chain_codes(chain)
    assert len(chain.issues) <= MAX_ISSUES + 1


def test_issue_cap() -> None:
    item = sig(";" * 1000)
    assert len(item.issues) == MAX_ISSUES + 1
    assert item.issues[-1].code == arc.TOO_MANY_ISSUES


def test_string_input_rejected() -> None:
    with pytest.raises(TypeError):
        parse_arc_values("ARC-Seal: i=1")  # type: ignore[arg-type]


def test_issues_never_echo_input() -> None:
    secret = "secret-token.example.com"
    fields = [
        (AS_NAME, f"i={secret}; a={secret}; cv={secret}; d=x; s=s; t={secret}; {secret}; b={B}"),
        (AAR_NAME, f"i={secret}; {secret}"),
    ]
    chain = parse_arc_values(fields)
    for item in (*chain.signatures, *chain.results):
        for issue in item.issues:
            assert secret not in issue.term
    for issue in chain.issues:
        assert secret not in issue.term


# --- fuzz ---------------------------------------------------------------------------------

FUZZ_ALPHABET = 'i=;0123456789 \t\r\nabcdhstv-()"\\.:\x00é'
FUZZ_NAMES = (AS_NAME, AMS_NAME, AAR_NAME, "arc-seal", "Subject")
FUZZ_SEED = 8617
FUZZ_CASES = 1_500
FUZZ_CASE_SECONDS = 1.0


def _fuzz_value(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.3:
        # Mutate a valid field: drop, duplicate or flip characters.
        base = list(rng.choice([seal("1", "none")[1], ams("2")[1], aar("3")[1]]))
        for _ in range(rng.randint(1, 6)):
            pos = rng.randrange(len(base))
            base[pos] = rng.choice(FUZZ_ALPHABET)
        return "".join(base)
    if roll < 0.35:
        return rng.choice(FUZZ_ALPHABET) * rng.randint(0, MAX_ARC_HEADER_LENGTH + 10)
    return "".join(rng.choice(FUZZ_ALPHABET) for _ in range(rng.randint(0, 60)))


def test_fuzz_never_hangs_or_raises() -> None:
    rng = random.Random(FUZZ_SEED)
    for _ in range(FUZZ_CASES):
        fields = [(rng.choice(FUZZ_NAMES), _fuzz_value(rng)) for _ in range(rng.randint(0, 6))]
        outcome: list[ArcChain | BaseException] = []

        def run(
            f: list[tuple[str, str]] = fields, out: list[ArcChain | BaseException] = outcome
        ) -> None:
            try:
                out.append(parse_arc_values(f))
            except BaseException as exc:  # reported below with the failing input
                out.append(exc)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(FUZZ_CASE_SECONDS)
        assert not worker.is_alive(), (
            f"parser did not finish within {FUZZ_CASE_SECONDS}s: {fields!r}"
        )
        (result,) = outcome
        assert isinstance(result, ArcChain), f"{fields!r} raised {result!r}"
        assert result.verified is None and result.crypto_checked is False
        assert result.status in ("none", "structurally_valid", "invalid", "cv_fail")
        for item in (*result.signatures, *result.results):
            for issue in item.issues:
                assert issue.position >= 0
