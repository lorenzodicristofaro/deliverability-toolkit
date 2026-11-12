"""Tests for app.services.message_findings (M4-09). Offline; no network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.checks.models import CODE_RE
from app.core import i18n
from app.parsers.arc import parse_arc_chain
from app.parsers.message import (
    MAX_HEADER_COUNT,
    MAX_RAW_BYTES,
    MessageParseError,
    parse_header_block,
)
from app.parsers.mime import parse_mime
from app.parsers.received import parse_received_chain
from app.services import message_findings as mf
from app.services.message_alignment import analyze_alignment
from app.services.message_findings import (
    CODES,
    HOP_DELAY_HIGH_SECONDS,
    MAX_EXCERPT,
    MessageFindings,
    build_message_findings,
    excerpt,
    rejected_input_findings,
)

LOCALES = Path(__file__).resolve().parents[2] / "locales"
EN = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
IT = json.loads((LOCALES / "it.json").read_text(encoding="utf-8"))

AR = (
    "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@example.com;"
    " dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
)
RECEIVED = (
    "Received: from mail.example.com (mail.example.com [8.8.4.4]) by mx.example.net"
    " with ESMTPS id 1; Tue, 03 Nov 2026 10:00:05 +0000"
)
BASE: dict[str, str] = {
    "Return-Path": "<b@example.com>",
    "Received": RECEIVED.split(": ", 1)[1],
    "From": "A <a@example.com>",
    "To": "x@example.net",
    "Subject": "hi",
    "Date": "Tue, 03 Nov 2026 10:00:00 +0000",
    "Message-ID": "<1@example.com>",
    "List-Unsubscribe": "<https://example.com/u>",
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    "Authentication-Results": AR.split(": ", 1)[1],
    "MIME-Version": "1.0",
    "Content-Type": "text/plain",
}


def analyze_message(raw: bytes) -> MessageFindings:
    """Test-only wiring of the parsers (M4-10 owns the real orchestration)."""
    try:
        block = parse_header_block(raw)
        mime = parse_mime(raw)
    except MessageParseError as exc:
        return rejected_input_findings(exc.code)
    return build_message_findings(
        block,
        received=parse_received_chain(block),
        mime=mime,
        arc=parse_arc_chain(block),
        alignment=analyze_alignment(block),
    )


def msg(drop: tuple[str, ...] = (), add: tuple[str, ...] = (), body: str = "hello") -> bytes:
    lines = [f"{k}: {v}" for k, v in BASE.items() if k not in drop]
    lines.extend(add)
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def run(drop: tuple[str, ...] = (), add: tuple[str, ...] = (), **kw: str) -> MessageFindings:
    return analyze_message(msg(drop, add, **kw))


def codes(result: MessageFindings) -> set[str]:
    return {f.code for f in result.findings}


def test_base_message_is_clean_and_ok() -> None:
    r = run()
    assert codes(r) == set()
    assert r.unevaluated == () and r.evaluated and r.status == "ok"


_NO_AUTHSERV_AR = (
    "Authentication-Results: spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com;"
    " dmarc=pass header.from=example.com"
)

# (code, drop, add, body)   -- each must contain the code
POSITIVE = [
    ("MSG_MISSING_FROM", ("From",), (), "x"),
    ("MSG_AUTHRES_UNPARSED", ("Authentication-Results",), (_NO_AUTHSERV_AR,), "x"),
    (
        "MSG_ALIGNMENT_NOT_EVALUATED",
        ("Authentication-Results",),
        ("Authentication-Results: dkim=fail",),
        "x",
    ),
    ("MSG_MISSING_FROM", ("From",), ("From:   ",), "x"),
    ("MSG_MULTIPLE_FROM", (), ("From: b@example.com",), "x"),
    ("MSG_MISSING_DATE", ("Date",), (), "x"),
    ("MSG_MISSING_DATE", ("Date",), ("Date: ",), "x"),
    ("MSG_DATE_INVALID", ("Date",), ("Date: yesterday afternoon",), "x"),
    ("MSG_DATE_INVALID", ("Date",), ("Date: Tue, 30 Feb 2026 10:00:00 +0000",), "x"),
    ("MSG_DATE_INVALID", ("Date",), ("Date: Tue, 03 Nov 2026 25:00:00 +0000",), "x"),
    ("MSG_DATE_INVALID", ("Date",), ("Date: Tue, 03 Nov 2026 10:00:00 +0000; x",), "x"),
    ("MSG_DATE_NO_TIMEZONE", ("Date",), ("Date: Tue, 03 Nov 2026 10:00:00",), "x"),
    ("MSG_DATE_FAR_FROM_RECEIVED", ("Date",), ("Date: Mon, 02 Nov 2026 09:00:00 +0000",), "x"),
    ("MSG_DATE_FAR_FROM_RECEIVED", ("Date",), ("Date: Wed, 04 Nov 2026 11:00:00 +0000",), "x"),
    ("MSG_MISSING_MESSAGE_ID", ("Message-ID",), (), "x"),
    ("MSG_MISSING_MESSAGE_ID", ("Message-ID",), ("Message-ID:",), "x"),
    ("MSG_DUPLICATE_SINGLETON_HEADER", (), ("Subject: again",), "x"),
    ("MSG_DUPLICATE_SINGLETON_HEADER", (), ("Message-ID: <2@example.com>",), "x"),
    ("MSG_DUPLICATE_SINGLETON_HEADER", (), (f"Date: {BASE['Date']}",), "x"),
    ("MSG_RECEIVED_NONE", ("Received",), (), "x"),
    ("MSG_RECEIVED_UNPARSED", ("Received",), ("Received: nonsense without keywords",), "x"),
    ("MSG_RECEIVED_UNPARSED", ("Received",), ("Received: ",), "x"),
    (
        "MSG_RECEIVED_CLOCK_SKEW",
        ("Received",),
        (
            "Received: from a.example (a.example [8.8.8.8]) by b.example; Tue, 03 Nov 2026 10:00:10 +0000",  # noqa: E501
            "Received: from c.example (c.example [8.8.4.4]) by a.example; Tue, 03 Nov 2026 10:00:20 +0000",  # noqa: E501
        ),
        "x",
    ),
    (
        "MSG_HOP_DELAY_HIGH",
        ("Received",),
        (
            "Received: from a.example (a.example [8.8.8.8]) by b.example; Tue, 03 Nov 2026 12:00:00 +0000",  # noqa: E501
            "Received: from c.example (c.example [8.8.4.4]) by a.example; Tue, 03 Nov 2026 10:00:00 +0000",  # noqa: E501
        ),
        "x",
    ),
    (
        "MSG_RECEIVED_PRIVATE_IP_ORIGIN",
        ("Received",),
        (f"Received: from pc (pc [192.168.1.5]) by mx.example.net; {BASE['Date'][5:]}",),
        "x",
    ),
    ("MSG_AUTHRES_MISSING", ("Authentication-Results",), (), "x"),
    (
        "MSG_AUTHRES_AUTHSERV_MISMATCH",
        ("Authentication-Results",),
        (
            "Authentication-Results: mx.other.net; dmarc=pass header.from=example.com",
            "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@example.com;"
            " dkim=pass header.d=example.com",
        ),
        "x",
    ),
    (
        "MSG_SPF_NOT_PASS",
        ("Authentication-Results",),
        (AR.replace("spf=pass", "spf=fail"),),
        "x",
    ),
    (
        "MSG_SPF_NOT_PASS",
        ("Authentication-Results",),
        ("Authentication-Results: mx.example.net; dkim=pass header.d=example.com",),
        "x",
    ),
    (
        "MSG_DKIM_NOT_PASS",
        ("Authentication-Results",),
        (AR.replace("dkim=pass", "dkim=fail"),),
        "x",
    ),
    (
        "MSG_DKIM_NOT_PASS",
        ("Authentication-Results",),
        ("Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@example.com",),
        "x",
    ),
    (
        "MSG_DMARC_NOT_PASS",
        ("Authentication-Results",),
        (AR.replace("dmarc=pass", "dmarc=fail"),),
        "x",
    ),
    (
        "MSG_DMARC_NOT_PASS",
        ("Authentication-Results",),
        (AR.split("; dmarc")[0],),
        "x",
    ),
    (
        "MSG_ALIGNMENT_FAIL",
        ("Authentication-Results",),
        (
            "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@other.org;"
            " dkim=pass header.d=other.org",
        ),
        "x",
    ),
    (
        "MSG_ALIGNMENT_STATED_MISMATCH",
        ("Authentication-Results",),
        (
            "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@other.org;"
            " dkim=pass header.d=other.org; dmarc=pass header.from=example.com",
        ),
        "x",
    ),
    (
        "MSG_UNVERIFIED_DKIM_SIGNATURE",
        (),
        ("DKIM-Signature: v=1; a=rsa-sha256; d=unseen.example; s=s1; h=from; bh=x; b=y",),
        "x",
    ),
    (
        "MSG_ARC_INVALID",
        (),
        ("ARC-Seal: i=1; a=rsa-sha256; d=example.net; s=s1; cv=none; b=abc",),
        "x",
    ),
    (
        "MSG_ARC_CV_FAIL",
        (),
        (
            "ARC-Seal: i=1; a=rsa-sha256; d=example.net; s=s1; cv=fail; b=abc",
            "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.net; s=s1; h=from; bh=x; b=abc",
            "ARC-Authentication-Results: i=1; mx.example.net; spf=pass",
        ),
        "x",
    ),
    ("MSG_RETURN_PATH_MISSING", ("Return-Path",), (), "x"),
    ("MSG_REPLY_TO_DIFFERS", (), ("Reply-To: help@other.org",), "x"),
    ("MSG_REPLY_TO_UNUSABLE", (), ("Reply-To: not an address",), "x"),
    ("MSG_REPLY_TO_UNUSABLE", (), ("Reply-To: nobody@",), "x"),
    ("MSG_LIST_UNSUBSCRIBE_MISSING", ("List-Unsubscribe", "List-Unsubscribe-Post"), (), "x"),
    ("MSG_LIST_UNSUBSCRIBE_NO_ONECLICK", ("List-Unsubscribe-Post",), (), "x"),
    (
        "MSG_LIST_UNSUBSCRIBE_NO_ONECLICK",
        ("List-Unsubscribe-Post",),
        ("List-Unsubscribe-Post: something-else",),
        "x",
    ),
    ("MSG_ENCODED_HEADER_BROKEN", (), ("X-Note: =?utf-8?B?!!!!?=",), "x"),
    ("MSG_ENCODED_HEADER_BROKEN", (), ("X-Note: =?no-such-charset?Q?abc?=",), "x"),
    (
        "MSG_MIME_TRUNCATED",
        ("Content-Type",),
        ('Content-Type: multipart/mixed; boundary="b"',),
        "".join("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n" for _ in range(250)) + "--b--\r\n",
    ),
    ("MSG_NO_TEXT_PART", ("Content-Type",), ("Content-Type: text/html",), "<p>x</p>"),
]


@pytest.mark.parametrize(
    ("code", "drop", "add", "body"),
    POSITIVE,
    ids=[f"{p[0]}-{i}" for i, p in enumerate(POSITIVE)],
)
def test_positive(code: str, drop: tuple[str, ...], add: tuple[str, ...], body: str) -> None:
    r = run(drop, add, body=body)
    assert code in codes(r)
    assert r.status != "ok"


# (code that must NOT appear, drop, add)
NEGATIVE = [
    ("MSG_AUTHRES_UNPARSED", (), ()),
    ("MSG_ALIGNMENT_NOT_EVALUATED", (), ()),
    ("MSG_MULTIPLE_FROM", (), ("To: y@example.net",)),
    ("MSG_DATE_NO_TIMEZONE", ("Date",), ("Date: Tue, 03 Nov 2026 10:00:00 GMT",)),
    ("MSG_DATE_NO_TIMEZONE", ("Date",), ("Date: Tue, 03 Nov 2026 10:00:00 -0000",)),
    ("MSG_DATE_FAR_FROM_RECEIVED", ("Date",), ("Date: Mon, 02 Nov 2026 10:30:00 +0000",)),
    ("MSG_DATE_FAR_FROM_RECEIVED", ("Date",), ("Date: Tue, 03 Nov 2026 14:00:00 +0400",)),
    (
        "MSG_DATE_FAR_FROM_RECEIVED",
        ("Date", "Received"),
        ("Date: Mon, 01 Jun 2026 10:00:00 +0000",),
    ),
    ("MSG_DUPLICATE_SINGLETON_HEADER", (), ("Received: from x by y; " + BASE["Date"][5:],)),
    ("MSG_DUPLICATE_SINGLETON_HEADER", (), ("From: second@example.com",)),
    ("MSG_HOP_DELAY_HIGH", (), ()),
    ("MSG_RECEIVED_PRIVATE_IP_ORIGIN", (), ()),
    ("MSG_RECEIVED_CLOCK_SKEW", (), ()),
    ("MSG_AUTHRES_AUTHSERV_MISMATCH", (), ()),
    (
        "MSG_AUTHRES_AUTHSERV_MISMATCH",
        ("Authentication-Results",),
        ("Authentication-Results: MX.example.net.; dmarc=pass header.from=example.com", AR),
    ),
    ("MSG_SPF_NOT_PASS", (), ()),
    (
        "MSG_DKIM_NOT_PASS",
        ("Authentication-Results",),
        (AR.replace("dkim=pass", "dkim=fail") + "; dkim=pass header.d=example.com",),
    ),
    ("MSG_DMARC_NOT_PASS", (), ()),
    ("MSG_ALIGNMENT_FAIL", (), ()),
    ("MSG_ALIGNMENT_STATED_MISMATCH", (), ()),
    (
        "MSG_UNVERIFIED_DKIM_SIGNATURE",
        (),
        ("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from; bh=x; b=y",),
    ),
    ("MSG_ARC_INVALID", (), ()),
    ("MSG_ARC_CV_FAIL", (), ()),
    ("MSG_REPLY_TO_DIFFERS", (), ("Reply-To: help@mail.example.com",)),
    ("MSG_REPLY_TO_DIFFERS", (), ("Reply-To: help@EXAMPLE.com",)),
    ("MSG_REPLY_TO_UNUSABLE", (), ("Reply-To: help@example.com",)),
    ("MSG_LIST_UNSUBSCRIBE_NO_ONECLICK", ("List-Unsubscribe", "List-Unsubscribe-Post"), ()),
    (
        "MSG_LIST_UNSUBSCRIBE_NO_ONECLICK",
        ("List-Unsubscribe-Post",),
        ("List-Unsubscribe-Post: list-unsubscribe=one-click",),
    ),
    ("MSG_ENCODED_HEADER_BROKEN", (), ("X-Note: =?utf-8?B?aGVsbG8=?=",)),
    ("MSG_MIME_TRUNCATED", (), ()),
    ("MSG_NO_TEXT_PART", ("Content-Type",), ('Content-Type: multipart/alternative; boundary="b"',)),
]


@pytest.mark.parametrize(
    ("code", "drop", "add"), NEGATIVE, ids=[f"{n[0]}-{i}" for i, n in enumerate(NEGATIVE)]
)
def test_negative(code: str, drop: tuple[str, ...], add: tuple[str, ...]) -> None:
    body = "x"
    if code == "MSG_NO_TEXT_PART":
        body = (
            "--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
            "--b\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n--b--\r\n"
        )
    assert code not in codes(run(drop, add, body=body))


def _find(result: MessageFindings, code: str):
    (f,) = [f for f in result.findings if f.code == code]
    return f


# Malformed input: error status, never ok, and never a pass.
MALFORMED = [
    (("Date",), ("Date: ???",), "date", "MSG_DATE_INVALID"),
    (("Date",), ("Date: Tue, 03 Nov 2026 10:00:00",), "date", "MSG_DATE_NO_TIMEZONE"),
    (("Date",), ("Date: " + "x" * 5000,), "date", "MSG_DATE_INVALID"),
    (("Received",), ("Received: garbage",), "received", "MSG_RECEIVED_UNPARSED"),
    (("Received",), ("Received: from (",), "received", "MSG_RECEIVED_UNPARSED"),
    (("Authentication-Results",), ("Authentication-Results: ;;;",), "authres", None),
    (
        ("Authentication-Results",),
        ("Authentication-Results: mx.example.net; spf",),
        "authres",
        None,
    ),
    (("Authentication-Results",), ("Authentication-Results: (unterminated",), "authres", None),
    (("From",), ("From: <<<>>>",), "alignment", None),
    (("From",), ("From: nobody",), "alignment", None),
]


@pytest.mark.parametrize(
    ("drop", "add", "area", "code"), MALFORMED, ids=[f"{m[2]}-{i}" for i, m in enumerate(MALFORMED)]
)
def test_malformed_is_error_not_ok(
    drop: tuple[str, ...], add: tuple[str, ...], area: str, code: str | None
) -> None:
    r = run(drop, add)
    assert area in r.unevaluated
    assert r.status == "error" and not r.evaluated
    if code:
        assert code in codes(r)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00",
        b"no headers at all",
        b"From: a@example.com\x00\r\n\r\n",
        b"\xff\xfe\x00\x01",
        b"Received: from x by y; Tue, 03 Nov 2026 10:00:00 +0000\r\n",
        b"\r\n\r\n",
        b"X: " + b"a" * 100_000 + b"\r\n\r\n",
    ],
    ids=[
        "empty",
        "nul",
        "no-headers",
        "nul-header",
        "binary",
        "headers-only",
        "blank",
        "huge-line",
    ],
)
def test_garbage_never_ok(raw: bytes) -> None:
    r = analyze_message(raw)
    assert r.status != "ok"
    assert r.findings


@pytest.mark.parametrize(
    "raw",
    [
        b"From: a@example.com\x00\r\n\r\n",
        b"X: " + b"a" * 100_000 + b"\r\n\r\n",
        b"".join(b"X%d: v\r\n" % i for i in range(MAX_HEADER_COUNT + 1)) + b"\r\n",
        b"A: " + b"b" * (MAX_RAW_BYTES + 1),
    ],
    ids=["nul", "unfolded-too-long", "too-many-headers", "too-large"],
)
def test_parser_limits_are_error_with_parser_limit_finding(raw: bytes) -> None:
    r = analyze_message(raw)
    assert [f.code for f in r.findings] == ["MSG_PARSER_LIMIT"]
    assert r.status == "error" and r.unevaluated == ("parser",)


def test_received_cap_is_reported_as_limit() -> None:
    hops = tuple(
        f"Received: from a{i}.example (a{i}.example [8.8.8.8]) by b.example; {BASE['Date'][5:]}"
        for i in range(120)
    )
    r = run(("Received",), hops)
    f = _find(r, "MSG_PARSER_LIMIT")
    assert "received" in f.params["limits"]
    assert r.status == "error"


# --- parameters and details -------------------------------------------------------------------


def test_hop_delay_params_and_threshold() -> None:
    assert HOP_DELAY_HIGH_SECONDS == 3600
    at = (
        "Received: from a.example (a.example [8.8.8.8]) by b.example; Tue, 03 Nov 2026 11:00:00 +0000",  # noqa: E501
    )
    old = (
        "Received: from c.example (c.example [8.8.4.4]) by a.example; Tue, 03 Nov 2026 10:00:00 +0000",  # noqa: E501
    )
    assert "MSG_HOP_DELAY_HIGH" not in codes(run(("Received",), at + old))  # exactly 3600 s
    over = at[0].replace("11:00:00", "11:00:01")
    f = _find(run(("Received",), (over,) + old), "MSG_HOP_DELAY_HIGH")
    assert f.params["delay_seconds"] == 3601 and f.params["hop"] == 2


def test_date_skew_params() -> None:
    f = _find(
        run(("Date",), ("Date: Mon, 02 Nov 2026 08:00:00 +0000",)), "MSG_DATE_FAR_FROM_RECEIVED"
    )
    assert f.params["skew_hours"] == 26 and f.params["max_hours"] == 24


def test_spf_severity_and_result_param() -> None:
    fail = _find(
        run(("Authentication-Results",), (AR.replace("spf=pass", "spf=fail"),)), "MSG_SPF_NOT_PASS"
    )
    soft = _find(
        run(("Authentication-Results",), (AR.replace("spf=pass", "spf=softfail"),)),
        "MSG_SPF_NOT_PASS",
    )
    assert (fail.severity, fail.params["result"]) == ("high", "fail")
    assert (soft.severity, soft.params["result"]) == ("medium", "softfail")
    none = _find(
        run(
            ("Authentication-Results",),
            ("Authentication-Results: mx.example.net; dkim=pass header.d=example.com",),
        ),
        "MSG_SPF_NOT_PASS",
    )
    assert none.severity == "low" and none.detail_key.endswith("detail_not_stated")


def test_authserv_mismatch_lists_ids_escaped() -> None:
    r = run(
        ("Authentication-Results",),
        (
            'Authentication-Results: "<b>x</b>.example"; dmarc=pass header.from=example.com',
            "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@example.com;"
            " dkim=pass header.d=example.com",
        ),
    )
    f = _find(r, "MSG_AUTHRES_AUTHSERV_MISMATCH")
    assert f.params["count"] == 2
    assert "<b>x</b>.example" in f.params["ids"]  # raw: the output layer escapes


def test_untrusted_authres_does_not_make_message_pass() -> None:
    # A forged all-pass header from an unrelated server still yields a mismatch finding.
    r = run(
        ("Authentication-Results",),
        (
            "Authentication-Results: forged.example; dmarc=pass header.from=example.com",
            "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=b@example.com;"
            " dkim=pass header.d=example.com",
        ),
    )
    assert "MSG_AUTHRES_AUTHSERV_MISMATCH" in codes(r) and r.status != "ok"


def test_private_ip_origin_param() -> None:
    r = run(
        ("Received",), (f"Received: from pc (pc [10.1.2.3]) by mx.example.net; {BASE['Date'][5:]}",)
    )
    f = _find(r, "MSG_RECEIVED_PRIVATE_IP_ORIGIN")
    assert (f.severity, f.params["ip"]) == ("info", "10.1.2.3")


def test_received_for_address_never_in_findings() -> None:
    secret = "victim.secret@example.org"
    hop = f"Received: from pc (pc [10.1.2.3]) by mx.example.net for <{secret}>; {BASE['Date'][5:]}"
    r = run(("Received",), (hop, "Received: garbage"))
    assert r.findings
    assert all(secret not in f.model_dump_json() for f in r.findings)


def test_info_codes_are_info() -> None:
    r = run(
        ("Return-Path", "List-Unsubscribe", "List-Unsubscribe-Post"), ("Reply-To: help@other.org",)
    )
    assert {f.severity for f in r.findings} == {"info"}
    assert r.status == "info"


def test_missing_data_is_never_ok() -> None:
    bare = analyze_message(b"Subject: x\r\n\r\nbody")
    assert bare.status != "ok"
    assert {
        "MSG_MISSING_FROM",
        "MSG_MISSING_DATE",
        "MSG_RECEIVED_NONE",
        "MSG_AUTHRES_MISSING",
    } <= codes(bare)


def test_findings_build_through_finding_and_have_matching_keys() -> None:
    r = run(("Date", "From"), ("Reply-To: help@other.org",))
    for f in r.findings:
        assert f.title_key == f"finding.{f.code}.title"
        assert f.detail_key == f"finding.{f.code}.detail"
        assert f.remediation_key == f"finding.{f.code}.remediation"


# --- excerpt ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "plain"),
        ("a\x00b\x1b[31mc\r\nd\te", "ab[31mcde"),
        ("a&b", "a&b"),
        ("<script>alert('x')</script>", "<script>alert('x')</script>"),
        ("a‮b​c d", "abcd"),
        ("", ""),
        (None, "None"),
        (12, "12"),
    ],
)
def test_excerpt_cases(text: object, expected: str) -> None:
    assert excerpt(text) == expected


@pytest.mark.parametrize("filler", ["a", "<", "&", "\x00a", "é", "\"'"])
def test_excerpt_is_bounded_and_unescaped(filler: str) -> None:
    out = excerpt(filler * 1000)
    assert len(out) <= MAX_EXCERPT
    assert not any(ord(c) < 32 for c in out)
    if filler == "<":
        assert out == "<" * MAX_EXCERPT


def test_long_header_derived_params_are_bounded() -> None:
    ident = "x" * 150 + ".example"
    ars = (
        f"Authentication-Results: {ident}1; dmarc=pass header.from=example.com",
        f"Authentication-Results: {ident}2; spf=pass smtp.mailfrom=b@example.com;"
        " dkim=pass header.d=example.com",
    )
    f = _find(run(("Authentication-Results",), ars), "MSG_AUTHRES_AUTHSERV_MISMATCH")
    assert len(f.params["ids"]) <= (mf.MAX_EXCERPT + 2) * 6


# --- i18n -------------------------------------------------------------------------------------


def test_codes_are_valid_unique_and_prefixed() -> None:
    assert len(set(CODES)) == len(CODES) == 34
    assert all(CODE_RE.fullmatch(c) and c.startswith("MSG_") for c in CODES)


def test_every_positive_case_covers_a_code() -> None:
    assert {p[0] for p in POSITIVE} | {"MSG_PARSER_LIMIT"} == set(CODES)  # limit: own tests


def test_every_code_has_a_negative_case() -> None:
    assert {n[0] for n in NEGATIVE} >= set(CODES) - {
        "MSG_MISSING_FROM",
        "MSG_MISSING_DATE",
        "MSG_DATE_INVALID",
        "MSG_MISSING_MESSAGE_ID",
        "MSG_RECEIVED_NONE",
        "MSG_RECEIVED_UNPARSED",
        "MSG_AUTHRES_MISSING",
        "MSG_RETURN_PATH_MISSING",
        "MSG_LIST_UNSUBSCRIBE_MISSING",
        "MSG_PARSER_LIMIT",
    }


def test_every_emitted_code_is_declared() -> None:
    emitted = {p[0] for p in POSITIVE}
    for _, drop, add, body in POSITIVE:
        emitted |= codes(run(drop, add, body=body))
    assert emitted <= set(CODES)


@pytest.mark.parametrize("code", CODES)
def test_codes_have_complete_i18n(code: str) -> None:
    for part in ("title", "detail", "remediation"):
        k = f"finding.{code}.{part}"
        assert EN.get(k) and IT.get(k), k
        assert i18n.placeholders(EN[k]) == i18n.placeholders(IT[k]), k
    rem = f"finding.{code}.remediation"
    assert EN[rem] != IT[rem], f"{rem}: it is a copy of en"
    assert EN[f"finding.{code}.detail"] != IT[f"finding.{code}.detail"]


def test_italian_texts_are_not_english_placeholders() -> None:
    for code in CODES:
        title = IT[f"finding.{code}.title"]
        assert not title.startswith("["), title
        assert title != EN[f"finding.{code}.title"]


@pytest.mark.parametrize("code", CODES)
def test_placeholders_are_supplied_by_the_emitted_params(code: str) -> None:
    """Every placeholder in a text is a param of at least one emitted finding."""
    wanted: set[str] = set()
    for part in ("title", "detail", "remediation"):
        wanted |= i18n.placeholders(EN[f"finding.{code}.{part}"])
    if not wanted:
        return
    seen: set[str] = set()
    for _c, drop, add, body in POSITIVE:
        for f in run(drop, add, body=body).findings:
            if f.code == code:
                seen |= set(f.params)
    assert wanted <= seen, (code, wanted - seen)


def test_unusable_reply_to_is_info_and_does_not_make_status_error() -> None:
    r = run((), ("Reply-To: not an address",))
    assert "reply_to" not in r.unevaluated and r.evaluated
    f = _find(r, "MSG_REPLY_TO_UNUSABLE")
    assert f.severity == "info" and r.status == "info"


@pytest.mark.parametrize("variant", ["spf", "dkim", "dmarc"])
def test_not_stated_uses_its_own_translated_detail(variant: str) -> None:
    code = f"MSG_{variant.upper()}_NOT_PASS"
    key = f"finding.{code}.detail_not_stated"
    assert EN[key] and IT[key] and EN[key] != IT[key]
    assert i18n.placeholders(EN[key]) == i18n.placeholders(IT[key]) == set()
    r = run(("Authentication-Results",), ("Authentication-Results: mx.example.net; auth=pass",))
    f = _find(r, code)
    assert f.detail_key == key and "result" not in f.params


@pytest.mark.parametrize("code", CODES)
def test_no_english_tokens_are_substituted_into_text(code: str) -> None:
    banned = {"limits", "computed", "issues"}
    for part in ("title", "detail", "remediation"):
        assert not (i18n.placeholders(EN[f"finding.{code}.{part}"]) & banned)
    assert "not_stated" not in "".join(
        f"{EN[k]}{IT[k]}" for k in EN if k.startswith(f"finding.{code}.")
    )


def _nested_body(depth: int) -> str:
    """Body under boundary ``b0`` nesting multipart containers ``depth`` levels deep."""
    head = "".join(
        f"--b{i}\r\nContent-Type: multipart/mixed; boundary=b{i + 1}\r\n\r\n" for i in range(depth)
    )
    return head + f"--b{depth}\r\nContent-Type: text/plain\r\n\r\nx\r\n"


_MANY_PARTS = (
    "".join("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n" for _ in range(250)) + "--b--\r\n"
)
_FEW_PARTS = "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n"
_MIXED = ('Content-Type: multipart/mixed; boundary="b"',)

# (id, add, body, capped limits); depth bodies replace the whole message body
MIME_CAP_CASES = [
    ("neither", _MIXED, _FEW_PARTS, ()),
    ("parts", _MIXED, _MANY_PARTS, ("mime_parts",)),
    ("depth", ('Content-Type: multipart/mixed; boundary="b0"',), _nested_body(30), ("mime_depth",)),
    (
        "both",
        _MIXED,
        _nested_body(30).replace("--b0", "--b") + _MANY_PARTS,
        ("mime_parts", "mime_depth"),
    ),
    (
        "boundary_too_long",
        ('Content-Type: multipart/mixed; boundary="' + "b" * 100 + '"',),
        "x",
        ("mime_boundary",),
    ),
]


@pytest.mark.parametrize(
    ("add", "body", "limits"),
    [c[1:] for c in MIME_CAP_CASES],
    ids=[c[0] for c in MIME_CAP_CASES],
)
def test_mime_cap_is_error_class(add: tuple[str, ...], body: str, limits: tuple[str, ...]) -> None:
    r = run(("Content-Type",), add, body=body)
    found = codes(r)
    if limits == ():
        assert r.status != "error" and "MSG_PARSER_LIMIT" not in found
        assert "MSG_MIME_TRUNCATED" not in found
        return
    assert r.status == "error"
    assert "MSG_PARSER_LIMIT" in found and "MSG_MIME_TRUNCATED" in found
    assert "parser" in r.unevaluated
    text = " ".join(str(f.params) for f in r.findings if f.code == "MSG_PARSER_LIMIT")
    for label in limits or ():
        assert label in text


_BAD_PART = "--b\r\nContent-Type: ;;;\r\nContent-Transfer-Encoding: ???\r\n\r\nx\r\n"


@pytest.mark.parametrize(
    "body",
    [
        # warnings list full before the depth cap is reached
        "".join(_BAD_PART for _ in range(150)) + _nested_body(30).replace("--b0", "--b"),
        # warnings list full, then the part cap
        "".join(_BAD_PART for _ in range(250)) + "--b--\r\n",
    ],
    ids=["warnings_full_then_depth", "warnings_full_then_parts"],
)
def test_mime_cap_after_warning_list_is_full(body: str) -> None:
    r = run(("Content-Type",), _MIXED, body=body)
    assert r.status == "error"
    assert "MSG_PARSER_LIMIT" in codes(r)


# --- R1-10: every error status carries a finding that says why ---------------------------------

EXPLAINS_ERROR = frozenset(
    {
        "MSG_DATE_INVALID",
        "MSG_DATE_NO_TIMEZONE",
        "MSG_RECEIVED_UNPARSED",
        "MSG_PARSER_LIMIT",
        "MSG_AUTHRES_UNPARSED",
        "MSG_ALIGNMENT_NOT_EVALUATED",
    }
)
_AR_DROP = ("Authentication-Results",)

# (add, expected code, text expected in the finding parameters)
SILENT_PATHS = [
    ((_NO_AUTHSERV_AR,), "MSG_AUTHRES_UNPARSED", "missing_authserv_id"),
    (("Authentication-Results: mx.example.net; spf",), "MSG_AUTHRES_UNPARSED", ""),
    (("Authentication-Results: dkim=fail",), "MSG_ALIGNMENT_NOT_EVALUATED", "missing_d"),
    (("Authentication-Results: mx.example.net; dkim=fail",), "MSG_ALIGNMENT_NOT_EVALUATED", ""),
]


@pytest.mark.parametrize(
    ("add", "code", "param"), SILENT_PATHS, ids=[f"{s[1]}-{i}" for i, s in enumerate(SILENT_PATHS)]
)
def test_silent_error_paths_are_explained(add: tuple[str, ...], code: str, param: str) -> None:
    r = run(_AR_DROP, add)
    assert r.status == "error" and not r.evaluated
    assert code in codes(r)
    f = _find(r, code)
    assert f.severity == "medium"
    assert param in str(f.params)


def test_alignment_finding_lists_reasons_only() -> None:
    r = run(_AR_DROP, ("Authentication-Results: dkim=fail",))
    f = _find(r, "MSG_ALIGNMENT_NOT_EVALUATED")
    assert "reasons" in f.params
    assert "dkim=fail" not in str(f.params)


HOSTILE: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    ((), ()),
    (("Date",), ("Date: ???",)),
    (("Date",), ("Date: Tue, 03 Nov 2026 10:00:00",)),
    (("Received",), ("Received: garbage",)),
    (("Received",), ("Received: ",)),
    (_AR_DROP, ("Authentication-Results: ;;;",)),
    (_AR_DROP, ("Authentication-Results: (unterminated",)),
    (_AR_DROP, ("Authentication-Results: mx.example.net; spf",)),
    (_AR_DROP, (_NO_AUTHSERV_AR,)),
    (_AR_DROP, ("Authentication-Results: dkim=fail",)),
    (_AR_DROP, ("Authentication-Results: =; =",)),
    (("From",), ("From: <<<>>>",)),
    (("From",), ("From: nobody",)),
    (("From",), ()),
    (
        ("Received",),
        tuple(f"Received: from a{i}.example by b.example; {BASE['Date'][5:]}" for i in range(120)),
    ),
]


@pytest.mark.parametrize("case", range(len(HOSTILE)))
def test_every_not_evaluated_result_has_an_explaining_finding(case: int) -> None:
    drop, add = HOSTILE[case]
    r = run(drop, add)
    if r.evaluated:
        return
    assert codes(r) & EXPLAINS_ERROR, (r.unevaluated, codes(r))


@pytest.mark.parametrize(
    "raw",
    [b"\x00", b"From: a@example.com\x00\r\n\r\n", b"A: " + b"b" * (MAX_RAW_BYTES + 1)],
    ids=["nul", "nul-header", "too-large"],
)
def test_rejected_input_is_explained(raw: bytes) -> None:
    r = analyze_message(raw)
    assert not r.evaluated
    assert codes(r) & EXPLAINS_ERROR
