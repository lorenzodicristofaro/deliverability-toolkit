"""Tests for app.services.message_analysis (M4-10). Offline; no network, clock or DB."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from app.checks.models import Finding
from app.parsers.message import MAX_HEADER_COUNT, MAX_RAW_BYTES
from app.services import message_analysis as ma
from app.services.message_analysis import MessageAnalysis, analyze_message, redact_received

SECRET = "victim.secret@private.example"
AR = (
    "mx.example.net; spf=pass smtp.mailfrom=b@example.com;"
    " dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
)


def msg(extra: str = "", body: str = "hello\r\n") -> bytes:
    head = (
        "Return-Path: <b@example.com>\r\n"
        f"Received: from mail.example.com (mail.example.com [8.8.4.4]) by mx.example.net"
        f" with ESMTPS id 1 for <{SECRET}>; Tue, 03 Nov 2026 10:00:05 +0000\r\n"
        "Received: from a.example.org (a.example.org [8.8.8.8]) by mail.example.com"
        " with SMTP id 0; Tue, 03 Nov 2026 10:00:01 +0000\r\n"
        "From: A <a@example.com>\r\n"
        "To: x@example.net, y@example.net\r\n"
        "Cc: z@example.net\r\n"
        "Subject: =?utf-8?B?Y2Fmw6k=?=\r\n"
        "Date: Tue, 03 Nov 2026 10:00:00 +0000\r\n"
        "Message-ID: <1@example.com>\r\n"
        f"Authentication-Results: {AR}\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain\r\n"
    )
    return (head + extra + "\r\n" + body).encode()


def test_happy_path_sections() -> None:
    a = analyze_message(msg())
    assert a.summary is not None
    assert a.summary.subject == "café"
    assert (a.summary.to_count, a.summary.cc_count) == (2, 1)
    assert a.summary.date_utc == "2026-11-03T10:00:00Z"
    assert a.received is not None and len(a.received.hops) == 2
    assert a.authentication is not None and a.authentication[0].authserv_id == "mx.example.net"
    assert a.arc is not None and a.arc.status == "none"
    assert a.alignment is not None and a.alignment.computed_dmarc == "pass"
    assert a.mime is not None and a.mime.has_text_plain
    assert a.mime.sizes.total_bytes == len(msg())
    assert a.status != "error"


def test_findings_sorted_severity_then_code() -> None:
    a = analyze_message(msg().replace(b"Message-ID: <1@example.com>\r\n", b""))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    keys = [(order[f.severity], f.code) for f in a.findings]
    assert keys == sorted(keys)
    assert a.findings


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"", "empty_input"),
        ("not bytes", "invalid_input"),
        (None, "invalid_input"),
        (12, "invalid_input"),
        (b"A: b\x00c\r\n\r\nbody", "nul_byte"),
        (b"\r\n\r\nonly body", "no_header_block"),
        (b"hello", "no_header_block"),
        (b"no header block here", "no_header_block"),
        (b"line one\r\nline two\r\n\r\nbody", "no_header_block"),
        (b"\x00", "nul_byte"),
        (b"x" * (MAX_RAW_BYTES + 1), "message_too_large"),
        (b"".join(b"H%d: v\r\n" % i for i in range(MAX_HEADER_COUNT + 1)) + b"\r\nb", None),
    ],
)
def test_input_errors_return_error_without_partial_data(raw: Any, code: str | None) -> None:
    a = analyze_message(raw)
    assert a.status == "error"
    assert a.summary is a.received is a.authentication is a.arc is a.alignment is a.mime is None
    assert [f.code for f in a.findings] == ["MSG_PARSER_LIMIT"]
    if code:
        assert a.findings[0].params["limits"] == code


@pytest.mark.parametrize(
    "raw",
    [
        b"Subject: x",
        b"garbage without colon\r\n\r\n",
        b" orphan continuation\r\nFrom: a@b\r\n\r\n",
        b"Received: \r\nAuthentication-Results: ;;;\r\nARC-Seal: i=zz\r\n\r\n",
        b"Content-Type: multipart/mixed; boundary=\r\n\r\n--\r\n",
        bytes(range(1, 256)) + b"\r\n\r\n",
        b"From: =?bogus?Q?x?= <>\r\nTo: <<<,,,\r\nDate: \xff\xfe\r\n\r\n",
    ],
)
def test_malformed_input_never_raises(raw: bytes) -> None:
    a = analyze_message(raw)
    assert isinstance(a, MessageAnalysis)
    json.loads(a.model_dump_json())


def test_received_for_clause_redacted_in_json() -> None:
    a = analyze_message(msg())
    assert a.received is not None
    assert any(h.has_for for h in a.received.hops)
    dumped = a.model_dump_json()
    assert SECRET not in dumped
    assert "private.example" not in dumped
    assert "victim.secret" not in dumped
    assert any("for [redacted]" in h.raw for h in a.received.hops)


@pytest.mark.parametrize(
    ("raw", "expect"),
    [
        ("from a by b for <x@y.z>; Tue, 03 Nov 2026 10:00:00 +0000", "from a by b for [redacted]"),
        ("from a by b FOR x@y.z; Tue, 03 Nov 2026", "FOR".join(["from a by b ", ""])),
        ('from a by b for <"a;b"@y.z>', "from a by b for [redacted]"),
        ('from a by b for <"a@y.z', "from a by b for [redacted]"),
        ("from a by b for\tx@y.z id 5", "from a by b for [redacted]"),
        ("from a by b", "from a by b"),
        ("from a by b for<x@y.z>; Tue, 03 Nov 2026", "from a by b for [redacted]"),
        ("from a by b for(c)<x@y.z>", "from a by b for [redacted]"),
        ("from a by b (for<x@y.z>)", "from a by b (for [redacted]"),
        ("", ""),
    ],
)
def test_redact_received(raw: str, expect: str) -> None:
    out = redact_received(raw)
    assert "@y.z" not in out
    assert "y.z" not in out
    if "FOR" not in raw:
        assert out.startswith(expect)


@pytest.mark.parametrize(
    "clause",
    [
        f"for<{SECRET}>",
        f"for(c)<{SECRET}>",
        f"(for<{SECRET}>)",
        f"FOR\t{SECRET}",
        f"f\u200bor <{SECRET}>",
        f"fo\u202er <{SECRET}>",
    ],
)
def test_for_clause_forms_absent_from_json(clause: str) -> None:
    raw = (
        f"Received: from a.example (a.example [8.8.8.8]) by b.example with SMTP {clause};"
        " Tue, 03 Nov 2026 10:00:00 +0000\r\nFrom: a@b.example\r\n\r\nx"
    ).encode()
    a = analyze_message(raw)
    assert SECRET not in a.model_dump_json()
    assert "private.example" not in a.model_dump_json()
    assert a.received is not None and a.received.hops


def test_redaction_when_hop_unparsed() -> None:
    raw = f"Received: garbage ((( for {SECRET}\r\nFrom: a@b.example\r\n\r\n".encode()
    assert SECRET not in analyze_message(raw).model_dump_json()


def test_deterministic_byte_identical() -> None:
    raw = msg("ARC-Seal: i=1; a=rsa-sha256; d=x.example; s=s; cv=none; b=AAAA\r\n")
    first = analyze_message(raw).model_dump_json()
    for _ in range(3):
        assert analyze_message(raw).model_dump_json() == first
    assert analyze_message(bytearray(raw)).model_dump_json() == first


def test_json_has_no_clock_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom:
        @staticmethod
        def now(*_: Any, **__: Any) -> None:
            raise AssertionError("clock used")

    monkeypatch.setattr(ma, "datetime", _Boom, raising=True)
    # module-level _EPOCH is already built; analysis must not call datetime.now.
    assert analyze_message(msg()).status != "error"


@pytest.mark.parametrize(
    "target",
    [
        "parse_received_chain",
        "parse_all_authentication_results",
        "parse_arc_chain",
        "analyze_alignment",
        "parse_mime",
    ],
)
def test_sub_parser_failure_is_isolated(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom " + SECRET)

    monkeypatch.setattr(ma, target, boom)
    a = analyze_message(msg())
    assert a.status == "error"
    sections = {
        "parse_received_chain": "received",
        "parse_all_authentication_results": "authentication",
        "parse_arc_chain": "arc",
        "analyze_alignment": "alignment",
        "parse_mime": "mime",
    }
    assert getattr(a, sections[target]) is None
    others = [n for n in sections.values() if n != sections[target]]
    assert all(getattr(a, n) is not None for n in others)
    assert a.summary is not None
    limits = [f.params["limits"] for f in a.findings if f.code == "MSG_PARSER_LIMIT"]
    assert any(str(x).endswith("_failed") for x in limits)
    assert SECRET not in a.model_dump_json()


def test_findings_builder_failure_is_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise ValueError("x")

    monkeypatch.setattr(ma, "build_message_findings", boom)
    a = analyze_message(msg())
    assert a.status == "error"
    assert a.received is not None and a.mime is not None
    assert [f.code for f in a.findings] == ["MSG_PARSER_LIMIT"]


def test_unexpected_error_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("x")

    monkeypatch.setattr(ma, "parse_header_block", boom)
    assert analyze_message(msg()).status == "error"


def test_strings_are_bounded_and_control_free() -> None:
    long_subject = "S" * 5000 + "\x07"
    a = analyze_message(f"Subject: {long_subject}\r\nFrom: a@b.example\r\n\r\n".encode())
    assert a.summary is not None and a.summary.subject is not None
    assert len(a.summary.subject) <= 200
    assert "\x07" not in a.model_dump_json()


def test_findings_are_finding_objects() -> None:
    assert all(isinstance(f, Finding) for f in analyze_message(msg()).findings)


# --- 2 MiB hostile-input time guard -----------------------------------------------------------

TIME_BUDGET_S = 30.0  # generous: guards against super-linear blowups, not micro-performance


def _pad(head: bytes, body: bytes = b"") -> bytes:
    """Header block (kept under the header cap so the parsers really run) plus filler body."""
    raw = head + b"\r\n" + body
    return raw + b"A" * (MAX_RAW_BYTES - len(raw))


def _fold_bomb() -> bytes:
    # one Subject folded across ~60 KiB, then a 2 MiB body
    return _pad(b"Subject: x\r\n" + b" y\r\n" * 15000)


def _many_headers() -> bytes:
    lines = [b"Received: from a (a [8.8.8.8]) by b; Tue, 03 Nov 2026 10:00:00 +0000\r\n"] * 100
    lines += [b"Authentication-Results: mx; spf=pass; dkim=none; x=y\r\n"] * 200
    lines += [b"ARC-Seal: i=%d; a=rsa-sha256; d=x; s=s; cv=none; b=A\r\n" % i for i in range(60)]
    lines += [b"X-H%d: v\r\n" % i for i in range(MAX_HEADER_COUNT - len(lines))]
    assert len(lines) == MAX_HEADER_COUNT
    return _pad(b"".join(lines))


def _deep_mime() -> bytes:
    head = b"Content-Type: multipart/mixed; boundary=b0\r\n"
    body = b"".join(
        b"--b%d\r\nContent-Type: multipart/mixed; boundary=b%d\r\n\r\n" % (i, i + 1)
        for i in range(20000)
    )
    return _pad(head, body)


def _many_parts() -> bytes:
    head = b"Content-Type: multipart/mixed; boundary=b\r\n"
    body = b"--b\r\nContent-Type: text/plain\r\n\r\nx\r\n" * 50000
    return _pad(head, body)


@pytest.mark.parametrize("build", [_fold_bomb, _many_headers, _deep_mime, _many_parts])
def test_hostile_two_mib_inputs_finish_in_bounded_time(build: Any) -> None:
    raw = build()
    assert len(raw) == MAX_RAW_BYTES
    start = time.perf_counter()
    a = analyze_message(raw)
    elapsed = time.perf_counter() - start
    assert elapsed < TIME_BUDGET_S, elapsed
    assert isinstance(a, MessageAnalysis)
    assert a.summary is not None  # header block accepted: the parsers really ran
    payload = a.model_dump_json()
    assert len(payload) < 16 * 1024 * 1024
    json.loads(payload)


_FALSE_CODES = {
    "parse_received_chain": {"MSG_RECEIVED_NONE", "MSG_RECEIVED_UNPARSED"},
    "parse_all_authentication_results": {"MSG_AUTHRES_MISSING", "MSG_DMARC_NOT_PASS"},
    "parse_arc_chain": {"MSG_ARC_INVALID", "MSG_ARC_CV_FAIL"},
    "analyze_alignment": {"MSG_DMARC_NOT_PASS", "MSG_ALIGNMENT_FAIL", "MSG_AUTHRES_MISSING"},
    "parse_mime": {"MSG_NO_TEXT_PART", "MSG_MIME_TRUNCATED"},
}


@pytest.mark.parametrize("target", list(_FALSE_CODES))
def test_failed_section_produces_no_false_findings(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    clean = {f.code for f in analyze_message(msg()).findings}
    assert not clean & _FALSE_CODES[target]

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(ma, target, boom)
    a = analyze_message(msg())
    assert a.status == "error"
    codes = {f.code for f in a.findings}
    assert not codes & _FALSE_CODES[target]
    assert any(f.params.get("limits", "").endswith("_failed") for f in a.findings)


def test_authres_failure_keeps_unrelated_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("boom")

    raw = msg().replace(b"Message-ID: <1@example.com>\r\n", b"")
    monkeypatch.setattr(ma, "parse_all_authentication_results", boom)
    a = analyze_message(raw)
    codes = {f.code for f in a.findings}
    assert "MSG_MISSING_MESSAGE_ID" in codes
    assert "MSG_AUTHRES_MISSING" not in codes
    assert "authentication_results_failed" in {f.params.get("limits") for f in a.findings}
    assert a.authentication is None and a.received is not None


def _hop_json(raw_hop: str) -> str:
    raw = f"Received: {raw_hop}\r\nFrom: a@b.example\r\n\r\nx".encode()
    return analyze_message(raw).model_dump_json()


@pytest.mark.parametrize(
    "hop",
    [
        f"from a.example by b\tf\u200bor <{SECRET}>; Tue, 03 Nov 2026 10:00:00 +0000",
        f"from a.example by b\u200bFO\tR<{SECRET}>; Tue, 03 Nov 2026 10:00:00 +0000",
        f"from a.example by b\u200bfor\u200b<{SECRET}>; Tue, 03 Nov 2026 10:00:00 +0000",
        f"from a.example by b.example (envelope-from <{SECRET}>); Tue, 03 Nov 2026 10:00:00 +0000",
        f"from a.example by b.example (user {SECRET} ok); Tue, 03 Nov 2026 10:00:00 +0000",
        'from a.example by b.example (envelope-from "victim secret"@private.example);'
        " Tue, 03 Nov 2026 10:00:00 +0000",
        'from a.example by b.example (x <"victim secret"@private.example>);'
        " Tue, 03 Nov 2026 10:00:00 +0000",
        f"from a.example by {SECRET} with SMTP; Tue, 03 Nov 2026 10:00:00 +0000",
        f"from {SECRET} by b.example id <{SECRET}>; Tue, 03 Nov 2026 10:00:00 +0000",
    ],
)
def test_hop_address_leaks_closed(hop: str) -> None:
    dumped = _hop_json(hop)
    for needle in ("victim.secret", "private.example", "victim secret", "SECRET"):
        assert needle not in dumped
    assert '"victim' not in dumped


def test_clean_raw_masks_at_tokens_and_envelope_from() -> None:
    out = ma._clean_raw("from a (envelope-from <a@b>) by c (u@h) id 1")
    assert "@" not in out and out.count("[redacted]") == 2
    assert out.startswith("from a (envelope-from [redacted]")


def test_hop_field_with_address_is_dropped_with_warning() -> None:
    from app.parsers.received import ReceivedHop

    hop = ReceivedHop(
        index=0,
        raw="from x by y",
        parsed=True,
        from_host="ok.example",
        from_ip=None,
        from_ip_reserved=None,
        by_host=f"b\u200b@{SECRET}",
        via=None,
        with_protocol="SMTP<x>",
        id=SECRET,
        has_for=False,
        timestamp=None,
        delay_seconds=None,
        warnings=(),
    )
    v = ma._hop(hop)
    assert (v.by_host, v.with_protocol, v.id) == (None, None, None)
    assert v.from_host == "ok.example"
    assert v.warnings == ("hop_field_redacted",)


def test_for_keyword_obfuscation_fuzz() -> None:
    import random

    base = f"from a.example by b.example for <{SECRET}>; Tue, 03 Nov 2026 10:00:00 +0000"
    start = base.index("for <")
    end = start + len("for <" + SECRET + ">")
    chars = ["\t", "\u200b", "\u202e", "\r", "\n", "\x00", "\u2028", "\ufeff", "\x0b"]
    # every position of the keyword + address, every inserted character
    for pos in range(start, end + 1):
        for ch in chars:
            text = base[:pos] + ch + base[pos:]
            assert SECRET not in ma._clean_raw(text)
            assert "victim.secret" not in ma._clean_raw(text)
    rng = random.Random(20261107)
    for _ in range(300):
        text = base
        for _ in range(rng.randint(1, 4)):
            p = rng.randint(start, end)
            text = text[:p] + rng.choice(chars) + text[p:]
        assert "victim.secret" not in ma._clean_raw(text)
        if not any(c in text for c in "\r\n\x00\x0b\u2028"):
            assert "victim.secret" not in _hop_json(text)


def test_colonless_lines_with_one_valid_header_stay_evaluated() -> None:
    a = analyze_message(b"junk line\r\nFrom: a@b.example\r\nmore junk\r\n\r\nbody")
    assert a.status != "error"
    assert a.summary is not None
