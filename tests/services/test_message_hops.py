"""Tests for app.services.message_hops (F-01-01). Offline; no network, clock or DB."""

from __future__ import annotations

from typing import Any

import pytest

from app.parsers.arc import parse_arc_chain
from app.parsers.authres import AuthResParseError, parse_all_authentication_results
from app.parsers.message import HeaderBlock, HeaderField, parse_header_block
from app.parsers.received import parse_received_chain
from app.services.message_hops import (
    BREAK_RESULTS,
    HopTimeline,
    build_hop_view,
    find_auth_breaks,
)


def _view_of(block: HeaderBlock, *, auth_failed: bool = False) -> HopTimeline:
    headers: Any
    try:
        headers = None if auth_failed else parse_all_authentication_results(block)
    except AuthResParseError:
        headers = None
    return build_hop_view(block, parse_received_chain(block), headers, parse_arc_chain(block))


def view(*lines: str, auth_failed: bool = False) -> HopTimeline:
    raw = ("\r\n".join(("From: a@example.com", *lines)) + "\r\n\r\nbody").encode()
    return _view_of(parse_header_block(raw), auth_failed=auth_failed)


def rcv(by: str, sec: int) -> str:
    return f"Received: from h{sec}.example by {by}; Tue, 03 Nov 2026 10:00:{sec:02d} +0000"


def ar(authserv: str, body: str) -> str:
    return f"Authentication-Results: {authserv}; {body}"


def arc_set(i: int, cv: str, aar: str, *, d: str = "list.example") -> tuple[str, str, str]:
    return (
        f"ARC-Seal: i={i}; a=rsa-sha256; cv={cv}; d={d}; s=s1; b=abc",
        f"ARC-Message-Signature: i={i}; a=rsa-sha256; d={d}; s=s1; h=from; bh=x; b=abc",
        f"ARC-Authentication-Results: i={i}; {aar}",
    )


def shape(t: HopTimeline) -> list[tuple[Any, ...]]:
    return [(e.kind, e.hop, e.authres_index, e.arc_instance, e.parsed) for e in t.entries]


PASS_ALL = (
    "spf=pass smtp.mailfrom=b@example.com; dkim=pass header.d=example.com;"
    " dmarc=pass header.from=example.com"
)


# --- ordering ---------------------------------------------------------------------------------


def test_interleaved_entries_follow_header_position_oldest_first() -> None:
    # ARC set i=1 sits above i=2 (instances out of header order): position decides.
    t = view(
        *arc_set(1, "none", "mx.final.example; arc=pass"),
        ar("mx.final.example", "dkim=fail header.d=example.com"),
        rcv("mx.final.example", 20),
        *arc_set(2, "pass", "list.example; dkim=pass header.d=example.com"),
        rcv("list.example", 10),
        ar("list.example", "dkim=pass header.d=example.com"),
        rcv("out.example.com", 1),
    )
    assert shape(t) == [
        ("received", 0, None, None, True),
        ("authres", 0, 1, None, True),
        ("received", 1, None, None, True),
        ("arc_set", 1, None, 2, True),
        ("received", 2, None, None, True),
        ("authres", 2, 0, None, True),
        ("arc_set", 2, None, 1, True),
    ]
    assert [e.order for e in t.entries] == list(range(7))
    positions = [e.position for e in t.entries]
    assert positions == sorted(positions, reverse=True)
    top_arc = t.entries[-1]
    assert (top_arc.arc_domain, top_arc.arc_cv, top_arc.authserv_id) == (
        "list.example",
        "none",
        "mx.final.example",
    )
    assert [(r.method, r.result) for r in top_arc.results] == [("arc", "pass")]


def test_entries_are_interleaved_by_position_not_by_type() -> None:
    t = view(
        ar("mx.example.org", "spf=pass smtp.mailfrom=b@example.com"),
        ar("mx.example.org", "dkim=pass header.d=example.com"),
        rcv("mx.example.org", 5),
    )
    assert [e.kind for e in t.entries] == ["received", "authres", "authres"]
    assert [e.authres_index for e in t.entries] == [None, 1, 0]
    assert [e.hop for e in t.entries] == [0, 0, 0]


def test_field_above_no_received_has_no_hop() -> None:
    t = view(rcv("mx.example.org", 5), ar("mx.example.net", "spf=pass"))
    assert [(e.kind, e.hop) for e in t.entries] == [("authres", None), ("received", 0)]


def test_empty_message_and_failed_sections() -> None:
    assert view().entries == ()
    raw = (rcv("x.example", 1) + "\r\n" + ar("mx.example.org", "spf=pass") + "\r\n\r\n").encode()
    block = parse_header_block(raw)
    t = build_hop_view(block, None, None, None)
    # Received and ARC failed: no entries for them; Authentication-Results read field by field.
    assert shape(t) == [("authres", None, 0, None, True)]


# --- stated, not verifiable -------------------------------------------------------------------


def test_forged_lower_field_is_flagged_with_its_authserv_id() -> None:
    t = view(
        ar("mx.example.org", "spf=fail smtp.mailfrom=evil.example; dmarc=fail"),
        rcv("mx.example.org", 5),
        ar("mx.example.org", "dkim=pass header.d=example.com"),
    )
    by_index = {e.authres_index: e for e in t.entries if e.kind == "authres"}
    assert by_index[0].stated_not_verifiable is False
    assert by_index[1].stated_not_verifiable is True
    assert by_index[1].authserv_id == "mx.example.org"
    assert all(
        e.stated_not_verifiable for e in view(*arc_set(1, "none", "a.example; spf=pass")).entries
    )
    assert not any(e.stated_not_verifiable for e in t.entries if e.kind == "received")


# --- breaks -----------------------------------------------------------------------------------


BREAK_CASES = [
    # forwarding: spf/dkim/dmarc pass at the first receiver, spf fail after the forwarder
    (
        (
            ar(
                "mx.final.example",
                "spf=fail smtp.mailfrom=b@example.com; dkim=pass header.d=example.com;"
                " dmarc=pass header.from=example.com",
            ),
            rcv("mx.final.example", 30),
            ar("mx.first.example", PASS_ALL),
            rcv("mx.first.example", 10),
            rcv("out.example.com", 1),
        ),
        [("spf", 1, "fail", "mx.final.example")],
    ),
    # mailing list: dkim pass recorded by the list (AAR), dkim fail after modification
    (
        (
            ar("mx.final.example", "dkim=fail header.d=example.com; arc=pass"),
            rcv("mx.final.example", 30),
            *arc_set(1, "none", "list.example; dkim=pass header.d=example.com"),
            rcv("list.example", 10),
            rcv("out.example.com", 1),
        ),
        [("dkim", 1, "fail", "mx.final.example")],
    ),
    # several methods at the same step, softfail and permerror classes
    (
        (
            ar("mx.b.example", "spf=softfail; dkim=permerror; dmarc=temperror"),
            rcv("mx.b.example", 30),
            ar("mx.a.example", PASS_ALL),
            rcv("mx.a.example", 1),
        ),
        [
            ("dkim", 0, "permerror", "mx.b.example"),
            ("dmarc", 0, "temperror", "mx.b.example"),
            ("spf", 0, "softfail", "mx.b.example"),
        ],
    ),
    # dkim: one passing signature among several counts as pass in both fields: no break
    (
        (
            ar("mx.b.example", "dkim=fail header.d=x.example; dkim=pass header.d=example.com"),
            rcv("mx.b.example", 30),
            ar("mx.a.example", "dkim=pass header.d=example.com"),
            rcv("mx.a.example", 1),
        ),
        [],
    ),
    # pass then none/neutral/policy: not a failure class
    (
        (
            ar("mx.b.example", "spf=neutral; dkim=none; dmarc=none"),
            rcv("mx.b.example", 30),
            ar("mx.a.example", PASS_ALL),
            rcv("mx.a.example", 1),
        ),
        [],
    ),
    # pass, then neutral, then fail: compared with the next newer field only, so no break
    (
        (
            ar("mx.c.example", "spf=fail"),
            ar("mx.b.example", "spf=neutral"),
            ar("mx.a.example", "spf=pass"),
            rcv("mx.a.example", 1),
        ),
        [],
    ),
    # fail then pass (repair): no break
    (
        (
            ar("mx.b.example", "spf=pass"),
            rcv("mx.b.example", 30),
            ar("mx.a.example", "spf=fail"),
            rcv("mx.a.example", 1),
        ),
        [],
    ),
    # a field without the method in between is skipped
    (
        (
            ar("mx.c.example", "spf=fail"),
            ar("mx.b.example", "dkim=pass header.d=example.com"),
            ar("mx.a.example", "spf=pass"),
        ),
        [("spf", None, "fail", "mx.c.example")],
    ),
]


@pytest.mark.parametrize(("lines", "expected"), BREAK_CASES)
def test_breaks_table(lines: tuple[str, ...], expected: list[tuple[Any, ...]]) -> None:
    t = view(*lines)
    got = sorted((b.method, b.hop, b.result, b.authserv_id) for b in find_auth_breaks(t))
    assert got == expected
    for b in find_auth_breaks(t):
        assert b.result in BREAK_RESULTS
        assert b.from_order < b.to_order


# --- malformed --------------------------------------------------------------------------------

_BIG = "x" * (65 * 1024)

# (lines top first, expected (kind, parsed, issue) for the malformed entry)
MALFORMED = [
    (ar("", "spf=pass").replace(": ;", ":"), ("authres", "missing_authserv_id")),
    (
        "Authentication-Results: spf=pass smtp.mailfrom=example.com",
        ("authres", "missing_authserv_id"),
    ),
    (ar("mx.a.example", "spf=pass; dkim="), ("authres", "empty_result")),
    (ar("mx.a.example", "spf"), ("authres", "missing_equals")),
    (ar("mx.a.example", 'spf=pass reason="open'), ("authres", "unterminated_quote")),
    ("Authentication-Results: ", ("authres", "missing_authserv_id")),
    (
        "ARC-Authentication-Results: i=0; mx.a.example; spf=pass",
        ("arc_set", "invalid_instance"),
    ),
    (
        "ARC-Authentication-Results: i=x; mx.a.example; spf=pass",
        ("arc_set", "invalid_instance"),
    ),
    ("ARC-Authentication-Results: mx.a.example; spf=pass", ("arc_set", "ungrouped_field")),
    ("ARC-Authentication-Results: ", ("arc_set", "ungrouped_field")),
]


@pytest.mark.parametrize(("line", "expected"), MALFORMED)
def test_malformed_fields_are_unparsed_and_never_break(
    line: str, expected: tuple[str, str]
) -> None:
    # The malformed field states pass below a fail: it must not produce a break.
    for auth_failed in (False, True):
        t = view(
            ar("mx.top.example", "spf=fail; dkim=fail; arc=fail"),
            rcv("m.example", 5),
            line,
            auth_failed=auth_failed,
        )
        bad = [e for e in t.entries if not e.parsed]
        assert len(bad) == 1
        kind, issue = expected
        assert bad[0].kind == kind and issue in bad[0].issues
        assert bad[0].results == () and bad[0].authserv_id is None and bad[0].arc_domain is None
        assert find_auth_breaks(t) == ()


def test_duplicate_arc_instance_is_kept_as_unparsed_entry() -> None:
    dup = arc_set(1, "none", "b.example; spf=pass", d="b.example")
    t = view(*arc_set(1, "none", "a.example; spf=fail", d="a.example"), *dup)
    arc = [e for e in t.entries if e.kind == "arc_set"]
    grouped = [e for e in arc if e.parsed]
    assert len(grouped) == 1 and grouped[0].arc_domain == "a.example"
    loose = [e for e in arc if not e.parsed]
    assert len(loose) == 3
    assert all("duplicate_instance" in e.issues and e.arc_instance == 1 for e in loose)
    assert find_auth_breaks(t) == ()


def test_incomplete_arc_set_is_unparsed() -> None:
    seal, _ams, aar = arc_set(1, "none", "a.example; dkim=pass")
    t = view(ar("mx.example.org", "dkim=fail"), seal, aar)
    entry = next(e for e in t.entries if e.kind == "arc_set")
    assert not entry.parsed and "missing_member" in entry.issues and entry.results == ()
    assert find_auth_breaks(t) == ()


def _manual_block(*fields: tuple[str, str]) -> HeaderBlock:
    out, pos = [], 0
    for name, value in fields:
        out.append(HeaderField(name, value, value, pos))
        pos += len(name) + len(value) + 4
    return HeaderBlock(tuple(out), pos, ())


@pytest.mark.parametrize(
    ("name", "issue"),
    [
        ("Authentication-Results", "authres_too_large"),
        ("ARC-Authentication-Results", "header_too_large"),
        ("ARC-Seal", "header_too_large"),
    ],
)
def test_oversized_fields_are_unparsed(name: str, issue: str) -> None:
    block = _manual_block(
        ("Authentication-Results", "mx.top.example; spf=fail"),
        (name, f"i=1; mx.a.example; spf=pass {_BIG}"),
    )
    t = _view_of(block)
    bad = [e for e in t.entries if not e.parsed]
    assert len(bad) == 1 and issue in bad[0].issues
    assert find_auth_breaks(t) == ()


def test_nul_byte_field_is_unparsed_when_read_alone() -> None:
    block = _manual_block(
        ("Authentication-Results", "mx.top.example; spf=fail"),
        ("Authentication-Results", "mx.a.example; spf=pass\x00"),
    )
    t = _view_of(block)
    assert [(e.parsed, e.issues) for e in t.entries] == [
        (False, ("nul_byte",)),
        (True, ()),
    ]


def test_deterministic() -> None:
    lines = (
        *arc_set(2, "pass", "b.example; dkim=fail"),
        rcv("b.example", 9),
        *arc_set(1, "none", "a.example; dkim=pass"),
        rcv("a.example", 1),
    )
    assert view(*lines) == view(*lines)
