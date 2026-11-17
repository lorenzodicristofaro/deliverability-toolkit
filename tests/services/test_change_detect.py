"""M7-10 change detection: pure, table-driven, no database, no network."""

from typing import Any

import pytest

from app.services.change_detect import (
    STATUS_RANK,
    ChangeEvent,
    CheckState,
    detect_check_events,
    detect_events,
    detect_record_events,
    evaluated_ids,
    fingerprint,
    listed_ids,
)
from app.services.dns_diff import build_entry, build_snapshot, carry_forward

D = 7


def st(status: str, listed: tuple[str, ...] = (), *, check: str = "spf", **kw: Any) -> CheckState:
    return CheckState(check, status, frozenset(listed), **kw)


def bl(status: str, listed: tuple[str, ...] = (), **kw: Any) -> CheckState:
    return st(status, listed, check="dnsbl", **kw)


def kinds(events: list[ChangeEvent]) -> list[tuple[str, str]]:
    return [(e.kind, e.subject) for e in events]


# --- severity ordering -------------------------------------------------------------------------


def test_status_rank_orders_evaluated_statuses_and_leaves_error_out() -> None:
    assert STATUS_RANK["ok"] == STATUS_RANK["info"] < STATUS_RANK["warn"] < STATUS_RANK["fail"]
    assert "error" not in STATUS_RANK
    assert st("error").is_error and st("bogus").is_error and not st("info").is_error


# --- check events ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("current", "previous", "baseline", "expected"),
    [
        # first run (no history at all): the baseline, whatever it is
        (st("fail"), None, None, []),
        (st("error"), None, None, []),
        # unchanged / improvements / not-worse
        (st("ok"), st("ok"), st("ok"), []),
        (st("ok"), st("fail"), st("fail"), []),
        (st("info"), st("ok"), st("ok"), []),
        (st("ok"), st("info"), st("info"), []),
        (st("warn"), st("warn"), st("warn"), []),
        # regressions by the ordering
        (st("warn"), st("ok"), st("ok"), [("policy_regression", "spf")]),
        (st("fail"), st("ok"), st("ok"), [("policy_regression", "spf")]),
        (st("fail"), st("warn"), st("warn"), [("policy_regression", "spf")]),
        (st("warn"), st("info"), st("info"), [("policy_regression", "spf")]),
        # error: only the error events, never a regression
        (st("error"), st("ok"), st("ok"), [("check_error_started", "spf")]),
        (st("error"), st("error"), st("ok"), []),
        (st("ok"), st("error"), st("ok"), [("check_error_cleared", "spf")]),
        # recovery compares against the last non-error baseline: ok, error, fail = regression
        (
            st("fail"),
            st("error"),
            st("ok"),
            [("check_error_cleared", "spf"), ("policy_regression", "spf")],
        ),
        # first evaluated run after only errors: cleared, no regression (it is the baseline)
        (st("fail"), st("error"), None, [("check_error_cleared", "spf")]),
        # malformed stored status counts as error, never as ok
        (st("fail"), st("bogus"), None, [("check_error_cleared", "spf")]),
    ],
)
def test_check_events(
    current: CheckState,
    previous: CheckState | None,
    baseline: CheckState | None,
    expected: list[tuple[str, str]],
) -> None:
    assert kinds(detect_check_events(D, current, previous=previous, baseline=baseline)) == expected


@pytest.mark.parametrize(
    ("current", "previous", "baseline", "expected"),
    [
        (bl("ok", evaluated=frozenset({"a"})), None, None, []),
        (bl("fail", ("a",)), None, None, []),  # listed on the first run: baseline, no event
        (bl("fail", ("a",)), bl("ok"), bl("ok"), [("new_listing", "a")]),
        (
            bl("fail", ("a", "b")),
            bl("fail", ("b",)),
            bl("fail", ("b",)),
            [("new_listing", "a")],
        ),
        (
            bl("ok", evaluated=frozenset({"a", "b"})),
            bl("fail", ("a",)),
            bl("fail", ("a",)),
            [("listing_cleared", "a")],
        ),
        # cleared only when the new run evaluated the list (disabled / unknown: no "cleared")
        (bl("ok", evaluated=frozenset({"b"})), bl("fail", ("a",)), bl("fail", ("a",)), []),
        (bl("ok"), bl("fail", ("a",)), bl("fail", ("a",)), []),
        # an error run: only the error event, no listing and no cleared
        (
            bl("error", ("c",)),
            bl("fail", ("a",)),
            bl("fail", ("a",)),
            [("check_error_started", "dnsbl")],
        ),
        (bl("error"), bl("error"), bl("fail", ("a",)), []),
        # back from error: against the last non-error baseline, so a listing that stayed is quiet
        (
            bl("fail", ("a",), evaluated=frozenset({"a"})),
            bl("error"),
            bl("fail", ("a",)),
            [("check_error_cleared", "dnsbl")],
        ),
        (
            bl("fail", ("b",), evaluated=frozenset({"a", "b"})),
            bl("error"),
            bl("fail", ("a",)),
            [("check_error_cleared", "dnsbl"), ("new_listing", "b"), ("listing_cleared", "a")],
        ),
        # dnsbl status changes are listing events, not policy regressions
        (bl("warn", ("a",)), bl("ok"), bl("ok"), [("new_listing", "a")]),
        # truncated baseline: its ids may be incomplete, no new listing against it
        (bl("fail", ("a",)), bl("ok"), bl("ok", complete=False), []),
    ],
)
def test_dnsbl_events(
    current: CheckState,
    previous: CheckState | None,
    baseline: CheckState | None,
    expected: list[tuple[str, str]],
) -> None:
    assert kinds(detect_check_events(D, current, previous=previous, baseline=baseline)) == expected


def test_event_fields() -> None:
    [event] = detect_check_events(D, bl("fail", ("a",)), previous=bl("ok"), baseline=bl("ok"))
    assert (event.domain_id, event.before, event.after, event.check_id) == (
        D,
        "not_listed",
        "listed",
        "dnsbl",
    )
    [reg] = detect_check_events(D, st("fail"), previous=st("warn"), baseline=st("warn"))
    assert (reg.before, reg.after) == ("warn", "fail")


# --- findings / data parsing (malformed input) -------------------------------------------------


@pytest.mark.parametrize(
    ("findings", "expected"),
    [
        ([], set()),
        ([("DNSBL_LISTED", {"list_id": "a"}), ("DNSBL_LISTED", {"list_id": "b"})], {"a", "b"}),
        ([("DNSBL_LISTED", {"list_id": "a"}), ("DNSBL_LISTED", {"list_id": "a"})], {"a"}),
        ([("DNSBL_LIST_ERROR", {"list_id": "a"})], set()),
        ([("DNSBL_LISTED", {})], set()),
        ([("DNSBL_LISTED", {"list_id": ""})], set()),
        ([("DNSBL_LISTED", {"list_id": 3})], set()),
        ([("DNSBL_LISTED", {"list_id": None})], set()),
        ([("DNSBL_LISTED", "not a mapping")], set()),
    ],
)
def test_listed_ids(findings: list[tuple[str, Any]], expected: set[str]) -> None:
    assert listed_ids(findings) == frozenset(expected)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({}, None),
        ({"lists": "x"}, None),
        ({"lists": [1]}, None),
        ({"lists": [{"id": "a"}]}, None),
        ({"lists": [{"id": 1, "outcome": "listed"}]}, None),
        ({"lists": []}, set()),
        (
            {
                "lists": [
                    {"id": "a", "outcome": "listed"},
                    {"id": "b", "outcome": "not_listed"},
                    {"id": "c", "outcome": "info"},
                    {"id": "d", "outcome": "not_applicable"},
                    {"id": "e", "outcome": "error"},
                ]
            },
            {"a", "b", "c"},
        ),
    ],
)
def test_evaluated_ids(data: Any, expected: set[str] | None) -> None:
    got = evaluated_ids(data)
    assert got == (None if expected is None else frozenset(expected))


# --- record events -----------------------------------------------------------------------------


def snap(**entries: Any) -> Any:
    """name -> (state, values) for apex TXT style entries; key `x` -> name `x`."""
    return build_snapshot(
        build_entry("@" if k == "apex" else k, "TXT", state, values)
        for k, (state, values) in entries.items()
    )


X = ("ok", ["v=spf1 -all"])
Y = ("ok", ["v=spf1 ~all"])
ERR = ("error", [])
NX = ("nxdomain", [])


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (None, snap(apex=X), []),  # first snapshot: baseline
        (snap(apex=X), None, []),  # could not be taken
        (snap(apex=X), snap(apex=X), []),
        (snap(apex=X), snap(apex=Y), [("record_changed", "@ TXT")]),
        (snap(apex=NX), snap(apex=X), [("record_changed", "@ TXT")]),
        (snap(apex=X), snap(apex=NX), [("record_changed", "@ TXT")]),
        (snap(apex=X), snap(apex=ERR), []),  # inconclusive, never "removed"
        (snap(apex=ERR), snap(apex=X), []),
        (snap(apex=X), snap(apex=X, _dmarc=X), []),  # newly monitored name: inconclusive
    ],
)
def test_record_events(before: Any, after: Any, expected: list[tuple[str, str]]) -> None:
    assert kinds(detect_record_events(D, before, after)) == expected


def test_record_change_across_an_error_is_seen_with_carry_forward() -> None:
    a, b, c = snap(apex=X), snap(apex=ERR), snap(apex=Y)
    assert detect_record_events(D, a, b) == []
    baseline = carry_forward(a, b)
    [event] = detect_record_events(D, baseline, c)
    assert event.before == a.entries[0].entry_hash and event.after == c.entries[0].entry_hash


def test_removed_record_after_is_absent() -> None:
    [event] = detect_record_events(D, snap(apex=X), snap(apex=NX))
    assert event.after == "absent" and event.check_id is None


def test_detect_events_combines_checks_then_records() -> None:
    events = detect_events(
        D,
        [(st("error"), st("ok"), st("ok")), (bl("fail", ("a",)), bl("ok"), bl("ok"))],
        snap(apex=X),
        snap(apex=Y),
    )
    assert kinds(events) == [
        ("check_error_started", "spf"),
        ("new_listing", "a"),
        ("record_changed", "@ TXT"),
    ]


# --- fingerprint -------------------------------------------------------------------------------


def test_fingerprint_is_deterministic_and_pinned() -> None:
    fp = fingerprint("new_listing", 7, "zen", "listed")
    assert fp == fingerprint("new_listing", 7, "zen", "listed")
    assert len(fp) == 64 and all(ch in "0123456789abcdef" for ch in fp)
    # pinned: a change of the formula changes dedup keys stored by M7-14
    assert fp == "e4b4888026c5b774bf528de2bda1b8131bae88ce9ed5551ede99fffba31fa29e"
    event = ChangeEvent("new_listing", 7, "zen", "not_listed", "listed", "dnsbl")
    assert event.fingerprint == fp


@pytest.mark.parametrize(
    "other",
    [
        ("listing_cleared", 7, "zen", "listed"),
        ("new_listing", 8, "zen", "listed"),
        ("new_listing", 7, "zen2", "listed"),
        ("new_listing", 7, "zen", "not_listed"),
    ],
)
def test_fingerprint_changes_with_each_component(other: tuple[str, int, str, str]) -> None:
    assert fingerprint(*other) != fingerprint("new_listing", 7, "zen", "listed")


def test_fingerprint_ignores_the_before_state() -> None:
    a = ChangeEvent("policy_regression", 7, "spf", "ok", "fail", "spf")
    b = ChangeEvent("policy_regression", 7, "spf", "warn", "fail", "spf")
    assert a.fingerprint == b.fingerprint
