"""M7-10 / M7-10b change detection: pure, table-driven, no database, no network."""

from collections.abc import Iterator
from typing import Any

import pytest

from app.services.change_detect import (
    STATUS_RANK,
    ChangeEvent,
    CheckInput,
    CheckState,
    ListView,
    detect_check_events,
    detect_events,
    detect_record_events,
    evaluated_ids,
    fingerprint,
    list_baseline,
    list_view_of_data,
    list_view_of_findings,
    listed_ids,
)
from app.services.dns_diff import build_entry, build_snapshot, carry_forward

D = 7


def st(status: str, *, check: str = "spf", lists: ListView | None = None) -> CheckState:
    return CheckState(check, status, lists)


def view(
    listed: tuple[str, ...] = (), clean: tuple[str, ...] = (), errored: tuple[str, ...] = ()
) -> ListView:
    """A fresh run's view: `listed` and `clean` evaluated, `errored` in error, others n/a."""
    return ListView(frozenset(listed), frozenset(errored), frozenset(listed + clean))


def bl(
    status: str,
    listed: tuple[str, ...] = (),
    clean: tuple[str, ...] = (),
    errored: tuple[str, ...] = (),
) -> CheckState:
    return st(status, check="dnsbl", lists=view(listed, clean, errored))


def prev(status: str) -> CheckState:
    return st(status, check="dnsbl")


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
        # a malformed baseline status is no baseline
        (st("fail"), st("ok"), st("bogus"), []),
    ],
)
def test_check_events(
    current: CheckState,
    previous: CheckState | None,
    baseline: CheckState | None,
    expected: list[tuple[str, str]],
) -> None:
    assert kinds(detect_check_events(D, current, previous=previous, baseline=baseline)) == expected


# DNSBL is judged per list against `lists_baseline` (each list's last evaluated outcome).
@pytest.mark.parametrize(
    ("current", "previous", "lists_baseline", "expected"),
    [
        # first run: the baseline, whatever is listed
        (bl("fail", ("a",)), None, None, []),
        (bl("fail", ("a",)), None, view(clean=("a",)), []),
        # all lists evaluated, both runs
        (bl("ok", clean=("a", "b")), prev("ok"), view(clean=("a", "b")), []),
        (bl("fail", ("a",), ("b",)), prev("ok"), view(clean=("a", "b")), [("new_listing", "a")]),
        (bl("fail", ("a", "b")), prev("fail"), view(("b",), ("a",)), [("new_listing", "a")]),
        (
            bl("ok", clean=("a", "b")),
            prev("fail"),
            view(("a",), ("b",)),
            [("listing_cleared", "a")],
        ),
        (
            bl("fail", ("b",), ("a",)),
            prev("fail"),
            view(("a",), ("b",)),
            [("new_listing", "b"), ("listing_cleared", "a")],
        ),
        (bl("fail", ("a",)), prev("fail"), view(("a",)), []),  # still listed
        # one list errors while another changes: the other one still gets its event
        (
            bl("error", ("a",), errored=("b",)),
            prev("ok"),
            view(clean=("a", "b")),
            [("check_error_started", "dnsbl"), ("new_listing", "a")],
        ),
        (
            bl("error", clean=("a",), errored=("b",)),
            prev("error"),
            view(("a", "b")),
            [("listing_cleared", "a")],
        ),
        # the erroring list itself: no listing and never a false "cleared"
        (bl("error", errored=("a",)), prev("error"), view(("a",)), []),
        (
            bl("error", errored=("a",)),
            prev("ok"),
            view(clean=("a",)),
            [("check_error_started", "dnsbl")],
        ),
        # list errors then recovers: judged against its own last evaluated outcome
        (bl("fail", ("a",)), prev("error"), view(("a",)), [("check_error_cleared", "dnsbl")]),
        (
            bl("ok", clean=("a",)),
            prev("error"),
            view(("a",)),
            [("check_error_cleared", "dnsbl"), ("listing_cleared", "a")],
        ),
        (
            bl("fail", ("a",)),
            prev("error"),
            view(clean=("a",)),
            [("check_error_cleared", "dnsbl"), ("new_listing", "a")],
        ),
        # list never evaluated in the baseline (errored in every earlier run): its own baseline
        (bl("fail", ("a",)), prev("error"), view(), [("check_error_cleared", "dnsbl")]),
        (bl("fail", ("a", "b")), prev("fail"), view(clean=("b",)), [("new_listing", "b")]),
        # not evaluated now (disabled / not applicable): never "cleared"
        (bl("ok", clean=("b",)), prev("fail"), view(("a",), ("b",)), []),
        # no per-list detail now (internal error, malformed data) or no baseline: no listing
        (prev("error"), prev("fail"), view(("a",)), [("check_error_started", "dnsbl")]),
        (st("ok", check="dnsbl", lists=ListView()), prev("fail"), view(("a",)), []),
        (bl("fail", ("a",)), prev("ok"), None, []),
        # dnsbl status changes are listing events, not policy regressions
        (bl("warn", ("a",)), prev("ok"), view(clean=("a",)), [("new_listing", "a")]),
    ],
)
def test_dnsbl_events(
    current: CheckState,
    previous: CheckState | None,
    lists_baseline: ListView | None,
    expected: list[tuple[str, str]],
) -> None:
    got = detect_check_events(
        D, current, previous=previous, baseline=previous, lists_baseline=lists_baseline
    )
    assert kinds(got) == expected


def test_event_fields() -> None:
    [event] = detect_check_events(
        D, bl("fail", ("a",)), previous=prev("ok"), baseline=None, lists_baseline=view(clean=("a",))
    )
    assert (event.domain_id, event.before, event.after, event.check_id) == (
        D,
        "not_listed",
        "listed",
        "dnsbl",
    )
    [reg] = detect_check_events(D, st("fail"), previous=st("warn"), baseline=st("warn"))
    assert (reg.before, reg.after) == ("warn", "fail")


def test_listing_fingerprints_are_stable_per_list() -> None:
    """The same listing gives the same fingerprint whatever else happens in the run (another
    list erroring, the overall status), and a different list a different one."""
    base = view(clean=("a", "b", "c"))

    def fp(current: CheckState) -> dict[str, str]:
        events = detect_check_events(
            D, current, previous=prev("ok"), baseline=None, lists_baseline=base
        )
        return {e.subject: e.fingerprint for e in events if e.kind == "new_listing"}

    alone = fp(bl("fail", ("a",), ("b", "c")))
    with_error = fp(bl("error", ("a",), ("b",), errored=("c",)))
    both = fp(bl("fail", ("a", "b"), ("c",)))
    assert alone == with_error == {"a": both["a"]} and both["b"] != both["a"]


# --- per-list baseline ---------------------------------------------------------------------------


def stored(status: str, listed: tuple[str, ...] = (), errored: tuple[str, ...] = ()) -> Any:
    findings = [("DNSBL_LISTED", {"list_id": i}) for i in listed]
    findings += [("DNSBL_LIST_ERROR", {"list_id": i}) for i in errored]
    return list_view_of_findings(status, findings)


@pytest.mark.parametrize(
    ("wanted", "views", "listed", "resolved"),
    [
        ((), [stored("fail", ("a",))], set(), set()),
        (("a", "b"), [], set(), set()),
        # the newest view evaluating each list wins
        (("a", "b"), [stored("fail", ("a",)), stored("ok")], {"a"}, {"a", "b"}),
        (("a",), [stored("ok"), stored("fail", ("a",))], set(), {"a"}),
        # a list in error is looked up further back, the other lists are not
        (
            ("a", "b"),
            [stored("error", errored=("a",)), stored("error", ("a",), ("b",))],
            {"a"},
            {"a", "b"},
        ),
        # whole-check errors (no per-list detail) are passed over
        (("a",), [None, stored("error"), stored("fail", ("a",))], {"a"}, {"a"}),
        # errored in every run: no baseline for that list
        (("a", "b"), [stored("error", errored=("a",))] * 3, set(), {"b"}),
    ],
)
def test_list_baseline(
    wanted: tuple[str, ...], views: list[Any], listed: set[str], resolved: set[str]
) -> None:
    got = list_baseline(wanted, views)
    assert (got.listed, got.evaluated, got.errored) == (
        frozenset(listed),
        frozenset(resolved),
        frozenset(),
    )


def test_list_baseline_reads_no_further_than_needed() -> None:
    consumed: list[int] = []

    def views() -> Iterator[ListView | None]:
        for i in range(1000):
            consumed.append(i)
            yield stored("error", errored=("a",)) if i < 60 else stored("ok")

    got = list_baseline(["a", "b"], views())
    assert got.evaluated == frozenset({"a", "b"}) and got.listed == frozenset()
    assert consumed == list(range(61))  # 60 runs with `a` in error, then the one resolving it


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
    ("status", "findings", "expected"),
    [
        ("ok", [], ((), ())),
        ("fail", [("DNSBL_LISTED", {"list_id": "a"})], (("a",), ())),
        (
            "error",
            [
                ("DNSBL_LISTED", {"list_id": "a"}),
                ("DNSBL_LIST_ERROR", {"list_id": "b"}),
                ("DNSBL_LIST_REFUSED", {"list_id": "c"}),
                ("DNSBL_LIST_UNVERIFIED", {"list_id": "d"}),
            ],
            (("a",), ("b", "c", "d")),
        ),
        # an error run without per-list errors failed as a whole: no per-list view
        ("error", [], None),
        ("error", [("CHECK_INTERNAL_ERROR", {"reason": "timeout"})], None),
        ("error", [("DNSBL_ENABLEMENT_UNAVAILABLE", {"reason": "x"})], None),
        ("error", [("DNSBL_LISTED", {"list_id": "a"})], None),
        ("bogus", [("DNSBL_LIST_ERROR", {"list_id": "a"})], ((), ("a",))),
        # malformed params are ignored; a list both listed and errored counts as errored
        ("error", [("DNSBL_LIST_ERROR", {"list_id": 3})], None),
        (
            "error",
            [("DNSBL_LIST_ERROR", "x"), ("DNSBL_LIST_ERROR", {"list_id": "a"})],
            ((), ("a",)),
        ),
        (
            "error",
            [("DNSBL_LISTED", {"list_id": "a"}), ("DNSBL_LIST_ERROR", {"list_id": "a"})],
            ((), ("a",)),
        ),
        ("ok", [("OTHER", {"list_id": "a"})], ((), ())),
    ],
)
def test_list_view_of_findings(status: str, findings: list[tuple[str, Any]], expected: Any) -> None:
    got = list_view_of_findings(status, findings)
    if expected is None:
        assert got is None
        return
    assert got == ListView(frozenset(expected[0]), frozenset(expected[1]), None)
    # every list neither listed nor errored reads as evaluated, not listed
    assert got.outcome("zz") == "not_listed"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({}, None),
        ("x", None),
        ({"lists": "x"}, None),
        ({"lists": [1]}, None),
        ({"lists": [{"id": "a"}]}, None),
        ({"lists": [{"id": 1, "outcome": "listed"}]}, None),
        ({"lists": [{"id": "", "outcome": "listed"}]}, None),
        ({"lists": []}, set()),
        (
            {
                "lists": [
                    {"id": "a", "outcome": "listed"},
                    {"id": "b", "outcome": "not_listed"},
                    {"id": "c", "outcome": "info"},
                    {"id": "d", "outcome": "not_applicable"},
                    {"id": "e", "outcome": "error"},
                    {"id": "f", "outcome": "something new"},
                ]
            },
            {"a", "b", "c"},
        ),
    ],
)
def test_evaluated_ids(data: Any, expected: set[str] | None) -> None:
    got = evaluated_ids(data)
    assert got == (None if expected is None else frozenset(expected))


def test_list_view_of_data_outcomes() -> None:
    got = list_view_of_data({"lists": lists_data(a="listed", b="not_listed", d="n", e="error")})
    assert got is not None
    assert [got.outcome(i) for i in ("a", "b", "d", "e", "x")] == [
        "listed",
        "not_listed",
        None,
        "error",
        None,
    ]


def lists_data(**outcomes: str) -> list[dict[str, str]]:
    return [{"id": k, "outcome": "not_applicable" if v == "n" else v} for k, v in outcomes.items()]


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
        [
            CheckInput(st("error"), st("ok"), st("ok")),
            CheckInput(bl("fail", ("a",)), prev("ok"), prev("ok"), view(clean=("a",))),
        ],
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
