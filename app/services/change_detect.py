"""Change events of a scheduled run (M7-10). Pure: no database, no network, no clock.

Inputs are plain values: the stored state of a check (`CheckState`, from a `check_runs` row or a
fresh `CheckResult`) and DNS snapshots (`app.services.dns_diff.Snapshot`). Outputs are typed
`ChangeEvent`s. Delivery, dedup state and alert storage are M7-14; this module only says what
changed.

Event kinds:
- `record_changed`: a monitored DNS entry was added, removed or changed between the baseline and
  the new snapshot (`dns_diff.diff_snapshots`). The caller passes as baseline the LAST NON-ERROR
  state of each entry (`dns_diff.carry_forward` folded over the stored history), so a change
  across a transient lookup error is still seen; `inconclusive` changes produce nothing.
- `new_listing` / `listing_cleared` (check `dnsbl` only), one event per list id, judged PER LIST
  (M7-10b): a list the new run evaluated (`listed` or not listed) is compared with that list's
  own baseline, its outcome in the newest earlier run where THAT list was evaluated
  (`list_baseline`). `listed` now and not listed then is `new_listing`; the reverse is
  `listing_cleared`. A list in `error` (or not applicable, or unknown) in the new run yields no
  listing event for that list, never a false "cleared"; a list never evaluated before is its own
  baseline (no event). Other lists are judged normally even when one list errors, so one list
  failing for good no longer blocks the listing events of every list. The check's overall status
  is untouched (one list in error keeps the whole run `error`, see app.checks.dnsbl).
  Stored runs keep findings only, so a stored run's per-list view comes from them
  (`list_view_of_findings`): `DNSBL_LISTED` = listed, `DNSBL_LIST_ERROR` / `_REFUSED` /
  `_UNVERIFIED` = error, any other list = not listed (or disabled: indistinguishable). A stored
  `error` run without per-list error findings (enablement unreadable, timeout, internal error)
  has no per-list view and is skipped. Truncated stored findings are read as they are: no event
  is suppressed because of them; a repeated `new_listing` has the same fingerprint, so M7-14
  dedups it.
- `policy_regression`: the status of an evaluated check got worse than the baseline by
  `STATUS_RANK` (ok = info < warn < fail). `ok -> info` is not a regression; improvements produce
  nothing. The `dnsbl` check is excluded: its changes are the listing events above, and one new
  listing must not alert twice.
- `check_error_started` / `check_error_cleared`: the check could not evaluate (`error`) after a
  run that could, and back.

Rules shared by every kind:
- An `error` result produces ONLY `check_error_started` (or nothing while it stays `error`): never
  a cleared listing or a regression. The one exception is the per-list DNSBL judgement above: in
  a DNSBL run that is `error` because some lists errored, the lists that WERE evaluated still get
  their listing events.
- `baseline` for regressions is the last NON-ERROR run of the check; `previous` (the latest run,
  any status) is used only for the error transitions; listings use the per-list baseline.
- No baseline (first evaluated run) means no listing/regression event: the run is the baseline.
  No previous run at all means no event at all.

Not produced here: expiring certificates or keys (SPEC 4.3). No check reads certificates or key
expiry before M9; documented in docs/MONITORING.md (M7-20).

Fingerprint: SHA-256 over the canonical JSON `[kind, domain_id, subject, state_hash]`, where
`state_hash` is SHA-256 of the event's new state (`after`). Identical facts give identical
fingerprints across runs and processes; M7-14 dedups on it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, NamedTuple

from app.services.dns_diff import Snapshot, diff_snapshots

EventKind = Literal[
    "record_changed",
    "new_listing",
    "listing_cleared",
    "policy_regression",
    "check_error_started",
    "check_error_cleared",
]

DNSBL_CHECK_ID: Final = "dnsbl"
DNSBL_LISTED: Final = "DNSBL_LISTED"
# Per-list error findings of app.checks.dnsbl (that list could not be evaluated).
DNSBL_LIST_ERRORS: Final = frozenset(
    {"DNSBL_LIST_ERROR", "DNSBL_LIST_REFUSED", "DNSBL_LIST_UNVERIFIED"}
)
ListOutcome = Literal["listed", "not_listed", "error"]
ERROR: Final = "error"
# Severity ordering of evaluated statuses (`error` is outside it: not evaluated).
STATUS_RANK: Final[Mapping[str, int]] = {"ok": 0, "info": 0, "warn": 1, "fail": 2}
ABSENT: Final = "absent"  # the `after` of a removed record


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True, slots=True)
class ChangeEvent:
    """One change. `subject` names what changed (a check id, a DNSBL list id or
    `<name> <rdtype>` of a DNS entry); `before`/`after` are short state values (a status, an
    entry hash, `listed`/`not_listed`, `absent`), never record text or finding text."""

    kind: EventKind
    domain_id: int
    subject: str
    before: str | None
    after: str
    check_id: str | None = None

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.kind, self.domain_id, self.subject, self.after)


def fingerprint(kind: str, domain_id: int, subject: str, new_state: str) -> str:
    """Deterministic dedup key: (kind, domain_id, subject, hash of the new state)."""
    payload = json.dumps(
        [kind, domain_id, subject, _sha(new_state)], ensure_ascii=True, separators=(",", ":")
    )
    return _sha(payload)


@dataclass(frozen=True, slots=True)
class ListView:
    """Per-list outcome of one DNSBL run.

    `listed` / `errored`: list ids listed / in error. `evaluated`: the ids known to be evaluated
    (listed or not listed); None means "every list neither listed nor errored was evaluated and
    not listed", which is how a stored run is read (its findings name only listed and errored
    lists)."""

    listed: frozenset[str] = frozenset()
    errored: frozenset[str] = frozenset()
    evaluated: frozenset[str] | None = None

    def outcome(self, list_id: str) -> ListOutcome | None:
        """`listed`, `not_listed`, `error`, or None (not evaluated: not applicable or unknown)."""
        if list_id in self.errored:
            return "error"
        if list_id in self.listed:
            return "listed"
        if self.evaluated is None or list_id in self.evaluated:
            return "not_listed"
        return None


@dataclass(frozen=True, slots=True)
class CheckState:
    """What change detection needs of one check run: its id, its status and, for the DNSBL
    check, its per-list view (None: not DNSBL, or no per-list detail, e.g. the whole check
    failed before any list was queried)."""

    check_id: str
    status: str
    lists: ListView | None = None

    @property
    def is_error(self) -> bool:
        return self.status not in STATUS_RANK


class CheckInput(NamedTuple):
    """One check of a run for `detect_events`: the new state, the latest stored run (any
    status), the latest stored non-error run, and (DNSBL only) the per-list baseline built by
    `list_baseline`."""

    current: CheckState
    previous: CheckState | None
    baseline: CheckState | None
    lists_baseline: ListView | None = None


def _list_id(params: object) -> str | None:
    if not isinstance(params, Mapping):
        return None
    list_id = params.get("list_id")
    return list_id if isinstance(list_id, str) and list_id else None


def listed_ids(findings: Iterable[tuple[str, Mapping[str, Any]]]) -> frozenset[str]:
    """List ids of `DNSBL_LISTED` findings given as (code, params); malformed params are ignored."""
    out: set[str] = set()
    for code, params in findings:
        list_id = _list_id(params)
        if code == DNSBL_LISTED and list_id is not None:
            out.add(list_id)
    return frozenset(out)


def list_view_of_findings(
    status: str, findings: Iterable[tuple[str, Mapping[str, Any]]]
) -> ListView | None:
    """The per-list view of a STORED DNSBL run (code + params only): `DNSBL_LISTED` is listed,
    the per-list error codes are error, every other list counts as not listed. None for an
    `error` run without any per-list error finding (the check failed as a whole, so nothing is
    known about any list). Malformed params are ignored."""
    listed: set[str] = set()
    errored: set[str] = set()
    for code, params in findings:
        list_id = _list_id(params)
        if list_id is None:
            continue
        if code == DNSBL_LISTED:
            listed.add(list_id)
        elif code in DNSBL_LIST_ERRORS:
            errored.add(list_id)
    if status not in STATUS_RANK and not errored:
        return None
    return ListView(frozenset(listed - errored), frozenset(errored))


def list_view_of_data(data: Mapping[str, Any]) -> ListView | None:
    """The per-list view of a FRESH DNSBL result from `data.lists[*]`: `listed`; `not_listed`
    or `info` (evaluated, not listed); `error`; `not_applicable` (not evaluated). None when the
    data is missing or malformed (then no listing event at all)."""
    lists = data.get("lists") if isinstance(data, Mapping) else None
    if not isinstance(lists, (list, tuple)):
        return None
    listed: set[str] = set()
    errored: set[str] = set()
    evaluated: set[str] = set()
    for item in lists:
        if not isinstance(item, Mapping):
            return None
        list_id, outcome = item.get("id"), item.get("outcome")
        if not isinstance(list_id, str) or not list_id or not isinstance(outcome, str):
            return None
        if outcome == "error":
            errored.add(list_id)
        elif outcome == "listed":
            listed.add(list_id)
            evaluated.add(list_id)
        elif outcome in ("not_listed", "info"):
            evaluated.add(list_id)
    return ListView(frozenset(listed - errored), frozenset(errored), frozenset(evaluated - errored))


def evaluated_ids(data: Mapping[str, Any]) -> frozenset[str] | None:
    """List ids a fresh DNSBL result evaluated (outcome other than `not_applicable` or `error`);
    None when the data is missing or malformed."""
    view = list_view_of_data(data)
    return None if view is None else view.evaluated


def list_baseline(wanted: Iterable[str], views: Iterable[ListView | None]) -> ListView:
    """The per-list baseline: for each wanted list id, its outcome in the newest view (`views`
    newest first) where THAT list was evaluated. Views of None (no per-list detail) and views
    where the list errored or was not evaluated are passed over. `views` is consumed lazily and
    no further than needed, so the caller can page through history. The result's `evaluated`
    names the lists that have a baseline; a list without one gets no listing event."""
    pending = set(wanted)
    listed: set[str] = set()
    resolved: set[str] = set()
    if pending:
        for view in views:
            if view is None:
                continue
            for list_id in sorted(pending):
                outcome = view.outcome(list_id)
                if outcome not in ("listed", "not_listed"):
                    continue
                if outcome == "listed":
                    listed.add(list_id)
                resolved.add(list_id)
                pending.discard(list_id)
            if not pending:
                break
    return ListView(frozenset(listed), frozenset(), frozenset(resolved))


def detect_check_events(
    domain_id: int,
    current: CheckState,
    *,
    previous: CheckState | None,
    baseline: CheckState | None,
    lists_baseline: ListView | None = None,
) -> list[ChangeEvent]:
    """Events of one check. `previous`: the latest stored run (any status); `baseline`: the
    latest stored run that was not `error`; `lists_baseline` (DNSBL only): the per-list baseline
    from `list_baseline` (rules in the module docstring)."""
    cid = current.check_id
    events: list[ChangeEvent] = []
    if previous is None:
        return events  # first run: the baseline
    if current.is_error:
        if not previous.is_error:
            events.append(
                ChangeEvent("check_error_started", domain_id, cid, previous.status, ERROR, cid)
            )
    elif previous.is_error:
        events.append(
            ChangeEvent("check_error_cleared", domain_id, cid, ERROR, current.status, cid)
        )
    if cid == DNSBL_CHECK_ID:
        events.extend(_listing_events(domain_id, current.lists, lists_baseline))
        return events
    if current.is_error or baseline is None or baseline.is_error:
        return events
    if STATUS_RANK[current.status] > STATUS_RANK[baseline.status]:
        events.append(
            ChangeEvent("policy_regression", domain_id, cid, baseline.status, current.status, cid)
        )
    return events


def _listing_events(
    domain_id: int, current: ListView | None, baseline: ListView | None
) -> list[ChangeEvent]:
    """Per-list events, new listings then cleared ones, each sorted by list id. Only lists the
    new run evaluated (`current.evaluated`) and that have a baseline are judged."""
    if current is None or current.evaluated is None or baseline is None:
        return []
    new: list[str] = []
    cleared: list[str] = []
    for list_id in sorted(current.evaluated):
        now, before = current.outcome(list_id), baseline.outcome(list_id)
        if now == "listed" and before == "not_listed":
            new.append(list_id)
        elif now == "not_listed" and before == "listed":
            cleared.append(list_id)
    cid = DNSBL_CHECK_ID
    return [
        *(ChangeEvent("new_listing", domain_id, i, "not_listed", "listed", cid) for i in new),
        *(
            ChangeEvent("listing_cleared", domain_id, i, "listed", "not_listed", cid)
            for i in cleared
        ),
    ]


def detect_record_events(
    domain_id: int, baseline: Snapshot | None, current: Snapshot | None
) -> list[ChangeEvent]:
    """`record_changed` events from the baseline (last non-error state per entry) to the new
    snapshot. No baseline (first snapshot) or no new snapshot (could not be taken): none."""
    if baseline is None or current is None:
        return []
    events: list[ChangeEvent] = []
    for change in diff_snapshots(baseline, current):
        if change.kind == "inconclusive":
            continue
        events.append(
            ChangeEvent(
                "record_changed",
                domain_id,
                f"{change.name} {change.rdtype}",
                change.before_hash if change.before_hash is not None else ABSENT,
                change.after_hash if change.after_hash is not None else ABSENT,
            )
        )
    return events


def detect_events(
    domain_id: int,
    checks: Sequence[CheckInput],
    snapshot_baseline: Snapshot | None,
    snapshot: Snapshot | None,
) -> list[ChangeEvent]:
    """All events of one run: one `CheckInput` per check, then the record changes. Order:
    checks in the given order, then records sorted by entry."""
    events: list[ChangeEvent] = []
    for item in checks:
        events.extend(
            detect_check_events(
                domain_id,
                item.current,
                previous=item.previous,
                baseline=item.baseline,
                lists_baseline=item.lists_baseline,
            )
        )
    events.extend(detect_record_events(domain_id, snapshot_baseline, snapshot))
    return events


__all__ = [
    "DNSBL_CHECK_ID",
    "STATUS_RANK",
    "ChangeEvent",
    "CheckInput",
    "CheckState",
    "ListView",
    "EventKind",
    "detect_check_events",
    "detect_events",
    "detect_record_events",
    "evaluated_ids",
    "fingerprint",
    "list_baseline",
    "list_view_of_data",
    "list_view_of_findings",
    "listed_ids",
]
