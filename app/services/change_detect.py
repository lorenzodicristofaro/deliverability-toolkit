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
- `new_listing` / `listing_cleared` (check `dnsbl` only), one event per list id: a list id in
  `DNSBL_LISTED` findings now and not in the baseline, or the reverse. A list is reported cleared
  only when the new run actually evaluated it (a list that was disabled, or that the new run did
  not report on, is not "cleared"). Against a baseline whose stored findings were truncated no new
  listing is reported (its list ids may be incomplete).
- `policy_regression`: the status of an evaluated check got worse than the baseline by
  `STATUS_RANK` (ok = info < warn < fail). `ok -> info` is not a regression; improvements produce
  nothing. The `dnsbl` check is excluded: its changes are the listing events above, and one new
  listing must not alert twice.
- `check_error_started` / `check_error_cleared`: the check could not evaluate (`error`) after a
  run that could, and back.

Rules shared by every kind:
- An `error` result produces ONLY `check_error_started` (or nothing while it stays `error`): never
  a listing, a cleared listing or a regression. A DNSBL run where any list errors is `error` as a
  whole (app.checks.dnsbl), so listing changes wait until a run evaluates every list.
- `baseline` for listings and regressions is the last NON-ERROR run of the check; `previous` (the
  latest run, any status) is used only for the error transitions.
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
from typing import Any, Final, Literal

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
class CheckState:
    """What change detection needs of one check run.

    `listed`: DNSBL list ids in `DNSBL_LISTED` findings. `evaluated`: list ids the run evaluated
    (from a fresh result's data); None when unknown (a stored row keeps no data), and then no list
    is reported cleared against it. `complete`: False when the stored findings were truncated, so
    `listed` may miss ids; no new listing is then reported against it."""

    check_id: str
    status: str
    listed: frozenset[str] = frozenset()
    evaluated: frozenset[str] | None = None
    complete: bool = True

    @property
    def is_error(self) -> bool:
        return self.status not in STATUS_RANK


def listed_ids(findings: Iterable[tuple[str, Mapping[str, Any]]]) -> frozenset[str]:
    """List ids of `DNSBL_LISTED` findings given as (code, params); malformed params are ignored."""
    out: set[str] = set()
    for code, params in findings:
        if code != DNSBL_LISTED or not isinstance(params, Mapping):
            continue
        list_id = params.get("list_id")
        if isinstance(list_id, str) and list_id:
            out.add(list_id)
    return frozenset(out)


def evaluated_ids(data: Mapping[str, Any]) -> frozenset[str] | None:
    """List ids a fresh DNSBL result evaluated (`data.lists[*]` with an outcome other than
    `not_applicable` or `error`); None when the data is missing or malformed."""
    lists = data.get("lists") if isinstance(data, Mapping) else None
    if not isinstance(lists, (list, tuple)):
        return None
    out: set[str] = set()
    for item in lists:
        if not isinstance(item, Mapping):
            return None
        list_id, outcome = item.get("id"), item.get("outcome")
        if not isinstance(list_id, str) or not isinstance(outcome, str):
            return None
        if outcome not in ("not_applicable", "error"):
            out.add(list_id)
    return frozenset(out)


def detect_check_events(
    domain_id: int,
    current: CheckState,
    *,
    previous: CheckState | None,
    baseline: CheckState | None,
) -> list[ChangeEvent]:
    """Events of one check. `previous`: the latest stored run (any status); `baseline`: the
    latest stored run that was not `error` (rules in the module docstring)."""
    cid = current.check_id
    events: list[ChangeEvent] = []
    if previous is None:
        return events  # first run: the baseline
    if current.is_error:
        if not previous.is_error:
            events.append(
                ChangeEvent("check_error_started", domain_id, cid, previous.status, ERROR, cid)
            )
        return events
    if previous.is_error:
        events.append(
            ChangeEvent("check_error_cleared", domain_id, cid, ERROR, current.status, cid)
        )
    if baseline is None or baseline.is_error:
        return events
    if cid == DNSBL_CHECK_ID:
        new = current.listed - baseline.listed if baseline.complete else frozenset()
        for list_id in sorted(new):
            events.append(
                ChangeEvent("new_listing", domain_id, list_id, "not_listed", "listed", cid)
            )
        if current.evaluated is not None:
            for list_id in sorted((baseline.listed - current.listed) & current.evaluated):
                events.append(
                    ChangeEvent("listing_cleared", domain_id, list_id, "listed", "not_listed", cid)
                )
        return events
    if STATUS_RANK[current.status] > STATUS_RANK[baseline.status]:
        events.append(
            ChangeEvent("policy_regression", domain_id, cid, baseline.status, current.status, cid)
        )
    return events


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
    checks: Sequence[tuple[CheckState, CheckState | None, CheckState | None]],
    snapshot_baseline: Snapshot | None,
    snapshot: Snapshot | None,
) -> list[ChangeEvent]:
    """All events of one run: `checks` is (current, previous, baseline) per check, then the
    record changes. Order: checks in the given order, then records sorted by entry."""
    events: list[ChangeEvent] = []
    for current, previous, baseline in checks:
        events.extend(detect_check_events(domain_id, current, previous=previous, baseline=baseline))
    events.extend(detect_record_events(domain_id, snapshot_baseline, snapshot))
    return events


__all__ = [
    "DNSBL_CHECK_ID",
    "STATUS_RANK",
    "ChangeEvent",
    "CheckState",
    "EventKind",
    "detect_check_events",
    "detect_events",
    "detect_record_events",
    "evaluated_ids",
    "fingerprint",
    "listed_ids",
]
