"""Per-hop authentication view of one message (F-01-01).

Pure and offline: no clock, DNS, network, filesystem or DB, and nothing is verified
cryptographically. :func:`build_hop_view` places every ``Received`` field, every
``Authentication-Results`` field and every ARC set in one list ordered by header position,
and :func:`find_auth_breaks` reports where a stated result goes from pass to a failure class.

Ordering (header position only, never by field type):

- ``Received`` and ``Authentication-Results`` are trace fields that are prepended, so a field
  lower in the header block was added earlier (RFC 5321 section 4.4; RFC 8601 sections 2.1
  and 4.1). RFC 8601 section 4.1 also notes that some handlers only append, and section 7.3
  that fields are sometimes reordered en route, so position is an indication, not proof.
- RFC 8617 orders ARC sets by their instance number (section 4.2.1), not by position, and
  says nothing about where ARC fields sit in the header. Placing an ARC set among the
  ``Received`` fields by the position of its topmost member is a display convention of this
  tool; the instance number is reported next to it.

Entries are listed oldest first: ``order`` 0 is the bottommost field. ``hop`` of a
``Received`` entry is its :attr:`~app.parsers.received.ReceivedHop.index` (0 = oldest); for
the other kinds it is the index of the nearest ``Received`` field below it (the newest hop
added before the field), or None when there is none.

Display only (R1-22 rule: the verdict uses the topmost field): nothing here feeds
``computed_dmarc``, the alignment pairs or any other finding. Every Authentication-Results
field below the topmost one, and every ARC set (its seal is not verified), is marked
``stated_not_verifiable``. Unparsed or malformed fields are kept as ``parsed=False`` entries
with issue codes only and never produce a break. Strings are returned as parsed; the view
layer (``message_analysis``) bounds and cleans them.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, replace
from typing import Literal

from app.parsers.arc import (
    ArcAuthenticationResults,
    ArcChain,
    ArcSet,
    ArcSignature,
)
from app.parsers.authres import (
    HEADER_NAME,
    AuthResHeader,
    AuthResParseError,
    parse_authentication_results,
)
from app.parsers.message import HeaderBlock
from app.parsers.received import ReceivedChain
from app.parsers.spf import ParseIssue

__all__ = [
    "BREAK_RESULTS",
    "HOP_METHODS",
    "HopBreak",
    "HopEntry",
    "HopResult",
    "HopTimeline",
    "build_hop_view",
    "find_auth_breaks",
]

HopKind = Literal["received", "authres", "arc_set"]

# Methods shown per hop. Result names: spf and dkim RFC 8601 sections 2.7.2 and 2.7.1, dmarc
# RFC 7489 section 11.2, arc RFC 8617 section 10.1 (chain validation status, section 4.4).
HOP_METHODS = ("spf", "dkim", "dmarc", "arc")
# Results that count as "broke" after an older pass. Every one is a registered name for at
# least one method above: fail (all four), softfail (spf), temperror and permerror (spf,
# dkim, dmarc). Not included: none, neutral, policy (a choice, not a breakage).
BREAK_RESULTS = frozenset({"fail", "softfail", "temperror", "permerror"})

MISSING_MEMBER = "missing_member"
DUPLICATE_INSTANCE = "duplicate_instance"
UNGROUPED_FIELD = "ungrouped_field"
MISSING_AUTHSERV_ID = "missing_authserv_id"
_KIND_RANK = {"received": 0, "authres": 1, "arc_set": 2}


@dataclass(frozen=True, slots=True)
class HopResult:
    method: str
    result: str


@dataclass(frozen=True, slots=True)
class HopEntry:
    """One field (or ARC set) of the per-hop view. See the module docstring."""

    order: int
    kind: HopKind
    position: int
    hop: int | None
    parsed: bool
    authserv_id: str | None
    authres_index: int | None
    arc_instance: int | None
    arc_domain: str | None
    arc_cv: str | None
    results: tuple[HopResult, ...]
    stated_not_verifiable: bool
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HopTimeline:
    entries: tuple[HopEntry, ...]
    received_truncated: bool
    arc_truncated: bool


@dataclass(frozen=True, slots=True)
class HopBreak:
    """A method stated ``pass`` in an older entry and a :data:`BREAK_RESULTS` result in the
    next newer parsed entry that states it."""

    method: str
    hop: int | None  # hop of the older entry (the last one that stated pass)
    result: str
    authserv_id: str | None  # of the newer entry
    from_order: int
    to_order: int


def _issue_codes(*groups: tuple[ParseIssue, ...], errors_only: bool = False) -> list[str]:
    return [i.code for g in groups for i in g if not errors_only or i.severity == "error"]


def _results(header: AuthResHeader) -> tuple[HopResult, ...]:
    seen = dict.fromkeys((r.method, r.result) for r in header.resinfo if r.method in HOP_METHODS)
    return tuple(HopResult(m, r) for m, r in seen)


def _usable(header: AuthResHeader) -> bool:
    # Same rule as MSG_AUTHRES_UNPARSED: an authserv-id (RFC 8601 section 2.2) and no error.
    return header.authserv_id is not None and not any(i.severity == "error" for i in header.issues)


def _entry(
    kind: HopKind,
    position: int,
    *,
    parsed: bool,
    hop: int | None = None,
    authserv_id: str | None = None,
    authres_index: int | None = None,
    arc_instance: int | None = None,
    arc_domain: str | None = None,
    arc_cv: str | None = None,
    results: tuple[HopResult, ...] = (),
    stated_not_verifiable: bool = False,
    issues: list[str] | tuple[str, ...] = (),
) -> HopEntry:
    return HopEntry(
        order=0,
        kind=kind,
        position=position,
        hop=hop,
        parsed=parsed,
        authserv_id=authserv_id if parsed else None,
        authres_index=authres_index,
        arc_instance=arc_instance,
        arc_domain=arc_domain if parsed else None,
        arc_cv=arc_cv if parsed else None,
        results=results if parsed else (),
        stated_not_verifiable=stated_not_verifiable,
        issues=tuple(dict.fromkeys(issues)),
    )


def _received_entries(block: HeaderBlock, received: ReceivedChain | None) -> list[HopEntry]:
    if received is None:
        return []
    # The chain keeps the newest (topmost) fields and lists them oldest first.
    fields = block.get_all("Received")
    count = min(len(received.hops), len(fields))
    out = []
    for j in range(count):
        hop = received.hops[count - 1 - j]
        out.append(
            _entry(
                "received",
                fields[j].position,
                parsed=hop.parsed,
                hop=hop.index,
                issues=_issue_codes(hop.warnings),
            )
        )
    return out


def _authres_entries(
    block: HeaderBlock, headers: tuple[AuthResHeader, ...] | None
) -> list[HopEntry]:
    out = []
    for j, field in enumerate(block.get_all(HEADER_NAME)):
        header: AuthResHeader | None = None
        failure: str | None = None
        if headers is not None and j < len(headers) and headers[j].position == field.position:
            header = headers[j]
        else:  # the section parse failed: read this field alone so one bad field stays local
            try:
                header = parse_authentication_results(
                    field.raw_value, position=field.position, index=j
                )
            except AuthResParseError as exc:
                failure = exc.code
        lower = j > 0
        if header is None:
            out.append(
                _entry(
                    "authres",
                    field.position,
                    parsed=False,
                    authres_index=j,
                    stated_not_verifiable=lower,
                    issues=[failure or "unparsed"],
                )
            )
            continue
        codes = _issue_codes(header.issues)
        if header.authserv_id is None and MISSING_AUTHSERV_ID not in codes:
            codes.append(MISSING_AUTHSERV_ID)
        out.append(
            _entry(
                "authres",
                field.position,
                parsed=_usable(header),
                authserv_id=header.authserv_id,
                authres_index=j,
                results=_results(header),
                stated_not_verifiable=lower,
                issues=codes,
            )
        )
    return out


def _arc_set_entry(s: ArcSet) -> HopEntry:
    members: list[ArcSignature | ArcAuthenticationResults] = [
        m for m in (s.seal, s.message_signature, s.authentication_results) if m is not None
    ]
    codes = _issue_codes(*(m.issues for m in members), errors_only=True)
    if len(members) < 3:
        codes.append(MISSING_MEMBER)
    payload = s.results
    if payload is not None:
        codes.extend(_issue_codes(payload.issues, errors_only=True))
        if payload.authserv_id is None:
            codes.append(MISSING_AUTHSERV_ID)
    parsed = not codes and payload is not None
    return _entry(
        "arc_set",
        min(m.position for m in members),
        parsed=parsed,
        authserv_id=payload.authserv_id if payload is not None else None,
        arc_instance=s.instance,
        arc_domain=s.domain,
        arc_cv=s.cv,
        results=_results(payload) if payload is not None else (),
        stated_not_verifiable=True,
        issues=codes,
    )


def _arc_entries(arc: ArcChain | None) -> list[HopEntry]:
    if arc is None:
        return []
    out = [_arc_set_entry(s) for s in arc.sets]
    grouped = {
        id(m)
        for s in arc.sets
        for m in (s.seal, s.message_signature, s.authentication_results)
        if m is not None
    }
    # Fields the chain could not group (bad or duplicate instance): unparsed, codes only.
    loose: list[ArcSignature | ArcAuthenticationResults] = [*arc.signatures, *arc.results]
    for m in loose:
        if id(m) in grouped:
            continue
        codes = _issue_codes(m.issues, errors_only=True)
        codes.append(UNGROUPED_FIELD if m.instance is None else DUPLICATE_INSTANCE)
        out.append(
            _entry(
                "arc_set",
                m.position,
                parsed=False,
                arc_instance=m.instance,
                stated_not_verifiable=True,
                issues=codes,
            )
        )
    return out


def build_hop_view(
    block: HeaderBlock,
    received: ReceivedChain | None,
    auth_headers: tuple[AuthResHeader, ...] | None,
    arc: ArcChain | None,
) -> HopTimeline:
    """Order every Received, Authentication-Results and ARC entry by header position.

    A section passed as None (its parse failed) contributes no entries, except
    Authentication-Results, whose fields are then read one by one. Deterministic.
    """
    received_entries = _received_entries(block, received)
    others = _authres_entries(block, auth_headers) + _arc_entries(arc)
    # Nearest Received field below each other entry (header positions grow downwards).
    below = sorted((e.position, e.hop) for e in received_entries)
    starts = [p for p, _ in below]
    placed = []
    for e in others:
        k = bisect_right(starts, e.position)
        hop = below[k][1] if k < len(below) else None
        placed.append(replace(e, hop=hop))
    entries = sorted(
        received_entries + placed,
        key=lambda e: (-e.position, _KIND_RANK[e.kind], e.arc_instance or 0),
    )
    return HopTimeline(
        entries=tuple(replace(e, order=i) for i, e in enumerate(entries)),
        received_truncated=bool(received and received.truncated),
        arc_truncated=bool(arc and arc.truncated),
    )


def _state(entry: HopEntry, method: str) -> str | None:
    results = [r.result for r in entry.results if r.method == method]
    if not results:
        return None
    if "pass" in results:
        return "pass"
    return next((r for r in results if r in BREAK_RESULTS), "other")


def find_auth_breaks(timeline: HopTimeline) -> tuple[HopBreak, ...]:
    """At most one break per method: the oldest pass -> failure-class step.

    Only parsed entries that state the method are compared, oldest to newest; an entry
    stating another result (none, neutral, policy, ...) resets the comparison.
    """
    stated = [e for e in timeline.entries if e.parsed and e.results]
    breaks: list[HopBreak] = []
    for method in HOP_METHODS:
        previous: tuple[HopEntry, str] | None = None
        for entry in stated:
            state = _state(entry, method)
            if state is None:
                continue
            if previous is not None and previous[1] == "pass" and state in BREAK_RESULTS:
                breaks.append(
                    HopBreak(
                        method=method,
                        hop=previous[0].hop,
                        result=state,
                        authserv_id=entry.authserv_id,
                        from_order=previous[0].order,
                        to_order=entry.order,
                    )
                )
                break
            previous = (entry, state)
    return tuple(sorted(breaks, key=lambda b: (b.to_order, b.from_order, b.method)))
