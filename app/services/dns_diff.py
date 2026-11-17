"""DNS snapshot content and its diff (M7-08). Pure: no database, no network, no clock.

A snapshot is the set of monitored (name, type) entries of one domain. Names are RELATIVE to the
domain (`@` apex, `_dmarc`, `<selector>._domainkey`), so they are at most `MAX_NAME_LENGTH`
characters whatever the length of the domain, and a rename does not change a snapshot.

Each entry has a lookup `state` (ok, nxdomain, nodata, error) and sorted, de-duplicated,
normalised values. Normalisation (what "the same record" means):
- TXT: presentation-form quoted strings (`"a" "b"`) are joined as one TXT record (the resolver
  already joins character-strings); runs of whitespace collapse to one space and the ends are
  trimmed; non-printable characters (controls, surrogates, unassigned) become U+FFFD; an SPF
  record (`v=spf1`) is compared case-insensitively (lower-cased), every other TXT keeps its case
  (DKIM keys are base64). Whether DMARC tags are case-sensitive is not assumed: unverified.
- MX: `<preference> <host>` with the preference as an int and the host lower-cased without the
  trailing dot; NS: the host lower-cased without the trailing dot.

Bounds. Per value `MAX_VALUE_CHARS` characters of text are stored, but the value hash (SHA-256 of
the full normalised value) always covers everything, so a change beyond the cut is still seen.
At most `MAX_VALUES_PER_ENTRY` values are stored per entry (`count` says how many existed; the
entry hash covers all of them). If the stored JSON would exceed `MAX_ENTRIES_BYTES` (measured on
the text as stored) the value texts are dropped and only hashes kept. `Snapshot.truncated` tells
that anything was cut.

The diff is order-insensitive, compares entry hashes, and is conservative: an entry in state
`error` on either side, or an entry that exists on only one side (the name was not monitored on
the other), is `inconclusive`, never added or removed. Two absent states (nxdomain, nodata) are
the same "no record".
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from app.models.dns_snapshot import HASH_LENGTH, MAX_ENTRIES, MAX_ENTRIES_BYTES

STATES: Final[tuple[str, ...]] = ("ok", "nxdomain", "nodata", "error")
RDTYPES: Final[tuple[str, ...]] = ("TXT", "MX", "NS")
# `<selector (63)>._domainkey` is the longest relative name.
MAX_NAME_LENGTH: Final = 75
MAX_VALUE_CHARS: Final = 256
MAX_VALUES_PER_ENTRY: Final = 16
# Normalisation work bound for one raw value (a TXT is at most 64 KiB on the wire).
MAX_RAW_CHARS: Final = 1 << 16

ChangeKind = Literal["added", "removed", "changed", "inconclusive"]
_HASH_RE: Final = re.compile(r"[0-9a-f]{64}")
_WS_RE: Final = re.compile(r"\s+")
_REPLACEMENT: Final = "�"


class SnapshotFormatError(ValueError):
    """Stored or supplied snapshot content is malformed. Never contains the offending value."""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# --- normalisation --------------------------------------------------------------------------


def _clean(text: str) -> str:
    text = text[:MAX_RAW_CHARS]
    text = _WS_RE.sub(" ", text)
    text = "".join(c if c.isprintable() else _REPLACEMENT for c in text)
    return text.strip(" ")


def _unquote(text: str) -> str | None:
    """The joined contents if `text` is only quoted character-strings (`"a" "b"`), else None."""
    i, n = 0, len(text)
    parts: list[str] = []
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i == n:
            break
        if text[i] != '"':
            return None
        i += 1
        chunk: list[str] = []
        while i < n and text[i] != '"':
            if text[i] == "\\" and i + 1 < n:
                i += 1
            chunk.append(text[i])
            i += 1
        if i >= n:
            return None  # unterminated quote: leave the value as it is
        i += 1
        parts.append("".join(chunk))
    return "".join(parts) if parts else None


def normalise_txt(raw: str) -> str:
    text = raw[:MAX_RAW_CHARS]
    joined = _unquote(text) if text.lstrip().startswith('"') else None
    value = _clean(text if joined is None else joined)
    return value.lower() if is_spf(value) else value


def _is_version(value: str, prefix: str) -> bool:
    head = value[: len(prefix)].lower()
    rest = value[len(prefix) :]
    return head == prefix and (rest == "" or rest[0] in " ;")


def is_spf(value: str) -> bool:
    return _is_version(value, "v=spf1")


def is_dmarc(value: str) -> bool:
    return _is_version(value, "v=dmarc1")


def _host(text: str) -> str:
    return _clean(text).lower().removesuffix(".")


def normalise_ns(raw: str) -> str:
    return _host(raw)


def normalise_mx(raw: str) -> str:
    parts = _clean(raw).split(" ")
    if len(parts) == 2 and parts[0].isascii() and parts[0].isdigit() and len(parts[0]) <= 5:
        return f"{int(parts[0])} {_host(parts[1])}"
    return _host(raw)


# --- entries and snapshots -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Value:
    """`hash` covers the full normalised value; `text` is bounded, None once texts were dropped."""

    hash: str
    text: str | None


@dataclass(frozen=True, slots=True)
class Entry:
    name: str
    rdtype: str
    state: str
    values: tuple[Value, ...]
    count: int  # number of distinct values that existed (>= len(values))
    entry_hash: str  # over all the sorted distinct values; independent of the state
    cut: bool = False  # a value text or the value list was shortened (set when built, not stored)


def _entry_hash(values: Sequence[str]) -> str:
    return _sha(json.dumps(sorted(values), ensure_ascii=True, separators=(",", ":")))


def build_entry(name: str, rdtype: str, state: str, normalised: Iterable[str]) -> Entry:
    """An entry from already-normalised values. Values of an absent or `error` state are
    dropped (they cannot exist); an `ok` entry needs at least one value."""
    if not isinstance(name, str) or not 1 <= len(name) <= MAX_NAME_LENGTH:
        raise SnapshotFormatError("name")
    if rdtype not in RDTYPES:
        raise SnapshotFormatError("rdtype")
    if state not in STATES:
        raise SnapshotFormatError("state")
    distinct = sorted(set(normalised)) if state == "ok" else []
    if state == "ok" and not distinct:
        raise SnapshotFormatError("ok_without_values")
    shown = distinct[:MAX_VALUES_PER_ENTRY]
    kept = tuple(Value(_sha(v), v[:MAX_VALUE_CHARS]) for v in shown)
    cut = len(distinct) > len(shown) or any(len(v) > MAX_VALUE_CHARS for v in shown)
    return Entry(name, rdtype, state, kept, len(distinct), _entry_hash(distinct), cut)


@dataclass(frozen=True, slots=True)
class Snapshot:
    entries: tuple[Entry, ...]  # sorted by (name, rdtype), unique
    content_hash: str  # over every entry's (name, rdtype, state, entry_hash), before truncation
    truncated: bool  # something was cut (values, texts or entries); content_hash is unaffected


def _content_hash(entries: Sequence[Entry]) -> str:
    return _sha(
        json.dumps(
            [[e.name, e.rdtype, e.state, e.entry_hash] for e in entries],
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )


def build_snapshot(entries: Iterable[Entry], *, truncated: bool = False) -> Snapshot:
    """`truncated` lets the caller say it left something out (e.g. selectors over the cap)."""
    ordered = sorted(entries, key=lambda e: (e.name, e.rdtype))
    if len(ordered) > MAX_ENTRIES:
        raise SnapshotFormatError("too_many_entries")
    keys = [(e.name, e.rdtype) for e in ordered]
    if len(set(keys)) != len(keys):
        raise SnapshotFormatError("duplicate_entry")
    return Snapshot(
        tuple(ordered), _content_hash(ordered), truncated or any(e.cut for e in ordered)
    )


# --- storage form ----------------------------------------------------------------------------


def _stored_entry(e: Entry, with_text: bool) -> dict[str, Any]:
    values = [
        {"h": v.hash, "v": v.text} if with_text and v.text is not None else {"h": v.hash}
        for v in e.values
    ]
    return {
        "name": e.name,
        "type": e.rdtype,
        "state": e.state,
        "count": e.count,
        "eh": e.entry_hash,
        "values": values,
    }


def to_stored(snapshot: Snapshot) -> tuple[list[dict[str, Any]], bool]:
    """(entries for the JSON column, truncated flag). The cap is measured on the JSON text as
    SQLAlchemy stores it (`json.dumps`, default separators). Over the cap the value texts are
    dropped; if even the hashes do not fit, SnapshotFormatError."""
    full = [_stored_entry(e, True) for e in snapshot.entries]
    if len(json.dumps(full)) <= MAX_ENTRIES_BYTES:
        return full, snapshot.truncated
    bare = [_stored_entry(e, False) for e in snapshot.entries]
    if len(json.dumps(bare)) > MAX_ENTRIES_BYTES:
        raise SnapshotFormatError("too_large")
    return bare, True


def _expect(cond: bool) -> None:
    if not cond:
        raise SnapshotFormatError("stored_entry")


def from_stored(stored: object, content_hash: str, truncated: bool = False) -> Snapshot:
    """Rebuild a snapshot from the JSON column. Strict: any malformed item is a
    SnapshotFormatError (never a partial snapshot). The stored `content_hash` is trusted."""
    _expect(isinstance(stored, list) and len(stored) <= MAX_ENTRIES)
    _expect(isinstance(content_hash, str) and _HASH_RE.fullmatch(content_hash) is not None)
    entries: list[Entry] = []
    for item in stored:  # type: ignore[attr-defined]
        _expect(isinstance(item, Mapping))
        name, rdtype, state = item.get("name"), item.get("type"), item.get("state")
        count, eh, raw_values = item.get("count"), item.get("eh"), item.get("values")
        _expect(isinstance(name, str) and 1 <= len(name) <= MAX_NAME_LENGTH)
        _expect(rdtype in RDTYPES and state in STATES)
        _expect(type(count) is int and isinstance(raw_values, list))
        _expect(0 <= count <= 10**6 and len(raw_values) <= min(count, MAX_VALUES_PER_ENTRY))
        _expect(isinstance(eh, str) and _HASH_RE.fullmatch(eh) is not None)
        _expect(state == "ok" or count == 0)
        values: list[Value] = []
        for v in raw_values:
            _expect(isinstance(v, Mapping))
            h, text = v.get("h"), v.get("v")
            _expect(isinstance(h, str) and _HASH_RE.fullmatch(h) is not None)
            _expect(text is None or (isinstance(text, str) and len(text) <= MAX_VALUE_CHARS))
            values.append(Value(h, text))
        entries.append(Entry(name, rdtype, state, tuple(values), count, eh))
    keys = [(e.name, e.rdtype) for e in entries]
    _expect(len(set(keys)) == len(keys))
    return Snapshot(tuple(entries), content_hash, bool(truncated))


# --- diff ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Change:
    """One stable change record. Hashes are entry hashes (None when the side has no record or
    could not be evaluated); values are the bounded stored texts (empty when absent/unknown)."""

    name: str
    rdtype: str
    kind: ChangeKind
    before_hash: str | None
    after_hash: str | None
    before_values: tuple[str, ...]
    after_values: tuple[str, ...]


def _present(e: Entry | None) -> bool:
    return e is not None and e.state == "ok"


def _hash(e: Entry | None) -> str | None:
    return e.entry_hash if e is not None and _present(e) else None


def _texts(e: Entry | None) -> tuple[str, ...]:
    if e is None or not _present(e):
        return ()
    return tuple(v.text for v in e.values if v.text is not None)


def diff_snapshots(before: Snapshot, after: Snapshot) -> tuple[Change, ...]:
    """Changes from `before` to `after`, sorted by (name, rdtype); empty when nothing changed."""
    old = {(e.name, e.rdtype): e for e in before.entries}
    new = {(e.name, e.rdtype): e for e in after.entries}
    changes: list[Change] = []
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        kind: ChangeKind
        if a is None or b is None or a.state == "error" or b.state == "error":
            kind = "inconclusive"
            ha, hb = _hash(a), _hash(b)
            va: tuple[str, ...] = ()
            vb: tuple[str, ...] = ()
        else:
            if not _present(a) and not _present(b):
                continue
            if _present(a) and _present(b):
                if a.entry_hash == b.entry_hash:
                    continue
                kind = "changed"
            else:
                kind = "added" if _present(b) else "removed"
            ha, hb, va, vb = _hash(a), _hash(b), _texts(a), _texts(b)
        changes.append(Change(key[0], key[1], kind, ha, hb, va, vb))
    return tuple(changes)


__all__ = [
    "HASH_LENGTH",
    "MAX_NAME_LENGTH",
    "MAX_RAW_CHARS",
    "MAX_VALUES_PER_ENTRY",
    "MAX_VALUE_CHARS",
    "RDTYPES",
    "STATES",
    "Change",
    "ChangeKind",
    "Entry",
    "Snapshot",
    "SnapshotFormatError",
    "Value",
    "build_entry",
    "build_snapshot",
    "diff_snapshots",
    "from_stored",
    "is_dmarc",
    "is_spf",
    "normalise_mx",
    "normalise_ns",
    "normalise_txt",
    "to_stored",
]
