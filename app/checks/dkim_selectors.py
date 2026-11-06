"""DKIM selector seed: probe candidates loaded from `seeds/dkim_selectors.yaml` (M3-12).

Follows the `app.dns.knowledge` pattern: strict schema, `verified_on` + `sources`, an entry is
`verified` only with at least one https source. Immutable, cached per path, no network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path

from app.dns.knowledge import (
    SEEDS_DIR,
    KnowledgeError,
    _check_keys,
    _date,
    _fail,
    _load_yaml,
    _status,
    _str,
    _url_list,
)
from app.dns.types import _validate_name

SELECTORS_FILE = "dkim_selectors.yaml"
MAX_SELECTORS = 200
_RECORD_TYPES = ("txt", "cname", "either")


@dataclass(frozen=True, slots=True)
class Selector:
    name: str
    provider: str | None
    record_type: str
    notes: str
    status: str
    sources: tuple[str, ...]


def parse_selectors(data: object, today: date | None = None) -> tuple[Selector, ...]:
    today = today or date.today()
    root = _check_keys(data, "selectors file", {"verified_on", "sources", "selectors"})
    _date(root["verified_on"], "verified_on", today)
    _url_list(root["sources"], "sources")
    items = root["selectors"]
    if not isinstance(items, list) or not items:
        raise _fail("selectors", "must be a non-empty list")
    if len(items) > MAX_SELECTORS:
        raise _fail("selectors", f"at most {MAX_SELECTORS} entries")
    out: list[Selector] = []
    seen: set[str] = set()
    for i, raw in enumerate(items):
        w = f"selectors[{i}]"
        e = _check_keys(raw, w, {"name", "provider", "record_type", "notes", "status", "sources"})
        name = _str(e["name"], f"{w}.name")
        try:
            _validate_name(name)
        except ValueError as exc:
            raise _fail(f"{w}.name", str(exc)) from None
        if "." in name:
            raise _fail(f"{w}.name", f"must be a single DNS label: {name!r}")
        if name in seen:
            raise _fail(f"{w}.name", f"duplicate name {name!r}")
        seen.add(name)
        rtype = e["record_type"]
        if rtype not in _RECORD_TYPES:
            raise _fail(f"{w}.record_type", f"must be one of {_RECORD_TYPES}")
        raw_provider = e["provider"]
        provider = None if raw_provider is None else _str(raw_provider, f"{w}.provider")
        status = _status(e["status"], f"{w}.status")
        sources = _url_list(e["sources"], f"{w}.sources")
        if status == "verified" and not sources:
            raise _fail(w, "verified entries need a non-empty sources list")
        if status == "unverified" and provider is not None:
            raise _fail(w, "unverified entries must not claim a provider")
        out.append(Selector(name, provider, rtype, _str(e["notes"], f"{w}.notes"), status, sources))
    return tuple(sorted(out, key=lambda s: s.name))


@cache
def _selectors(seeds_dir: Path) -> tuple[Selector, ...]:
    return parse_selectors(_load_yaml(seeds_dir / SELECTORS_FILE))


def list_selectors(seeds_dir: Path = SEEDS_DIR) -> tuple[Selector, ...]:
    return _selectors(seeds_dir)


__all__ = ["KnowledgeError", "Selector", "list_selectors", "parse_selectors"]
