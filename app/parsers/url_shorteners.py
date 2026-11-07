"""URL shortener seed: domains loaded from `seeds/url_shorteners.yaml` (M5-09).

Follows the `app.checks.dkim_selectors` / `app.dns.knowledge` pattern: strict schema, top-level
`verified_on` + `sources`, an entry is `verified` only with at least one https source, and
`unverified` entries must not claim an operator. Domains are stored in normalised ASCII form
(`app.core.domain_names.to_ascii_domain`). Immutable, cached per path, no network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path

from app.core.domain_names import InvalidDomainName, to_ascii_domain
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

SHORTENERS_FILE = "url_shorteners.yaml"
MAX_SHORTENERS = 500


@dataclass(frozen=True, slots=True)
class Shortener:
    domain: str
    operator: str | None
    notes: str
    status: str
    sources: tuple[str, ...]


def parse_shorteners(data: object, today: date | None = None) -> tuple[Shortener, ...]:
    today = today or date.today()
    root = _check_keys(data, "shorteners file", {"verified_on", "sources", "shorteners"})
    _date(root["verified_on"], "verified_on", today)
    _url_list(root["sources"], "sources")
    items = root["shorteners"]
    if not isinstance(items, list) or not items:
        raise _fail("shorteners", "must be a non-empty list")
    if len(items) > MAX_SHORTENERS:
        raise _fail("shorteners", f"at most {MAX_SHORTENERS} entries")
    out: list[Shortener] = []
    seen: set[str] = set()
    for i, raw in enumerate(items):
        w = f"shorteners[{i}]"
        e = _check_keys(raw, w, {"domain", "operator", "notes", "status", "sources"})
        domain = _str(e["domain"], f"{w}.domain")
        try:
            normalised = to_ascii_domain(domain)
        except InvalidDomainName as exc:
            raise _fail(f"{w}.domain", f"invalid domain ({exc.reason})") from None
        if normalised != domain:
            raise _fail(f"{w}.domain", f"must be normalised ASCII lowercase: {normalised!r}")
        if domain in seen:
            raise _fail(f"{w}.domain", f"duplicate domain {domain!r}")
        seen.add(domain)
        raw_operator = e["operator"]
        operator = None if raw_operator is None else _str(raw_operator, f"{w}.operator")
        status = _status(e["status"], f"{w}.status")
        sources = _url_list(e["sources"], f"{w}.sources")
        if status == "verified" and not sources:
            raise _fail(w, "verified entries need a non-empty sources list")
        if status == "unverified" and operator is not None:
            raise _fail(w, "unverified entries must not claim an operator")
        out.append(Shortener(domain, operator, _str(e["notes"], f"{w}.notes"), status, sources))
    return tuple(sorted(out, key=lambda s: s.domain))


@cache
def _shorteners(seeds_dir: Path) -> tuple[Shortener, ...]:
    return parse_shorteners(_load_yaml(seeds_dir / SHORTENERS_FILE))


def list_shorteners(seeds_dir: Path = SEEDS_DIR) -> tuple[Shortener, ...]:
    return _shorteners(seeds_dir)


__all__ = ["KnowledgeError", "Shortener", "list_shorteners", "parse_shorteners"]
