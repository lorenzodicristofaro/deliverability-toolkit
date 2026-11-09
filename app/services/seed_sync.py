"""Seed sync (M5-06): idempotent upsert of global knowledge rows from the YAML seeds.

`sync_seed` is the generic helper (reused by M5-12 for content rules). It works on any global
store that lists its seeded rows and creates/updates global rows; it never sees tenant rows
because the global repositories cannot reach them. Rules, keyed by `seed_key`:
- a seed entry without a row is created (with the entry's `enabled`, `locally_modified` false,
  no actor);
- a row that is not `locally_modified` gets every seed-owned field from the seed, including the
  entry's `enabled`, so a row disabled because its entry was removed comes back;
- a `locally_modified` row (an instance admin edited it) keeps its `local_fields` (for DKIM
  selectors: enabled and notes; for content rules: every field the seed sets, so the row is
  skipped); the other seed-owned fields still follow the seed;
- a row whose entry left the seed is disabled, never deleted; a locally modified row keeps its
  enabled flag (the admin's choice) and is reported in `kept_local`;
- DKIM only: an instance-managed global row (no seed_key) whose selector a seed entry now names is
  adopted before the sync: it gets that seed_key and `locally_modified`, so it keeps `enabled` and
  `notes` like any locally modified seeded row, instead of failing every sync on the unique
  selector. Content rules cannot clash this way: only their seed_key is unique, and the admin API
  never sets it on a global row.

The seed file is parsed and every entry validated before the first write, so a malformed seed
raises `SeedSyncError` and writes nothing. Writes are flushed, not committed: `run_seed_sync`
(app start, CLI hook) runs all syncs in one transaction that commits on success and rolls back
on any error. Offline: no network.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence, Set
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Final, Protocol

from sqlalchemy.orm import Session, sessionmaker

from app.checks.content_rules_seed import CONTENT_RULES_FILE, parse_content_rules
from app.checks.dkim_selectors import SELECTORS_FILE, parse_selectors
from app.dns.knowledge import SEEDS_DIR, KnowledgeError, _load_yaml
from app.repositories.base import MAX_LIMIT
from app.repositories.content_rules import (
    GLOBAL_FIELDS,
    ContentRuleInvalid,
    ContentRuleRecord,
    GlobalContentRuleRepository,
    _clean_values,
)
from app.repositories.dkim_selectors import (
    DkimSelectorInvalid,
    DkimSelectorRecord,
    GlobalDkimSelectorRepository,
    clean_global_values,
)

# Fields the sync owns and an entry must not carry itself.
_RESERVED: Final = frozenset({"seed_key", "enabled", "locally_modified"})
# Fields an instance admin may edit on a seeded DKIM selector without the sync undoing it.
DKIM_LOCAL_FIELDS: Final = frozenset({"enabled", "notes"})
# A locally modified seeded content rule is skipped entirely: everything the seed sets is local.
CONTENT_RULE_LOCAL_FIELDS: Final = frozenset(
    {
        "name",
        "kind",
        "pattern",
        "flags",
        "weight",
        "category",
        "severity",
        "language",
        "enabled",
        "status",
        "sources",
        "verified_on",
    }
)


class SeedSyncError(Exception):
    """The seed file is missing, malformed or invalid; nothing was written."""


@dataclass(frozen=True, slots=True)
class SeedEntry:
    key: str
    values: Mapping[str, Any]
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class SeedSyncResult:
    created: tuple[str, ...] = ()
    updated: tuple[str, ...] = ()
    unchanged: tuple[str, ...] = ()
    disabled: tuple[str, ...] = ()
    kept_local: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.created or self.updated or self.disabled)


class SeedRecord(Protocol):
    @property
    def id(self) -> int: ...
    @property
    def seed_key(self) -> str | None: ...
    @property
    def enabled(self) -> bool: ...
    @property
    def locally_modified(self) -> bool: ...


class SeedStore(Protocol):
    def list_seeded(self) -> Sequence[SeedRecord]: ...
    def create(self, values: Mapping[str, Any], *, actor: int | None) -> object: ...
    def update(self, id_: object, values: Mapping[str, Any]) -> object: ...


def _norm(value: object) -> object:
    return tuple(value) if isinstance(value, list | tuple) else value


@dataclass
class _Tally:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    kept_local: list[str] = field(default_factory=list)

    def result(self) -> SeedSyncResult:
        return SeedSyncResult(
            tuple(self.created),
            tuple(self.updated),
            tuple(self.unchanged),
            tuple(self.disabled),
            tuple(self.kept_local),
        )


def sync_seed(
    store: SeedStore, entries: Iterable[SeedEntry], *, local_fields: frozenset[str]
) -> SeedSyncResult:
    """Upsert `entries` into the global `store` (rules in the module docstring)."""
    entries = tuple(entries)
    keys = [e.key for e in entries]
    if len(set(keys)) != len(keys):
        raise SeedSyncError("duplicate seed keys")
    for entry in entries:
        if _RESERVED & entry.values.keys():
            raise ValueError("seed entries must not set seed_key, enabled or locally_modified")

    existing = {r.seed_key: r for r in store.list_seeded() if r.seed_key is not None}
    tally = _Tally()
    for entry in entries:
        desired = {**entry.values, "enabled": entry.enabled}
        row = existing.get(entry.key)
        if row is None:
            store.create({**desired, "seed_key": entry.key}, actor=None)
            tally.created.append(entry.key)
            continue
        skip = local_fields if row.locally_modified else frozenset()
        diff = {
            k: v for k, v in desired.items() if k not in skip and _norm(getattr(row, k)) != _norm(v)
        }
        if diff:
            store.update(row.id, diff)
            tally.updated.append(entry.key)
        else:
            tally.unchanged.append(entry.key)
        if row.locally_modified:
            tally.kept_local.append(entry.key)

    wanted = set(keys)
    for key, row in existing.items():
        if key in wanted:
            continue
        if row.locally_modified and "enabled" in local_fields:
            tally.kept_local.append(key)
        elif row.enabled:
            store.update(row.id, {"enabled": False})
            tally.disabled.append(key)
        else:
            tally.unchanged.append(key)
    return tally.result()


# --- DKIM selectors ------------------------------------------------------------------------------


def load_dkim_selector_seed(
    seeds_dir: Path = SEEDS_DIR, today: date | None = None
) -> tuple[SeedEntry, ...]:
    """Parse and fully validate `dkim_selectors.yaml` (the M3 schema plus the repository rules).
    The file-level `verified_on` is inherited by every entry (the file has no per-entry date)."""
    try:
        data = _load_yaml(seeds_dir / SELECTORS_FILE)
        selectors = parse_selectors(data, today)
    except KnowledgeError as exc:
        raise SeedSyncError(f"{SELECTORS_FILE}: {exc}") from None
    assert isinstance(data, dict)  # parse_selectors checked the shape
    verified_on = data["verified_on"]
    entries: list[SeedEntry] = []
    for s in selectors:
        values = {
            "selector": s.name,
            "provider": s.provider,
            "record_type": s.record_type,
            "notes": s.notes,
            "status": s.status,
            "sources": list(s.sources) or None,
            "verified_on": verified_on,
        }
        try:
            clean_global_values({**values, "seed_key": s.name})
        except DkimSelectorInvalid as exc:
            raise SeedSyncError(f"{SELECTORS_FILE}: {s.name}: {exc}") from None
        entries.append(SeedEntry(s.name, values))
    return tuple(entries)


def _adopt_unseeded_selectors(store: GlobalDkimSelectorRepository, keys: Set[str]) -> None:
    """Link instance-managed global rows to the seed entry of the same name (module docstring)."""
    rows: list[DkimSelectorRecord] = []
    while True:
        page = store.list(limit=MAX_LIMIT, offset=len(rows))
        rows.extend(page)
        if len(page) < MAX_LIMIT:
            break
    for row in rows:
        if row.seed_key is None and row.selector in keys:
            store.update(row.id, {"seed_key": row.selector, "locally_modified": True})


def sync_dkim_selectors(
    session: Session, seeds_dir: Path = SEEDS_DIR, today: date | None = None
) -> SeedSyncResult:
    """Sync global DKIM selectors from the seed on `session` (flushed, not committed)."""
    entries = load_dkim_selector_seed(seeds_dir, today)
    store = GlobalDkimSelectorRepository(session)
    _adopt_unseeded_selectors(store, {e.key for e in entries})
    return sync_seed(store, entries, local_fields=DKIM_LOCAL_FIELDS)


# --- content rules -------------------------------------------------------------------------------


class _SeededContentRules(GlobalContentRuleRepository):
    """The global repository as a `SeedStore`: seeded rows, read through its public paged list."""

    __slots__ = ()

    def list_seeded(self) -> Sequence[ContentRuleRecord]:
        """Every global row with a seed_key, enabled or not."""
        rows: list[ContentRuleRecord] = []
        offset = 0
        while True:
            page = self.list(limit=MAX_LIMIT, offset=offset)
            rows.extend(r for r in page if r.seed_key is not None)
            if len(page) < MAX_LIMIT:
                return rows
            offset += len(page)


def load_content_rule_seed(
    seeds_dir: Path = SEEDS_DIR, today: date | None = None
) -> tuple[SeedEntry, ...]:
    """Parse and fully validate `content_rules.yaml` (the M5-12 schema plus the repository rules).
    The name is the seed key: display text comes from the i18n keys derived from it."""
    try:
        rules = parse_content_rules(_load_yaml(seeds_dir / CONTENT_RULES_FILE), today)
    except ValueError as exc:  # KnowledgeError, or PyYAML on an impossible date (2026-13-45)
        raise SeedSyncError(f"{CONTENT_RULES_FILE}: {exc}") from None
    entries: list[SeedEntry] = []
    for r in rules:
        values = {
            "name": r.key,
            "kind": r.kind,
            "pattern": r.pattern,
            "flags": r.flags,
            "weight": r.weight,
            "category": r.category,
            "severity": r.severity,
            "language": r.language,
            "status": r.status,
            "sources": list(r.sources) or None,
            "verified_on": r.verified_on,
        }
        try:
            _clean_values({**values, "seed_key": r.key, "enabled": r.enabled}, GLOBAL_FIELDS)
        except ContentRuleInvalid as exc:
            raise SeedSyncError(f"{CONTENT_RULES_FILE}: {r.key}: {exc}") from None
        entries.append(SeedEntry(r.key, values, enabled=r.enabled))
    return tuple(entries)


def sync_content_rules(
    session: Session, seeds_dir: Path = SEEDS_DIR, today: date | None = None
) -> SeedSyncResult:
    """Sync global content rules from the seed on `session` (flushed, not committed)."""
    entries = load_content_rule_seed(seeds_dir, today)
    return sync_seed(_SeededContentRules(session), entries, local_fields=CONTENT_RULE_LOCAL_FIELDS)


_SYNCS: Final[Mapping[str, Callable[[Session, Path], SeedSyncResult]]] = {
    "dkim_selectors": lambda session, seeds_dir: sync_dkim_selectors(session, seeds_dir),
    "content_rules": lambda session, seeds_dir: sync_content_rules(session, seeds_dir),
}


def run_seed_sync(
    session_factory: sessionmaker[Session], seeds_dir: Path = SEEDS_DIR
) -> dict[str, SeedSyncResult]:
    """App-start / CLI entry: every seed sync in one transaction; commit on success, roll back
    everything on any error (the error propagates)."""
    with session_factory.begin() as session:
        return {name: sync(session, seeds_dir) for name, sync in _SYNCS.items()}
