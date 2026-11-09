"""M5-06 seed sync: global DKIM selectors from seeds/dkim_selectors.yaml, plus the generic helper.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared DB fixture). The
schema is built by Alembic. Seeds are read from disk (the shipped file or a tmp copy); no
network.
"""

import datetime as dt
import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

import app.main as app_main
import app.services.seed_sync as seed_sync
from app.checks.content_rules_seed import CONTENT_RULES_FILE, parse_content_rules
from app.checks.dkim_selectors import list_selectors
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.dns.knowledge import SEEDS_DIR, _load_yaml
from app.models import Tenant
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.content_rules import (
    ContentRuleInvalid,
    ContentRuleRecord,
    GlobalContentRuleRepository,
)
from app.repositories.dkim_selectors import DkimSelectorRecord, SelectorTaken
from app.services.seed_sync import (
    CONTENT_RULE_LOCAL_FIELDS,
    DKIM_LOCAL_FIELDS,
    SeedEntry,
    SeedSyncError,
    load_content_rule_seed,
    load_dkim_selector_seed,
    run_seed_sync,
    sync_content_rules,
    sync_dkim_selectors,
    sync_seed,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
TODAY = dt.date(2026, 11, 7)
SHIPPED = SEEDS_DIR / "dkim_selectors.yaml"


@pytest.fixture
def engine(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    eng = create_db_engine(migrated_db_url)
    try:
        yield eng
    finally:
        eng.dispose()


@dataclass
class World:
    factory: sessionmaker[Session]
    session: Session
    tenant: int

    def by_key(self) -> dict[str, DkimSelectorRecord]:
        return {
            r.seed_key: r
            for r in GlobalDkimSelectorRepository(self.session).list_seeded()
            if r.seed_key is not None
        }

    def count(self) -> int:
        return int(self.session.execute(text("SELECT COUNT(*) FROM dkim_selectors")).scalar_one())


@pytest.fixture
def world(engine: Engine) -> Iterator[World]:
    factory = create_session_factory(engine)
    session = factory()
    try:
        tenant = Tenant(name="A", slug="a")
        session.add(tenant)
        session.commit()
        yield World(factory, session, tenant.id)
    finally:
        session.close()


def _entry(name: str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": name,
        "provider": "acme",
        "record_type": "txt",
        "notes": f"note for {name}",
        "status": "verified",
        "sources": ["https://acme.example/dkim"],
    }
    entry.update(overrides)
    return entry


def _seed(tmp_path: Path, entries: list[dict[str, Any]], verified_on: str = "2026-11-01") -> Path:
    body = {"verified_on": dt.date.fromisoformat(verified_on), "sources": [], "selectors": entries}
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "dkim_selectors.yaml").write_text(yaml.safe_dump(body), encoding="utf-8")
    return tmp_path


def _sync(world: World, seeds: Path = SEEDS_DIR) -> seed_sync.SeedSyncResult:
    result = sync_dkim_selectors(world.session, seeds, today=TODAY)
    world.session.commit()
    return result


# --- shipped seed --------------------------------------------------------------------------------


def test_first_sync_loads_the_shipped_selectors_unchanged(world: World) -> None:
    result = _sync(world)
    shipped = list_selectors()
    assert sorted(result.created) == sorted(s.name for s in shipped)
    rows = world.by_key()
    verified_on = yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))["verified_on"]
    for s in shipped:
        row = rows[s.name]
        assert (row.scope, row.tenant_id, row.selector) == ("global", None, s.name)
        assert (row.provider, row.record_type, row.notes) == (s.provider, s.record_type, s.notes)
        assert (row.status, row.sources) == (s.status, s.sources or None)
        assert row.verified_on == verified_on
        assert row.enabled and not row.locally_modified and row.created_by is None
    # The DKIM check (M3-13) still reads the YAML; the enabled DB set matches it exactly, so
    # moving the check onto the table (M5-20) keeps the probed selectors.
    enabled = {r.selector for r in GlobalDkimSelectorRepository(world.session).list() if r.enabled}
    assert enabled == {s.name for s in shipped}
    assert list_selectors() == shipped


def test_resync_is_a_noop(world: World) -> None:
    _sync(world)
    before = world.by_key()
    result = _sync(world)
    assert not result.changed
    assert sorted(result.unchanged) == sorted(before)
    assert result.created == result.updated == result.disabled == result.kept_local == ()
    assert world.by_key() == before


def test_run_seed_sync_commits_in_one_transaction(world: World) -> None:
    results = run_seed_sync(world.factory)
    assert set(results) == {"dkim_selectors", "content_rules"}
    assert len(results["dkim_selectors"].created) == len(list_selectors())
    world.session.expire_all()
    assert world.count() == len(list_selectors())
    assert not run_seed_sync(world.factory)["dkim_selectors"].changed


def test_run_seed_sync_rolls_back_everything_on_error(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(session: Session, seeds_dir: Path) -> seed_sync.SeedSyncResult:
        sync_dkim_selectors(session, seeds_dir, today=TODAY)
        raise RuntimeError("later sync failed")

    monkeypatch.setattr(seed_sync, "_SYNCS", {"dkim_selectors": boom})
    with pytest.raises(RuntimeError):
        run_seed_sync(world.factory)
    world.session.expire_all()
    assert world.count() == 0


# --- seed changes --------------------------------------------------------------------------------


def test_seed_change_updates_creates_and_disables(world: World, tmp_path: Path) -> None:
    _sync(world, _seed(tmp_path / "v1", [_entry("aa1"), _entry("bb1"), _entry("cc1")]))
    ids = {k: r.id for k, r in world.by_key().items()}
    v2 = [
        _entry("aa1", provider="acme_mail", notes="new note", record_type="cname"),
        _entry("bb1"),
        _entry("dd1", status="unverified", provider=None, sources=[]),
    ]
    result = _sync(world, _seed(tmp_path / "v2", v2, verified_on="2026-11-05"))
    assert result.created == ("dd1",)
    assert sorted(result.updated) == ["aa1", "bb1"]  # bb1: verified_on moved
    assert result.disabled == ("cc1",)
    rows = world.by_key()
    assert rows["aa1"].id == ids["aa1"]
    assert (rows["aa1"].provider, rows["aa1"].notes, rows["aa1"].record_type) == (
        "acme_mail",
        "new note",
        "cname",
    )
    assert rows["bb1"].verified_on == dt.date(2026, 11, 5)
    assert rows["dd1"].sources is None and rows["dd1"].provider is None
    # Removed from the seed: disabled, not deleted.
    assert rows["cc1"].id == ids["cc1"] and rows["cc1"].enabled is False
    # Back in the seed: re-enabled.
    result = _sync(world, _seed(tmp_path / "v3", [*v2, _entry("cc1")], verified_on="2026-11-05"))
    assert result.updated == ("cc1",) and world.by_key()["cc1"].enabled is True


def test_removed_row_already_disabled_stays_unchanged(world: World, tmp_path: Path) -> None:
    _sync(world, _seed(tmp_path / "v1", [_entry("aa1"), _entry("bb1")]))
    _sync(world, _seed(tmp_path / "v2", [_entry("aa1")]))
    result = _sync(world, _seed(tmp_path / "v2b", [_entry("aa1")]))
    assert not result.changed and sorted(result.unchanged) == ["aa1", "bb1"]


def test_admin_modified_row_keeps_local_fields(world: World, tmp_path: Path) -> None:
    _sync(world, _seed(tmp_path / "v1", [_entry("aa1"), _entry("bb1")]))
    g = GlobalDkimSelectorRepository(world.session)
    aa1 = world.by_key()["aa1"]
    g.update(aa1.id, {"enabled": False, "notes": "admin note", "locally_modified": True})
    world.session.commit()
    v2 = [_entry("aa1", notes="seed note", provider="acme_mail"), _entry("bb1")]
    result = _sync(world, _seed(tmp_path / "v2", v2))
    row = world.by_key()["aa1"]
    assert (row.enabled, row.notes, row.locally_modified) == (False, "admin note", True)
    assert row.provider == "acme_mail"  # seed-owned fields still follow the seed
    assert result.updated == ("aa1",) and result.kept_local == ("aa1",)
    # Re-sync of the same seed: no change, admin edit still kept.
    again = _sync(world, _seed(tmp_path / "v2b", v2))
    assert not again.changed and again.kept_local == ("aa1",)


def test_admin_enabled_row_removed_from_seed_stays_enabled(world: World, tmp_path: Path) -> None:
    _sync(world, _seed(tmp_path / "v1", [_entry("aa1"), _entry("bb1")]))
    g = GlobalDkimSelectorRepository(world.session)
    g.update(world.by_key()["bb1"].id, {"locally_modified": True})
    world.session.commit()
    result = _sync(world, _seed(tmp_path / "v2", [_entry("aa1")]))
    assert result.disabled == () and result.kept_local == ("bb1",)
    assert world.by_key()["bb1"].enabled is True


def test_sync_never_touches_tenant_or_unseeded_global_rows(world: World, tmp_path: Path) -> None:
    tenant_repo = repo_for(TenantContext(world.tenant, None), world.session).dkim_selectors
    t1 = tenant_repo.create({"selector": "aa1", "notes": "tenant copy", "enabled": False})
    t2 = tenant_repo.create({"selector": "zz9"})
    admin = GlobalDkimSelectorRepository(world.session).create({"selector": "adm1"}, actor=None)
    world.session.commit()
    _sync(world, _seed(tmp_path / "v1", [_entry("aa1"), _entry("zz9")]))
    _sync(world, _seed(tmp_path / "v2", [_entry("bb1")]))
    assert tenant_repo.get(t1.id) == t1
    assert tenant_repo.get(t2.id) == t2
    assert GlobalDkimSelectorRepository(world.session).get(admin.id) == admin
    assert set(world.by_key()) == {"aa1", "zz9", "bb1"}


def _admin_row(world: World, selector: str, **values: Any) -> Any:
    record = GlobalDkimSelectorRepository(world.session).create(
        {"selector": selector, **values}, actor=None
    )
    world.session.commit()
    return record


def _row(world: World, selector: str) -> Any:
    world.session.expire_all()
    rows = GlobalDkimSelectorRepository(world.session).list(limit=MAX_LIMIT)
    return next(r for r in rows if r.selector == selector)


def test_seed_entry_naming_an_admin_global_row_adopts_it(world: World, tmp_path: Path) -> None:
    admin = _admin_row(world, "bb1", notes="admin note", enabled=False)
    result = _sync(world, _seed(tmp_path, [_entry("aa1"), _entry("bb1")]))
    assert "bb1" in result.kept_local and "bb1" not in result.created
    row = _row(world, "bb1")
    assert row.id == admin.id  # the same row, not a new one
    assert (row.seed_key, row.locally_modified) == ("bb1", True)
    assert (row.notes, row.enabled) == ("admin note", False)  # the admin's values survive
    assert row.status == "verified"  # seed-owned fields follow the seed, as on any seeded row
    assert world.count() == 2


def test_adoption_is_idempotent(world: World, tmp_path: Path) -> None:
    _admin_row(world, "bb1", notes="admin note")
    seeds = _seed(tmp_path, [_entry("bb1")])
    _sync(world, seeds)
    before = _row(world, "bb1")
    assert not _sync(world, seeds).changed
    assert _row(world, "bb1") == before


def test_row_the_seed_does_not_name_is_not_adopted(world: World, tmp_path: Path) -> None:
    _admin_row(world, "zz9", notes="mine")
    _sync(world, _seed(tmp_path, [_entry("aa1")]))
    row = _row(world, "zz9")
    assert (row.seed_key, row.locally_modified, row.notes) == (None, False, "mine")


def test_tenant_row_of_the_same_name_is_never_adopted(world: World, tmp_path: Path) -> None:
    ctx = TenantContext(world.tenant, None)
    tenant = repo_for(ctx, world.session).dkim_selectors.create({"selector": "bb1", "notes": "t"})
    world.session.commit()
    _sync(world, _seed(tmp_path, [_entry("bb1")]))
    world.session.expire_all()
    after = repo_for(ctx, world.session).dkim_selectors.get(tenant.id)
    assert after is not None
    assert (after.scope, after.seed_key, after.notes) == ("tenant", None, "t")


def test_real_sync_with_a_clash_still_syncs_content_rules(world: World, tmp_path: Path) -> None:
    """The whole sync is one transaction: a clash used to roll the content rules back too."""
    _admin_row(world, "bb1", notes="admin note")
    seeds = _seed(tmp_path, [_entry("aa1"), _entry("bb1")])
    _rules_seed(seeds, [_rule("adopted_clash_rule")])
    results = run_seed_sync(world.factory, seeds)
    assert results["content_rules"].created == ("adopted_clash_rule",)
    assert "aa1" in results["dkim_selectors"].created
    world.session.expire_all()
    assert "adopted_clash_rule" in _global_rules(world)
    assert _row(world, "bb1").seed_key == "bb1"


def test_content_rule_named_like_a_new_seed_key_does_not_clash(
    world: World, tmp_path: Path
) -> None:
    """Content rules have no such exposure: only seed_key is unique, and this row has none."""
    GlobalContentRuleRepository(world.session).create(
        {
            "name": "new_seed_rule",
            "kind": "keyword",
            "pattern": "admin",
            "weight": 1,
            "category": "spam",
            "severity": "low",
            "title": "Admin title",
        },
        actor=None,
    )
    world.session.commit()
    result = _sync_rules(world, _rules_seed(tmp_path, [_rule("new_seed_rule")]))
    assert result.created == ("new_seed_rule",)
    rows = GlobalContentRuleRepository(world.session).list(limit=MAX_LIMIT)
    same = [r for r in rows if r.name == "new_seed_rule"]
    assert sorted(r.seed_key or "" for r in same) == ["", "new_seed_rule"]


# --- malformed seeds: error, nothing written ------------------------------------------------------

MALFORMED: list[tuple[str, str]] = [
    ("unparsable yaml", "selectors: [\n  - name: x\n"),
    ("not a mapping", "- just\n- a list\n"),
    ("empty file", ""),
    ("missing selectors", "verified_on: 2026-11-01\nsources: []\n"),
    ("missing verified_on", "sources: []\nselectors: []\n"),
]

MALFORMED_ENTRIES: list[tuple[str, list[dict[str, Any]]]] = [
    ("empty list", []),
    ("uppercase name", [_entry("Bad")]),
    ("dotted name", [_entry("a.b")]),
    ("name with space", [_entry("a b")]),
    ("duplicate name", [_entry("aa1"), _entry("aa1")]),
    ("verified without sources", [_entry("aa1", sources=[])]),
    ("unverified with provider", [_entry("aa1", status="unverified")]),
    ("bad record type", [_entry("aa1", record_type="mx")]),
    ("unknown key", [{**_entry("aa1"), "extra": 1}]),
    ("http source", [_entry("aa1", sources=["http://acme.example"])]),
    ("nul in notes", [_entry("aa1", notes="a\x00b")]),
    ("control char in notes", [_entry("aa1", notes="a\x1bb")]),
    ("notes too long", [_entry("aa1", notes="n" * 501)]),
    ("provider not a slug", [_entry("aa1", provider="Acme Mail")]),
    ("too many sources", [_entry("aa1", sources=[f"https://a.example/{i}" for i in range(11)])]),
    ("valid then invalid", [_entry("aa1"), _entry("bb1", notes="x\x00")]),
]


def _assert_nothing_written(world: World, seeds: Path, before: dict[str, Any]) -> None:
    with pytest.raises(SeedSyncError):
        sync_dkim_selectors(world.session, seeds, today=TODAY)
    world.session.rollback()
    assert world.by_key() == before


@pytest.mark.parametrize(("case", "raw"), MALFORMED, ids=[c for c, _ in MALFORMED])
def test_malformed_seed_file_is_an_error(world: World, tmp_path: Path, case: str, raw: str) -> None:
    _sync(world, _seed(tmp_path / "ok", [_entry("aa1")]))
    before = world.by_key()
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "dkim_selectors.yaml").write_text(raw, encoding="utf-8")
    _assert_nothing_written(world, tmp_path / "bad", before)


@pytest.mark.parametrize(
    ("case", "entries"), MALFORMED_ENTRIES, ids=[c for c, _ in MALFORMED_ENTRIES]
)
def test_malformed_seed_entries_are_an_error(
    world: World, tmp_path: Path, case: str, entries: list[dict[str, Any]]
) -> None:
    _sync(world, _seed(tmp_path / "ok", [_entry("zz1")]))
    before = world.by_key()
    _assert_nothing_written(world, _seed(tmp_path / "bad", entries), before)


def test_future_verified_on_is_an_error(world: World, tmp_path: Path) -> None:
    _assert_nothing_written(world, _seed(tmp_path, [_entry("aa1")], "2026-12-01"), {})


def test_missing_seed_file_is_an_error(world: World, tmp_path: Path) -> None:
    _assert_nothing_written(world, tmp_path, {})


def test_shipped_seed_loads(world: World) -> None:
    entries = load_dkim_selector_seed(today=TODAY)
    assert {e.key for e in entries} == {s.name for s in list_selectors()}
    assert all(e.key == e.values["selector"] for e in entries)


# --- generic helper ------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rec:
    id: int
    seed_key: str | None
    enabled: bool
    locally_modified: bool
    value: str


class _FakeStore:
    def __init__(self, rows: list[_Rec]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, Any]] = []

    def list_seeded(self) -> list[_Rec]:
        return self.rows

    def create(self, values: Mapping[str, Any], *, actor: int | None) -> object:
        self.calls.append(("create", dict(values)))
        return None

    def update(self, id_: object, values: Mapping[str, Any]) -> object:
        self.calls.append(("update", (id_, dict(values))))
        return None


def test_generic_sync_against_a_fake_store() -> None:
    store = _FakeStore(
        [
            _Rec(1, "same", True, False, "v"),
            _Rec(2, "changed", True, False, "old"),
            _Rec(3, "gone", True, False, "v"),
            _Rec(4, "local", False, True, "old"),
        ]
    )
    entries = [
        SeedEntry("same", {"value": "v"}),
        SeedEntry("changed", {"value": "new"}),
        SeedEntry("local", {"value": "new"}),
        SeedEntry("fresh", {"value": "v"}),
    ]
    result = sync_seed(store, entries, local_fields=frozenset({"enabled"}))
    assert result.created == ("fresh",)
    assert result.updated == ("changed", "local")
    assert result.unchanged == ("same",)
    assert result.disabled == ("gone",)
    assert result.kept_local == ("local",)
    assert store.calls == [
        ("update", (2, {"value": "new"})),
        ("update", (4, {"value": "new"})),  # enabled stays False (local field)
        ("create", {"value": "v", "enabled": True, "seed_key": "fresh"}),
        ("update", (3, {"enabled": False})),
    ]


def test_generic_sync_rejects_duplicate_keys_before_writing() -> None:
    store = _FakeStore([])
    with pytest.raises(SeedSyncError):
        sync_seed(store, [SeedEntry("a", {}), SeedEntry("a", {})], local_fields=frozenset())
    assert store.calls == []


@pytest.mark.parametrize("reserved", ["seed_key", "enabled", "locally_modified"])
def test_generic_sync_rejects_reserved_fields(reserved: str) -> None:
    store = _FakeStore([])
    with pytest.raises(ValueError):
        sync_seed(store, [SeedEntry("a", {reserved: True})], local_fields=frozenset())
    assert store.calls == []


def test_dkim_local_fields() -> None:
    assert frozenset({"enabled", "notes"}) == DKIM_LOCAL_FIELDS


def test_generic_sync_applies_the_entry_enabled_flag() -> None:
    store = _FakeStore([_Rec(1, "on_now", True, False, "v")])
    entries = [
        SeedEntry("on_now", {"value": "v"}, enabled=False),
        SeedEntry("fresh", {"value": "v"}, enabled=False),
    ]
    sync_seed(store, entries, local_fields=frozenset({"enabled"}))
    assert store.calls == [
        ("update", (1, {"enabled": False})),
        ("create", {"value": "v", "enabled": False, "seed_key": "fresh"}),
    ]


# --- content rules (M5-12) -----------------------------------------------------------------------

SHIPPED_RULES = parse_content_rules(_load_yaml(SEEDS_DIR / CONTENT_RULES_FILE))


def _rule(key: str, **overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "key": key,
        "kind": "regex",
        "pattern": "a+b",
        "flags": ["ignorecase"],
        "weight": 10,
        "category": "formatting",
        "severity": "low",
        "language": None,
        "enabled": True,
        "status": "verified",
        "verified_on": dt.date(2026, 11, 1),
        "sources": ["https://acme.example/rules"],
    }
    rule.update(overrides)
    return rule


def _rules_seed(tmp_path: Path, rules: list[dict[str, Any]]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / CONTENT_RULES_FILE).write_text(yaml.safe_dump({"rules": rules}), encoding="utf-8")
    return tmp_path


def _sync_rules(world: World, seeds: Path = SEEDS_DIR) -> seed_sync.SeedSyncResult:
    result = sync_content_rules(world.session, seeds, today=dt.date(2026, 11, 8))
    world.session.commit()
    return result


def _global_rules(world: World) -> dict[str, ContentRuleRecord]:
    return {
        r.seed_key: r
        for r in GlobalContentRuleRepository(world.session).list(limit=MAX_LIMIT)
        if r.seed_key is not None
    }


def _rule_count(world: World) -> int:
    return int(world.session.execute(text("SELECT COUNT(*) FROM content_rules")).scalar_one())


def _tenant_rules(world: World) -> Any:
    return repo_for(TenantContext(world.tenant, None), world.session).content_rules


def _override(key: str, **overrides: Any) -> dict[str, Any]:
    return {
        "name": "tenant copy",
        "kind": "keyword",
        "pattern": "tenant",
        "weight": 1,
        "category": "tenant_cat",
        "severity": "info",
        "seed_key": key,
        **overrides,
    }


def test_first_rule_sync_creates_the_shipped_seed(world: World) -> None:
    result = _sync_rules(world)
    assert sorted(result.created) == sorted(r.key for r in SHIPPED_RULES)
    rows = _global_rules(world)
    for rule in SHIPPED_RULES:
        row = rows[rule.key]
        assert (row.scope, row.tenant_id, row.name) == ("global", None, rule.key)
        assert (row.kind, row.pattern, row.flags) == (rule.kind, rule.pattern, rule.flags)
        assert (row.weight, row.category, row.severity) == (
            rule.weight,
            rule.category,
            rule.severity,
        )
        assert (row.language, row.enabled, row.status) == (rule.language, rule.enabled, rule.status)
        assert (row.verified_on, row.sources) == (rule.verified_on, rule.sources or None)
        # Text comes from the i18n keys, never from the row.
        assert (row.title, row.advice) == (None, None)
        assert not row.locally_modified and row.created_by is None


def test_unverified_shipped_rules_stay_disabled_after_sync(world: World) -> None:
    _sync_rules(world)
    assert all(not r.enabled for r in _global_rules(world).values() if r.status == "unverified")


def test_rule_resync_is_a_noop(world: World) -> None:
    _sync_rules(world)
    before = _global_rules(world)
    result = _sync_rules(world)
    assert not result.changed and sorted(result.unchanged) == sorted(before)
    assert result.created == result.updated == result.disabled == result.kept_local == ()
    assert _global_rules(world) == before


def test_run_seed_sync_is_idempotent_for_content_rules(world: World) -> None:
    results = run_seed_sync(world.factory)
    assert len(results["content_rules"].created) == len(SHIPPED_RULES)
    world.session.expire_all()
    assert _rule_count(world) == len(SHIPPED_RULES)
    assert not run_seed_sync(world.factory)["content_rules"].changed


def test_rule_seed_change_updates_and_follows_enabled(world: World, tmp_path: Path) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "v1", [_rule("aa"), _rule("bb")]))
    ids = {k: r.id for k, r in _global_rules(world).items()}
    v2 = [
        _rule("aa", pattern="c+d", flags=[], weight=30, language="it", severity="high"),
        _rule("bb", status="unverified", enabled=False, sources=[]),
    ]
    result = _sync_rules(world, _rules_seed(tmp_path / "v2", v2))
    assert sorted(result.updated) == ["aa", "bb"]
    rows = _global_rules(world)
    assert rows["aa"].id == ids["aa"] and rows["bb"].id == ids["bb"]
    assert (rows["aa"].pattern, rows["aa"].flags, rows["aa"].weight) == ("c+d", 0, 30)
    assert (rows["aa"].language, rows["aa"].severity) == ("it", "high")
    assert (rows["bb"].enabled, rows["bb"].status, rows["bb"].sources) == (
        False,
        "unverified",
        None,
    )


def test_removed_rule_is_disabled_not_deleted_and_can_return(world: World, tmp_path: Path) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "v1", [_rule("aa"), _rule("bb")]))
    bb_id = _global_rules(world)["bb"].id
    result = _sync_rules(world, _rules_seed(tmp_path / "v2", [_rule("aa")]))
    assert result.disabled == ("bb",)
    row = _global_rules(world)["bb"]
    assert row.id == bb_id and row.enabled is False
    again = _sync_rules(world, _rules_seed(tmp_path / "v2b", [_rule("aa")]))
    assert not again.changed
    back = _sync_rules(world, _rules_seed(tmp_path / "v3", [_rule("aa"), _rule("bb")]))
    assert back.updated == ("bb",) and _global_rules(world)["bb"].enabled is True


def test_admin_modified_rule_is_left_alone(world: World, tmp_path: Path) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "v1", [_rule("aa"), _rule("bb")]))
    GlobalContentRuleRepository(world.session).update(
        _global_rules(world)["aa"].id,
        {"pattern": "admin", "weight": 77, "enabled": False, "locally_modified": True},
    )
    world.session.commit()
    before = _global_rules(world)["aa"]
    v2 = [
        _rule("aa", pattern="seed", weight=1, severity="high", sources=["https://acme.example/2"]),
        _rule("bb"),
    ]
    result = _sync_rules(world, _rules_seed(tmp_path / "v2", v2))
    assert result.updated == () and result.kept_local == ("aa",)
    assert _global_rules(world)["aa"] == before


def test_admin_modified_rule_removed_from_seed_keeps_enabled(world: World, tmp_path: Path) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "v1", [_rule("aa"), _rule("bb")]))
    GlobalContentRuleRepository(world.session).update(
        _global_rules(world)["bb"].id, {"locally_modified": True}
    )
    world.session.commit()
    result = _sync_rules(world, _rules_seed(tmp_path / "v2", [_rule("aa")]))
    assert result.disabled == () and result.kept_local == ("bb",)
    assert _global_rules(world)["bb"].enabled is True


def test_rule_sync_never_touches_tenant_or_unseeded_rows(world: World, tmp_path: Path) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "v1", [_rule("aa"), _rule("bb")]))
    tenant = _tenant_rules(world)
    override = tenant.create(_override("aa", enabled=False))
    admin = GlobalContentRuleRepository(world.session).create(
        {
            "name": "admin rule",
            "title": "Admin title",
            "kind": "keyword",
            "pattern": "x",
            "weight": 1,
            "category": "c",
            "severity": "low",
        },
        actor=None,
    )
    world.session.commit()
    _sync_rules(world, _rules_seed(tmp_path / "v2", [_rule("aa", weight=50)]))
    _sync_rules(world, _rules_seed(tmp_path / "v3", [_rule("bb")]))
    assert tenant.get(override.id) == override
    assert GlobalContentRuleRepository(world.session).get(admin.id) == admin
    assert set(_global_rules(world)) == {"aa", "bb"}


def test_tenant_override_needs_an_existing_seed_key_and_survives_removal(
    world: World, tmp_path: Path
) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "v1", [_rule("aa")]))
    tenant = _tenant_rules(world)
    with pytest.raises(ContentRuleInvalid):
        tenant.create(_override("not_in_seed"))
    override = tenant.create(_override("aa"))
    world.session.commit()
    # The global row is only disabled, so the override still points at a row.
    _sync_rules(world, _rules_seed(tmp_path / "v2", [_rule("bb")]))
    assert _global_rules(world)["aa"].enabled is False
    assert tenant.get(override.id) == override


RULE_FILES_MALFORMED: list[tuple[str, str]] = [
    ("unparsable yaml", "rules: [\n  - key: x\n"),
    ("not a mapping", "- a\n- b\n"),
    ("empty file", ""),
    ("missing rules", "other: 1\n"),
    ("empty rules", "rules: []\n"),
    ("impossible date", "rules:\n  - key: a\n    verified_on: 2026-13-45\n"),
]

RULE_ENTRIES_MALFORMED: list[tuple[str, list[dict[str, Any]]]] = [
    ("unknown key", [{**_rule("aa"), "title": "x"}]),
    ("invalid regex", [_rule("aa", pattern="(")]),
    ("nul in regex", [_rule("aa", pattern="a\x00")]),
    ("nul in keyword", [_rule("aa", kind="keyword", pattern="a\x00", flags=[])]),
    ("future date", [_rule("aa", verified_on=dt.date(2027, 1, 1))]),
    ("no sources", [_rule("aa", sources=[])]),
    ("unverified enabled", [_rule("aa", status="unverified")]),
    ("duplicate key", [_rule("aa"), _rule("aa")]),
    ("bad language", [_rule("aa", language="EN")]),
    ("source without host", [_rule("aa", sources=["https://"])]),
    ("valid then invalid", [_rule("aa"), _rule("bb", weight=500)]),
]


def _assert_rules_unchanged(world: World, seeds: Path, before: dict[str, Any]) -> None:
    with pytest.raises(SeedSyncError):
        sync_content_rules(world.session, seeds, today=dt.date(2026, 11, 8))
    world.session.rollback()
    assert _global_rules(world) == before


@pytest.mark.parametrize(
    ("case", "raw"), RULE_FILES_MALFORMED, ids=[c for c, _ in RULE_FILES_MALFORMED]
)
def test_malformed_rule_file_is_an_error(world: World, tmp_path: Path, case: str, raw: str) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "ok", [_rule("zz")]))
    before = _global_rules(world)
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / CONTENT_RULES_FILE).write_text(raw, encoding="utf-8")
    _assert_rules_unchanged(world, tmp_path / "bad", before)


@pytest.mark.parametrize(
    ("case", "entries"), RULE_ENTRIES_MALFORMED, ids=[c for c, _ in RULE_ENTRIES_MALFORMED]
)
def test_malformed_rule_entries_are_an_error(
    world: World, tmp_path: Path, case: str, entries: list[dict[str, Any]]
) -> None:
    _sync_rules(world, _rules_seed(tmp_path / "ok", [_rule("zz")]))
    before = _global_rules(world)
    _assert_rules_unchanged(world, _rules_seed(tmp_path / "bad", entries), before)


def test_missing_rule_file_is_an_error(world: World, tmp_path: Path) -> None:
    _assert_rules_unchanged(world, tmp_path, {})


def test_loader_marks_unverified_entries_disabled_and_drops_empty_sources(tmp_path: Path) -> None:
    seeds = _rules_seed(tmp_path, [_rule("aa", status="unverified", enabled=False, sources=[])])
    (entry,) = load_content_rule_seed(seeds, today=dt.date(2026, 11, 8))
    assert entry.enabled is False and entry.values["sources"] is None


def test_content_rule_local_fields_cover_everything_the_seed_sets(tmp_path: Path) -> None:
    (entry,) = load_content_rule_seed(_rules_seed(tmp_path, [_rule("aa")]), dt.date(2026, 11, 8))
    assert {*entry.values, "enabled"} == CONTENT_RULE_LOCAL_FIELDS


# --- startup wiring ------------------------------------------------------------------------------


def _start(world: World, migrated_db_url: str) -> int:
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    with TestClient(app_main.create_app(settings)) as client:
        return client.get("/healthz").status_code


def test_startup_runs_the_seed_sync(
    world: World, migrated_db_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    assert _start(world, migrated_db_url) == 200
    world.session.expire_all()
    assert _rule_count(world) == len(SHIPPED_RULES)
    assert world.count() == len(list_selectors())
    assert any(getattr(r, "event", None) == "seed_sync.done" for r in caplog.records)


def test_startup_survives_an_invalid_seed_and_keeps_the_previous_state(
    world: World,
    migrated_db_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    run_seed_sync(world.factory)
    world.session.expire_all()
    rules, selectors = _global_rules(world), world.by_key()
    bad = tmp_path / "bad"
    bad.mkdir()
    for name in ("dkim_selectors.yaml", CONTENT_RULES_FILE):
        (bad / name).write_text((SEEDS_DIR / name).read_text(encoding="utf-8"), encoding="utf-8")
    (bad / CONTENT_RULES_FILE).write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr(app_main, "run_seed_sync", lambda factory: run_seed_sync(factory, bad))
    assert _start(world, migrated_db_url) == 200
    world.session.expire_all()
    assert _global_rules(world) == rules and world.by_key() == selectors
    failed = [r for r in caplog.records if getattr(r, "event", None) == "seed_sync.failed"]
    assert len(failed) == 1 and failed[0].levelno == logging.ERROR
    assert CONTENT_RULES_FILE in failed[0].getMessage()


@pytest.mark.parametrize(
    "error",
    [SeedSyncError("bad seed"), SelectorTaken(), RuntimeError("secret query detail")],
    ids=["seed", "conflict", "unexpected"],
)
def test_startup_survives_any_sync_failure(
    world: World,
    migrated_db_url: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: Exception,
) -> None:
    def fail(factory: object) -> None:
        raise error

    monkeypatch.setattr(app_main, "run_seed_sync", fail)
    assert _start(world, migrated_db_url) == 200
    failed = [r for r in caplog.records if getattr(r, "event", None) == "seed_sync.failed"]
    assert len(failed) == 1
    assert "secret query detail" not in failed[0].getMessage()
