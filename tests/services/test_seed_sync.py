"""M5-06 seed sync: global DKIM selectors from seeds/dkim_selectors.yaml, plus the generic helper.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url` fixture). The
schema is built by Alembic. Seeds are read from disk (the shipped file or a tmp copy); no
network.
"""

import datetime as dt
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

import app.services.seed_sync as seed_sync
from app.checks.dkim_selectors import list_selectors
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.dns.knowledge import SEEDS_DIR
from app.models import Tenant
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.repositories.dkim_selectors import DkimSelectorRecord, SelectorTaken
from app.services.seed_sync import (
    DKIM_LOCAL_FIELDS,
    SeedEntry,
    SeedSyncError,
    load_dkim_selector_seed,
    run_seed_sync,
    sync_dkim_selectors,
    sync_seed,
)

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
TODAY = dt.date(2026, 11, 7)
SHIPPED = SEEDS_DIR / "dkim_selectors.yaml"


@pytest.fixture
def engine(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    eng = create_db_engine(db_url)
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
    assert set(results) == {"dkim_selectors"}
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


def test_seed_entry_clashing_with_admin_global_row_fails_whole_sync(
    world: World, tmp_path: Path
) -> None:
    GlobalDkimSelectorRepository(world.session).create({"selector": "bb1"}, actor=None)
    world.session.commit()
    before = world.count()
    with pytest.raises(SelectorTaken):
        sync_dkim_selectors(world.session, _seed(tmp_path, [_entry("aa1"), _entry("bb1")]), TODAY)
    world.session.rollback()
    assert world.count() == before


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
