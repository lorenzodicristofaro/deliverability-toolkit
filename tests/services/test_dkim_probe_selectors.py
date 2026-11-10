"""M5-20 DKIM probe list resolver. SQLite and, with TEST_DATABASE_URL, PostgreSQL. No network."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.checks.dkim import DkimCheck, seed_providers
from app.checks.dkim_selectors import KnowledgeError, list_selectors
from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Tenant, User
from app.models.dkim_selector import DkimSelector
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.services import dkim_probe_selectors as probe
from app.services.checks import default_registry
from app.services.dkim_probe_selectors import (
    MAX_PROBE_SELECTORS,
    ProbeSelectors,
    all_visible,
    registry_for,
    resolve_and_release,
    resolve_probe_selectors,
)
from app.services.seed_sync import sync_dkim_selectors
from tests.support.socket_guard import db_endpoint, install

SEED = tuple(s.name for s in list_selectors())
SEED_PROVIDERS = seed_providers()
WITH_PROVIDER = next(n for n in SEED if n in SEED_PROVIDERS)
WITHOUT_PROVIDER = next(n for n in SEED if n not in SEED_PROVIDERS)


@dataclass
class World:
    db: Session
    a: TenantContext
    b: TenantContext

    def tenant(self, ctx: TenantContext, selector: str, **values: Any) -> None:
        repo_for(ctx, self.db).dkim_selectors.create({"selector": selector, **values})
        self.db.commit()

    def disable_global(self, *names: str) -> None:
        store = GlobalDkimSelectorRepository(self.db)
        for row in store.list(limit=1000):
            if not names or row.selector in names:
                store.update(row.id, {"enabled": False})
        self.db.commit()

    def clear_global(self) -> None:
        self.db.execute(delete(DkimSelector).where(DkimSelector.scope == "global"))
        self.db.commit()

    def resolve(self, ctx: TenantContext) -> ProbeSelectors:
        return resolve_probe_selectors(ctx, self.db)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "dkim probe selectors", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str) -> Iterator[World]:
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        a, b = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        ua, ub = User(email="a@example.com"), User(email="b@example.com")
        db.add_all([a, b, ua, ub])
        db.commit()
        sync_dkim_selectors(db)
        db.commit()
        yield World(db, TenantContext(a.id, ua.id), TenantContext(b.id, ub.id))
    finally:
        db.close()
        engine.dispose()


def test_only_the_synced_seed_equals_the_seed_list(world: World) -> None:
    assert world.resolve(world.a) == ProbeSelectors(SEED, 0, SEED_PROVIDERS)
    assert list(SEED) == sorted(SEED)


def test_tenant_rows_are_merged_in_python_sort_order(world: World) -> None:
    # '-' < digits < '_' < letters in code point order; a locale collation may differ.
    for name in ("zz-last", "a-first", "0zero", "a_under", "a0"):
        world.tenant(world.a, name)
    expected = tuple(sorted({*SEED, "zz-last", "a-first", "0zero", "a_under", "a0"}))
    assert world.resolve(world.a).names == expected


def test_another_tenants_rows_never_appear(world: World) -> None:
    world.tenant(world.a, "a-private")
    world.tenant(world.b, "b-private")
    a_names, b_names = world.resolve(world.a).names, world.resolve(world.b).names
    assert a_names is not None and b_names is not None
    assert "a-private" in a_names and "b-private" not in a_names
    assert "b-private" in b_names and "a-private" not in b_names


def test_same_name_in_global_and_tenant_is_probed_once(world: World) -> None:
    world.tenant(world.a, SEED[0])
    assert world.resolve(world.a).names == SEED


def test_disabled_rows_are_not_probed(world: World) -> None:
    world.tenant(world.a, "off", enabled=False)
    world.disable_global(SEED[0])
    names = world.resolve(world.a).names
    assert names == SEED[1:]


def test_disabled_tenant_row_does_not_hide_an_enabled_global_row(world: World) -> None:
    world.tenant(world.a, SEED[0], enabled=False)
    assert world.resolve(world.a).names == SEED


def test_empty_global_table_falls_back_to_the_seed(world: World) -> None:
    world.clear_global()
    assert world.resolve(world.a) == ProbeSelectors(SEED, 0, SEED_PROVIDERS)


def test_fallback_keeps_the_tenants_rows(world: World) -> None:
    world.clear_global()
    world.tenant(world.a, "mine")
    assert world.resolve(world.a).names == tuple(sorted({*SEED, "mine"}))
    assert world.resolve(world.b).names == SEED


def test_unreadable_seed_on_fallback_leaves_the_error_to_the_check(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.clear_global()

    def broken() -> Any:
        raise KnowledgeError("seed unreadable")

    monkeypatch.setattr(probe, "list_selectors", broken)
    assert world.resolve(world.a) == ProbeSelectors(None)


def test_all_global_rows_disabled_is_an_empty_list_not_the_fallback(world: World) -> None:
    world.disable_global()
    assert world.resolve(world.a) == ProbeSelectors((), 0, {})


def test_all_global_disabled_keeps_enabled_tenant_rows(world: World) -> None:
    world.disable_global()
    world.tenant(world.a, "mine")
    assert world.resolve(world.a) == ProbeSelectors(("mine",), 0, {})


def test_rows_past_the_repository_limit_are_read(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "MAX_LIMIT", 5)
    world.tenant(world.a, "zzz-last-page", enabled=True)
    assert world.resolve(world.a).names == tuple(sorted({*SEED, "zzz-last-page"}))


def test_paging_sees_every_row_when_a_page_is_exactly_full(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "MAX_LIMIT", len(SEED))
    assert len(all_visible(repo_for(world.a, world.db).dkim_selectors)) == len(SEED)


@pytest.mark.parametrize(
    ("over", "dropped"), [(-1, 0), (0, 0), (1, 1), (7, 7)], ids=["below", "at", "one", "many"]
)
def test_probe_cap(world: World, over: int, dropped: int) -> None:
    store = GlobalDkimSelectorRepository(world.db)
    extra = MAX_PROBE_SELECTORS + over - len(SEED)
    for n in range(extra):
        store.create({"selector": f"r{n:04d}"}, actor=None)
    world.db.commit()
    expected = sorted({*SEED, *(f"r{n:04d}" for n in range(extra))})
    result = world.resolve(world.a)
    assert result.dropped == dropped
    assert result.names == tuple(expected[:MAX_PROBE_SELECTORS])
    assert result.providers is not None
    assert set(result.providers) <= set(result.names)


def test_release_ends_the_transaction(world: World) -> None:
    resolve_and_release(world.a, world.db)
    assert world.db.in_transaction() is False


def test_release_also_on_failure(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        world.db.connection()
        raise RuntimeError("repository failed")

    monkeypatch.setattr(probe, "resolve_probe_selectors", boom)
    with pytest.raises(RuntimeError):
        resolve_and_release(world.a, world.db)
    assert world.db.in_transaction() is False


def test_registry_for_replaces_only_dkim() -> None:
    base = default_registry()
    registry = registry_for(ProbeSelectors(("a", "b"), 3))
    assert registry.all_ids() == base.all_ids()
    for check_id in base.all_ids():
        if check_id == DkimCheck.id:
            assert registry.get(check_id) is not base.get(check_id)
        else:
            assert registry.get(check_id) is base.get(check_id)


# --- providers (M5-23b) --------------------------------------------------------------------------


def test_seed_has_names_with_and_without_a_provider() -> None:
    assert SEED_PROVIDERS and WITH_PROVIDER != WITHOUT_PROVIDER


def test_tenant_provider_wins_inside_its_tenant_only(world: World) -> None:
    world.tenant(world.a, WITH_PROVIDER, provider="a_custom")
    world.tenant(world.b, WITH_PROVIDER, provider="b_custom")
    a, b = world.resolve(world.a), world.resolve(world.b)
    assert a.providers is not None and b.providers is not None
    assert a.providers[WITH_PROVIDER] == "a_custom"
    assert b.providers[WITH_PROVIDER] == "b_custom"
    assert "b_custom" not in a.providers.values() and "a_custom" not in b.providers.values()


def test_tenant_provider_on_a_name_without_a_global_one(world: World) -> None:
    world.tenant(world.a, WITHOUT_PROVIDER, provider="a_only")
    a, b = world.resolve(world.a), world.resolve(world.b)
    assert a.providers is not None and b.providers is not None
    assert a.providers[WITHOUT_PROVIDER] == "a_only"
    assert WITHOUT_PROVIDER not in b.providers


def test_empty_tenant_provider_falls_back_to_the_global_one(world: World) -> None:
    world.tenant(world.a, WITH_PROVIDER)  # provider NULL
    providers = world.resolve(world.a).providers
    assert providers is not None
    assert providers[WITH_PROVIDER] == SEED_PROVIDERS[WITH_PROVIDER]


def test_disabled_tenant_row_contributes_no_provider(world: World) -> None:
    world.tenant(world.a, WITH_PROVIDER, provider="a_custom", enabled=False)
    world.tenant(world.a, "off-only", provider="a_off", enabled=False)
    providers = world.resolve(world.a).providers
    assert providers is not None
    assert providers[WITH_PROVIDER] == SEED_PROVIDERS[WITH_PROVIDER]
    assert "off-only" not in providers


def test_disabled_global_row_contributes_no_provider(world: World) -> None:
    world.disable_global(WITH_PROVIDER)
    result = world.resolve(world.a)
    assert result.names is not None and result.providers is not None
    assert WITH_PROVIDER not in result.names and WITH_PROVIDER not in result.providers


def test_tenant_only_row_provider_never_reaches_another_tenant(world: World) -> None:
    world.tenant(world.a, "a-private", provider="a_secret")
    b = world.resolve(world.b)
    assert b.names is not None and b.providers is not None
    assert "a-private" not in b.names and "a_secret" not in b.providers.values()


def test_fallback_uses_seed_providers_and_tenant_override(world: World) -> None:
    world.clear_global()
    world.tenant(world.a, WITH_PROVIDER, provider="a_custom")
    a, b = world.resolve(world.a), world.resolve(world.b)
    assert a.providers is not None and b.providers is not None
    assert a.providers[WITH_PROVIDER] == "a_custom"
    assert dict(b.providers) == SEED_PROVIDERS


def _row(selector: str, scope: str, provider: str | None, enabled: bool = True) -> Any:
    return SimpleNamespace(selector=selector, scope=scope, provider=provider, enabled=enabled)


@pytest.mark.parametrize(
    ("rows", "seed", "expected"),
    [
        ([], {}, {}),
        ([_row("s", "global", "g")], {}, {"s": "g"}),
        ([_row("s", "global", "g"), _row("s", "tenant", "t")], {}, {"s": "t"}),
        ([_row("s", "tenant", "t"), _row("s", "global", "g")], {}, {"s": "t"}),
        ([_row("s", "global", "g"), _row("s", "tenant", None)], {}, {"s": "g"}),
        ([_row("s", "global", "g"), _row("s", "tenant", "")], {}, {"s": "g"}),
        ([_row("s", "global", "g"), _row("s", "tenant", "   ")], {}, {"s": "g"}),
        ([_row("s", "global", "g"), _row("s", "tenant", "t", False)], {}, {"s": "g"}),
        ([_row("s", "global", "g", False)], {}, {}),
        ([_row("s", "global", None)], {}, {}),
        ([_row("s", "global", "")], {"s": "seed"}, {"s": "seed"}),
        ([], {"s": "seed"}, {"s": "seed"}),
        ([_row("s", "tenant", "t")], {"s": "seed"}, {"s": "t"}),
        ([_row("x", "tenant", "t")], {}, {}),  # not probed: no entry
        ([_row("s", "bogus", "z")], {}, {}),  # malformed scope is ignored
    ],
)
def test_provider_precedence(
    rows: list[Any], seed: dict[str, str], expected: dict[str, str]
) -> None:
    assert dict(probe._providers(rows, seed, ("s",))) == expected


def test_registry_for_passes_the_providers() -> None:
    registry = registry_for(ProbeSelectors(("a",), 0, {"a": "prov"}))
    check = registry.get(DkimCheck.id)
    assert isinstance(check, DkimCheck)
    assert check._provider_map() == {"a": "prov"}
