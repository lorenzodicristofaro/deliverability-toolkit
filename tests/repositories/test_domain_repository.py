"""M1-18 DomainRepository: tenant isolation, duplicates per tenant, malformed ids.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url` fixture); the
schema is built by Alembic. No network.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Domain, Tenant
from app.repositories.domain import DomainNameTaken, DomainRecord, DomainRepository

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**63, [1], b"1"]


@dataclass
class World:
    session: Session
    tenant_a: int
    tenant_b: int
    domains: dict[str, int]

    def repo(self, tenant: str = "a") -> DomainRepository:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return DomainRepository(TenantContext(tid, None), self.session)


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        session.add_all([ta, tb])
        session.flush()
        rows = {
            "a1": Domain(tenant_id=ta.id, name="a1.example"),
            "a2": Domain(tenant_id=ta.id, name="shared.example"),
            "b1": Domain(tenant_id=tb.id, name="b1.example"),
            "b2": Domain(tenant_id=tb.id, name="shared.example"),
        }
        session.add_all(rows.values())
        session.commit()
        yield World(session, ta.id, tb.id, {k: v.id for k, v in rows.items()})
    finally:
        session.close()
        engine.dispose()


def test_list_and_get_are_tenant_scoped(world: World) -> None:
    repo = world.repo()
    assert [d.id for d in repo.list()] == [world.domains["a1"], world.domains["a2"]]
    assert repo.get(world.domains["b1"]) is None
    assert repo.get(world.domains["a1"]) is not None


@pytest.mark.parametrize("bad", MALFORMED_IDS)
def test_malformed_ids_are_not_found(world: World, bad: object) -> None:
    repo = world.repo()
    assert repo.get(bad) is None
    assert repo.rename(bad, "x.example") is None
    assert repo.delete(bad) is False
    assert repo.list_by_ids([bad]) == []


def test_get_by_name_is_tenant_scoped(world: World) -> None:
    found = world.repo().get_by_name("shared.example")
    assert found is not None and found.id == world.domains["a2"]
    assert world.repo().get_by_name("b1.example") is None


def test_list_by_ids_ignores_foreign_ids(world: World) -> None:
    ids = [world.domains["b1"], world.domains["a2"], world.domains["b2"], "x"]
    assert [d.id for d in world.repo().list_by_ids(ids)] == [world.domains["a2"]]
    assert world.repo().list_by_ids([]) == []


@pytest.mark.parametrize(("limit", "offset"), [(-1, 0), (10**6, 0), (True, 0), (1, -1), ("1", 0)])
def test_list_by_ids_rejects_bad_pages(world: World, limit: object, offset: object) -> None:
    with pytest.raises(ValueError):
        world.repo().list_by_ids([world.domains["a1"]], limit=limit, offset=offset)  # type: ignore[arg-type]


def test_create_in_context_tenant(world: World) -> None:
    created = world.repo().create("new.example")
    world.session.commit()
    assert created.tenant_id == world.tenant_a
    assert world.repo("b").get(created.id) is None
    record = DomainRecord.from_model(created)
    assert (record.id, record.name) == (created.id, "new.example")


def test_duplicate_name_same_tenant_is_taken(world: World) -> None:
    with pytest.raises(DomainNameTaken):
        world.repo().create("a1.example")


def test_same_name_other_tenant_is_allowed(world: World) -> None:
    created = world.repo("b").create("a1.example")
    world.session.commit()
    assert created.tenant_id == world.tenant_b


def test_rename(world: World) -> None:
    repo = world.repo()
    renamed = repo.rename(world.domains["a1"], "renamed.example")
    assert renamed is not None and renamed.name == "renamed.example"
    assert repo.rename(world.domains["a1"], "renamed.example") is not None  # same name: ok
    with pytest.raises(DomainNameTaken):
        repo.rename(world.domains["a1"], "shared.example")
    assert repo.rename(world.domains["b1"], "stolen.example") is None
    world.session.rollback()
    world.session.expire_all()
    b1 = world.repo("b").get(world.domains["b1"])
    assert b1 is not None and b1.name == "b1.example"


def test_delete_is_tenant_scoped(world: World) -> None:
    assert world.repo().delete(world.domains["b1"]) is False
    assert world.repo().delete(world.domains["a1"]) is True
    world.session.commit()
    assert world.repo("b").get(world.domains["b1"]) is not None
    assert world.repo().get(world.domains["a1"]) is None
