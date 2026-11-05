"""M1-18 DomainAccessRepository: assign, unassign, list assigned, replace, cross-tenant isolation.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url` fixture); the
schema is built by Alembic. No network.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Domain, DomainAccess, Membership, MembershipRole, Tenant, User
from app.repositories.domain_access import MAX_ASSIGNMENTS, DomainAccessRepository

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
MALFORMED_IDS = [None, "1", "abc", 1.0, True, False, 0, -1, 2**63, [1], b"1"]


@dataclass
class World:
    session: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    members: dict[str, int]  # "a_v1", "a_v2", "b_v1" (client viewers)
    domains: dict[str, int]  # "a1", "a2", "b1"

    def repo(self, tenant: str = "a") -> DomainAccessRepository:
        tid = self.tenant_a if tenant == "a" else self.tenant_b
        return DomainAccessRepository(TenantContext(tid, None), self.session)

    def all_rows(self) -> set[tuple[int, int, int]]:
        self.session.flush()
        rows = self.session.execute(
            select(DomainAccess.membership_id, DomainAccess.domain_id, DomainAccess.tenant_id)
        ).all()
        return {tuple(r) for r in rows}  # type: ignore[misc]


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
        users = {n: User(email=f"{n}@example.com") for n in ("v1", "v2")}
        session.add_all([ta, tb, *users.values()])
        session.flush()
        viewer = MembershipRole.CLIENT_VIEWER
        members = {
            "a_v1": Membership(user_id=users["v1"].id, tenant_id=ta.id, role=viewer),
            "a_v2": Membership(user_id=users["v2"].id, tenant_id=ta.id, role=viewer),
            "b_v1": Membership(user_id=users["v1"].id, tenant_id=tb.id, role=viewer),
        }
        domains = {
            "a1": Domain(tenant_id=ta.id, name="a1.example"),
            "a2": Domain(tenant_id=ta.id, name="a2.example"),
            "b1": Domain(tenant_id=tb.id, name="b1.example"),
        }
        session.add_all([*members.values(), *domains.values()])
        session.flush()
        session.add(
            DomainAccess(
                membership_id=members["b_v1"].id, domain_id=domains["b1"].id, tenant_id=tb.id
            )
        )
        session.commit()
        yield World(
            session,
            ta.id,
            tb.id,
            {k: v.id for k, v in users.items()},
            {k: v.id for k, v in members.items()},
            {k: v.id for k, v in domains.items()},
        )
    finally:
        session.close()
        engine.dispose()


def test_requires_tenant_context(world: World) -> None:
    with pytest.raises(TypeError):
        DomainAccessRepository(world.tenant_a, world.session)  # type: ignore[arg-type]


def test_assign_and_list(world: World) -> None:
    repo, m, d = world.repo(), world.members, world.domains
    assert repo.assign(m["a_v1"], d["a1"]) is True
    assert repo.assign(m["a_v1"], d["a1"]) is True  # idempotent
    assert repo.assign(m["a_v1"], d["a2"]) is True
    assert repo.domain_ids_for_membership(m["a_v1"]) == {d["a1"], d["a2"]}
    assert repo.domain_ids_for_user(world.users["v1"]) == {d["a1"], d["a2"]}
    assert repo.membership_ids_for_domain(d["a1"]) == [m["a_v1"]]
    # the same user's grant in tenant B is not mixed in, and vice versa
    assert world.repo("b").domain_ids_for_user(world.users["v1"]) == {d["b1"]}


def test_unassign(world: World) -> None:
    repo, m, d = world.repo(), world.members, world.domains
    repo.assign(m["a_v1"], d["a1"])
    assert repo.unassign(m["a_v1"], d["a1"]) is True
    assert repo.unassign(m["a_v1"], d["a1"]) is False
    assert repo.domain_ids_for_membership(m["a_v1"]) == frozenset()


@pytest.mark.parametrize(
    ("member", "domain"),
    [("b_v1", "a1"), ("a_v1", "b1"), ("b_v1", "b1")],
)
def test_assign_cross_tenant_is_refused(world: World, member: str, domain: str) -> None:
    before = world.all_rows()
    assert world.repo().assign(world.members[member], world.domains[domain]) is False
    assert world.all_rows() == before


def test_cross_tenant_reads_and_unassign_see_nothing(world: World) -> None:
    repo, m, d = world.repo(), world.members, world.domains
    assert repo.domain_ids_for_membership(m["b_v1"]) == frozenset()
    assert repo.membership_ids_for_domain(d["b1"]) == []
    assert repo.unassign(m["b_v1"], d["b1"]) is False
    assert (m["b_v1"], d["b1"], world.tenant_b) in world.all_rows()


@pytest.mark.parametrize("bad", MALFORMED_IDS)
def test_malformed_ids(world: World, bad: object) -> None:
    repo, m, d = world.repo(), world.members, world.domains
    before = world.all_rows()
    assert repo.assign(bad, d["a1"]) is False
    assert repo.assign(m["a_v1"], bad) is False
    assert repo.unassign(bad, d["a1"]) is False
    assert repo.domain_ids_for_membership(bad) == frozenset()
    assert repo.domain_ids_for_user(bad) == frozenset()
    assert repo.membership_ids_for_domain(bad) == []
    assert repo.replace_for_domain(bad, []) is None
    assert repo.replace_for_domain(d["a1"], [bad]) is None
    assert world.all_rows() == before


def test_replace_for_domain(world: World) -> None:
    repo, m, d = world.repo(), world.members, world.domains
    assert repo.replace_for_domain(d["a1"], [m["a_v1"], m["a_v2"], m["a_v1"]]) == sorted(
        [m["a_v1"], m["a_v2"]]
    )
    assert repo.replace_for_domain(d["a1"], [m["a_v2"]]) == [m["a_v2"]]
    assert repo.membership_ids_for_domain(d["a1"]) == [m["a_v2"]]
    assert repo.replace_for_domain(d["a1"], []) == []
    assert repo.membership_ids_for_domain(d["a1"]) == []


@pytest.mark.parametrize(
    ("domain", "members"),
    [("b1", ["a_v1"]), ("a1", ["a_v1", "b_v1"]), ("b1", [])],
)
def test_replace_cross_tenant_changes_nothing(
    world: World, domain: str, members: list[str]
) -> None:
    world.repo().assign(world.members["a_v1"], world.domains["a2"])
    before = world.all_rows()
    ids = [world.members[k] for k in members]
    assert world.repo().replace_for_domain(world.domains[domain], ids) is None
    assert world.all_rows() == before


def test_replace_refuses_too_many(world: World) -> None:
    ids = [world.members["a_v1"]] * (MAX_ASSIGNMENTS + 1)
    assert world.repo().replace_for_domain(world.domains["a1"], ids) is None


def test_rows_written_with_context_tenant(world: World) -> None:
    world.repo().assign(world.members["a_v1"], world.domains["a1"])
    rows = {r for r in world.all_rows() if r[1] == world.domains["a1"]}
    assert rows == {(world.members["a_v1"], world.domains["a1"], world.tenant_a)}
