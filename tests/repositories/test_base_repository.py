"""M1-12 TenantContext and tenant-scoped repositories.

Every DB test runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url`
fixture); the schema is built by Alembic. Two tenants with rows: every repository method used from
tenant A is checked never to return, change or delete tenant B rows, including malformed ids.
"""

import dataclasses
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.tenancy import TenantContext
from app.models import Base, Domain, DomainAccess, Membership, MembershipRole, Tenant, User
from app.repositories import (
    TenantMembershipRepository,
    TenantScopedRepository,
    TenantScopeError,
    UserMembershipsRepository,
    repo_for,
)
from app.repositories.base import coerce_id

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40


class DomainRepo(TenantScopedRepository[Domain]):
    """Test-only repository: exercises the base on a second model (the real one is M1-18)."""

    model = Domain


@dataclass
class World:
    session: Session
    engine: Engine
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]  # "a1", "a_shared", "b1", "b_shared"
    memberships: dict[str, int]  # "a_u1", "a_u2", "b_u1", "b_u3"

    def ctx_a(self) -> TenantContext:
        return TenantContext(self.tenant_a, self.users["u1"])


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    session = create_session_factory(engine)()
    try:
        ta, tb = Tenant(name="Zeta A", slug="a"), Tenant(name="Alpha B", slug="b")
        users = {n: User(email=f"{n}@example.com") for n in ("u1", "u2", "u3")}
        session.add_all([ta, tb, *users.values()])
        session.flush()
        domains = {
            "a1": Domain(tenant_id=ta.id, name="a1.example"),
            "a_shared": Domain(tenant_id=ta.id, name="shared.example"),
            "b1": Domain(tenant_id=tb.id, name="b1.example"),
            "b_shared": Domain(tenant_id=tb.id, name="shared.example"),
        }
        members = {
            "a_u1": Membership(user_id=users["u1"].id, tenant_id=ta.id, role=MembershipRole.OWNER),
            "a_u2": Membership(
                user_id=users["u2"].id, tenant_id=ta.id, role=MembershipRole.ANALYST
            ),
            "b_u1": Membership(
                user_id=users["u1"].id, tenant_id=tb.id, role=MembershipRole.CLIENT_VIEWER
            ),
            "b_u3": Membership(user_id=users["u3"].id, tenant_id=tb.id, role=MembershipRole.ADMIN),
        }
        session.add_all([*domains.values(), *members.values()])
        session.commit()
        yield World(
            session=session,
            engine=engine,
            tenant_a=ta.id,
            tenant_b=tb.id,
            users={k: v.id for k, v in users.items()},
            domains={k: v.id for k, v in domains.items()},
            memberships={k: v.id for k, v in members.items()},
        )
    finally:
        session.close()
        engine.dispose()


def _db_rows(world: World, table: str, tenant_id: int) -> list[tuple[Any, ...]]:
    """Ground truth read on a separate connection (bypasses session and repositories)."""
    world.session.commit()
    with world.engine.connect() as conn:
        result = conn.execute(
            text(f"SELECT * FROM {table} WHERE tenant_id = :t ORDER BY id"), {"t": tenant_id}
        )
        return [tuple(row) for row in result]


# Both tenant-scoped repositories, as (factory, table, own keys, foreign keys, key->id map).
REPOS = {
    "domains": (DomainRepo, "domains", ("a1", "a_shared"), ("b1", "b_shared"), "domains"),
    "memberships": (
        TenantMembershipRepository,
        "memberships",
        ("a_u1", "a_u2"),
        ("b_u1", "b_u3"),
        "memberships",
    ),
}
REPO_PARAMS = pytest.mark.parametrize("repo_name", list(REPOS))

MALFORMED_IDS = [None, "1", "abc", "1 OR 1=1", 1.0, True, False, 0, -1, 2**63, 2**80, [1], b"1"]


def _setup(world: World, repo_name: str) -> tuple[Any, str, list[int], list[int]]:
    factory, table, own, foreign, attr = REPOS[repo_name]
    ids: dict[str, int] = getattr(world, attr)
    repo = factory(world.ctx_a(), world.session)
    return repo, table, [ids[k] for k in own], [ids[k] for k in foreign]


# --- TenantContext -----------------------------------------------------------------------------


def test_tenant_context_is_immutable() -> None:
    ctx = TenantContext(1, 7)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.tenant_id = 2  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        ctx.extra = 1  # type: ignore[attr-defined]
    assert ctx == TenantContext(1, 7)
    assert TenantContext(1, None).principal is None


def test_tenant_context_requires_tenant_id() -> None:
    with pytest.raises(TypeError):
        TenantContext()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        TenantContext(principal=1)  # type: ignore[call-arg]


@pytest.mark.parametrize("tenant_id", [None, 0, -1, True, False, "1", 1.0, [1]])
def test_tenant_context_rejects_malformed_tenant_id(tenant_id: Any) -> None:
    with pytest.raises(ValueError):
        TenantContext(tenant_id, 1)


@pytest.mark.parametrize("principal", [0, -3, True, "7", 7.0])
def test_tenant_context_rejects_malformed_principal(principal: Any) -> None:
    with pytest.raises(ValueError):
        TenantContext(1, principal)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(1, 1), (2**63 - 1, 2**63 - 1), *[(v, None) for v in MALFORMED_IDS]],
)
def test_coerce_id(value: Any, expected: int | None) -> None:
    assert coerce_id(value) == expected


# --- construction ------------------------------------------------------------------------------


class _FakeCtx:
    tenant_id = 1
    principal = 1


@pytest.mark.parametrize("ctx", [None, 1, {"tenant_id": 1}, _FakeCtx()])
@pytest.mark.parametrize("factory", [DomainRepo, TenantMembershipRepository, repo_for])
def test_repositories_need_a_tenant_context(ctx: Any, factory: Any) -> None:
    with pytest.raises(TypeError):
        factory(ctx, Session())


def test_base_rejects_models_without_tenant_or_with_composite_key() -> None:
    with pytest.raises(TypeError, match="tenant_id"):

        class _UserRepo(TenantScopedRepository[User]):
            model = User

    with pytest.raises(TypeError, match="primary key"):

        class _AccessRepo(TenantScopedRepository[DomainAccess]):
            model = DomainAccess


# --- base methods: tenant A never reaches tenant B ---------------------------------------------


@REPO_PARAMS
def test_get_own_foreign_and_malformed(world: World, repo_name: str) -> None:
    repo, _table, own, foreign = _setup(world, repo_name)
    for pk in own:
        row = repo.get(pk)
        assert row is not None and row.tenant_id == world.tenant_a
    for pk in foreign:
        assert repo.get(pk) is None
    for bad in MALFORMED_IDS:
        assert repo.get(bad) is None
    assert repo.get(10**9) is None


@REPO_PARAMS
def test_get_foreign_even_if_in_identity_map(world: World, repo_name: str) -> None:
    """A foreign row already loaded in the session must still not be returned."""
    repo, _table, _own, foreign = _setup(world, repo_name)
    model = REPOS[repo_name][0].model
    assert world.session.get(model, foreign[0]) is not None  # now in the identity map
    assert repo.get(foreign[0]) is None


@REPO_PARAMS
def test_list_and_count_only_own_tenant(world: World, repo_name: str) -> None:
    repo, _table, own, _foreign = _setup(world, repo_name)
    assert [r.id for r in repo.list()] == sorted(own)
    assert {r.tenant_id for r in repo.list()} == {world.tenant_a}
    assert repo.count() == len(own)
    assert [r.id for r in repo.list(limit=1)] == [min(own)]
    assert [r.id for r in repo.list(limit=10, offset=1)] == [max(own)]
    assert repo.list(limit=10, offset=5) == []
    assert repo.list(limit=0) == []


@REPO_PARAMS
@pytest.mark.parametrize(
    "kwargs", [{"limit": -1}, {"limit": 1001}, {"limit": True}, {"limit": "5"}, {"offset": -1}]
)
def test_list_rejects_malformed_paging(world: World, repo_name: str, kwargs: Any) -> None:
    repo, *_ = _setup(world, repo_name)
    with pytest.raises(ValueError):
        repo.list(**kwargs)


def test_tenant_b_view_is_symmetric(world: World) -> None:
    ctx_b = TenantContext(world.tenant_b, world.users["u3"])
    repo = DomainRepo(ctx_b, world.session)
    assert [d.id for d in repo.list()] == sorted([world.domains["b1"], world.domains["b_shared"]])
    assert repo.get(world.domains["a1"]) is None
    assert repo.count() == 2


def _new_obj(world: World, repo_name: str, tenant_id: int | None) -> Any:
    if repo_name == "domains":
        return Domain(name="new.example", tenant_id=tenant_id)
    user = User(email="new@example.com")
    world.session.add(user)
    world.session.flush()
    return Membership(user_id=user.id, role=MembershipRole.ANALYST, tenant_id=tenant_id)


@REPO_PARAMS
@pytest.mark.parametrize("given", ["none", "own"])
def test_add_forces_context_tenant(world: World, repo_name: str, given: str) -> None:
    repo, table, own, _foreign = _setup(world, repo_name)
    obj = _new_obj(world, repo_name, None if given == "none" else world.tenant_a)
    before_b = _db_rows(world, table, world.tenant_b)
    added = repo.add(obj)
    assert added.tenant_id == world.tenant_a and added.id is not None
    assert repo.get(added.id) is added
    assert len(_db_rows(world, table, world.tenant_a)) == len(own) + 1
    assert _db_rows(world, table, world.tenant_b) == before_b


@REPO_PARAMS
def test_add_rejects_foreign_tenant_id(world: World, repo_name: str) -> None:
    repo, table, own, foreign = _setup(world, repo_name)
    obj = _new_obj(world, repo_name, world.tenant_b)
    with pytest.raises(TenantScopeError):
        repo.add(obj)
    assert obj not in world.session
    assert len(_db_rows(world, table, world.tenant_b)) == len(foreign)
    assert len(_db_rows(world, table, world.tenant_a)) == len(own)


@REPO_PARAMS
def test_add_rejects_existing_rows_and_wrong_types(world: World, repo_name: str) -> None:
    repo, _table, own, foreign = _setup(world, repo_name)
    model = REPOS[repo_name][0].model
    with pytest.raises(TenantScopeError):
        repo.add(world.session.get(model, foreign[0]))  # persistent row of tenant B
    with pytest.raises(TenantScopeError):
        repo.add(world.session.get(model, own[0]))
    with pytest.raises(TypeError):
        repo.add(Tenant(name="x", slug="x"))


def _update_values(repo_name: str) -> dict[str, Any]:
    if repo_name == "domains":
        return {"name": "renamed.example"}
    return {"role": MembershipRole.CLIENT_VIEWER}


@REPO_PARAMS
def test_update_own_row(world: World, repo_name: str) -> None:
    repo, _table, own, _foreign = _setup(world, repo_name)
    values = _update_values(repo_name)
    updated = repo.update(own[0], values)
    assert updated is not None
    for key, value in values.items():
        assert getattr(updated, key) == value
    assert updated.tenant_id == world.tenant_a


@REPO_PARAMS
def test_update_foreign_or_malformed_changes_nothing(world: World, repo_name: str) -> None:
    repo, table, _own, foreign = _setup(world, repo_name)
    before_a = _db_rows(world, table, world.tenant_a)
    before_b = _db_rows(world, table, world.tenant_b)
    for pk in [*foreign, *MALFORMED_IDS, 10**9]:
        assert repo.update(pk, _update_values(repo_name)) is None
    assert _db_rows(world, table, world.tenant_a) == before_a
    assert _db_rows(world, table, world.tenant_b) == before_b


@REPO_PARAMS
@pytest.mark.parametrize(
    ("values", "error"),
    [
        ({"tenant_id": "B"}, TenantScopeError),
        ({"tenant_id": "A"}, TenantScopeError),
        ({"id": 999}, TenantScopeError),
        ({"no_such_column": 1}, ValueError),
    ],
)
def test_update_rejects_tenant_pk_and_unknown(
    world: World, repo_name: str, values: dict[str, Any], error: type[Exception]
) -> None:
    repo, table, own, _foreign = _setup(world, repo_name)
    tenants = {"A": world.tenant_a, "B": world.tenant_b}
    values = {k: tenants.get(v, v) if k == "tenant_id" else v for k, v in values.items()}
    before_a = _db_rows(world, table, world.tenant_a)
    before_b = _db_rows(world, table, world.tenant_b)
    with pytest.raises(error):
        repo.update(own[0], {**_update_values(repo_name), **values})
    assert _db_rows(world, table, world.tenant_a) == before_a
    assert _db_rows(world, table, world.tenant_b) == before_b


@REPO_PARAMS
def test_loaded_row_cannot_be_moved_to_another_tenant(world: World, repo_name: str) -> None:
    repo, table, own, foreign = _setup(world, repo_name)
    row = repo.get(own[0])
    with pytest.raises(TenantScopeError):
        row.tenant_id = world.tenant_b
    world.session.expire(row)  # guard also holds when the old value has to be reloaded
    with pytest.raises(TenantScopeError):
        row.tenant_id = world.tenant_b
    world.session.rollback()
    assert len(_db_rows(world, table, world.tenant_b)) == len(foreign)


@REPO_PARAMS
def test_delete_foreign_or_malformed_deletes_nothing(world: World, repo_name: str) -> None:
    repo, table, own, foreign = _setup(world, repo_name)
    for pk in [*foreign, *MALFORMED_IDS, 10**9]:
        assert repo.delete(pk) is False
    assert len(_db_rows(world, table, world.tenant_a)) == len(own)
    assert len(_db_rows(world, table, world.tenant_b)) == len(foreign)


@REPO_PARAMS
def test_delete_own_row(world: World, repo_name: str) -> None:
    repo, table, own, foreign = _setup(world, repo_name)
    assert repo.delete(own[0]) is True
    assert repo.get(own[0]) is None
    assert repo.delete(own[0]) is False
    assert [r[0] for r in _db_rows(world, table, world.tenant_a)] == own[1:]
    assert len(_db_rows(world, table, world.tenant_b)) == len(foreign)


# --- specific repositories ---------------------------------------------------------------------


def test_membership_get_by_user(world: World) -> None:
    repo = repo_for(world.ctx_a(), world.session).memberships
    found = repo.get_by_user(world.users["u2"])
    assert found is not None and found.id == world.memberships["a_u2"]
    assert repo.get_by_user(world.users["u3"]) is None  # member of B only
    for bad in MALFORMED_IDS:
        assert repo.get_by_user(bad) is None


def test_current_tenant_repository(world: World) -> None:
    repos = repo_for(world.ctx_a(), world.session)
    tenant = repos.tenant.get()
    assert tenant is not None and tenant.id == world.tenant_a
    assert repos.ctx == world.ctx_a()
    missing = repo_for(TenantContext(10**9, None), world.session)
    assert missing.tenant.get() is None
    assert missing.memberships.list() == []


def test_user_memberships_are_user_scoped(world: World) -> None:
    u1 = UserMembershipsRepository(world.session, world.users["u1"])
    listed = u1.list()
    # ordered by tenant name: "Alpha B" before "Zeta A"
    assert [(m.tenant_id, m.role) for m in listed] == [
        (world.tenant_b, MembershipRole.CLIENT_VIEWER),
        (world.tenant_a, MembershipRole.OWNER),
    ]
    assert listed[0].tenant_slug == "b" and listed[0].membership_id == world.memberships["b_u1"]
    u2 = UserMembershipsRepository(world.session, world.users["u2"])
    assert [m.tenant_id for m in u2.list()] == [world.tenant_a]
    assert u2.get_for_tenant(world.tenant_b) is None
    found = u2.get_for_tenant(world.tenant_a)
    assert found is not None and found.role is MembershipRole.ANALYST
    for bad in MALFORMED_IDS:
        assert u2.get_for_tenant(bad) is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        found.role = MembershipRole.OWNER  # type: ignore[misc]


@pytest.mark.parametrize("user_id", [None, 0, -1, True, "1", 1.5])
def test_user_memberships_reject_malformed_user(user_id: Any) -> None:
    with pytest.raises(ValueError):
        UserMembershipsRepository(Session(), user_id)


# --- static rule: queries on tenant-owned tables live only in app/repositories -----------------


def _tenant_model_names() -> list[str]:
    return sorted(
        mapper.class_.__name__
        for mapper in Base.registry.mappers
        if "tenant_id" in mapper.columns and not mapper.columns["tenant_id"].nullable
    )


def _query_pattern() -> re.Pattern[str]:
    models = "|".join(_tenant_model_names())
    return re.compile(
        rf"\b(?:select|update|delete|insert)\s*\(\s*(?:{models})\b"
        rf"|\.(?:query|get|merge)\s*\(\s*(?:{models})\b"
    )


def test_tenant_model_list_is_complete() -> None:
    assert {"Domain", "DomainAccess", "Membership"} <= set(_tenant_model_names())


@pytest.mark.parametrize(
    ("source", "matches"),
    [
        ("stmt = select(Domain).where(Domain.id == 1)", True),
        ("session.query( Membership ).all()", True),
        ("session.get(DomainAccess, (1, 2))", True),
        ("update(Domain).values(name='x')", True),
        ("select(Tenant)", False),
        ("select(User.id)", False),
        ("repos.memberships.get(1)", False),
    ],
)
def test_query_pattern(source: str, matches: bool) -> None:
    assert bool(_query_pattern().search(source)) is matches


def test_no_tenant_queries_outside_repositories() -> None:
    pattern = _query_pattern()
    offenders = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        if (ROOT / "app" / "repositories") in path.parents:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
    assert offenders == []
