"""Shared world for the M1-20 tenancy matrix and the M1 acceptance tests.

Two tenants with data, one user per role in tenant A (owner, admin, analyst, client viewer with
an assigned and an unassigned domain), the instance admin (created by the real setup service, as
owner of tenant A), tenant B users, and anonymous requests. Seeding goes through services and
repositories only (no raw SQL):
- instance admin + tenant A: `app.services.setup.issue_setup_token` / `complete_setup`;
- memberships: `repo_for(ctx).memberships.add`;
- domains and client-viewer assignments: `DomainService.create` / `DomainService.set_access`.
Users and tenant B are plain ORM rows: `users` and `tenants` are not tenant-owned tables and no
service creates them yet (M2 tenant/user management).

The world is module scoped (one schema per test module and database) and runs on SQLite and, when
TEST_DATABASE_URL is set, on PostgreSQL. Every cross-tenant request must fail, so the shared state
stays as seeded; tests that change sessions (logout, switch) use fresh sessions. No network.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import i18n
from app.core.config import Settings
from app.core.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER,
    new_double_submit_token,
    session_csrf_token,
)
from app.core.db import create_db_engine, create_session_factory
from app.core.domain_names import to_display_name
from app.core.security import SESSION_COOKIE_NAME, unsign_session_token
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import MembershipRole, Tenant, User
from app.repositories import principal_from_models, repo_for
from app.services import setup as setup_service
from app.services.auth import SessionPolicy, create_session
from app.services.domains import DomainService
from tests.conftest import _reset_postgres

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
HTML = "text/html"
JSON = "application/json"

# Authenticated roles of the matrix (all members of tenant A). "instance_admin" holds the
# instance flag and is the owner of tenant A created by the setup wizard.
ROLES = ("owner", "admin", "analyst", "viewer", "instance_admin")
_A_ROLE = {
    "owner": MembershipRole.OWNER,
    "admin": MembershipRole.ADMIN,
    "analyst": MembershipRole.ANALYST,
    "viewer": MembershipRole.CLIENT_VIEWER,
}

A_TENANT_NAME = "Agency A"
A_DOMAINS = {"assigned": "assigned.example", "unassigned": "unassigned.example"}
# Tenant B data: none of these strings may appear in any response or log line produced for a
# tenant A user (case-insensitive). Distinctive on purpose so a hit is never a coincidence.
B_TENANT_NAME = "Zanzibar Confidential Holdings"
B_DOMAINS = {"secret": "zanzibar-secret.example", "idn": "zanzibär-geheim.example"}
B_USERS = ("b_owner", "b_viewer")


@dataclass
class World:
    client: TestClient
    db: Session
    settings: Settings
    tenants: dict[str, int]  # "a", "b"
    users: dict[str, int]
    domains: dict[str, int]  # "assigned", "unassigned" (A); "secret", "idn" (B)
    b_secrets: tuple[str, ...]
    cookies: dict[tuple[str, str], str] = field(default_factory=dict)

    def user(self, who: str) -> User:
        return self.db.scalars(select(User).where(User.id == self.users[who])).one()

    def new_cookie(self, who: str, tenant: str) -> str:
        """A fresh live session for `who` whose active tenant is `tenant` ("a" or "b"); a user
        of tenant A with tenant "b" is a forged/stale active tenant id."""
        issued = create_session(
            self.db,
            self.user(who),
            self.settings.secret_key,
            active_tenant_id=self.tenants[tenant],
            policy=SessionPolicy.from_settings(self.settings),
        )
        self.db.commit()
        return issued.cookie_value

    def cookie(self, who: str, tenant: str) -> str:
        if (who, tenant) not in self.cookies:
            self.cookies[(who, tenant)] = self.new_cookie(who, tenant)
        return self.cookies[(who, tenant)]

    def send(
        self,
        who: str,
        method: str,
        path: str,
        *,
        tenant: str = "a",
        fresh: bool = False,
        form: dict[str, str] | None = None,
        json: Any = None,
    ) -> Any:
        """Send a request as `who` (a seeded user or "anon") with a valid CSRF token. UI paths
        are sent as a browser (Accept: text/html, urlencoded forms), /api paths as JSON."""
        self.client.cookies.clear()
        api = path.startswith("/api/")
        headers = {"Accept": JSON if api else HTML}
        if who == "anon":
            token = new_double_submit_token(self.settings.secret_key)
            self.client.cookies.set(CSRF_COOKIE_NAME, token)
        else:
            cookie = self.new_cookie(who, tenant) if fresh else self.cookie(who, tenant)
            self.client.cookies.set(SESSION_COOKIE_NAME, cookie)
            session_token = unsign_session_token(cookie, self.settings.secret_key)
            assert session_token is not None
            token = session_csrf_token(session_token, self.settings.secret_key)
        if method in ("GET", "HEAD"):
            return self.client.request(method, path, headers=headers, follow_redirects=False)
        headers[CSRF_HEADER] = token
        if api:
            return self.client.request(
                method, path, json=json, headers=headers, follow_redirects=False
            )
        return self.client.request(
            method, path, data=dict(form or {}), headers=headers, follow_redirects=False
        )

    def state(self, tenant: str) -> tuple[Any, ...]:
        """Ground truth of one tenant read through its repositories: tenant row, memberships,
        domains and every domain's access list."""
        self.db.expire_all()
        repos = repo_for(TenantContext(self.tenants[tenant], None), self.db)
        row = repos.tenant.get()
        assert row is not None
        members = tuple(
            sorted((m.id, m.user_id, str(m.role)) for m in repos.memberships.list(limit=1000))
        )
        domains = tuple(sorted((d.id, d.name) for d in repos.domains.list(limit=1000)))
        access = tuple(
            (d_id, tuple(sorted(repos.domain_access.membership_ids_for_domain(d_id))))
            for d_id, _ in domains
        )
        return (row.id, row.name, row.slug, members, domains, access)


@pytest.fixture(autouse=True)
def _strict_i18n() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


def _service(db: Session, tenant_id: int, user: User) -> DomainService:
    """A DomainService acting as `user` in `tenant_id` (memberships loaded via repositories)."""
    repos = repo_for(TenantContext(tenant_id, user.id), db)
    membership = repos.memberships.get_by_user(user.id)
    assert membership is not None
    principal = principal_from_models(user, [membership], [], tenant_id)
    return DomainService(db, TenantContext(tenant_id, user.id), principal)


def _add_member(db: Session, tenant_id: int, user: User, role: MembershipRole) -> None:
    memberships = repo_for(TenantContext(tenant_id, None), db).memberships
    memberships.add(memberships.model(user_id=user.id, role=role))


def _seed(db: Session, settings: Settings) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    token = setup_service.issue_setup_token(db)
    db.commit()
    assert token is not None
    result = setup_service.complete_setup(
        db,
        setup_service.SetupInput("root@agency-a.example", "x" * 20, A_TENANT_NAME),
        token,
        secret_key=settings.secret_key,
        policy=SessionPolicy.from_settings(settings),
        hasher=FAST,
    )
    assert result.outcome is setup_service.SetupOutcome.COMPLETED
    assert result.user_id is not None and result.tenant_id is not None
    tenant_a = result.tenant_id

    users = {who: User(email=f"{who}@agency-a.example") for who in _A_ROLE}
    users |= {who: User(email=f"{who.replace('_', '-')}@zanzibar.example") for who in B_USERS}
    tenant_b = Tenant(name=B_TENANT_NAME, slug="zanzibar-confidential")
    db.add_all([tenant_b, *users.values()])
    db.flush()
    for who, role in _A_ROLE.items():
        _add_member(db, tenant_a, users[who], role)
    _add_member(db, tenant_b.id, users["b_owner"], MembershipRole.OWNER)
    _add_member(db, tenant_b.id, users["b_viewer"], MembershipRole.CLIENT_VIEWER)
    db.commit()

    a_service = _service(db, tenant_a, users["owner"])
    domains = {key: a_service.create(name).id for key, name in A_DOMAINS.items()}
    a_service.set_access(domains["assigned"], [users["viewer"].id])
    b_service = _service(db, tenant_b.id, users["b_owner"])
    domains |= {key: b_service.create(name).id for key, name in B_DOMAINS.items()}
    b_service.set_access(domains["secret"], [users["b_viewer"].id])

    user_ids = {who: u.id for who, u in users.items()} | {"instance_admin": result.user_id}
    return {"a": tenant_a, "b": tenant_b.id}, user_ids, domains


def _b_secrets(db: Session, tenant_b: int) -> tuple[str, ...]:
    repos = repo_for(TenantContext(tenant_b, None), db)
    tenant = repos.tenant.get()
    assert tenant is not None
    secrets = {tenant.name, tenant.slug}
    for domain in repos.domains.list(limit=1000):
        secrets |= {domain.name, to_display_name(domain.name)}
    for who in B_USERS:
        secrets.add(f"{who.replace('_', '-')}@zanzibar.example")
    return tuple(sorted(secrets))


@pytest.fixture(
    scope="module",
    params=[
        "sqlite",
        pytest.param(
            "postgresql",
            marks=pytest.mark.skipif(
                not os.environ.get("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL not set"
            ),
        ),
    ],
)
def world(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[World]:
    if request.param == "sqlite":
        db_url = f"sqlite:///{tmp_path_factory.mktemp('tenancy') / 'test.db'}"
    else:
        db_url = os.environ["TEST_DATABASE_URL"]  # vetted in tests/conftest.py
        _reset_postgres(db_url)
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("DATABASE_URL", db_url)
        mp.setenv("SECRET_KEY", KEY)
        mp.setenv("ENCRYPTION_KEY", KEY)
        command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
        engine = create_db_engine(db_url)
        db = create_session_factory(engine)()
        settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
        tenants, users, domains = _seed(db, settings)
        application = create_app(settings)
        try:
            with TestClient(application, raise_server_exceptions=True) as client:
                yield World(
                    client, db, settings, tenants, users, domains, _b_secrets(db, tenants["b"])
                )
        finally:
            db.close()
            app_engine = getattr(application.state, "db_engine", None)
            if app_engine is not None:
                app_engine.dispose()
            engine.dispose()
            if request.param == "postgresql":
                _reset_postgres(db_url)


def leaks(world: World, response: Any, caplog: pytest.LogCaptureFixture) -> list[str]:
    """Tenant B strings found in the response (body and headers) or the captured log records
    (message and every extra field). Case-insensitive."""
    haystacks = {
        "body": response.text,
        "headers": "\n".join(f"{k}: {v}" for k, v in response.headers.items()),
        "logs": "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records),
    }
    return [
        f"{where}: {secret!r}"
        for where, text in haystacks.items()
        for secret in world.b_secrets
        if secret.casefold() in text.casefold()
    ]


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG)
    return caplog
