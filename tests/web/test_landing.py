"""M1-19 tenant landing page `/` through the real app and middleware.

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url`
fixture); the schema is built by Alembic. Sessions are created directly with
`app.services.auth.create_session`; the setup test drives the real wizard. No network.
"""

from __future__ import annotations

import logging
import re
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
from app.core.db import create_db_engine, create_session_factory
from app.core.domain_names import to_ascii_domain
from app.core.security import SESSION_COOKIE_NAME
from app.main import create_app
from app.models import Domain, DomainAccess, Membership, MembershipRole, Tenant, User
from app.services import domains as domain_service
from app.services.auth import SessionPolicy, create_session
from app.web import auth as web_auth

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
HTML = {"Accept": "text/html"}
B_SECRET_NAME = "tenantb-secret.example"
B_TENANT_NAME = "Secret Agency B"
IDN = "bücher.example"
LOOKALIKE = "pаypal.example"  # Cyrillic "а"
A_DOMAINS = ("assigned.example", "unassigned.example", IDN, LOOKALIKE)
ROW = re.compile(r'<tr data-domain-id="(\d+)">')


@dataclass
class World:
    client: TestClient
    db: Session
    settings: Settings
    tenants: dict[str, int]
    users: dict[str, int]
    domains: dict[str, int]
    cookies: dict[tuple[str, int | None], str] = field(default_factory=dict)


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


def _seed(db: Session) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    tenants = {
        "a": Tenant(name="Agency A", slug="agency-a"),
        "b": Tenant(name=B_TENANT_NAME, slug="agency-b"),
        "empty": Tenant(name="Empty Agency", slug="empty"),
        "html": Tenant(name="<script>alert(1)</script> & Co", slug="html-co"),
    }
    names = ("owner", "admin", "analyst", "viewer", "lonely_viewer", "b_owner", "multi")
    users = {n: User(email=f"{n}@example.com") for n in (*names, "empty_owner", "html_owner")}
    users["nomember"] = User(email="nomember@example.com", is_instance_admin=True)
    db.add_all([*tenants.values(), *users.values()])
    db.flush()
    role = MembershipRole
    a, b = tenants["a"].id, tenants["b"].id

    def member(user: str, tenant: int, r: MembershipRole) -> Membership:
        return Membership(user_id=users[user].id, tenant_id=tenant, role=r)

    members = {
        "owner": member("owner", a, role.OWNER),
        "admin": member("admin", a, role.ADMIN),
        "analyst": member("analyst", a, role.ANALYST),
        "viewer": member("viewer", a, role.CLIENT_VIEWER),
        "lonely_viewer": member("lonely_viewer", a, role.CLIENT_VIEWER),
        "b_owner": member("b_owner", b, role.OWNER),
        "multi_a": member("multi", a, role.ANALYST),
        "multi_b": member("multi", b, role.OWNER),
        "empty_owner": member("empty_owner", tenants["empty"].id, role.OWNER),
        "html_owner": member("html_owner", tenants["html"].id, role.OWNER),
    }
    domains = {name: Domain(tenant_id=a, name=to_ascii_domain(name)) for name in A_DOMAINS}
    domains[B_SECRET_NAME] = Domain(tenant_id=b, name=B_SECRET_NAME)
    db.add_all([*members.values(), *domains.values()])
    db.flush()
    db.add(
        DomainAccess(
            membership_id=members["viewer"].id,
            domain_id=domains["assigned.example"].id,
            tenant_id=a,
        )
    )
    db.commit()
    return (
        {k: t.id for k, t in tenants.items()},
        {k: u.id for k, u in users.items()},
        {k: d.id for k, d in domains.items()},
    )


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenants, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenants, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


_DEFAULT_TENANT = {
    "b_owner": "b",
    "empty_owner": "empty",
    "html_owner": "html",
    "nomember": None,
}


def landing(w: World, who: str, tenant: str | None = "default", lang: str = "en") -> Any:
    w.client.cookies.clear()
    if who != "anon":
        key = _DEFAULT_TENANT.get(who, "a") if tenant == "default" else tenant
        tenant_id = None if key is None else w.tenants[key]
        if (who, tenant_id) not in w.cookies:
            user = w.db.scalars(select(User).where(User.id == w.users[who])).one()
            issued = create_session(
                w.db,
                user,
                w.settings.secret_key,
                active_tenant_id=tenant_id,
                policy=SessionPolicy.from_settings(w.settings),
            )
            w.db.commit()
            w.cookies[(who, tenant_id)] = issued.cookie_value
        w.client.cookies.set(SESSION_COOKIE_NAME, w.cookies[(who, tenant_id)])
    return w.client.get("/", headers={**HTML, "Accept-Language": lang}, follow_redirects=False)


def rows(w: World, html: str) -> set[str]:
    ids = {int(i) for i in ROW.findall(html)}
    return {name for name, did in w.domains.items() if did in ids}


# --- route and anonymous ------------------------------------------------------------------------


def test_root_is_a_registered_route() -> None:
    """`/` is a real route (named "landing"), not only a redirect target; the 200 responses
    below show it answers GET. FastAPI 0.162 wraps included routers, so the route is looked up
    by name through the public `url_path_for` instead of walking `app.routes`."""
    application = create_app(
        Settings(database_url="sqlite://", secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    )
    assert application.url_path_for("landing") == "/"


def test_anonymous_is_redirected_to_login(world: World) -> None:
    response = landing(world, "anon")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2F"


def test_anonymous_api_client_gets_401(world: World) -> None:
    world.client.cookies.clear()
    assert world.client.get("/", follow_redirects=False).status_code == 401


# --- visibility per role ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "visible", "can_add", "can_change"),
    [
        ("owner", set(A_DOMAINS), True, True),
        ("admin", set(A_DOMAINS), True, True),
        ("analyst", set(A_DOMAINS), False, False),
        ("viewer", {"assigned.example"}, False, False),
        ("b_owner", {B_SECRET_NAME}, True, True),
    ],
)
def test_landing_rows_and_buttons_per_role(
    world: World, who: str, visible: set[str], can_add: bool, can_change: bool
) -> None:
    response = landing(world, who)
    assert response.status_code == 200
    html = response.text
    assert rows(world, html) == visible
    assert ('data-testid="domain-add"' in html) is can_add
    assert ('data-testid="domain-rename"' in html) is can_change
    assert ('data-testid="domain-delete"' in html) is can_change
    assert html.count("Not checked yet") == len(visible)  # last-check empty state per row
    if who != "b_owner":
        assert B_SECRET_NAME not in html and B_TENANT_NAME not in html
        assert "Tenant: Agency A" in html
    else:
        assert "assigned.example" not in html and "Agency A" not in html


def test_viewer_does_not_see_unassigned_names_anywhere(world: World) -> None:
    html = landing(world, "viewer").text
    for name in ("unassigned.example", "xn--bcher-kva.example", IDN, LOOKALIKE):
        assert name not in html


def test_viewer_without_assignments_gets_empty_state(world: World) -> None:
    html = landing(world, "lonely_viewer").text
    assert 'data-testid="domains-empty"' in html
    assert rows(world, html) == set()


def test_empty_tenant_shows_empty_state(world: World) -> None:
    html = landing(world, "empty_owner").text
    assert 'data-testid="domains-empty"' in html
    assert "No domains yet." in html
    assert 'data-testid="domain-add"' in html


def test_user_without_tenant_gets_200_and_no_tenant_data(world: World) -> None:
    response = landing(world, "nomember")
    assert response.status_code == 200
    assert 'data-testid="no-tenant"' in response.text
    assert rows(world, response.text) == set()


def test_session_pointing_at_a_foreign_tenant_shows_no_tenant_data(world: World) -> None:
    """Owner of A whose session's active tenant is B (not a member there)."""
    response = landing(world, "owner", tenant="b")
    assert response.status_code == 200
    assert 'data-testid="no-tenant"' in response.text
    assert B_SECRET_NAME not in response.text and B_TENANT_NAME not in response.text
    assert rows(world, response.text) == set()


# --- tenant switcher ----------------------------------------------------------------------------


def test_switcher_shown_only_with_several_memberships(world: World) -> None:
    assert 'data-testid="tenant-switch"' not in landing(world, "owner").text
    html = landing(world, "multi").text
    assert 'data-testid="tenant-switch"' in html
    assert 'action="/tenants/switch"' in html and 'name="csrf_token"' in html
    assert f'<option value="{world.tenants["a"]}" selected>Agency A</option>' in html
    assert f'<option value="{world.tenants["b"]}">{B_TENANT_NAME}</option>' in html


def test_switching_tenant_changes_the_landing(world: World) -> None:
    html = landing(world, "multi").text
    assert rows(world, html) == set(A_DOMAINS)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert token
    response = world.client.post(
        "/tenants/switch",
        data={"csrf_token": token.group(1), "tenant_id": str(world.tenants["b"]), "next": "/"},
        follow_redirects=False,
    )
    assert (response.status_code, response.headers["location"]) == (303, "/")
    world.client.cookies.set(SESSION_COOKIE_NAME, response.cookies[SESSION_COOKIE_NAME])
    after = world.client.get("/", headers=HTML)
    assert rows(world, after.text) == {B_SECRET_NAME}
    assert f"Tenant: {B_TENANT_NAME}" in after.text


# --- display, i18n, escaping --------------------------------------------------------------------


def test_idn_shows_a_label_and_lookalike_flag(world: World) -> None:
    html = landing(world, "owner").text
    assert IDN in html and "ASCII form (A-label): xn--bcher-kva.example" in html
    assert f"ASCII form (A-label): {to_ascii_domain(LOOKALIKE)}" in html
    assert html.count('data-testid="mixed-script"') == 1  # only the Latin+Cyrillic name
    assert html.count('data-testid="a-label"') == 2  # ASCII names show no A-label


@pytest.mark.parametrize(
    ("lang", "texts"),
    [
        ("en", ("Domains", "Last check", "Not checked yet", "Add domain", "Rename", "Delete")),
        ("it", ("Domini", "Ultimo controllo", "Non ancora controllato", "Aggiungi dominio")),
    ],
)
def test_landing_renders_in_both_languages(world: World, lang: str, texts: tuple[str, ...]) -> None:
    html = landing(world, "owner", lang=lang).text
    assert f'<html lang="{lang}">' in html
    for text in texts:
        assert text in html
    assert ("Attenzione" in html) is (lang == "it")


def test_tenant_name_with_html_is_escaped(world: World) -> None:
    html = landing(world, "html_owner").text
    assert "<script>alert(1)</script>" not in html
    assert "Tenant: &lt;script&gt;alert(1)&lt;/script&gt; &amp; Co" in html


def test_domain_display_name_with_html_is_escaped(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(domain_service, "to_display_name", lambda _n: '<img src=x onerror="1">&')
    html = landing(world, "owner").text
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=&#34;1&#34;&gt;&amp;" in html


# --- setup -> landing ---------------------------------------------------------------------------


@pytest.fixture
def fresh(
    db_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> Iterator[tuple[TestClient, str]]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setattr(
        web_auth, "PASSWORD_HASHER", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    caplog.set_level(logging.DEBUG)
    application = create_app(
        Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    )
    with TestClient(application) as client:
        tokens = [
            str(r.args[1])  # type: ignore[index]
            for r in caplog.get_records("setup")
            if getattr(r, "event", None) == "setup.token_issued"
        ]
        assert len(tokens) == 1
        yield client, tokens[0]
    engine = getattr(application.state, "db_engine", None)
    if engine is not None:
        engine.dispose()


@pytest.mark.parametrize("tenant_name", ["Agency One", ""])
def test_setup_redirect_lands_on_a_200_landing(
    fresh: tuple[TestClient, str], tenant_name: str
) -> None:
    client, token = fresh
    pending = client.get("/", headers=HTML, follow_redirects=False)
    assert (pending.status_code, pending.headers["location"]) == (303, "/setup")
    form = client.get("/setup").text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', form)
    assert csrf
    password = "correct horse battery staple"
    response = client.post(
        "/setup",
        data={
            "csrf_token": csrf.group(1),
            "setup_token": token,
            "email": "admin@example.com",
            "password": password,
            "password_confirm": password,
            "tenant_name": tenant_name,
        },
        follow_redirects=False,
    )
    assert (response.status_code, response.headers["location"]) == (303, "/")
    page = client.get("/", headers=HTML, follow_redirects=False)
    assert page.status_code == 200
    if tenant_name:
        assert f"Tenant: {tenant_name}" in page.text
        assert 'data-testid="domains-empty"' in page.text
    else:
        assert 'data-testid="no-tenant"' in page.text
