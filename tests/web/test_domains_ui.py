"""M1-19 domain management UI (/domains/...) through the real app and middleware.

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url`
fixture); the schema is built by Alembic. Sessions are created directly with
`app.services.auth.create_session`. No network.

The tenancy matrix covers EVERY route x role (anonymous, owner, admin, analyst, client viewer)
x target (domain assigned to the viewer, unassigned domain of tenant A, domain of tenant B).
Expected statuses are written out explicitly, not derived from code.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
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
from app.core.domain_names import MAX_INPUT_LENGTH, to_ascii_domain
from app.core.security import SESSION_COOKIE_NAME, unsign_session_token
from app.main import create_app
from app.models import Domain, DomainAccess, Membership, MembershipRole, Tenant, User
from app.services import domains as domain_service
from app.services.auth import SessionPolicy, create_session
from app.web.domains import clean_field, mixed_script
from app.web.templating import MAX_FORM_BYTES

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
HTML = {"Accept": "text/html"}
B_SECRET_NAME = "tenantb-secret.example"
B_TENANT_NAME = "Secret Agency B"
ROLES = ("anon", "owner", "admin", "analyst", "viewer")
TARGETS = ("assigned", "unassigned", "other")


@dataclass
class World:
    client: TestClient
    db: Session
    settings: Settings
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]
    cookies: dict[tuple[str, int], str] = field(default_factory=dict)


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


def _seed(db: Session) -> tuple[int, int, dict[str, int], dict[str, int]]:
    a = Tenant(name="Agency A", slug="agency-a")
    b = Tenant(name=B_TENANT_NAME, slug="agency-b")
    users = {n: User(email=f"{n}@example.com") for n in (*ROLES[1:], "b_owner")}
    db.add_all([a, b, *users.values()])
    db.flush()
    role = MembershipRole
    members = {
        "owner": Membership(user_id=users["owner"].id, tenant_id=a.id, role=role.OWNER),
        "admin": Membership(user_id=users["admin"].id, tenant_id=a.id, role=role.ADMIN),
        "analyst": Membership(user_id=users["analyst"].id, tenant_id=a.id, role=role.ANALYST),
        "viewer": Membership(user_id=users["viewer"].id, tenant_id=a.id, role=role.CLIENT_VIEWER),
        "b_owner": Membership(user_id=users["b_owner"].id, tenant_id=b.id, role=role.OWNER),
    }
    domains = {
        "assigned": Domain(tenant_id=a.id, name="assigned.example"),
        "unassigned": Domain(tenant_id=a.id, name="unassigned.example"),
        "other": Domain(tenant_id=b.id, name=B_SECRET_NAME),
    }
    db.add_all([*members.values(), *domains.values()])
    db.flush()
    db.add(
        DomainAccess(
            membership_id=members["viewer"].id, domain_id=domains["assigned"].id, tenant_id=a.id
        )
    )
    db.commit()
    return a.id, b.id, {k: u.id for k, u in users.items()}, {k: d.id for k, d in domains.items()}


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- request helpers ----------------------------------------------------------------------------


def _cookie(w: World, who: str, tenant_id: int) -> str:
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
    return w.cookies[(who, tenant_id)]


def _login(w: World, who: str, tenant_id: int | None = None) -> str | None:
    """Set the cookies for `who` and return the CSRF token to submit (None: no token)."""
    w.client.cookies.clear()
    if who == "anon":
        token = new_double_submit_token(w.settings.secret_key)
        w.client.cookies.set(CSRF_COOKIE_NAME, token)
        return token
    cookie = _cookie(w, who, w.tenant_a if tenant_id is None else tenant_id)
    w.client.cookies.set(SESSION_COOKIE_NAME, cookie)
    session_token = unsign_session_token(cookie, w.settings.secret_key)
    assert session_token is not None
    return session_csrf_token(session_token, w.settings.secret_key)


def get(w: World, who: str, path: str, *, tenant_id: int | None = None, **headers: str) -> Any:
    _login(w, who, tenant_id)
    return w.client.get(path, headers={**HTML, **headers}, follow_redirects=False)


def post(
    w: World,
    who: str,
    path: str,
    data: dict[str, str] | None = None,
    *,
    tenant_id: int | None = None,
    csrf: bool = True,
    content: bytes | None = None,
    **headers: str,
) -> Any:
    token = _login(w, who, tenant_id)
    sent = {**HTML, **headers}
    if content is not None:
        sent.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if csrf and token:
            sent[CSRF_HEADER] = token
        return w.client.post(path, content=content, headers=sent, follow_redirects=False)
    body = dict(data or {})
    if csrf and token:
        body["csrf_token"] = token
    return w.client.post(path, data=body, headers=sent, follow_redirects=False)


def snapshot(w: World) -> list[tuple[Any, ...]]:
    w.db.expire_all()
    return [
        tuple(r)
        for r in w.db.execute(
            select(Domain.id, Domain.tenant_id, Domain.name).order_by(Domain.id)
        ).all()
    ]


def domain_path(w: World, target: str, suffix: str = "") -> str:
    return f"/domains/{w.domains[target]}{suffix}"


# --- tenancy / permission matrix ----------------------------------------------------------------

# (route, role) -> status per target (assigned, unassigned, other-tenant).
_READ = {"owner": (200, 200, 404), "admin": (200, 200, 404), "analyst": (200, 200, 404)}
_WRITE_FORM = {"owner": (200, 200, 404), "admin": (200, 200, 404), "analyst": (403, 403, 404)}
_WRITE = {"owner": (303, 303, 404), "admin": (303, 303, 404), "analyst": (403, 403, 404)}
EXPECTED: dict[tuple[str, str], tuple[int, int, int]] = {
    ("GET detail", "anon"): (303, 303, 303),
    ("GET detail", "viewer"): (200, 404, 404),
    **{("GET detail", r): v for r, v in _READ.items()},
    ("GET rename", "anon"): (303, 303, 303),
    ("GET rename", "viewer"): (403, 404, 404),
    **{("GET rename", r): v for r, v in _WRITE_FORM.items()},
    ("POST rename", "anon"): (401, 401, 401),
    ("POST rename", "viewer"): (403, 404, 404),
    **{("POST rename", r): v for r, v in _WRITE.items()},
    ("GET delete", "anon"): (303, 303, 303),
    ("GET delete", "viewer"): (403, 404, 404),
    **{("GET delete", r): v for r, v in _WRITE_FORM.items()},
    ("POST delete", "anon"): (401, 401, 401),
    ("POST delete", "viewer"): (403, 404, 404),
    **{("POST delete", r): v for r, v in _WRITE.items()},
}
DOMAIN_ROUTES = ("GET detail", "GET rename", "POST rename", "GET delete", "POST delete")


def _call(w: World, route: str, who: str, target: str, tenant_id: int | None = None) -> Any:
    method, page = route.split(" ")
    suffix = "" if page == "detail" else f"/{page}"
    path = domain_path(w, target, suffix)
    if method == "GET":
        return get(w, who, path, tenant_id=tenant_id)
    return post(w, who, path, {"name": "renamed.example"}, tenant_id=tenant_id)


def test_matrix_is_complete() -> None:
    assert {(r, who) for r in DOMAIN_ROUTES for who in ROLES} == set(EXPECTED)


@pytest.mark.parametrize("route", DOMAIN_ROUTES)
@pytest.mark.parametrize("who", ROLES)
@pytest.mark.parametrize("index", range(3), ids=TARGETS)
def test_domain_route_matrix(world: World, route: str, who: str, index: int) -> None:
    target = TARGETS[index]
    before = snapshot(world)
    response = _call(world, route, who, target)
    expected = EXPECTED[(route, who)][index]
    assert response.status_code == expected, (route, who, target, response.text[:300])
    if expected == 303 and who == "anon":
        assert response.headers["location"].startswith("/login?next=")
    if expected != 303 or route.startswith("GET"):
        assert snapshot(world) == before  # denied or read-only: nothing changed
    else:
        assert snapshot(world) != before
    assert B_SECRET_NAME not in response.text and B_TENANT_NAME not in response.text
    if expected == 404:
        assert "assigned.example" not in response.text  # the 404 page shows nothing of A either


# (route, role) -> status for the tenant-level routes.
CREATE_EXPECTED = {
    ("GET new", "anon"): 303,
    ("GET new", "owner"): 200,
    ("GET new", "admin"): 200,
    ("GET new", "analyst"): 403,
    ("GET new", "viewer"): 403,
    ("POST create", "anon"): 401,
    ("POST create", "owner"): 303,
    ("POST create", "admin"): 303,
    ("POST create", "analyst"): 403,
    ("POST create", "viewer"): 403,
}


@pytest.mark.parametrize(("route", "who"), sorted(CREATE_EXPECTED))
def test_create_route_matrix(world: World, route: str, who: str) -> None:
    before = snapshot(world)
    if route == "GET new":
        response = get(world, who, "/domains/new")
    else:
        response = post(world, who, "/domains", {"name": "new-domain.example"})
    expected = CREATE_EXPECTED[(route, who)]
    assert response.status_code == expected, response.text[:300]
    after = snapshot(world)
    if route == "POST create" and expected == 303:
        assert response.headers["location"] == "/"
        (added,) = set(after) - set(before)
        assert added[1:] == (world.tenant_a, "new-domain.example")
    else:
        assert after == before
    if expected == 403:
        assert 'data-testid="forbidden"' in response.text
        assert 'name="name"' not in response.text  # no form rendered


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/domains/new"),
        ("POST", "/domains"),
        ("GET", "/domains/{id}"),
        ("GET", "/domains/{id}/rename"),
        ("POST", "/domains/{id}/rename"),
        ("GET", "/domains/{id}/delete"),
        ("POST", "/domains/{id}/delete"),
    ],
)
def test_session_without_active_tenant_membership_is_404(
    world: World, method: str, path: str
) -> None:
    """Owner of A whose session points at tenant B (not a member there): no TenantContext."""
    before = snapshot(world)
    url = path.replace("{id}", str(world.domains["assigned"]))
    if method == "GET":
        response = get(world, "owner", url, tenant_id=world.tenant_b)
    else:
        response = post(world, "owner", url, {"name": "x.example"}, tenant_id=world.tenant_b)
    assert response.status_code == 404
    assert snapshot(world) == before
    assert B_SECRET_NAME not in response.text


def test_tenant_b_owner_cannot_reach_tenant_a_domains(world: World) -> None:
    before = snapshot(world)
    for suffix in ("", "/rename", "/delete"):
        path = domain_path(world, "assigned", suffix)
        assert get(world, "b_owner", path, tenant_id=world.tenant_b).status_code == 404
        if suffix:
            data = {"name": "x.example"}
            response = post(world, "b_owner", path, data, tenant_id=world.tenant_b)
            assert response.status_code == 404
    assert snapshot(world) == before


@pytest.mark.parametrize("raw_id", ["abc", "0", "-1", "1.0", "99999999999999999999", "١"])
def test_malformed_ids_are_404(world: World, raw_id: str) -> None:
    for suffix in ("", "/rename", "/delete"):
        assert get(world, "owner", f"/domains/{raw_id}{suffix}").status_code == 404


@pytest.mark.parametrize("path", ["/domains", "/domains/{id}/rename", "/domains/{id}/delete"])
def test_posts_require_csrf(world: World, path: str) -> None:
    before = snapshot(world)
    url = path.replace("{id}", str(world.domains["assigned"]))
    response = post(world, "owner", url, {"name": "csrf.example"}, csrf=False)
    assert response.status_code == 403
    assert snapshot(world) == before


# --- action buttons -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "buttons"),
    [("owner", True), ("admin", True), ("analyst", False), ("viewer", False)],
)
def test_detail_buttons_follow_the_role(world: World, who: str, buttons: bool) -> None:
    html = get(world, who, domain_path(world, "assigned")).text
    assert ('data-testid="domain-rename"' in html) is buttons
    assert ('data-testid="domain-delete"' in html) is buttons
    assert ('data-testid="access-count"' in html) is buttons
    assert "Not checked yet" in html


def test_detail_shows_access_count_for_managers(world: World) -> None:
    html = get(world, "owner", domain_path(world, "assigned")).text
    assert "Client viewers with access: 1" in html
    html = get(world, "owner", domain_path(world, "unassigned")).text
    assert "Client viewers with access: 0" in html


# --- forms --------------------------------------------------------------------------------------


def test_create_rename_delete_happy_path(world: World) -> None:
    assert post(world, "owner", "/domains", {"name": "Bücher.Example"}).status_code == 303
    created = next(r for r in snapshot(world) if r[2] == "xn--bcher-kva.example")
    assert created[1] == world.tenant_a
    path = f"/domains/{created[0]}"
    html = get(world, "owner", path).text
    assert "bücher.example" in html and "xn--bcher-kva.example" in html

    form = get(world, "owner", f"{path}/rename").text
    assert 'value="bücher.example"' in form
    response = post(world, "owner", f"{path}/rename", {"name": "renamed.example"})
    assert (response.status_code, response.headers["location"]) == (303, path)
    assert (created[0], world.tenant_a, "renamed.example") in snapshot(world)

    confirm = get(world, "owner", f"{path}/delete").text
    assert "Delete the domain renamed.example? This cannot be undone." in confirm
    response = post(world, "owner", f"{path}/delete")
    assert (response.status_code, response.headers["location"]) == (303, "/")
    assert all(r[0] != created[0] for r in snapshot(world))


@pytest.mark.parametrize(
    ("body", "status", "echo"),
    [
        (b"name=bad%00name.example", 422, None),  # NUL
        (b"name=bad%01.example", 422, None),  # C0 control
        (b"name=bad%7F.example", 422, None),  # DEL
        (b"name=bad%C2%85.example", 422, None),  # C1 control (NEL)
        (b"name=a.example&name=b.example", 422, None),  # repeated field
        (b"other=a.example", 422, None),  # missing field
        (b"name=" + b"a" * (MAX_INPUT_LENGTH + 1), 422, None),  # over-long
        (b"name=", 422, None),
        (b"name=not+a+domain", 422, "not a domain"),
        (b"name=%3Cscript%3Ealert(1)%3C%2Fscript%3E.example", 422, None),
        (b"name=assigned.example", 409, "assigned.example"),
        (b"name=%FF%FE", 422, None),  # invalid UTF-8 -> replacement characters
        (b"%%%", 422, None),
    ],
)
def test_create_form_rejects_bad_input(
    world: World, body: bytes, status: int, echo: str | None
) -> None:
    before = snapshot(world)
    response = post(world, "owner", "/domains", content=body)
    assert response.status_code == status
    assert snapshot(world) == before
    html = response.text
    assert 'role="alert"' in html
    assert "\x00" not in html and "\x01" not in html and "\x7f" not in html
    assert "<script>alert" not in html
    if echo is not None:
        assert f'value="{echo}"' in html


def test_markup_in_rejected_name_is_escaped_when_echoed(world: World) -> None:
    response = post(world, "owner", "/domains", {"name": '"><b>x</b>'})
    assert response.status_code == 422
    assert "<b>x</b>" not in response.text
    assert "&#34;&gt;&lt;b&gt;x&lt;/b&gt;" in response.text


@pytest.mark.parametrize(
    ("body", "status"),
    [
        (b"name=bad%00.example", 422),
        (b"name=unassigned.example", 409),
        (b"name=x", 422),
        (b"name=a.example&name=b.example", 422),
    ],
)
def test_rename_form_rejects_bad_input(world: World, body: bytes, status: int) -> None:
    before = snapshot(world)
    response = post(world, "owner", domain_path(world, "assigned", "/rename"), content=body)
    assert response.status_code == status
    assert snapshot(world) == before
    assert 'role="alert"' in response.text


def test_oversized_form_is_413(world: World) -> None:
    before = snapshot(world)
    body = b"name=" + b"a" * (MAX_FORM_BYTES + 1)
    response = post(world, "owner", "/domains", content=body)
    assert response.status_code == 413
    assert snapshot(world) == before


def test_html_characters_in_display_name_are_escaped(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = "<script>alert(1)</script>\"&'.example"
    monkeypatch.setattr(domain_service, "to_display_name", lambda _name: payload)
    for path in ("", "/rename", "/delete"):
        html = get(world, "owner", domain_path(world, "assigned", path)).text
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;&#34;&amp;&#39;.example" in html


@pytest.mark.parametrize(
    ("lang", "texts"),
    [
        ("en", ("Domain details", "Not checked yet", "Rename", "Client viewer access")),
        ("it", ("Dettagli del dominio", "Non ancora controllato", "Rinomina", "Accesso dei")),
    ],
)
def test_pages_render_in_both_languages(world: World, lang: str, texts: tuple[str, ...]) -> None:
    html = get(world, "owner", domain_path(world, "assigned"), **{"Accept-Language": lang}).text
    assert f'<html lang="{lang}">' in html
    for text in texts:
        assert text in html
    add = get(world, "owner", "/domains/new", **{"Accept-Language": lang}).text
    assert ("Add domain" if lang == "en" else "Aggiungi dominio") in add


def test_idn_detail_shows_a_label_and_mixed_script_flag(world: World) -> None:
    lookalike = to_ascii_domain("pаypal.example")  # Cyrillic "а"
    assert post(world, "owner", "/domains", {"name": lookalike}).status_code == 303
    row = next(r for r in snapshot(world) if r[2] == lookalike)
    html = get(world, "owner", f"/domains/{row[0]}").text
    assert 'data-testid="mixed-script"' in html
    assert f"ASCII form (A-label): {lookalike}" in html
    plain = get(world, "owner", domain_path(world, "assigned")).text
    assert 'data-testid="mixed-script"' not in plain
    assert 'data-testid="a-label"' not in plain


# --- pure helpers (no DB) -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "flagged"),
    [
        ("example.com", False),
        ("bücher.example", False),  # Latin with diacritics
        ("москва.рф", False),  # Cyrillic only
        ("москва.example", False),  # scripts differ only across labels
        ("pаypal.example", True),  # Latin + Cyrillic а
        ("рaypal.com", True),  # Cyrillic р + Latin
        ("gοogle.com", True),  # Latin + Greek ο
        ("αβγ.example", False),  # Greek only
        ("東京.jp", False),  # Han only
        ("東京タワー.jp", False),  # Han + Katakana (Japanese)
        ("abcひらがな漢字.jp", False),  # Latin + Hiragana + Han
        ("한국어漢字.kr", False),  # Hangul + Han (Korean)
        ("ㄅㄆ中文.tw", False),  # Bopomofo + Han
        ("한국ひらがな.example", True),  # Hangul + Hiragana: not an allowed combination
        ("abcمثال.example", True),  # Latin + Arabic
        ("مثال٣.example", False),  # Arabic letters with Arabic-Indic digit
        ("éxample.com", False),  # combining mark inherits
        ("123-456.example", False),  # digits and hyphen are neutral
        ("", False),
        ("...", False),
    ],
)
def test_mixed_script_heuristic(name: str, flagged: bool) -> None:
    assert mixed_script(name) is flagged


@pytest.mark.parametrize(
    ("form", "expected"),
    [
        ({"name": ["example.com"]}, "example.com"),
        ({"name": ["bücher.example"]}, "bücher.example"),
        ({"name": [""]}, ""),
        ({}, None),
        ({"name": []}, None),
        ({"name": ["a.example", "b.example"]}, None),
        ({"name": ["a\x00.example"]}, None),
        ({"name": ["a\x1f.example"]}, None),
        ({"name": ["a\x7f.example"]}, None),
        ({"name": ["a\x85.example"]}, None),
        ({"name": ["a\ud800.example"]}, None),
        ({"name": ["a" * (MAX_INPUT_LENGTH + 1)]}, None),
        ({"name": ["a" * MAX_INPUT_LENGTH]}, "a" * MAX_INPUT_LENGTH),
    ],
)
def test_clean_field(form: dict[str, list[str]], expected: str | None) -> None:
    assert clean_field(form, "name") == expected
