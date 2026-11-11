"""M5-21 DKIM selectors admin UI (`/dkim-selectors`): access, CSRF, escaping, outcomes, seeded rows,
i18n.

No network (sockets are blocked except the test database). The service write methods are wrapped
by a spy so a denied request is proven never to reach them. Route x role coverage is also generated
by the tenancy matrix (tests/tenancy/test_matrix.py). This module needs the seeded global
selectors, so it stays out of `SEEDLESS_MODULES`.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import LOCALES_DIR
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import DkimSelector, Membership, MembershipRole, User
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.repositories.dkim_selectors import DkimSelectorRecord
from app.services.dkim_selectors_admin import (
    MAX_TENANT_SELECTORS,
    DkimSelectorsAdminError,
    DkimSelectorsAdminService,
    SelectorConflict,
    SelectorFieldInvalid,
    SelectorNotFound,
)
from app.web.dkim_selectors import MAX_SAVE_BYTES
from tests.support.socket_guard import db_endpoint, install
from tests.web.test_domains_ui import KEY, World, _login, _seed, get

ROOT = Path(__file__).resolve().parents[2]
HOSTILE = '<script>alert("x")</script> "><img src=x onerror=alert(1)>'
ATTR_HOSTILE = 'x" autofocus onfocus="alert(1)'
HOSTILE_NEEDLES = ("<script>alert", "<img src=x", '"><img', '" autofocus onfocus="')
HTML = {"Accept": "text/html"}
PAGES = ("index.html", "form.html", "_error.html", "denied.html")


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "a unit test", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    root = User(email="root@example.com", is_instance_admin=True)
    lonely_admin = User(email="lonely-admin@example.com", is_instance_admin=True)
    drifter = User(email="drifter@example.com")
    db.add_all([root, lonely_admin, drifter])
    db.flush()
    db.add(Membership(user_id=root.id, tenant_id=tenant_a, role=MembershipRole.OWNER))
    db.commit()
    users["root"] = root.id
    users["lonely_admin"] = lonely_admin.id  # no membership: the session resolves to no tenant
    users["drifter"] = drifter.id
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
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


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The writing service methods that were called."""
    calls: list[str] = []

    def wrap(name: str) -> None:
        original = getattr(DkimSelectorsAdminService, name)

        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(DkimSelectorsAdminService, name, wrapper)

    for method in ("create", "update", "delete"):
        wrap(method)
    return calls


# --- helpers ------------------------------------------------------------------------------------


def add_tenant_selector(w: World, **over: Any) -> DkimSelectorRecord:
    repo = repo_for(TenantContext(w.tenant_a, None), w.db).dkim_selectors
    record = repo.create({"selector": "zebra", "provider": "zebra_mail", "notes": "Zebra", **over})
    w.db.commit()
    return record


def add_global_selector(w: World, **over: Any) -> DkimSelectorRecord:
    values = {"selector": "globalzebra", "provider": "global_mail", "notes": "Global zebra", **over}
    record = GlobalDkimSelectorRepository(w.db).create(values, actor=w.users["root"])
    w.db.commit()
    return record


def seeded_selector(w: World) -> DkimSelectorRecord:
    w.db.expire_all()
    for record in GlobalDkimSelectorRepository(w.db).list(limit=1000):
        if record.seed_key is not None:
            return record
    raise AssertionError("no seeded global selector")


def tenant_selectors(w: World) -> list[DkimSelectorRecord]:
    w.db.expire_all()
    repo = repo_for(TenantContext(w.tenant_a, None), w.db).dkim_selectors
    return [r for r in repo.list(limit=1000) if r.scope == "tenant"]


def global_selector(w: World, selector_id: int) -> DkimSelectorRecord:
    w.db.expire_all()
    found = GlobalDkimSelectorRepository(w.db).get(selector_id)
    assert found is not None
    return found


def add_viewer_admin(w: World) -> str:
    """An instance admin who is only a client viewer of tenant A: no `rules.read` there."""
    user = User(email="viewer-admin@example.com", is_instance_admin=True)
    w.db.add(user)
    w.db.flush()
    w.db.add(Membership(user_id=user.id, tenant_id=w.tenant_a, role=MembershipRole.CLIENT_VIEWER))
    w.db.commit()
    w.users["viewer_admin"] = user.id
    return "viewer_admin"


def form(**over: Any) -> dict[str, Any]:
    return {
        "selector": "newsel",
        "provider": "new_mail",
        "record_type": "txt",
        "notes": "A note",
        "enabled": "1",
        **over,
    }


def send(
    w: World,
    who: str,
    path: str,
    data: dict[str, Any] | None = None,
    *,
    tenant_id: int | None = None,
    csrf: bool = True,
    headers: dict[str, str] | None = None,
) -> Any:
    """A urlencoded POST (lists become repeated fields), CSRF token in the form."""
    token = _login(w, who, tenant_id)
    body = dict(data or {})
    if csrf and token:
        body = {"csrf_token": token, **body}
    return w.client.post(
        path,
        content=urlencode(body, doseq=True).encode(),
        headers={
            **HTML,
            "Content-Type": "application/x-www-form-urlencoded",
            **(headers or {}),
        },
        follow_redirects=False,
    )


def send_raw(w: World, who: str, path: str, raw: bytes) -> Any:
    token = _login(w, who)
    body = urlencode({"csrf_token": token}).encode() + b"&" + raw
    return w.client.post(
        path,
        content=body,
        headers={**HTML, "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )


def oversize(w: World, path: str, size: int, headers: dict[str, str] | None = None) -> Any:
    """No-JS style: `csrf_token` first, then a field padded to `size` bytes in all."""
    token = _login(w, "owner")
    head = urlencode({"csrf_token": token}) + "&pad="
    content = (head + "a" * (size - len(head))).encode()
    return w.client.post(
        path,
        content=content,
        headers={**HTML, "Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
        follow_redirects=False,
    )


def assert_no_hostile_markup(text: str) -> None:
    for needle in HOSTILE_NEEDLES:
        assert needle not in text, needle


def row_html(page: str, selector_id: int) -> str:
    found = re.search(rf'<tr data-selector="{selector_id}">.*?</tr>', page, re.S)
    assert found is not None, selector_id
    return found.group(0)


class _SelectorFormFields(HTMLParser):
    """The fields a browser would submit for the page's selector form, as the HTML spec has it: a
    text input's value loses every CR and LF. The CSRF token is left out: `send` supplies the one
    of its own login."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, list[str]] = {}
        self._in_form = False
        self._select: str | None = None

    def _add(self, name: str, value: str) -> None:
        if name != "csrf_token":
            self.fields.setdefault(name, []).append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "form" and attr.get("data-testid") == "dkim-form":
            self._in_form = True
        if not self._in_form:
            return
        if tag == "input" and attr.get("name"):
            value = attr.get("value") or ""
            if attr.get("type") == "text":
                value = re.sub(r"[\r\n]", "", value)
            if attr.get("type") != "checkbox" or "checked" in attr:
                self._add(str(attr["name"]), value)
        elif tag == "select":
            self._select = attr.get("name")
        elif tag == "option" and "selected" in attr and self._select:
            self._add(self._select, attr.get("value") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False


def browser_fields(page: str) -> dict[str, list[str]]:
    parser = _SelectorFormFields()
    parser.feed(page)
    parser.close()
    assert parser.fields, "the page has no selector form"
    return parser.fields


# --- access -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "status"), [("owner", 200), ("admin", 200), ("analyst", 200), ("viewer", 403)]
)
def test_list_role_matrix_and_hidden_controls(world: World, who: str, status: int) -> None:
    row = add_tenant_selector(world)
    r = get(world, who, "/dkim-selectors")
    assert r.status_code == status
    assert r.headers["cache-control"] == "no-store"
    if status == 403:
        assert 'data-testid="forbidden"' in r.text
        assert "zebra" not in r.text
        assert "/dkim-selectors/new" not in r.text
        return
    assert "zebra" in r.text
    manage = who != "analyst"
    assert ('data-testid="dkim-new"' in r.text) is manage
    for control in ("edit", "toggle", "delete"):
        link = f"/dkim-selectors/{row.id}/{control}"
        assert (link in r.text) is manage, control
    if not manage:
        assert not re.search(r'<form[^>]*action="/dkim-selectors', r.text)


def test_viewer_sees_no_controls_anywhere(world: World) -> None:
    add_tenant_selector(world)
    for path in ("/dkim-selectors", "/dkim-selectors/new"):
        r = get(world, "viewer", path)
        assert r.status_code == 403
        assert 'href="/dkim-selectors/new' not in r.text
        assert 'data-testid="dkim-form"' not in r.text
        assert 'data-testid="nav-dkim-selectors"' not in r.text


def test_anonymous_gets_login_or_401(world: World, spy: list[str]) -> None:
    r = get(world, "anon", "/dkim-selectors")
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")
    assert send(world, "anon", "/dkim-selectors?scope=tenant", form()).status_code == 401
    assert spy == []


@pytest.mark.parametrize("who", ["analyst", "viewer"])
def test_denied_writers_never_reach_the_service(world: World, spy: list[str], who: str) -> None:
    row = add_tenant_selector(world)
    before = tenant_selectors(world)
    assert send(world, who, "/dkim-selectors?scope=tenant", form()).status_code == 403
    assert (
        send(world, who, f"/dkim-selectors/{row.id}/edit?scope=tenant", form()).status_code == 403
    )
    assert send(world, who, f"/dkim-selectors/{row.id}/toggle", {"enabled": "0"}).status_code == 403
    assert send(world, who, f"/dkim-selectors/{row.id}/delete").status_code == 403
    assert get(world, who, f"/dkim-selectors/{row.id}/edit").status_code == 403
    assert get(world, who, "/dkim-selectors/new").status_code == 403
    assert spy == []
    assert tenant_selectors(world) == before


@pytest.mark.parametrize("tenant", ["foreign", "own"])
def test_other_tenant_admin_cannot_touch_the_selector(
    world: World, spy: list[str], tenant: str
) -> None:
    row = add_tenant_selector(world)
    before = tenant_selectors(world)
    tid = world.tenant_b if tenant == "own" else world.tenant_a  # b_owner is not a member of A
    for path, data in (
        (f"/dkim-selectors/{row.id}/toggle", {"enabled": "0"}),
        (f"/dkim-selectors/{row.id}/delete", None),
        (f"/dkim-selectors/{row.id}/edit?scope=tenant", form(notes="hijack")),
    ):
        r = send(world, "b_owner", path, data, tenant_id=tid)
        assert r.status_code == 404, path
        assert "zebra" not in r.text
    assert get(world, "b_owner", f"/dkim-selectors/{row.id}/edit", tenant_id=tid).status_code == 404
    assert spy == []
    assert tenant_selectors(world) == before


def test_tenant_path_cannot_write_a_global_row(world: World, spy: list[str]) -> None:
    glob = seeded_selector(world)
    before = global_selector(world, glob.id)
    base = f"/dkim-selectors/{glob.id}"
    assert send(world, "owner", f"{base}/toggle", {"enabled": "0"}).status_code == 403
    assert send(world, "owner", f"{base}/delete").status_code == 403
    assert send(world, "owner", f"{base}/edit?scope=tenant", form()).status_code == 403
    assert get(world, "owner", f"{base}/edit").status_code == 403
    assert spy == []
    assert global_selector(world, glob.id) == before


def test_global_scope_needs_the_instance_admin(world: World, spy: list[str]) -> None:
    glob = add_global_selector(world)
    for who in ("owner", "admin", "analyst", "viewer"):
        assert get(world, who, "/dkim-selectors?scope=global").status_code == 403
        assert get(world, who, "/dkim-selectors/new?scope=global").status_code == 403
        assert send(world, who, "/dkim-selectors?scope=global", form()).status_code == 403
        assert send(world, who, f"/dkim-selectors/{glob.id}/delete?scope=global").status_code == 403
        assert (
            send(
                world, who, f"/dkim-selectors/{glob.id}/toggle?scope=global", {"enabled": "0"}
            ).status_code
            == 403
        )
    assert spy == []
    assert global_selector(world, glob.id) == glob


def test_post_without_csrf_is_refused(world: World, spy: list[str]) -> None:
    row = add_tenant_selector(world)
    for path, data in (
        ("/dkim-selectors?scope=tenant", form()),
        (f"/dkim-selectors/{row.id}/edit?scope=tenant", form(notes="hijack")),
        (f"/dkim-selectors/{row.id}/toggle", {"enabled": "0"}),
        (f"/dkim-selectors/{row.id}/delete", None),
    ):
        assert send(world, "owner", path, data, csrf=False).status_code == 403, path
    assert spy == []
    assert len(tenant_selectors(world)) == 1


def test_every_form_carries_a_csrf_token(world: World) -> None:
    row = add_tenant_selector(world)
    add_global_selector(world)
    pages = (
        get(world, "owner", "/dkim-selectors").text,
        get(world, "root", "/dkim-selectors?scope=global").text,
        get(world, "owner", "/dkim-selectors/new").text,
        get(world, "owner", f"/dkim-selectors/{row.id}/edit").text,
    )
    for page in pages:
        forms = re.findall(r"<form\b.*?</form>", page, re.S)
        assert forms
        for f in forms:
            assert 'name="csrf_token"' in f
            assert 'method="post"' in f


@pytest.mark.parametrize(
    "path",
    [
        "/dkim-selectors?scope=bogus",
        "/dkim-selectors?scope=",
        "/dkim-selectors/new?scope=",
        "/dkim-selectors/abc/edit",
        f"/dkim-selectors/{'9' * 30}/edit",
        "/dkim-selectors/0/edit",
        "/dkim-selectors/%20/edit",
        "/dkim-selectors?page=abc",
        "/dkim-selectors?page=0",
        "/dkim-selectors?page=-1",
        "/dkim-selectors?page=1e3",
        "/dkim-selectors?page=",
        f"/dkim-selectors?page={'9' * 30}",
        "/dkim-selectors?page=%00",
    ],
)
def test_malformed_scope_id_and_page_are_404(world: World, path: str) -> None:
    assert get(world, "owner", path).status_code == 404


def test_malformed_ids_in_posts_are_404(world: World, spy: list[str]) -> None:
    assert send(world, "owner", "/dkim-selectors/-1/delete").status_code == 404
    assert send(world, "owner", "/dkim-selectors/1e3/edit?scope=tenant", form()).status_code == 404
    assert send(world, "owner", "/dkim-selectors/abc/toggle", {"enabled": "0"}).status_code == 404
    assert send(world, "owner", "/dkim-selectors?scope=nope", form()).status_code == 404
    assert spy == []


@pytest.mark.parametrize(
    ("who", "visible_link"),
    [("owner", True), ("admin", True), ("analyst", True), ("viewer", False)],
)
def test_nav_link_visibility(world: World, who: str, visible_link: bool) -> None:
    r = get(world, who, "/")
    assert r.status_code == 200
    assert ('href="/dkim-selectors"' in r.text) is visible_link


def test_instance_admin_without_a_tenant_lands_on_the_global_tab(world: World) -> None:
    r = get(world, "lonely_admin", "/dkim-selectors")
    assert r.status_code == 200
    assert 'data-testid="dkim-global"' in r.text
    assert 'data-testid="tab-global"' in r.text
    assert 'data-testid="tab-tenant"' not in r.text
    assert 'data-testid="nav-dkim-selectors"' in r.text


def test_no_tenant_default_does_not_widen_access(world: World) -> None:
    assert get(world, "lonely_admin", "/dkim-selectors?scope=tenant").status_code == 404
    assert get(world, "lonely_admin", "/dkim-selectors/new?scope=tenant").status_code == 404
    r = get(world, "drifter", "/dkim-selectors")
    assert r.status_code == 404
    assert 'data-testid="nav-dkim-selectors"' not in r.text
    assert get(world, "drifter", "/dkim-selectors?scope=global").status_code == 403


def test_member_still_defaults_to_the_tenant_tab(world: World) -> None:
    r = get(world, "root", "/dkim-selectors")
    assert r.status_code == 200
    assert 'data-testid="dkim-tenant"' in r.text
    assert 'data-testid="nav-dkim-selectors"' in r.text


@pytest.mark.parametrize("path", ["/dkim-selectors", "/dkim-selectors?scope=global"])
def test_instance_admin_denied_the_tenant_gets_the_global_tab(world: World, path: str) -> None:
    who = add_viewer_admin(world)
    row = add_tenant_selector(world)
    r = get(world, who, path)
    assert r.status_code == 200
    assert 'data-testid="dkim-global"' in r.text
    assert 'data-testid="dkim-tenant"' not in r.text
    assert f'<tr data-selector="{row.id}">' not in r.text
    assert 'data-testid="tab-global"' in r.text
    assert 'data-testid="tab-tenant"' not in r.text
    assert 'data-testid="nav-dkim-selectors"' in r.text


def test_nav_link_for_an_instance_admin_denied_the_tenant(world: World) -> None:
    assert 'href="/dkim-selectors"' in get(world, add_viewer_admin(world), "/").text


@pytest.mark.parametrize("path", ["/dkim-selectors?scope=tenant", "/dkim-selectors/new"])
def test_global_default_leaves_the_tenant_tab_denied(world: World, path: str) -> None:
    add_tenant_selector(world)
    r = get(world, add_viewer_admin(world), path)
    assert r.status_code == 403
    assert 'data-testid="forbidden"' in r.text
    assert "zebra" not in r.text


@pytest.mark.parametrize(("who", "status"), [("viewer", 403), ("drifter", 404)])
def test_global_default_needs_the_global_permission(world: World, who: str, status: int) -> None:
    r = get(world, who, "/dkim-selectors")
    assert r.status_code == status
    assert 'data-testid="dkim-global"' not in r.text
    assert 'data-testid="tab-global"' not in r.text
    assert 'data-testid="nav-dkim-selectors"' not in r.text


@pytest.mark.parametrize("who", ["owner", "admin", "analyst"])
def test_global_tab_is_only_for_the_instance_admin(world: World, who: str) -> None:
    r = get(world, who, "/dkim-selectors")
    assert r.status_code == 200
    assert 'data-testid="tab-tenant"' in r.text
    assert 'data-testid="tab-global"' not in r.text


# --- list: pages, duplicates and the global section ---------------------------------------------


def test_same_name_past_the_first_batch_marks_the_global_row(world: World) -> None:
    seeded = seeded_selector(world)
    repo = repo_for(TenantContext(world.tenant_a, None), world.db).dkim_selectors
    for i in range(1100):  # sorted before every seeded name
        repo.create({"selector": f"aaa{i:04d}"})
    repo.create({"selector": seeded.selector, "enabled": False})
    world.db.commit()
    seen: set[int] = set()
    marked: str | None = None
    path: str | None = "/dkim-selectors?scope=tenant"
    while path is not None:
        r = get(world, "owner", path)
        assert r.status_code == 200
        seen |= {int(m) for m in re.findall(r'<tr data-selector="(\d+)"', r.text)}
        if f'<tr data-selector="{seeded.id}">' in r.text:
            marked = row_html(r.text, seeded.id)
        nxt = re.search(r'href="(/dkim-selectors\?[^"]*)" data-testid="dkim-page-next"', r.text)
        path = nxt.group(1).replace("&amp;", "&") if nxt else None
    assert marked is not None
    assert 'data-testid="dkim-also-tenant"' in marked
    total = repo.count()
    assert len(seen) == total  # nothing silently cut off


def test_unmatched_global_row_has_no_duplicate_marker(world: World) -> None:
    add_tenant_selector(world, selector="mine")
    seeded = seeded_selector(world)
    page = get(world, "owner", "/dkim-selectors").text
    assert 'data-testid="dkim-also-tenant"' not in row_html(page, seeded.id)


def test_pages_navigate_and_leave_out_a_section_with_rows_elsewhere(world: World) -> None:
    repo = repo_for(TenantContext(world.tenant_a, None), world.db).dkim_selectors
    for i in range(250):
        repo.create({"selector": f"bulk{i:04d}"})
    world.db.commit()
    first = get(world, "owner", "/dkim-selectors?scope=tenant").text
    assert 'data-testid="dkim-page-next"' in first
    assert 'data-testid="dkim-page-prev"' not in first
    assert "Page 1 of" in first
    assert 'data-testid="dkim-global"' not in first  # its rows are on the next pages
    last = get(world, "owner", "/dkim-selectors?scope=tenant&page=99").text
    assert 'data-testid="dkim-page-prev"' in last
    assert 'data-testid="dkim-page-next"' not in last


def test_one_page_has_no_navigation(world: World) -> None:
    add_tenant_selector(world)
    assert 'data-testid="dkim-pages"' not in get(world, "owner", "/dkim-selectors").text


# --- create / edit / toggle / delete ------------------------------------------------------------


def test_create_edit_toggle_delete_round_trip(world: World) -> None:
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form())
    assert r.status_code == 303
    assert r.headers["location"] == "/dkim-selectors?scope=tenant&notice=created"
    (row,) = tenant_selectors(world)
    assert (row.selector, row.provider, row.record_type, row.notes, row.enabled) == (
        "newsel",
        "new_mail",
        "txt",
        "A note",
        True,
    )
    assert "The selector was created." in get(world, "owner", r.headers["location"]).text
    r = send(
        world,
        "owner",
        f"/dkim-selectors/{row.id}/edit?scope=tenant",
        form(selector="renamed", provider="", record_type="cname", notes="", enabled="0"),
    )
    assert r.status_code == 303
    (row,) = tenant_selectors(world)
    assert (row.selector, row.provider, row.record_type, row.notes, row.enabled) == (
        "renamed",
        None,
        "cname",
        None,
        False,
    )
    toggle = send(world, "owner", f"/dkim-selectors/{row.id}/toggle", {"enabled": "1"})
    assert toggle.status_code == 303
    assert tenant_selectors(world)[0].enabled is True
    assert (
        send(world, "owner", f"/dkim-selectors/{row.id}/toggle", {"enabled": "0"}).status_code
        == 303
    )
    assert tenant_selectors(world)[0].enabled is False
    r = send(world, "owner", f"/dkim-selectors/{row.id}/delete")
    assert r.status_code == 303
    assert r.headers["location"].endswith("notice=deleted")
    assert tenant_selectors(world) == []


def test_disabling_a_seeded_global_row_works_and_keeps_its_fields(world: World) -> None:
    glob = seeded_selector(world)
    r = send(world, "root", f"/dkim-selectors/{glob.id}/toggle?scope=global", {"enabled": "0"})
    assert r.status_code == 303, r.text
    after = global_selector(world, glob.id)
    assert after.enabled is False
    assert (after.selector, after.provider, after.record_type, after.seed_key) == (
        glob.selector,
        glob.provider,
        glob.record_type,
        glob.seed_key,
    )
    assert after.locally_modified is True
    page = get(world, "root", "/dkim-selectors?scope=global").text
    assert f"/dkim-selectors/{glob.id}/toggle?scope=global" in page
    on = send(world, "root", f"/dkim-selectors/{glob.id}/toggle?scope=global", {"enabled": "1"})
    assert on.status_code == 303
    assert global_selector(world, glob.id).enabled is True


@pytest.mark.parametrize("data", [{}, {"enabled": "2"}, {"enabled": ["1", "0"]}, {"enabled": ""}])
def test_toggle_with_a_bad_body_is_422_on_the_list(
    world: World, spy: list[str], data: dict[str, Any]
) -> None:
    row = add_tenant_selector(world)
    r = send(world, "owner", f"/dkim-selectors/{row.id}/toggle", data)
    assert r.status_code == 422
    assert "The form could not be read." in r.text
    assert spy == []
    assert tenant_selectors(world)[0].enabled is True


@pytest.mark.parametrize(
    "stored",
    [
        pytest.param({"selector": "*"}, id="wildcard-selector"),
        pytest.param({"provider": "Not A Slug"}, id="invalid-provider"),
        pytest.param({"selector": "*", "provider": "Not A Slug"}, id="both"),
    ],
)
def test_toggle_works_on_a_stored_row_that_validation_would_refuse(
    world: World, stored: dict[str, str]
) -> None:
    row = add_tenant_selector(world)
    world.db.execute(update(DkimSelector).where(DkimSelector.id == row.id).values(**stored))
    world.db.commit()
    before = tenant_selectors(world)[0]
    path = f"/dkim-selectors/{row.id}/toggle"
    for target, expected in (("0", False), ("1", True)):
        r = send(world, "owner", path, {"enabled": target})
        assert r.status_code == 303, r.text
        after = tenant_selectors(world)[0]
        assert after.enabled is expected
        assert dataclasses.replace(after, updated_at=before.updated_at, enabled=True) == before


@pytest.mark.parametrize(
    ("error", "status", "message"),
    [
        pytest.param(
            SelectorFieldInvalid("selector", "invalid_label"),
            422,
            "The selector must be a single DNS label.",
            id="field-invalid",
        ),
        pytest.param(
            SelectorConflict(), 409, "This selector already exists in this scope.", id="conflict"
        ),
    ],
)
def test_toggle_refused_by_the_service_is_a_list_error(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    error: DkimSelectorsAdminError,
    status: int,
    message: str,
) -> None:
    row = add_tenant_selector(world)

    def refuse(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(DkimSelectorsAdminService, "update", refuse)
    r = send(world, "owner", f"/dkim-selectors/{row.id}/toggle", {"enabled": "0"})
    assert r.status_code == status
    assert 'data-testid="dkim-error"' in r.text
    assert message in r.text
    assert f'<tr data-selector="{row.id}">' in r.text
    assert tenant_selectors(world)[0].enabled is True


EDIT_ROUND_TRIPS = [
    pytest.param({}, id="minimal"),
    pytest.param({"provider": None, "notes": None}, id="nulls"),
    pytest.param(
        {"selector": "sel-1", "provider": "a.b-c_d", "record_type": "cname", "enabled": False},
        id="flags",
    ),
    pytest.param({"notes": "x < y & \"z\" 'q' <b>"}, id="markup-notes"),
    pytest.param({"notes": "é ü 日本   inside"}, id="unicode-notes"),
    pytest.param({"notes": "n" * 500}, id="max-notes"),
]


@pytest.mark.parametrize("values", EDIT_ROUND_TRIPS)
def test_unchanged_edit_in_a_browser_keeps_every_field(
    world: World, values: dict[str, Any]
) -> None:
    row = add_tenant_selector(world, **values)
    before = tenant_selectors(world)[0]
    path = f"/dkim-selectors/{row.id}/edit?scope=tenant"
    r = send(world, "owner", path, browser_fields(get(world, "owner", path).text))
    assert r.status_code == 303, r.text
    after = tenant_selectors(world)[0]
    assert dataclasses.replace(after, updated_at=before.updated_at) == before


def test_unchanged_edit_of_a_global_row_keeps_every_field(world: World) -> None:
    row = add_global_selector(world)
    before = global_selector(world, row.id)
    path = f"/dkim-selectors/{row.id}/edit?scope=global"
    r = send(world, "root", path, browser_fields(get(world, "root", path).text))
    assert r.status_code == 303, r.text
    after = global_selector(world, row.id)
    assert after.locally_modified is True  # every accepted global edit pins the row (M5-20)
    assert dataclasses.replace(
        after, updated_at=before.updated_at, locally_modified=before.locally_modified
    ) == dataclasses.replace(before)


def test_unchanged_edit_of_a_seeded_row_keeps_every_field(world: World) -> None:
    row = seeded_selector(world)
    before = global_selector(world, row.id)
    path = f"/dkim-selectors/{row.id}/edit?scope=global"
    fields = browser_fields(get(world, "root", path).text)
    r = send(world, "root", path, fields)
    assert r.status_code == 303, r.text
    after = global_selector(world, row.id)
    assert dataclasses.replace(
        after, updated_at=before.updated_at, locally_modified=before.locally_modified
    ) == dataclasses.replace(before)


def test_edit_form_shows_notes_in_a_one_line_input(world: World) -> None:
    row = add_tenant_selector(world, notes="line")
    page = get(world, "owner", f"/dkim-selectors/{row.id}/edit").text
    assert "<textarea" not in page
    notes = re.search(r'<input [^>]*name="notes"[^>]*>', page)
    assert notes is not None
    assert 'type="text"' in notes.group(0)
    assert 'value="line"' in notes.group(0)


def test_crlf_in_notes_is_normalized_then_refused_as_one_line(world: World) -> None:
    # Stored notes are single-line (the repository refuses control characters), so a newline in
    # the middle is a 422 whose echo keeps what was typed.
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form(notes="foo\r\nbar"))
    assert r.status_code == 422
    assert "Notes (optional, one line): One of the values is not valid." in r.text
    assert browser_fields(r.text)["notes"] == ["foobar"]
    assert tenant_selectors(world) == []


def test_form_echo_of_a_direct_post_has_its_newlines_normalized(world: World) -> None:
    r = send(
        world,
        "owner",
        "/dkim-selectors?scope=tenant",
        form(selector="BAD", notes="\r\nfoo\r\nbar"),
    )
    assert r.status_code == 422
    assert browser_fields(r.text)["notes"] == ["foobar"]
    assert 'value="\nfoo\nbar"' in r.text
    assert "\r" not in r.text


@pytest.mark.parametrize(
    ("raw", "stored"),
    [("  note \r\n", "note"), ("\r\n\r\nnote\r\n", "note"), ("   ", None), ("", None)],
)
def test_surrounding_whitespace_of_notes_is_trimmed(
    world: World, raw: str, stored: str | None
) -> None:
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form(notes=raw))
    assert r.status_code == 303, r.text
    assert tenant_selectors(world)[0].notes == stored


@pytest.mark.parametrize(
    ("over", "status", "message"),
    [
        ({"selector": ""}, 422, "must be a single DNS label"),
        ({"selector": "a.b"}, 422, "must be a single DNS label"),
        ({"selector": "*"}, 422, "must be a single DNS label"),
        ({"selector": "UPPER"}, 422, "must be a single DNS label"),
        ({"selector": "has space"}, 422, "must be a single DNS label"),
        ({"selector": "sél"}, 422, "must be a single DNS label"),
        ({"selector": "a" * 64}, 422, "too long"),
        ({"provider": "Not A Slug"}, 422, "Provider (optional, e.g. google_workspace): One of"),
        ({"provider": "p" * 65}, 422, "too long"),
        ({"record_type": "mx"}, 422, "Record type: One of the values is not valid."),
        ({"record_type": ""}, 422, "Record type: One of the values is not valid."),
        ({"notes": "n" * 501}, 422, "too long"),
        ({"notes": "tab\there"}, 422, "Notes (optional, one line): One of the values"),
        ({"enabled": ["1", "0"]}, 422, "could not be read"),
        ({"notes": ["a", "b"]}, 422, "could not be read"),
    ],
)
def test_invalid_forms_are_422_and_store_nothing(
    world: World, over: dict[str, Any], status: int, message: str
) -> None:
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form(**over))
    assert r.status_code == status
    assert message in r.text
    assert 'data-testid="dkim-error"' in r.text
    assert tenant_selectors(world) == []


def test_duplicate_selector_is_409_on_create_and_edit(world: World) -> None:
    add_tenant_selector(world, selector="taken")
    other = add_tenant_selector(world, selector="other")
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form(selector="taken"))
    assert r.status_code == 409
    assert "This selector already exists in this scope." in r.text
    r = send(
        world, "owner", f"/dkim-selectors/{other.id}/edit?scope=tenant", form(selector="taken")
    )
    assert r.status_code == 409
    assert {s.selector for s in tenant_selectors(world)} == {"taken", "other"}


def test_a_tenant_row_may_reuse_a_global_name(world: World) -> None:
    glob = seeded_selector(world)
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form(selector=glob.selector))
    assert r.status_code == 303


def test_too_many_selectors_is_a_422_with_the_cap_message(world: World) -> None:
    repo = repo_for(TenantContext(world.tenant_a, None), world.db).dkim_selectors
    for i in range(MAX_TENANT_SELECTORS):
        repo.create({"selector": f"cap{i:03d}"})
    world.db.commit()
    r = send(world, "owner", "/dkim-selectors?scope=tenant", form())
    assert r.status_code == 422
    assert "maximum number of selectors" in r.text
    assert len(tenant_selectors(world)) == MAX_TENANT_SELECTORS
    # the form is still usable, and an edit of an existing row is not a create
    first = tenant_selectors(world)[0]
    ok = send(
        world, "owner", f"/dkim-selectors/{first.id}/edit?scope=tenant", form(selector="cap-new")
    )
    assert ok.status_code == 303


def test_global_too_many_is_a_422(world: World) -> None:
    from app.checks.dkim_selectors import MAX_SELECTORS

    repo = GlobalDkimSelectorRepository(world.db)
    count = repo.count()
    for i in range(MAX_SELECTORS - count):
        repo.create({"selector": f"fill{i:03d}"}, actor=world.users["root"])
    world.db.commit()
    r = send(world, "root", "/dkim-selectors?scope=global", form())
    assert r.status_code == 422
    assert "maximum number of selectors" in r.text


@pytest.mark.parametrize("seeded_field", ["selector", "provider", "record_type"])
def test_seeded_row_fields_cannot_be_changed_by_a_direct_post(
    world: World, seeded_field: str
) -> None:
    glob = seeded_selector(world)
    before = global_selector(world, glob.id)
    values = {
        "selector": glob.selector,
        "provider": glob.provider or "",
        "record_type": glob.record_type,
        "notes": glob.notes or "",
        "enabled": "1",
    }
    values[seeded_field] = {
        "selector": "renamedsel",
        "provider": "other_provider",
        "record_type": "cname" if glob.record_type != "cname" else "txt",
    }[seeded_field]
    r = send(world, "root", f"/dkim-selectors/{glob.id}/edit?scope=global", values)
    assert r.status_code == 422
    assert "belongs to the shipped list" in r.text
    assert global_selector(world, glob.id) == before


def test_seeded_notes_and_enabled_can_be_edited(world: World) -> None:
    glob = seeded_selector(world)
    path = f"/dkim-selectors/{glob.id}/edit?scope=global"
    fields = browser_fields(get(world, "root", path).text)
    fields["notes"] = ["Local note"]
    fields.pop("enabled", None)
    assert send(world, "root", path, fields).status_code == 303
    after = global_selector(world, glob.id)
    assert (after.notes, after.enabled, after.locally_modified) == ("Local note", False, True)
    assert after.selector == glob.selector


def test_seeded_form_is_read_only_for_managed_fields(world: World) -> None:
    glob = seeded_selector(world)
    page = get(world, "root", f"/dkim-selectors/{glob.id}/edit?scope=global").text
    assert 'data-testid="dkim-seeded-note"' in page
    for name in ("selector", "provider", "record_type"):
        tag = re.search(rf'<input [^>]*name="{name}"[^>]*>', page)
        assert tag is not None, name
        assert " readonly" in tag.group(0), name
    assert "<select" not in page
    notes = re.search(r'<input [^>]*name="notes"[^>]*>', page)
    assert notes is not None
    assert "readonly" not in notes.group(0)


def test_unseeded_global_form_is_editable(world: World) -> None:
    row = add_global_selector(world)
    page = get(world, "root", f"/dkim-selectors/{row.id}/edit?scope=global").text
    assert 'data-testid="dkim-seeded-note"' not in page
    assert "readonly" not in page
    assert "<select" in page


def test_seeded_delete_is_hidden_and_a_direct_post_is_409(world: World, spy: list[str]) -> None:
    glob = seeded_selector(world)
    page = get(world, "root", "/dkim-selectors?scope=global").text
    assert f"/dkim-selectors/{glob.id}/delete" not in row_html(page, glob.id)
    assert f"/dkim-selectors/{glob.id}/toggle" in row_html(page, glob.id)
    r = send(world, "root", f"/dkim-selectors/{glob.id}/delete?scope=global")
    assert r.status_code == 409
    assert "cannot be deleted. Disable it instead." in r.text
    assert global_selector(world, glob.id) == glob
    assert spy == ["delete"]


def test_unseeded_global_row_can_be_deleted_by_the_instance_admin(world: World) -> None:
    row = add_global_selector(world)
    page = get(world, "root", "/dkim-selectors?scope=global").text
    assert f"/dkim-selectors/{row.id}/delete?scope=global" in row_html(page, row.id)
    assert send(world, "root", f"/dkim-selectors/{row.id}/delete?scope=global").status_code == 303
    assert GlobalDkimSelectorRepository(world.db).get(row.id) is None


def test_global_create_by_instance_admin(world: World) -> None:
    r = send(world, "root", "/dkim-selectors?scope=global", form(selector="globalnew"))
    assert r.status_code == 303
    assert r.headers["location"] == "/dkim-selectors?scope=global&notice=created"
    created = [
        s
        for s in GlobalDkimSelectorRepository(world.db).list(limit=1000)
        if s.selector == "globalnew"
    ]
    assert len(created) == 1
    assert created[0].tenant_id is None


@pytest.mark.parametrize("method", ["update", "delete"])
def test_a_stale_row_is_a_404_not_a_500(
    world: World, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    row = add_tenant_selector(world)

    def gone(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise SelectorNotFound

    monkeypatch.setattr(DkimSelectorsAdminService, method, gone)
    for path, data in (
        (f"/dkim-selectors/{row.id}/edit?scope=tenant", form()),
        (f"/dkim-selectors/{row.id}/toggle", {"enabled": "0"}),
        (f"/dkim-selectors/{row.id}/delete", None),
    ):
        if method == "delete" and "delete" not in path:
            continue
        if method == "update" and "delete" in path:
            continue
        r = send(world, "owner", path, data)
        assert r.status_code == 404, path


@pytest.mark.parametrize(
    "raw",
    [
        b"selector=a%00b&notes=x",  # NUL
        b"selector=%ED%A0%80&notes=x",  # a lone surrogate encoded in UTF-8: invalid UTF-8
        b"selector=%FF%FE",
        b"selector=%C0%AF",  # overlong encoding
        b"notes=%00",
        b"provider=%E2%82",  # truncated sequence
    ],
)
def test_nul_surrogate_and_bad_utf8_are_422_not_500(world: World, raw: bytes) -> None:
    r = send_raw(world, "owner", "/dkim-selectors?scope=tenant", raw)
    assert r.status_code == 422
    assert "\x00" not in r.text
    assert tenant_selectors(world) == []
    row = add_tenant_selector(world)
    for path in (f"/dkim-selectors/{row.id}/edit?scope=tenant", f"/dkim-selectors/{row.id}/toggle"):
        assert send_raw(world, "owner", path, raw).status_code == 422, path


def test_too_many_fields_are_422(world: World) -> None:
    pad = {f"f{i}": "x" for i in range(40)}
    r = send(world, "owner", "/dkim-selectors?scope=tenant", {**form(), **pad})
    assert r.status_code == 422
    assert tenant_selectors(world) == []


@pytest.mark.parametrize(
    ("path", "lang", "message"),
    [
        ("/dkim-selectors?scope=tenant", "en", "The form is too large."),
        ("/dkim-selectors?scope=tenant", "it", "Il modulo è troppo grande."),
    ],
)
def test_save_body_cap_is_a_localized_413(world: World, path: str, lang: str, message: str) -> None:
    headers = {"Accept-Language": lang}
    r = oversize(world, path, MAX_SAVE_BYTES + 1, headers)
    assert r.status_code == 413
    assert message in r.text
    assert 'data-testid="dkim-form"' in r.text
    ok = oversize(world, path, MAX_SAVE_BYTES, headers)
    assert ok.status_code == 422  # within the cap: reaches the form check, not the 413
    assert tenant_selectors(world) == []


def test_toggle_body_cap_is_a_localized_413(world: World, spy: list[str]) -> None:
    row = add_tenant_selector(world)
    r = oversize(world, f"/dkim-selectors/{row.id}/toggle", 5000, {"Accept-Language": "it"})
    assert r.status_code == 413
    assert "Il modulo è troppo grande." in r.text
    assert spy == []


# --- global rows, verification and escaping -----------------------------------------------------


def test_tenant_tab_shows_global_rows_read_only(world: World) -> None:
    glob = seeded_selector(world)
    own = add_tenant_selector(world)
    page = get(world, "owner", "/dkim-selectors").text
    assert f"/dkim-selectors/{own.id}/edit" in row_html(page, own.id)
    for control in ("edit", "toggle", "delete"):
        assert f"/dkim-selectors/{glob.id}/{control}" not in page
    assert "Global selectors are read-only here." in page


def test_unverified_badge_and_verification_details(world: World) -> None:
    add_global_selector(
        world,
        selector="unv",
        status="unverified",
        verified_on=dt.date(2026, 3, 4),
        sources=["https://example.com/doc", "https://example.org/other"],
    )
    add_global_selector(world, selector="ver", status="verified")
    add_global_selector(world, selector="plain")
    page = get(world, "root", "/dkim-selectors?scope=global").text
    assert page.count('data-testid="badge-unverified"') >= 1
    assert 'data-testid="badge-verified"' in page
    assert "Verified on: 2026-03-04" in page
    assert "<code>https://example.com/doc</code>, <code>https://example.org/other</code>" in page


def test_tenant_rows_show_no_verification_details(world: World) -> None:
    row = add_tenant_selector(world)
    html = row_html(get(world, "owner", "/dkim-selectors").text, row.id)
    assert "badge-" not in html
    assert "Verified on" not in html


def test_hostile_values_are_escaped_everywhere(world: World) -> None:
    add_tenant_selector(world, selector="hostile", notes=HOSTILE)
    add_global_selector(
        world,
        selector="hostileglobal",
        notes=HOSTILE,
        sources=['http://e.com/"><script>x</script>'],
    )
    row = tenant_selectors(world)[0]
    pages = [
        get(world, "owner", "/dkim-selectors").text,
        get(world, "root", "/dkim-selectors?scope=global").text,
        get(world, "owner", f"/dkim-selectors/{row.id}/edit").text,
    ]
    assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;" in pages[0]
    assert "&lt;script&gt;x&lt;/script&gt;" in pages[1]
    for page in pages:
        assert_no_hostile_markup(page)
        assert "<script>x" not in page


@pytest.mark.parametrize("field", ["selector", "provider", "record_type", "notes"])
@pytest.mark.parametrize("payload", [HOSTILE, ATTR_HOSTILE])
def test_hostile_form_input_is_escaped_in_the_re_render(
    world: World, field: str, payload: str
) -> None:
    r = send(
        world,
        "owner",
        "/dkim-selectors?scope=tenant",
        form(**{"selector": "BAD", **{field: payload}}),
    )
    assert r.status_code == 422
    assert_no_hostile_markup(r.text)
    if field != "notes":
        assert 'value="x" autofocus' not in r.text
    # nothing was stored, and no hostile text came back through a flash or a title either
    assert tenant_selectors(world) == []


def test_hostile_notice_and_scope_are_never_echoed(world: World) -> None:
    r = get(world, "owner", f"/dkim-selectors?scope=tenant&notice={HOSTILE}")
    assert r.status_code == 200
    assert_no_hostile_markup(r.text)
    assert "<script>alert" not in r.text
    assert get(world, "owner", f"/dkim-selectors?scope={HOSTILE}").status_code == 404


def test_hostile_stored_provider_like_values_are_escaped_in_the_list(world: World) -> None:
    # The repository only accepts slugs for provider, so a legacy row is simulated by a direct
    # update; the page must still escape it.
    from sqlalchemy import update

    from app.models import DkimSelector

    row = add_tenant_selector(world)
    world.db.execute(update(DkimSelector).where(DkimSelector.id == row.id).values(provider=HOSTILE))
    world.db.commit()
    page = get(world, "owner", "/dkim-selectors").text
    assert_no_hostile_markup(page)
    assert "&lt;script&gt;" in page


@pytest.mark.parametrize(
    ("who", "path"),
    [
        ("owner", "/dkim-selectors"),
        ("root", "/dkim-selectors?scope=global"),
        ("owner", "/dkim-selectors/new"),
        ("viewer", "/dkim-selectors"),
    ],
)
def test_pages_have_no_inline_script_style_or_handlers(world: World, who: str, path: str) -> None:
    add_tenant_selector(world)
    page = get(world, who, path).text
    assert not re.search(r"<script(?![^>]*\bsrc=)", page)
    assert not re.search(r"<[^>]+\sstyle=", page)
    assert not re.search(r"<[^>]+\son[a-z]+=", page)
    assert "|safe" not in page
    for name in PAGES:
        source = (ROOT / "app/web/templates/dkim_selectors" / name).read_text(encoding="utf-8")
        assert "|safe" not in source
        assert "{% autoescape false" not in source


# --- i18n ---------------------------------------------------------------------------------------


def _used_keys() -> set[str]:
    found: set[str] = set()
    sources = [ROOT / "app/web/dkim_selectors.py"]
    sources += sorted((ROOT / "app/web/templates/dkim_selectors").glob("*.html"))
    sources.append(ROOT / "app/web/templates/base.html")
    for path in sources:
        found |= set(
            re.findall(
                r"""["']((?:web\.dkim_selectors|nav\.tools\.dkim_selectors)\.[a-z_.]+)["']""",
                path.read_text(),
            )
        )
    return found


def test_every_selector_key_exists_in_both_locales() -> None:
    keys = {k for k in _used_keys() if not k.endswith(".")}
    assert len(keys) > 40
    keys |= {f"web.dkim_selectors.record_type.{k}" for k in ("txt", "cname", "either")}
    keys |= {f"web.dkim_selectors.scope.{k}" for k in ("tenant", "global")}
    for lang in ("en", "it"):
        catalogue = json.loads((LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        assert {k for k in keys if k not in catalogue} == set(), lang
    en = json.loads((LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
    it = json.loads((LOCALES_DIR / "it.json").read_text(encoding="utf-8"))
    mine = {k for k in en if k.startswith("web.dkim_selectors.")}
    assert mine == {k for k in it if k.startswith("web.dkim_selectors.")}
    assert mine <= keys  # no unused key


@pytest.mark.parametrize("lang", ["en", "it"])
def test_pages_render_in_both_languages(world: World, lang: str) -> None:
    row = add_tenant_selector(world)
    for who, path in (
        ("owner", "/dkim-selectors"),
        ("root", "/dkim-selectors?scope=global"),
        ("owner", "/dkim-selectors/new"),
        ("owner", f"/dkim-selectors/{row.id}/edit"),
        ("viewer", "/dkim-selectors"),
    ):
        r = get(world, who, path, **{"Accept-Language": lang})
        assert r.status_code in (200, 403), path
        assert f'<html lang="{lang}"' in r.text
    bad = send(
        world,
        "owner",
        "/dkim-selectors?scope=tenant",
        form(selector="BAD"),
        headers={"Accept-Language": lang},
    )
    assert bad.status_code == 422
    expected = "Il selector deve essere" if lang == "it" else "The selector must be"
    assert expected in bad.text
