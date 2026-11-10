"""M6-07 ESPs tab: `/domains/{id}/esps` and its attach / remove forms, through the real app.

Per role (owner, admin: controls; analyst, client viewer: read-only), tenancy (tenant B domain,
foreign active tenant, unassigned domain for a client viewer, malformed ids), CSRF, the detected-
not-assigned section for every role, unverified badge and https-only source links, hostile text.
Profiles come from tests/fixtures/esp/valid (plus a hostile one in a temp dir); DNS is the fake
backend: no network.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.dns_tools import dns_backend
from app.api.v1.domain_esps import esp_profiles
from app.core import i18n
from app.core.config import Settings
from app.core.csrf import session_csrf_token
from app.core.db import create_db_engine, create_session_factory
from app.core.security import SESSION_COOKIE_NAME, unsign_session_token
from app.core.tenancy import TenantContext
from app.esp.profile import load_esp_profiles
from app.main import create_app
from app.models import Membership
from app.models.domain_esp import DomainEsp
from app.repositories import repo_for
from app.services.domain_esps import ProfileSource
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _cookie, _seed, call
from tests.support.dns_backend import fake_backend

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "esp" / "valid"
HTML = {"Accept": "text/html"}
ESP = "example-esp"
HOSTILE = "<script>alert(1)</script>"

# `assigned.example` includes the example ESP's SPF host (detected when not assigned).
ZONES: dict[str, list[dict[str, Any]]] = {
    "default": [
        {
            "name": "assigned.example",
            "type": "TXT",
            "ttl": 300,
            "rdata": ["v=spf1 include:spf.esp.example.com -all"],
        },
        {"name": "spf.esp.example.com", "type": "TXT", "ttl": 300, "rdata": ["v=spf1 -all"]},
        {"name": "unassigned.example", "type": "TXT", "ttl": 300, "rdata": ["v=spf1 -all"]},
    ]
}

WRITERS = ["owner", "admin"]
READERS = ["analyst", "viewer"]


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


def _make_world(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, profiles: Callable[[], ProfileSource]
) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    backend, _ = fake_backend(ZONES)
    application.dependency_overrides[dns_backend] = lambda: backend
    application.dependency_overrides[esp_profiles] = profiles
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
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    yield from _make_world(
        migrated_db_url, monkeypatch, lambda: lambda: load_esp_profiles(FIXTURES)
    )


@pytest.fixture
def hostile_world(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[World]:
    directory = tmp_path / "esp"
    shutil.copytree(FIXTURES, directory)
    text = (FIXTURES / "example-esp.yaml").read_text()
    for before, after in (
        ("id: example-esp", "id: evil-esp"),
        ("ESP_EXAMPLE_ESP_", "ESP_EVIL_ESP_"),
        ("name: Example ESP", f'name: "{HOSTILE}"'),
    ):
        text = text.replace(before, after)
    (directory / "evil-esp.yaml").write_text(text)
    yield from _make_world(
        migrated_db_url, monkeypatch, lambda: lambda: load_esp_profiles(directory)
    )


def main_of(html: str) -> str:
    """The page content after the title (the layout has its own forms: logout, language)."""
    return html.split('data-testid="esps-title"')[1]


def path(w: World, which: str = "assigned") -> str:
    return f"/domains/{w.domains[which]}/esps"


def get(w: World, who: str, url: str, **kw: Any) -> Any:
    return call(w, who, "GET", url, headers=HTML, **kw)


def _urlencode(w: World, who: str, form: dict[str, str], tenant: str, csrf: bool) -> bytes:
    fields = dict(form)
    if csrf and who != "anon":
        cookie = _cookie(w, who, tenant)
        token = unsign_session_token(cookie, w.settings.secret_key)
        assert token is not None
        fields["csrf_token"] = session_csrf_token(token, w.settings.secret_key)
    return urlencode(fields).encode()


def post_as(
    w: World, who: str, url: str, form: dict[str, str] | None = None, *, tenant: str = "a",
    csrf: bool = True,
) -> Any:  # fmt: skip
    """A form POST as `who`: session cookie set, CSRF token in the form (or omitted)."""
    w.client.cookies.clear()
    w.client.cookies.set(SESSION_COOKIE_NAME, _cookie(w, who, tenant))
    return w.client.post(
        url,
        content=_urlencode(w, who, form or {}, tenant, csrf),
        headers={"Content-Type": "application/x-www-form-urlencoded", **HTML},
        follow_redirects=False,
    )


def assign(w: World, esp: str = ESP, domain: str = "assigned", **hosts: str | None) -> None:
    repo = repo_for(TenantContext(w.tenant_a, None), w.db).domain_esps
    assert repo.add(w.domains[domain], esp, **hosts) is not None
    w.db.commit()


def stored(w: World) -> list[tuple[int, str, str | None, str | None]]:
    w.db.expire_all()
    w.db.rollback()
    rows = w.db.execute(
        select(
            DomainEsp.domain_id,
            DomainEsp.esp_id,
            DomainEsp.return_path_host,
            DomainEsp.tracking_host,
        ).order_by(DomainEsp.id)
    ).all()
    w.db.rollback()
    return [tuple(r) for r in rows]  # type: ignore[misc]


def set_toggles(w: World, user: str, toggles: dict[str, bool]) -> None:
    m = w.db.scalars(select(Membership).where(Membership.user_id == w.users[user])).one()
    m.feature_toggles = toggles
    w.db.commit()


# --- render per role ----------------------------------------------------------------------------


@pytest.mark.parametrize("who", WRITERS)
def test_writer_sees_list_form_and_remove(world: World, who: str) -> None:
    assign(world, return_path_host="bounce.assigned.example")
    r = get(world, who, path(world))
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "Example ESP" in r.text and "bounce.assigned.example" in r.text
    assert "2026-01-15" in r.text  # verified_on
    assert 'data-testid="badge-verified"' in r.text
    assert 'data-testid="esps-attach"' in r.text
    assert f'action="{path(world)}/{ESP}/remove"' in r.text
    assert main_of(r.text).count('name="csrf_token"') == 2  # attach + one remove
    assert 'name="return_path_host"' in r.text and 'name="tracking_host"' in r.text
    assert 'data-testid="esps-result"' in r.text


@pytest.mark.parametrize("who", READERS)
def test_reader_is_read_only(world: World, who: str) -> None:
    assign(world, return_path_host="bounce.assigned.example")
    r = get(world, who, path(world))
    assert r.status_code == 200
    assert "Example ESP" in r.text and "bounce.assigned.example" in r.text
    for forbidden in (
        "<form",
        "<button",
        'name="csrf_token"',
        "/remove",
        'data-testid="esps-attach"',
    ):
        assert forbidden not in main_of(r.text)
    assert 'data-testid="esps-result"' in r.text  # the check result is read-only data


def test_empty_state(world: World) -> None:
    r = get(world, "owner", path(world))
    assert 'data-testid="esps-empty"' in r.text


def test_italian(world: World) -> None:
    world.client.cookies.clear()
    r = call(world, "owner", "GET", path(world), headers={**HTML, "Accept-Language": "it"})
    assert "Collega ESP" in r.text


def test_detail_page_links_the_tab(world: World) -> None:
    for who in ("owner", "analyst", "viewer"):
        r = get(world, who, f"/domains/{world.domains['assigned']}")
        assert f'href="{path(world)}"' in r.text


# --- unverified profile -------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "viewer"])
def test_unverified_badge_and_https_sources(world: World, who: str) -> None:
    assign(world, "other-esp")
    r = get(world, who, path(world))
    assert 'data-testid="badge-unverified"' in r.text
    assert 'href="https://other.example.net/docs/dns"' in r.text
    assert "2025-06-01" in r.text
    assert "return_path" in r.text


def test_https_only_test() -> None:
    # Profiles are validated to https; the template still must not link anything else.
    from app.web.authentication import https_only

    assert not https_only("javascript:alert(1)")
    assert not https_only("http://x.example")
    assert https_only("https://x.example")


# --- detection and grouping ---------------------------------------------------------------------


@pytest.mark.parametrize("who", [*WRITERS, *READERS])
def test_detected_not_assigned_section_for_every_role(world: World, who: str) -> None:
    r = get(world, who, path(world))
    section = r.text.split('data-testid="esps-detected"')[1]
    assert 'data-code="ESP_DETECTED_NOT_ASSIGNED"' in section
    assert "include:spf.esp.example.com" in section
    assert "Example ESP" in section


def test_findings_grouped_per_esp(world: World) -> None:
    assign(world, "other-esp")
    r = get(world, "owner", path(world))
    assert 'data-testid="esps-result"' in r.text
    # example-esp is not assigned: detected, never inside an assigned ESP's group
    assert 'data-testid="esp-findings-example-esp"' not in r.text
    assert 'data-code="ESP_DETECTED_NOT_ASSIGNED"' in r.text
    assert 'data-testid="esp-findings-other-esp"' in r.text


def test_no_check_run_hides_result_but_keeps_list(world: World) -> None:
    assign(world)
    set_toggles(world, "analyst", {"check.run": False})
    r = get(world, "analyst", path(world))
    assert r.status_code == 200
    assert "Example ESP" in r.text
    assert 'data-testid="esps-result"' not in r.text and 'data-testid="esps-detected"' not in r.text


# --- hostile text -------------------------------------------------------------------------------


def test_hostile_profile_name_is_escaped(hostile_world: World) -> None:
    w = hostile_world
    assign(w, "evil-esp")
    for who in ("owner", "viewer"):
        r = get(w, who, path(w))
        assert r.status_code == 200
        assert HOSTILE not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_hostile_host_is_rejected_and_echo_is_escaped(world: World) -> None:
    payload = '"><script>alert(1)</script>'
    r = post_as(world, "owner", path(world), {"esp_id": ESP, "return_path_host": payload})
    assert r.status_code == 422
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text
    assert stored(world) == []


# --- tenancy ------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_tenant_a_cannot_open_tenant_b_domain(world: World, who: str) -> None:
    r = get(world, who, path(world, "other"))
    assert r.status_code == 404
    assert B_SECRET_NAME not in r.text


@pytest.mark.parametrize("who", ["b_owner", "b_viewer"])
def test_tenant_b_users_cannot_open_tenant_a_domain(world: World, who: str) -> None:
    assert get(world, who, path(world), tenant="b").status_code == 404
    assert get(world, who, path(world, "unassigned"), tenant="b").status_code == 404


def test_tenant_b_owner_opens_own_domain(world: World) -> None:
    r = get(world, "b_owner", path(world, "other"), tenant="b")
    assert r.status_code == 200


@pytest.mark.parametrize(("who", "status"), [("owner", 200), ("analyst", 200), ("viewer", 404)])
def test_unassigned_domain(world: World, who: str, status: int) -> None:
    assert get(world, who, path(world, "unassigned")).status_code == status


def test_foreign_active_tenant_is_404(world: World) -> None:
    assert get(world, "analyst", path(world), tenant="b").status_code == 404


@pytest.mark.parametrize("domain_id", ["999999", "abc", "-1", "1" * 40])
def test_unknown_or_malformed_domain_id_is_404(world: World, domain_id: str) -> None:
    assert get(world, "owner", f"/domains/{domain_id}/esps").status_code == 404
    assert post_as(world, "owner", f"/domains/{domain_id}/esps", {"esp_id": ESP}).status_code == 404
    assert post_as(world, "owner", f"/domains/{domain_id}/esps/{ESP}/remove").status_code == 404


def test_anonymous(world: World) -> None:
    world.client.cookies.clear()
    r = world.client.get(path(world), headers=HTML, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")
    r = call(
        world,
        "anon",
        "POST",
        path(world),
        content=b"esp_id=example-esp",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 401
    assert stored(world) == []


# --- attach / remove ----------------------------------------------------------------------------


@pytest.mark.parametrize("who", WRITERS)
def test_attach_and_remove(world: World, who: str) -> None:
    r = post_as(
        world,
        who,
        path(world),
        {"esp_id": ESP, "return_path_host": " bounce.assigned.example ", "tracking_host": ""},
    )
    assert r.status_code == 303
    assert r.headers["location"] == f"{path(world)}?notice=attached"
    did = world.domains["assigned"]
    assert stored(world) == [(did, ESP, "bounce.assigned.example", None)]
    page = get(world, who, r.headers["location"])
    assert 'data-testid="esps-flash"' in page.text
    # attaching again replaces the hosts
    post_as(world, who, path(world), {"esp_id": ESP, "tracking_host": "go.assigned.example"})
    assert stored(world) == [(did, ESP, None, "go.assigned.example")]
    r = post_as(world, who, f"{path(world)}/{ESP}/remove")
    assert r.status_code == 303 and r.headers["location"].endswith("?notice=removed")
    assert stored(world) == []


@pytest.mark.parametrize("who", READERS)
def test_readers_get_403_on_direct_posts(world: World, who: str) -> None:
    assign(world)
    before = stored(world)
    r = post_as(world, who, path(world), {"esp_id": "other-esp"})
    assert r.status_code == 403
    r = post_as(world, who, f"{path(world)}/{ESP}/remove")
    assert r.status_code == 403
    assert stored(world) == before


def test_viewer_post_on_unassigned_and_foreign_domains(world: World) -> None:
    for which in ("unassigned", "other"):
        r = post_as(world, "viewer", path(world, which), {"esp_id": ESP})
        assert r.status_code in (403, 404)
        assert B_SECRET_NAME not in r.text
    assert stored(world) == []


def test_analyst_on_foreign_domain_is_404(world: World) -> None:
    assert post_as(world, "analyst", path(world, "other"), {"esp_id": ESP}).status_code == 404
    assert post_as(world, "owner", path(world, "other"), {"esp_id": ESP}).status_code == 404
    assert post_as(world, "owner", f"{path(world, 'other')}/{ESP}/remove").status_code == 404
    assert stored(world) == []


def test_tenant_b_cannot_write_or_remove_in_tenant_a(world: World) -> None:
    assign(world)
    before = stored(world)
    for url in (path(world), f"{path(world)}/{ESP}/remove"):
        r = post_as(world, "b_owner", url, {"esp_id": ESP}, tenant="b")
        assert r.status_code == 404
    assert stored(world) == before


def test_toggle_update_off_hides_controls_and_denies(world: World) -> None:
    set_toggles(world, "admin", {"domain.update": False})
    r = get(world, "admin", path(world))
    assert r.status_code == 200 and "<form" not in main_of(r.text)
    assert post_as(world, "admin", path(world), {"esp_id": ESP}).status_code == 403


def test_remove_missing_assignment_is_404(world: World) -> None:
    assert post_as(world, "owner", f"{path(world)}/{ESP}/remove").status_code == 404


def test_csrf_missing_is_the_standard_error(world: World) -> None:
    r = post_as(world, "owner", path(world), {"esp_id": ESP}, csrf=False)
    assert r.status_code == 403
    r2 = post_as(world, "owner", f"{path(world)}/{ESP}/remove", csrf=False)
    assert r2.status_code == 403
    assert stored(world) == []


@pytest.mark.parametrize(
    ("form", "key"),
    [
        ({"esp_id": "nope"}, "No ESP profile with this id is available."),
        ({"esp_id": ESP, "return_path_host": "bounce.other.example"}, "must be the domain itself"),
        ({"esp_id": ESP, "tracking_host": "bad host!.assigned.example"}, "not a valid DNS name"),
        ({"esp_id": ESP, "tracking_host": "a\x00b"}, "could not be read"),
        ({}, "No ESP profile with this id is available."),
    ],
)
def test_invalid_input_is_422_and_stores_nothing(
    world: World, form: dict[str, str], key: str
) -> None:
    r = post_as(world, "owner", path(world), form)
    assert r.status_code == 422
    assert key in r.text
    assert 'data-testid="esps-form-error"' in r.text
    assert stored(world) == []


def test_repeated_field_is_422(world: World) -> None:
    world.client.cookies.clear()
    world.client.cookies.set(SESSION_COOKIE_NAME, _cookie(world, "owner", "a"))
    body = _urlencode(world, "owner", {"esp_id": ESP}, "a", True) + b"&esp_id=other-esp"
    r = world.client.post(
        path(world),
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", **HTML},
    )
    assert r.status_code == 422
    assert stored(world) == []


def test_oversized_body_is_413(world: World) -> None:
    r = post_as(world, "owner", path(world), {"esp_id": ESP, "return_path_host": "a" * 6000})
    assert r.status_code == 413
    assert stored(world) == []


def test_profiles_unavailable_is_shown_not_a_500(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    broken = tmp_path / "esp"
    broken.mkdir()
    (broken / "bad.yaml").write_text("id: [unclosed")
    gen = _make_world(migrated_db_url, monkeypatch, lambda: lambda: load_esp_profiles(broken))
    w = next(gen)
    try:
        r = get(w, "owner", path(w))
        assert r.status_code == 200
        assert 'data-testid="esps-error"' in r.text
        r = post_as(w, "owner", path(w), {"esp_id": ESP})
        assert r.status_code == 503
    finally:
        gen.close()
