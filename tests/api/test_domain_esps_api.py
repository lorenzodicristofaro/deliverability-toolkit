"""M6-03 ESP routes through the real app and middleware: `/api/v1/esp-profiles` and
`/api/v1/domains/{id}/esps[/{esp_id}]`.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role, per-verb table, error bodies and the
wire format. Profiles come from tests/fixtures/esp/valid (dependency override). No network.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1._common import MAX_BODY_BYTES
from app.api.v1.domain_esps import esp_profiles
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.esp.profile import load_esp_profiles
from app.main import create_app
from app.models import User
from app.models.domain_esp import DomainEsp
from app.repositories.domain_esps import MAX_ESPS_PER_DOMAIN
from app.services.domain_esps import ProfileSource
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _seed, call
from tests.support.socket_guard import db_endpoint, install

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "esp" / "valid"
CATALOGUE = "/api/v1/esp-profiles"
ESP = "example-esp"
NOT_FOUND = {"detail": t("api.domain_esps.error.not_found", "en")}
FORBIDDEN = {"detail": t("api.error.forbidden", "en")}
B_HOST = "bounce." + B_SECRET_NAME


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "domain esps API", db_endpoint())


def _fixture_profiles() -> ProfileSource:
    return lambda: load_esp_profiles(FIXTURES)


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    root = User(email="root@example.com", is_instance_admin=True)
    db.add(root)
    db.commit()
    users["root"] = root.id
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    application.dependency_overrides[esp_profiles] = _fixture_profiles
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def rows(db: Session) -> list[tuple[Any, ...]]:
    db.expire_all()
    db.rollback()
    found = db.execute(
        select(
            DomainEsp.tenant_id,
            DomainEsp.domain_id,
            DomainEsp.esp_id,
            DomainEsp.return_path_host,
            DomainEsp.tracking_host,
        ).order_by(DomainEsp.id)
    ).all()
    db.rollback()
    return [tuple(r) for r in found]


def esps(w: World, domain: str = "assigned") -> str:
    return f"/api/v1/domains/{w.domains[domain]}/esps"


def one(w: World, domain: str = "assigned", esp: str = ESP) -> str:
    return f"{esps(w, domain)}/{esp}"


def assign(w: World, who: str = "owner", domain: str = "assigned", **hosts: Any) -> Any:
    tenant = "b" if who.startswith("b_") else "a"
    return call(w, who, "PUT", one(w, domain), json=hosts or None, tenant=tenant)


def assert_problem(response: Any, key: str, field: str, reason: str | None = None) -> None:
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert {k: detail[k] for k in ("key", "message", "field")} == {
        "key": key,
        "message": t(key, "en"),
        "field": field,
    }
    if reason is not None:
        assert detail["reason"] == reason


# --- roles and verbs ----------------------------------------------------------------------------

READ = {"anon": 401, "owner": 200, "admin": 200, "analyst": 200, "viewer": 200, "root": 404}
WRITE = {"anon": 401, "owner": 0, "admin": 0, "analyst": 403, "viewer": 403, "root": 404}


@pytest.mark.parametrize(("who", "status"), READ.items())
def test_catalogue_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "GET", CATALOGUE)
    assert response.status_code == status
    if status == 403:
        assert response.json() == FORBIDDEN


@pytest.mark.parametrize(("who", "status"), READ.items())
def test_list_per_role(world: World, who: str, status: int) -> None:
    """The viewer's own assigned domain: readable (M6-06c)."""
    response = call(world, who, "GET", esps(world))
    assert response.status_code == status


@pytest.mark.parametrize(("who", "status"), WRITE.items())
def test_put_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "PUT", one(world))
    assert response.status_code == (status or 201)
    assert len(rows(world.db)) == (1 if status == 0 else 0)


@pytest.mark.parametrize(("who", "status"), WRITE.items())
def test_delete_per_role(world: World, who: str, status: int) -> None:
    assert assign(world).status_code == 201
    response = call(world, who, "DELETE", one(world))
    assert response.status_code == (status or 204)
    assert len(rows(world.db)) == (0 if status == 0 else 1)


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_viewer_unassigned_domain_is_404(world: World, method: str) -> None:
    path = esps(world, "unassigned") if method == "GET" else one(world, "unassigned")
    response = call(world, "viewer", method, path)
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_foreign_domain_is_404_and_unchanged(world: World, method: str, who: str) -> None:
    assert assign(world, "b_owner", "other", return_path_host=B_HOST).status_code == 201
    before = rows(world.db)
    path = esps(world, "other") if method == "GET" else one(world, "other")
    response = call(world, who, method, path, json={"return_path_host": None})
    assert response.status_code == 404
    assert response.json() == NOT_FOUND
    assert B_SECRET_NAME not in response.text
    assert rows(world.db) == before


@pytest.mark.parametrize("path", ["catalogue", "list", "put", "delete"])
def test_session_in_a_foreign_tenant_gets_404(world: World, path: str) -> None:
    method, url = {
        "catalogue": ("GET", CATALOGUE),
        "list": ("GET", esps(world)),
        "put": ("PUT", one(world)),
        "delete": ("DELETE", one(world)),
    }[path]
    response = call(world, "owner", method, url, tenant="b")
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "1.5", "99999999999999999999", "%C2%B2"])
@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_malformed_domain_id_is_a_404(world: World, method: str, raw: str) -> None:
    path = f"/api/v1/domains/{raw}/esps" + ("" if method == "GET" else f"/{ESP}")
    response = call(world, "owner", method, path)
    assert response.status_code == 404
    assert response.json() == NOT_FOUND


def test_mutation_without_csrf_is_refused(world: World) -> None:
    response = call(world, "owner", "PUT", one(world), csrf=False)
    assert response.status_code == 403
    assert rows(world.db) == []


def test_denied_caller_gets_403_whatever_the_body(world: World) -> None:
    response = call(world, "analyst", "PUT", one(world), content=b"{")
    assert response.status_code == 403
    response = call(world, "viewer", "PUT", one(world), content=b"{")
    assert response.status_code == 403


def test_missing_domain_with_malformed_body_is_404(world: World) -> None:
    response = call(world, "owner", "PUT", one(world, "other"), content=b"{")
    assert response.status_code == 404


def test_viewer_reads_what_the_analyst_reads(world: World) -> None:
    """Client viewers see the assignments of their assigned domain unredacted (M6-06c)."""
    hosts = {"return_path_host": "bounce.assigned.example", "tracking_host": "t.assigned.example"}
    assert assign(world, **hosts).status_code == 201
    viewer = call(world, "viewer", "GET", esps(world))
    analyst = call(world, "analyst", "GET", esps(world))
    assert viewer.status_code == analyst.status_code == 200
    assert viewer.json() == analyst.json()
    assert viewer.json()["items"][0]["tracking_host"] == "t.assigned.example"
    assert call(world, "viewer", "GET", CATALOGUE).json() == (
        call(world, "analyst", "GET", CATALOGUE).json()
    )


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_viewer_write_on_assigned_domain_is_403_and_unchanged(world: World, method: str) -> None:
    assert assign(world).status_code == 201
    before = rows(world.db)
    response = call(world, "viewer", method, one(world), json={"return_path_host": None})
    assert (response.status_code, response.json()) == (403, FORBIDDEN)
    assert rows(world.db) == before


def test_two_tenants_viewer_on_foreign_domain_sees_no_esp_data(world: World) -> None:
    assert assign(world, "b_owner", "other", return_path_host=B_HOST).status_code == 201
    response = call(world, "viewer", "GET", esps(world, "other"))
    assert (response.status_code, response.json()) == (404, NOT_FOUND)
    assert B_SECRET_NAME not in response.text and ESP not in response.text


def test_two_tenants_no_leak_through_list_or_catalogue(world: World) -> None:
    assert assign(world, "b_owner", "other", return_path_host=B_HOST).status_code == 201
    assert assign(world, return_path_host="bounce.assigned.example").status_code == 201
    listed = call(world, "analyst", "GET", esps(world))
    assert listed.status_code == 200
    assert [i["esp_id"] for i in listed.json()["items"]] == [ESP]
    assert B_SECRET_NAME not in listed.text
    catalogue = call(world, "analyst", "GET", CATALOGUE)
    assert B_SECRET_NAME not in catalogue.text
    assert "tenant" not in listed.text


# --- wire format and PUT semantics --------------------------------------------------------------


def test_catalogue_wire_format(world: World) -> None:
    items = call(world, "owner", "GET", CATALOGUE).json()["items"]
    assert [i["id"] for i in items] == ["example-esp", "other-esp"]
    assert items[0] == {
        "id": "example-esp",
        "name": "Example ESP",
        "homepage": "https://esp.example.com",
        "status": "verified",
        "verified_on": "2026-01-15",
        "sources": ["https://docs.esp.example.com/dns-setup"],
    }
    assert items[1]["status"] == "unverified"


def test_round_trip(world: World) -> None:
    created = assign(world, return_path_host="Bounce.Assigned.Example.")
    assert created.status_code == 201
    body = created.json()
    assert body["esp_id"] == ESP
    assert body["name"] == "Example ESP"
    assert body["domain_id"] == world.domains["assigned"]
    assert body["return_path_host"] == "bounce.assigned.example"
    assert body["tracking_host"] is None
    assert set(body) == {
        "domain_id",
        "esp_id",
        "name",
        "return_path_host",
        "tracking_host",
        "created_at",
    }
    listed = call(world, "owner", "GET", esps(world)).json()["items"]
    assert listed == [body]
    assert call(world, "owner", "DELETE", one(world)).status_code == 204
    assert call(world, "owner", "GET", esps(world)).json() == {"items": []}
    assert call(world, "owner", "DELETE", one(world)).status_code == 404


def test_duplicate_put_is_idempotent(world: World) -> None:
    first = assign(world, return_path_host="bounce.assigned.example")
    second = assign(world, return_path_host="bounce.assigned.example")
    assert (first.status_code, second.status_code) == (201, 200)
    assert second.json() == first.json()
    assert len(rows(world.db)) == 1


def test_put_with_other_hosts_replaces_them(world: World) -> None:
    assign(world, return_path_host="bounce.assigned.example")
    response = assign(world, tracking_host="t.assigned.example")
    assert response.status_code == 200
    assert (response.json()["return_path_host"], response.json()["tracking_host"]) == (
        None,
        "t.assigned.example",
    )
    assert len(rows(world.db)) == 1


def test_empty_object_body_and_no_body_are_the_same(world: World) -> None:
    assert call(world, "owner", "PUT", one(world), json={}).status_code == 201
    assert call(world, "owner", "PUT", one(world)).status_code == 200


def test_tenant_comes_from_the_session(world: World) -> None:
    response = call(world, "owner", "PUT", one(world), json={"tenant_id": world.tenant_b})
    assert response.status_code == 422
    assert rows(world.db) == []


# --- validation ---------------------------------------------------------------------------------


@pytest.mark.parametrize("esp_id", ["not-loaded", "EXAMPLE-ESP", "x" * 41, "a%00b", "-a"])
def test_unknown_esp_is_a_422(world: World, esp_id: str) -> None:
    response = call(world, "owner", "PUT", f"{esps(world)}/{esp_id}")
    assert_problem(response, "api.domain_esps.error.unknown_esp", "esp_id", "unknown")
    assert esp_id not in response.text
    assert rows(world.db) == []


@pytest.mark.parametrize(
    ("hosts", "key", "field"),
    [
        (
            {"return_path_host": "bounce.other.example"},
            "host_outside_domain",
            "return_path_host",
        ),
        ({"tracking_host": B_HOST}, "host_outside_domain", "tracking_host"),
        ({"tracking_host": "192.0.2.1"}, "invalid_host", "tracking_host"),
        ({"tracking_host": "bücher.assigned.example"}, "invalid_host", "tracking_host"),
        ({"return_path_host": "a..assigned.example"}, "invalid_host", "return_path_host"),
        ({"return_path_host": "x" * 300}, "invalid_host", "return_path_host"),
        ({"return_path_host": "bad\u0000.assigned.example"}, "invalid_host", "return_path_host"),
    ],
)
def test_invalid_hosts_have_the_problem_shape(
    world: World, hosts: dict[str, str], key: str, field: str
) -> None:
    response = assign(world, **hosts)
    assert_problem(response, f"api.domain_esps.error.{key}", field)
    for value in hosts.values():
        assert value not in response.text
    assert rows(world.db) == []


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[1]",
        b'"x"',
        b'{"return_path_host": 1}',
        b'{"return_path_host": "a", "return_path_host": "b"}',
        b'{"return_path_host": NaN}',
        b'{"unknown": "x"}',
        b"\xff\xfe",
    ],
)
def test_malformed_bodies_are_422(world: World, raw: bytes) -> None:
    response = call(
        world, "owner", "PUT", one(world), content=raw, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json() == {"detail": t("api.error.invalid_request", "en")}
    assert rows(world.db) == []


def test_non_json_content_type_is_415(world: World) -> None:
    response = call(
        world, "owner", "PUT", one(world), content=b"x=1", headers={"content-type": "text/plain"}
    )
    assert response.status_code == 415


def test_oversized_body_is_413(world: World) -> None:
    response = call(
        world,
        "owner",
        "PUT",
        one(world),
        content=b" " * (MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_cap_is_a_422_too_many(world: World) -> None:
    base = load_esp_profiles(FIXTURES)[0]
    ids = [f"esp-{n}" for n in range(MAX_ESPS_PER_DOMAIN + 1)]
    profiles = tuple(dataclasses.replace(base, id=i) for i in ids)
    app = world.client.app
    app.dependency_overrides[esp_profiles] = lambda: lambda: profiles  # type: ignore[attr-defined]
    for esp_id in ids[:-1]:
        assert call(world, "owner", "PUT", f"{esps(world)}/{esp_id}").status_code == 201
    response = call(world, "owner", "PUT", f"{esps(world)}/{ids[-1]}")
    assert_problem(response, "api.domain_esps.error.too_many", "esp_id", "too_many")
    assert len(rows(world.db)) == MAX_ESPS_PER_DOMAIN


def test_list_names_null_for_a_profile_no_longer_loaded(world: World) -> None:
    assign(world)
    app = world.client.app
    app.dependency_overrides[esp_profiles] = lambda: lambda: ()  # type: ignore[attr-defined]
    items = call(world, "owner", "GET", esps(world)).json()["items"]
    assert [(i["esp_id"], i["name"]) for i in items] == [(ESP, None)]
    assert call(world, "owner", "DELETE", one(world)).status_code == 204


@pytest.mark.parametrize("lang", ["en", "it"])
def test_error_keys_exist_in_both_languages(lang: str) -> None:
    names = ("unknown_esp", "invalid_host", "host_outside_domain", "too_many", "not_found")
    for name in (*names, "profiles_unavailable"):
        key = f"api.domain_esps.error.{name}"
        assert t(key, lang) != key


# --- broken profile directory (M6-06) -----------------------------------------------------------

MALFORMED = FIXTURES.parent / "malformed"
UNAVAILABLE = {"detail": t("api.domain_esps.error.profiles_unavailable", "en")}
BROKEN_SOURCES = {
    "missing_dir": lambda: load_esp_profiles(FIXTURES.parent / "no-such-dir"),
    "malformed_files": lambda: load_esp_profiles(MALFORMED),
}


def _break_profiles(w: World, source: ProfileSource) -> None:
    w.client.app.dependency_overrides[esp_profiles] = lambda: source  # type: ignore[attr-defined]


@pytest.mark.parametrize("source", BROKEN_SOURCES)
@pytest.mark.parametrize("route", ["catalogue", "list", "put"])
def test_broken_profiles_are_a_localized_503(
    world: World, route: str, source: str, caplog: pytest.LogCaptureFixture
) -> None:
    assert assign(world).status_code == 201
    _break_profiles(world, BROKEN_SOURCES[source])
    caplog.set_level("WARNING", logger="app.domain_esps")
    method, url = {
        "catalogue": ("GET", CATALOGUE),
        "list": ("GET", esps(world)),
        "put": ("PUT", one(world)),
    }[route]
    response = call(world, "owner", method, url)
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE
    events = [r.__dict__.get("event") for r in caplog.records]
    assert "domain_esps.profiles_unreadable" in events
    assert len(rows(world.db)) == 1


def test_broken_profiles_503_is_in_italian_too(world: World) -> None:
    _break_profiles(world, BROKEN_SOURCES["missing_dir"])
    response = call(world, "owner", "GET", CATALOGUE, headers={"Accept-Language": "it"})
    assert response.status_code == 503
    assert response.json() == {"detail": t("api.domain_esps.error.profiles_unavailable", "it")}


@pytest.mark.parametrize(
    ("who", "status"), [("anon", 401), ("viewer", 403), ("analyst", 403), ("root", 404)]
)
def test_broken_profiles_do_not_change_denials(world: World, who: str, status: int) -> None:
    _break_profiles(world, BROKEN_SOURCES["missing_dir"])
    assert call(world, who, "PUT", one(world)).status_code == status


def test_broken_profiles_still_allow_delete(world: World) -> None:
    assert assign(world).status_code == 201
    _break_profiles(world, BROKEN_SOURCES["malformed_files"])
    assert call(world, "owner", "DELETE", one(world)).status_code == 204
    assert rows(world.db) == []
