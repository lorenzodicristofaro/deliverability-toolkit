"""M6-11 end to end: assign a shipped ESP profile through the API, run `esp`, read the findings.

Real app and middleware, shipped profiles from `profiles/esp/` (the default `esp_profiles`
source), and a fake resolver whose zone is built from the profile (tests/esp/dns_builder.py)
for the tenant domain `assigned.example`. Roles (maintainer decision 2026-11-10, M6-06c): a
client viewer on a domain assigned to them reads the assignments and the `esp` result and gets
403 on writes; a client viewer on an unassigned domain and users of another tenant get 404, as
the existing ESP and check routes already return. No network: the socket guard allows only the
test database.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1 import checks as checks_api
from app.api.v1.dns_tools import dns_backend
from app.checks.models import CheckContext
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.esp.profile import PROFILES_DIR, EspProfile, load_esp_profiles
from app.main import create_app
from app.models.domain_esp import DomainEsp
from tests.api.test_domains import KEY, World, _seed, call
from tests.esp.dns_builder import (
    correct_zone,
    return_path_host,
    selector_name,
    to_fixture_records,
    tracking_host,
)
from tests.support.dns_backend import fake_backend
from tests.support.socket_guard import db_endpoint, install

DOMAIN = "assigned.example"  # the "assigned" domain seeded by tests/api/test_domains.py
FIXED = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
ESP_NOT_FOUND = {"detail": t("api.domain_esps.error.not_found", "en")}
CHECK_NOT_FOUND = {"detail": t("api.error.not_found", "en")}
FORBIDDEN = {"detail": t("api.error.forbidden", "en")}


def _pick() -> EspProfile:
    """The first shipped profile (by id) with verified SPF includes and a verified DKIM selector:
    derived, so the test follows the shipped data instead of naming a vendor."""
    for p in load_esp_profiles(PROFILES_DIR):
        verified_sels = [s for s in p.dkim_selectors if p.is_verified(f"dkim.selectors.{s.name}")]
        if p.spf_includes and p.is_verified("spf.includes") and verified_sels:
            return p
    raise AssertionError("no shipped profile with verified SPF includes and DKIM selectors")


PROFILE = _pick()
REMOVED = next(s for s in PROFILE.dkim_selectors if PROFILE.is_verified(f"dkim.selectors.{s.name}"))
NAMES = {"assigned": DOMAIN, "unassigned": "unassigned.example"}  # tenant A's seeded domains


def hosts(which: str = "assigned") -> dict[str, str]:
    return {
        "return_path_host": return_path_host(NAMES[which]),
        "tracking_host": tracking_host(NAMES[which]),
    }


def _zone() -> dict[str, list[dict[str, Any]]]:
    """The profile's correct zone with one DKIM record removed: one known failure."""
    zone = correct_zone(PROFILE, DOMAIN)
    del zone[(selector_name(REMOVED, DOMAIN), REMOVED.type.upper())]
    return {"default": to_fixture_records(zone)}


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "ESP acceptance API", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    real = checks_api._context

    def fixed(*args: Any, **kw: Any) -> CheckContext:
        return real(*args, **kw).model_copy(update={"clock": lambda: FIXED})

    monkeypatch.setattr(checks_api, "_context", fixed)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)
    application = create_app(settings)
    backend, _ = fake_backend(_zone())
    application.dependency_overrides[dns_backend] = lambda: backend
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def esps(w: World, which: str = "assigned") -> str:
    return f"/api/v1/domains/{w.domains[which]}/esps"


def one(w: World, which: str = "assigned") -> str:
    return f"{esps(w, which)}/{PROFILE.id}"


def run_esp(w: World, which: str = "assigned") -> str:
    return f"/api/v1/domains/{w.domains[which]}/checks/esp"


def rows(w: World) -> list[tuple[Any, ...]]:
    w.db.rollback()
    found = w.db.execute(
        select(DomainEsp.domain_id, DomainEsp.esp_id, DomainEsp.return_path_host).order_by(
            DomainEsp.id
        )
    ).all()
    w.db.rollback()
    return [tuple(r) for r in found]


def codes(body: dict[str, Any]) -> list[str]:
    return [f["code"] for f in body["findings"]]


def test_owner_assigns_runs_and_sees_the_findings(world: World) -> None:
    put = call(world, "owner", "PUT", one(world), json=hosts())
    assert put.status_code == 201, put.text
    listed = call(world, "owner", "GET", esps(world))
    assert listed.status_code == 200
    assert PROFILE.id in listed.text

    r = call(world, "owner", "POST", run_esp(world))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["check_id"] == "esp" and body["target"] == DOMAIN
    assert [s["id"] for s in body["data"]["esps"]] == [PROFILE.id]
    failures = [c for c in codes(body) if c not in ("ESP_PITFALL", "ESP_PROFILE_UNVERIFIED")]
    assert failures == ["ESP_DKIM_RECORD_MISSING"]
    (missing,) = [f for f in body["findings"] if f["code"] == "ESP_DKIM_RECORD_MISSING"]
    assert missing["params"]["selector"] == REMOVED.name
    assert body["status"] == "fail"
    assert body["data"]["esps"][0]["spf"]["state"] == "ok"


def test_owner_removes_and_the_records_are_detected_as_not_assigned(world: World) -> None:
    assert call(world, "owner", "PUT", one(world), json=hosts()).status_code == 201
    assert call(world, "owner", "DELETE", one(world)).status_code == 204
    assert rows(world) == []
    body = call(world, "owner", "POST", run_esp(world)).json()
    assert body["data"]["esps"] == []
    assert "ESP_NONE_ASSIGNED" in codes(body)
    detected = [f for f in body["findings"] if f["code"] == "ESP_DETECTED_NOT_ASSIGNED"]
    assert [f["params"]["esp_id"] for f in detected] == [PROFILE.id]


def test_client_viewer_on_assigned_domain_reads_but_cannot_write(world: World) -> None:
    assert call(world, "owner", "PUT", one(world), json=hosts()).status_code == 201
    before = rows(world)

    owner_list = call(world, "owner", "GET", esps(world))
    viewer_list = call(world, "viewer", "GET", esps(world))
    assert viewer_list.status_code == 200
    assert viewer_list.content == owner_list.content

    owner_run = call(world, "owner", "POST", run_esp(world))
    viewer_run = call(world, "viewer", "POST", run_esp(world))
    assert viewer_run.status_code == 200
    assert viewer_run.content == owner_run.content
    assert "ESP_DKIM_RECORD_MISSING" in codes(viewer_run.json())

    for method, body in (("PUT", {"return_path_host": None}), ("DELETE", None)):
        r = call(world, "viewer", method, one(world), json=body)
        assert (r.status_code, r.json()) == (403, FORBIDDEN), method
    assert rows(world) == before


@pytest.mark.parametrize(
    ("who", "tenant", "which"),
    [
        ("viewer", "a", "unassigned"),  # client viewer, domain not assigned to them
        ("b_owner", "b", "assigned"),  # another tenant's owner on tenant A's domain
        ("b_viewer", "b", "assigned"),  # another tenant's client viewer on tenant A's domain
    ],
    ids=["viewer_unassigned_domain", "other_tenant_owner", "other_tenant_viewer"],
)
def test_invisible_domain_is_404_without_esp_data(
    world: World, who: str, tenant: str, which: str
) -> None:
    assert call(world, "owner", "PUT", one(world, which), json=hosts(which)).status_code == 201
    before = rows(world)
    for method, path, expected in (
        ("GET", esps(world, which), ESP_NOT_FOUND),
        ("PUT", one(world, which), ESP_NOT_FOUND),
        ("DELETE", one(world, which), ESP_NOT_FOUND),
        ("POST", run_esp(world, which), CHECK_NOT_FOUND),
    ):
        r = call(world, who, method, path, tenant=tenant)
        assert (r.status_code, r.json()) == (404, expected), (method, path)
        assert PROFILE.id not in r.text and "bounce." not in r.text
    assert rows(world) == before
