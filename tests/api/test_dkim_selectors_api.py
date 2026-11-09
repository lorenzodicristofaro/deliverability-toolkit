"""M5-20 `/api/v1/dkim-selectors` through the real app and middleware.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role, per-verb and per-scope table, error
bodies and the wire format. The startup seed sync runs here: these tests need the seeded global
rows. No network.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1._common import MAX_BODY_BYTES
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.main import create_app
from app.models import User
from app.models.dkim_selector import DkimSelector
from app.repositories import GlobalDkimSelectorRepository
from app.services.dkim_selectors_admin import MAX_TENANT_SELECTORS
from tests.api.test_domains import KEY, World, _seed, call
from tests.support.socket_guard import db_endpoint, install

URL = "/api/v1/dkim-selectors"
GLOBAL_Q = "?scope=global"
SEED_KEY = "selector1"
SECRET = "SECRET-NOTE-5512"


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "dkim selectors API", db_endpoint())


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
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def seeded(w: World) -> Any:
    w.db.expire_all()
    w.db.rollback()
    for record in GlobalDkimSelectorRepository(w.db).list_seeded():
        if record.seed_key == SEED_KEY:
            w.db.rollback()
            return record
    raise AssertionError("seeded selector missing")


def rows(db: Session) -> list[tuple[Any, ...]]:
    db.expire_all()
    db.rollback()
    found = db.execute(
        select(
            DkimSelector.id,
            DkimSelector.scope,
            DkimSelector.tenant_id,
            DkimSelector.selector,
            DkimSelector.notes,
            DkimSelector.enabled,
            DkimSelector.locally_modified,
        ).order_by(DkimSelector.id)
    ).all()
    db.rollback()
    return [tuple(r) for r in found]


def make(w: World, who: str = "owner", tenant: str = "a", **values: Any) -> dict[str, Any]:
    response = call(w, who, "POST", URL, json={"selector": "mine", **values}, tenant=tenant)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def assert_problem(response: Any, status: int, key: str, field: str, reason: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["detail"] == {
        "key": key,
        "message": t(key, "en"),
        "field": field,
        "reason": reason,
    }


# --- roles, verbs, scopes ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 200),
        ("admin", 200),
        ("analyst", 200),
        ("viewer", 403),
        ("root", 404),  # no membership: the flag gives no tenant path
    ],
)
def test_tenant_list_per_role(world: World, who: str, status: int) -> None:
    assert call(world, who, "GET", URL).status_code == status


@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 403),
        ("admin", 403),
        ("analyst", 403),
        ("viewer", 403),
        ("root", 200),
    ],
)
def test_global_list_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "GET", URL + GLOBAL_Q)
    assert response.status_code == status
    if status == 200:
        assert {item["scope"] for item in response.json()["items"]} == {"global"}


@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 201),
        ("admin", 201),
        ("analyst", 403),
        ("viewer", 403),
        ("root", 404),
    ],
)
def test_tenant_create_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "POST", URL, json={"selector": "mine"})
    assert response.status_code == status
    if status == 201:
        assert response.json()["scope"] == "tenant"


@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 403),
        ("admin", 403),
        ("analyst", 403),
        ("viewer", 403),
        ("root", 201),
    ],
)
def test_global_create_per_role(world: World, who: str, status: int) -> None:
    before = rows(world.db)
    response = call(world, who, "POST", URL + GLOBAL_Q, json={"selector": "instance-only"})
    assert response.status_code == status
    if status != 201:
        assert rows(world.db) == before
    else:
        assert response.json()["scope"] == "global"


@pytest.mark.parametrize(
    ("method", "who", "status"),
    [
        ("GET", "anon", 401),
        ("GET", "owner", 200),
        ("GET", "analyst", 200),
        ("GET", "viewer", 403),
        ("GET", "root", 404),
        ("GET", "b_owner", 404),
        ("PATCH", "anon", 401),
        ("PATCH", "owner", 200),
        ("PATCH", "admin", 200),
        ("PATCH", "analyst", 403),
        ("PATCH", "viewer", 403),
        ("PATCH", "root", 404),
        ("PATCH", "b_owner", 404),
        ("DELETE", "anon", 401),
        ("DELETE", "owner", 204),
        ("DELETE", "admin", 204),
        ("DELETE", "analyst", 403),
        ("DELETE", "viewer", 403),
        ("DELETE", "root", 404),
        ("DELETE", "b_owner", 404),
    ],
)
def test_tenant_item_per_role_and_verb(world: World, method: str, who: str, status: int) -> None:
    target = make(world)
    before = rows(world.db)
    response = call(
        world,
        who,
        method,
        f"{URL}/{target['id']}",
        json={"notes": "edited"} if method == "PATCH" else None,
        tenant="b" if who == "b_owner" else "a",
    )
    assert response.status_code == status, response.text
    if status not in (200, 204) or method == "GET":
        assert rows(world.db) == before


@pytest.mark.parametrize("method", ["PATCH", "DELETE"])
@pytest.mark.parametrize(
    ("who", "status"),
    [("anon", 401), ("owner", 403), ("admin", 403), ("analyst", 403), ("viewer", 403)],
)
def test_global_item_writes_denied_on_the_global_path(
    world: World, method: str, who: str, status: int
) -> None:
    target = seeded(world)
    before = rows(world.db)
    response = call(
        world,
        who,
        method,
        f"{URL}/{target.id}{GLOBAL_Q}",
        json={"notes": "x"} if method == "PATCH" else None,
    )
    assert response.status_code == status
    assert rows(world.db) == before


@pytest.mark.parametrize("method", ["PATCH", "DELETE"])
@pytest.mark.parametrize("who", ["owner", "admin"])
def test_global_row_from_the_tenant_path_is_forbidden(world: World, method: str, who: str) -> None:
    target = seeded(world)
    before = rows(world.db)
    response = call(
        world,
        who,
        method,
        f"{URL}/{target.id}",
        json={"notes": "x"} if method == "PATCH" else None,
    )
    assert response.status_code == 403
    assert response.json() == {"detail": t("api.dkim_selectors.error.scope_forbidden", "en")}
    assert rows(world.db) == before


@pytest.mark.parametrize("method", ["GET", "PATCH", "DELETE"])
@pytest.mark.parametrize("who", ["owner", "admin"])
def test_foreign_selector_is_a_404_for_every_verb(world: World, method: str, who: str) -> None:
    foreign = make(world, "b_owner", tenant="b", selector="b-private", notes=SECRET)
    before = rows(world.db)
    response = call(
        world,
        who,
        method,
        f"{URL}/{foreign['id']}",
        json={"notes": "x"} if method == "PATCH" else None,
    )
    assert response.status_code == 404
    assert response.json() == {"detail": t("api.dkim_selectors.error.not_found", "en")}
    assert SECRET not in response.text
    assert rows(world.db) == before


def test_foreign_id_with_malformed_json_is_404_not_422(world: World) -> None:
    foreign = make(world, "b_owner", tenant="b", selector="b-private")
    response = call(world, "owner", "PATCH", f"{URL}/{foreign['id']}", content=b"{")
    assert response.status_code == 404


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "1.5", "99999999999999999999", "%C2%B2"])
@pytest.mark.parametrize("method", ["GET", "PATCH", "DELETE"])
def test_malformed_id_is_a_404(world: World, method: str, raw: str) -> None:
    response = call(
        world, "owner", method, f"{URL}/{raw}", json={"notes": "x"} if method == "PATCH" else None
    )
    assert response.status_code == 404
    assert response.json() == {"detail": t("api.dkim_selectors.error.not_found", "en")}


def test_session_in_a_foreign_tenant_gets_404(world: World) -> None:
    assert call(world, "owner", "GET", URL, tenant="b").status_code == 404
    response = call(world, "owner", "POST", URL, json={"selector": "mine"}, tenant="b")
    assert response.status_code == 404


def test_mutation_without_csrf_is_refused(world: World) -> None:
    before = rows(world.db)
    response = call(world, "owner", "POST", URL, json={"selector": "mine"}, csrf=False)
    assert response.status_code == 403
    assert rows(world.db) == before


def test_denied_caller_gets_403_whatever_the_body(world: World) -> None:
    response = call(world, "analyst", "POST", URL, content=b"{")
    assert response.status_code == 403


@pytest.mark.parametrize("smuggled", ["tenant_id", "scope", "locally_modified", "seed_key"])
@pytest.mark.parametrize("who_query", [("owner", ""), ("root", GLOBAL_Q)])
def test_body_cannot_choose_tenant_or_scope(
    world: World, who_query: tuple[str, str], smuggled: str
) -> None:
    who, query = who_query
    before = rows(world.db)
    payload = {"selector": "mine", smuggled: world.tenant_b}
    response = call(world, who, "POST", URL + query, json=payload)
    assert_problem(response, 422, "api.dkim_selectors.error.invalid_field", "body", "unknown_field")
    assert rows(world.db) == before


def test_list_response_never_contains_another_tenant(world: World) -> None:
    make(world, "b_owner", tenant="b", selector="b-private", notes=SECRET)
    mine = make(world)
    response = call(world, "analyst", "GET", f"{URL}?limit=1000")
    names = {item["selector"] for item in response.json()["items"]}
    assert {"mine", SEED_KEY} <= names
    assert "b-private" not in names
    assert SECRET not in response.text
    assert "tenant_id" not in mine
    assert "created_by" not in mine


# --- wire format and error bodies ----------------------------------------------------------------


def test_round_trip(world: World) -> None:
    created = make(world, provider="acme", record_type="txt", notes="A note", enabled=False)
    assert created["selector"] == "mine"
    assert created["provider"] == "acme"
    assert created["record_type"] == "txt"
    assert created["notes"] == "A note"
    assert created["enabled"] is False
    assert created["seed_key"] is None
    assert call(world, "analyst", "GET", f"{URL}/{created['id']}").json() == created


@pytest.mark.parametrize(
    ("payload", "key", "field", "reason"),
    [
        ({"selector": "a.b"}, "invalid_selector", "selector", "not_a_label"),
        ({"selector": "UPPER"}, "invalid_selector", "selector", "invalid_label"),
        ({"selector": "a\x00b"}, "invalid_selector", "selector", "nul"),
        ({"selector": "a" * 64}, "too_long", "selector", "too_long"),
        ({"selector": "ok", "provider": "x" * 65}, "too_long", "provider", "too_long"),
        ({"selector": "ok", "provider": "a\x00"}, "invalid_field", "provider", "nul"),
        ({"selector": "ok", "notes": "x" * 501}, "too_long", "notes", "too_long"),
        ({"selector": "ok", "notes": "a\x00b"}, "invalid_field", "notes", "nul"),
        ({"selector": "ok", "record_type": "mx"}, "invalid_field", "record_type", "invalid_choice"),
    ],
)
def test_validation_errors_have_the_problem_shape(
    world: World, payload: dict[str, Any], key: str, field: str, reason: str
) -> None:
    before = rows(world.db)
    response = call(world, "owner", "POST", URL, json=payload)
    assert_problem(response, 422, f"api.dkim_selectors.error.{key}", field, reason)
    assert rows(world.db) == before


@pytest.mark.parametrize(
    ("raw", "field"),
    [
        (b'{"selector": "a\\ud800b"}', "selector"),
        (b'{"selector": "ok", "provider": "\\udfff"}', "provider"),
        (b'{"selector": "ok", "notes": "\\ud83d"}', "notes"),
    ],
)
def test_surrogates_are_rejected_before_the_database(world: World, raw: bytes, field: str) -> None:
    before = rows(world.db)
    response = call(
        world, "owner", "POST", URL, content=raw, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422
    assert (response.json()["detail"]["field"], response.json()["detail"]["reason"]) == (
        field,
        "surrogate",
    )
    assert rows(world.db) == before


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"{", "malformed_json"),
        (b"\xff", "malformed_json"),
        (b'{"selector": "a", "selector": "b"}', "malformed_json"),
        (b'{"selector": NaN}', "malformed_json"),
        (b"[1]", "not_an_object"),
        (b"{}", "empty"),
    ],
)
def test_malformed_bodies(world: World, raw: bytes, reason: str) -> None:
    response = call(
        world, "owner", "POST", URL, content=raw, headers={"content-type": "application/json"}
    )
    assert_problem(response, 422, "api.dkim_selectors.error.invalid_field", "body", reason)


def test_non_json_content_type_is_415(world: World) -> None:
    response = call(
        world, "owner", "POST", URL, content=b"selector=a", headers={"content-type": "text/plain"}
    )
    assert response.status_code == 415


def test_oversized_body_is_413(world: World) -> None:
    response = call(
        world,
        "owner",
        "POST",
        URL,
        content=b" " * (MAX_BODY_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_invalid_scope_is_a_problem(world: World) -> None:
    response = call(world, "owner", "GET", f"{URL}?scope=nope")
    assert_problem(
        response, 422, "api.dkim_selectors.error.invalid_field", "scope", "invalid_choice"
    )


def test_anonymous_with_invalid_scope_is_401(world: World) -> None:
    assert call(world, "anon", "GET", f"{URL}?scope=nope").status_code == 401


def test_duplicate_is_a_409(world: World) -> None:
    make(world)
    response = call(world, "owner", "POST", URL, json={"selector": "mine"})
    assert response.status_code == 409
    assert response.json() == {"detail": t("api.dkim_selectors.error.duplicate", "en")}


@pytest.mark.parametrize("lang", ["en", "it"])
def test_error_keys_exist_in_both_languages(lang: str) -> None:
    for name in (
        "invalid_selector",
        "too_long",
        "duplicate",
        "scope_forbidden",
        "not_found",
        "invalid_field",
        "seeded_delete",
    ):
        key = f"api.dkim_selectors.error.{name}"
        assert t(key, lang) != key


# --- seed semantics ------------------------------------------------------------------------------


def test_seeded_row_delete_is_a_409(world: World) -> None:
    target = seeded(world)
    before = rows(world.db)
    response = call(world, "root", "DELETE", f"{URL}/{target.id}{GLOBAL_Q}")
    assert response.status_code == 409
    assert response.json() == {"detail": t("api.dkim_selectors.error.seeded_delete", "en")}
    assert rows(world.db) == before


def test_root_disables_a_seeded_row(world: World) -> None:
    target = seeded(world)
    response = call(world, "root", "PATCH", f"{URL}/{target.id}{GLOBAL_Q}", json={"enabled": False})
    assert response.status_code == 200, response.text
    assert response.json()["enabled"] is False
    assert response.json()["locally_modified"] is True


def test_seed_managed_field_is_a_422(world: World) -> None:
    target = seeded(world)
    response = call(
        world, "root", "PATCH", f"{URL}/{target.id}{GLOBAL_Q}", json={"selector": "renamed"}
    )
    assert_problem(
        response, 422, "api.dkim_selectors.error.invalid_selector", "selector", "seed_managed"
    )


def test_root_manages_an_unseeded_global_row(world: World) -> None:
    payload = {"selector": "instance-only"}
    created = call(world, "root", "POST", URL + GLOBAL_Q, json=payload).json()
    item = f"{URL}/{created['id']}{GLOBAL_Q}"
    assert call(world, "root", "GET", item).json()["selector"] == "instance-only"
    assert call(world, "root", "PATCH", item, json={"notes": "n"}).json()["notes"] == "n"
    assert call(world, "root", "DELETE", item).status_code == 204
    assert call(world, "root", "GET", item).status_code == 404


# --- caps ----------------------------------------------------------------------------------------


def test_tenant_cap_is_a_422_too_many(world: World) -> None:
    for n in range(MAX_TENANT_SELECTORS):
        make(world, selector=f"t{n:03d}")
    before = rows(world.db)
    response = call(world, "owner", "POST", URL, json={"selector": "one-more"})
    assert_problem(response, 422, "api.dkim_selectors.error.too_many", "selector", "too_many")
    assert rows(world.db) == before


@pytest.mark.parametrize("lang", ["en", "it"])
def test_too_many_exists_in_both_languages(lang: str) -> None:
    key = "api.dkim_selectors.error.too_many"
    assert t(key, lang) != key
