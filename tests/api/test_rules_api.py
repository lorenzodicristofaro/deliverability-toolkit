"""M5-18 `/api/v1/rules` through the real app and middleware.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role, per-verb and per-scope table, error
bodies, the sample tester's wire format and the effect on the next analysis. The startup seed sync
runs here: these tests need the seeded global rows. No network.
"""

from __future__ import annotations

import json
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
from app.core.safe_regex import MatchResult, SearchFailure
from app.main import create_app
from app.models import User
from app.models.content_rule import ContentRule
from app.repositories import GlobalContentRuleRepository
from app.services import content_rules_admin as admin
from app.services.seed_sync import sync_content_rules
from tests.api.test_domains import KEY, World, _seed, call
from tests.support.socket_guard import db_endpoint, install

URL = "/api/v1/rules"
GLOBAL_Q = "?scope=global"
SEED_KEY = "all_caps_run"
SECRET = "SECRET-PATTERN-5512"
CAPS_TEXT = "THIS TEXT IS SHOUTING ALL OVER THE PLACE"


def rule(**overrides: Any) -> dict[str, Any]:
    return {
        "name": "Rule",
        "kind": "keyword",
        "pattern": "free money",
        "weight": 10,
        "category": "spam",
        "severity": "low",
        "title": "A title",
        **overrides,
    }


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "rules API", db_endpoint())


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
    record = GlobalContentRuleRepository(w.db).get_by_seed_key(SEED_KEY)
    assert record is not None
    return record


def rows(db: Session) -> list[tuple[Any, ...]]:
    db.expire_all()
    db.rollback()
    found = db.execute(
        select(
            ContentRule.id,
            ContentRule.scope,
            ContentRule.tenant_id,
            ContentRule.name,
            ContentRule.pattern,
            ContentRule.weight,
            ContentRule.enabled,
            ContentRule.locally_modified,
        ).order_by(ContentRule.id)
    ).all()
    db.rollback()
    return [tuple(r) for r in found]


def make(w: World, who: str = "owner", tenant: str = "a", **overrides: Any) -> dict[str, Any]:
    response = call(w, who, "POST", URL, json=rule(**overrides), tenant=tenant)
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

READ_OK = {"owner": 200, "admin": 200, "analyst": 200}
WRITERS = ("owner", "admin")


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
    response = call(world, who, "POST", URL, json=rule())
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
    response = call(world, who, "POST", URL + GLOBAL_Q, json=rule())
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
    tenant = "b" if who == "b_owner" else "a"
    response = call(
        world,
        who,
        method,
        f"{URL}/{target['id']}",
        json={"weight": 3} if method == "PATCH" else None,
        tenant=tenant,
    )
    assert response.status_code == status, response.text
    if status not in (200, 204) or method == "GET":
        assert rows(world.db) == before


@pytest.mark.parametrize("method", ["PATCH", "DELETE"])
@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 403),
        ("admin", 403),
        ("analyst", 403),
        ("viewer", 403),
    ],
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
        json={"weight": 3} if method == "PATCH" else None,
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
        json={"weight": 3} if method == "PATCH" else None,
    )
    assert response.status_code == 403
    assert response.json() == {"detail": t("api.rules.error.scope_forbidden", "en")}
    assert rows(world.db) == before


@pytest.mark.parametrize("method", ["GET", "PATCH", "DELETE"])
@pytest.mark.parametrize("who", ["owner", "admin"])
def test_foreign_tenant_rule_is_a_404_for_every_verb(world: World, method: str, who: str) -> None:
    foreign = make(world, "b_owner", tenant="b", name="B private rule")
    before = rows(world.db)
    response = call(
        world,
        who,
        method,
        f"{URL}/{foreign['id']}",
        json={"weight": 3} if method == "PATCH" else None,
    )
    assert response.status_code == 404
    assert response.json() == {"detail": t("api.rules.error.not_found", "en")}
    assert "B private rule" not in response.text
    assert rows(world.db) == before


def test_session_in_a_foreign_tenant_gets_404(world: World) -> None:
    assert call(world, "owner", "GET", URL, tenant="b").status_code == 404
    assert call(world, "owner", "POST", URL, json=rule(), tenant="b").status_code == 404


def test_root_edits_and_deletes_global_rows_on_the_global_path(world: World) -> None:
    created = call(world, "root", "POST", URL + GLOBAL_Q, json=rule(name="Mine")).json()
    item = f"{URL}/{created['id']}{GLOBAL_Q}"
    assert call(world, "root", "GET", item).json()["name"] == "Mine"
    assert call(world, "root", "PATCH", item, json={"weight": 9}).json()["weight"] == 9
    assert call(world, "root", "DELETE", item).status_code == 204
    assert call(world, "root", "GET", item).status_code == 404


def test_instance_admin_flag_adds_nothing_to_a_tenant_owner(world: World) -> None:
    """An owner gets global writes only through the flag, never through the role."""
    target = seeded(world)
    assert call(world, "owner", "GET", f"{URL}/{target.id}").status_code == 200
    assert call(world, "owner", "GET", f"{URL}/{target.id}{GLOBAL_Q}").status_code == 403


@pytest.mark.parametrize("smuggled", ["tenant_id", "scope", "locally_modified", "created_by"])
def test_body_cannot_choose_tenant_or_scope(world: World, smuggled: str) -> None:
    before = rows(world.db)
    response = call(world, "owner", "POST", URL, json=rule(**{smuggled: world.tenant_b}))
    assert_problem(response, 422, "api.rules.error.invalid_field", "body", "unknown_field")
    assert rows(world.db) == before


def test_list_response_never_contains_another_tenant(world: World) -> None:
    make(world, "b_owner", tenant="b", name="B private rule")
    mine = make(world, name="A rule")
    response = call(world, "analyst", "GET", f"{URL}?limit=1000")
    names = {item["name"] for item in response.json()["items"]}
    assert "A rule" in names
    assert "B private rule" not in names
    assert mine["scope"] == "tenant"
    assert "tenant_id" not in mine
    assert "created_by" not in mine


# --- wire format and error bodies ----------------------------------------------------------------


def test_created_rule_round_trip(world: World) -> None:
    created = make(world, name="Round", language="EN", advice="Line one\nLine two")
    assert created["language"] == "en"
    fetched = call(world, "analyst", "GET", f"{URL}/{created['id']}").json()
    assert fetched == created


@pytest.mark.parametrize(
    ("change", "key", "field", "reason"),
    [
        (
            {"kind": "regex", "pattern": f"({SECRET}"},
            "invalid_pattern",
            "pattern",
            "invalid_syntax",
        ),
        ({"pattern": "a" * 1025}, "pattern_too_long", "pattern", "too_long"),
        ({"weight": 101}, "invalid_weight", "weight", "out_of_range"),
        ({"language": "not a language"}, "invalid_language", "language", "invalid_format"),
        ({"category": "Not A Slug"}, "invalid_field", "category", "invalid_format"),
        ({"name": "x" * 201}, "invalid_field", "name", "too_long"),
        ({"name": "a\x00b"}, "invalid_field", "name", "nul"),
        ({"pattern": "a\x00b"}, "invalid_pattern", "pattern", "nul"),
        ({"title": "a\x00b"}, "invalid_field", "title", "nul"),
        ({"advice": "a\x00b"}, "invalid_field", "advice", "nul"),
        ({"category": "a\x00b"}, "invalid_field", "category", "nul"),
        ({"language": "e\x00"}, "invalid_language", "language", "nul"),
    ],
)
def test_validation_errors_have_the_problem_shape(
    world: World, change: dict[str, Any], key: str, field: str, reason: str
) -> None:
    before = rows(world.db)
    response = call(world, "owner", "POST", URL, json=rule(**change))
    assert_problem(response, 422, f"api.rules.error.{key}", field, reason)
    assert SECRET not in response.text
    assert rows(world.db) == before


@pytest.mark.parametrize(
    ("raw", "field"),
    [
        (b'{"name": "a\\ud800b"}', "name"),
        (b'{"pattern": "\\udfff"}', "pattern"),
        (b'{"title": "\\ud83d"}', "title"),
        (b'{"advice": "x\\ud800"}', "advice"),
        (b'{"category": "\\ud800"}', "category"),
        (b'{"language": "\\ud800"}', "language"),
    ],
)
def test_lone_surrogates_never_reach_the_database(world: World, raw: bytes, field: str) -> None:
    target = make(world)
    response = call(world, "owner", "PATCH", f"{URL}/{target['id']}", content=raw)
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["field"] == field
    assert response.json()["detail"]["reason"] == "surrogate"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"{", "malformed_json"),
        (b"\xff\xfe", "malformed_json"),
        (b'{"a": 1, "a": 2}', "malformed_json"),
        (b'{"weight": NaN}', "malformed_json"),
        (b"[]", "not_an_object"),
        (b'"text"', "not_an_object"),
        (b"null", "not_an_object"),
        (b'{"nope": 1}', "unknown_field"),
    ],
)
def test_malformed_bodies(world: World, raw: bytes, reason: str) -> None:
    response = call(world, "owner", "POST", URL, content=raw)
    assert_problem(response, 422, "api.rules.error.invalid_field", "body", reason)


def test_deeply_nested_json_is_a_clean_422(world: World) -> None:
    response = call(world, "owner", "POST", URL, content=b"[" * (MAX_BODY_BYTES - 1))
    assert_problem(response, 422, "api.rules.error.invalid_field", "body", "malformed_json")


def test_not_json_is_415(world: World) -> None:
    response = call(
        world, "owner", "POST", URL, content=b"x", headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 415


def test_oversized_body_is_413_for_a_permitted_caller(world: World) -> None:
    raw = json.dumps(rule(advice="x" * (MAX_BODY_BYTES + 1))).encode()
    assert call(world, "owner", "POST", URL, content=raw).status_code == 413


@pytest.mark.parametrize("path", [URL, f"{URL}/test"])
def test_denied_caller_gets_403_whatever_the_body(world: World, path: str) -> None:
    raw = b"x" * (MAX_BODY_BYTES + 1)
    assert call(world, "analyst", "POST", path + GLOBAL_Q, content=raw).status_code == 403


@pytest.mark.parametrize("value", ["nope", "GLOBAL", "", "global%00"])
def test_unknown_scope_is_rejected(world: World, value: str) -> None:
    response = call(world, "owner", "GET", f"{URL}?scope={value}")
    assert_problem(response, 422, "api.rules.error.invalid_field", "scope", "invalid_choice")


def test_anonymous_with_a_bad_scope_is_401(world: World) -> None:
    assert call(world, "anon", "GET", f"{URL}?scope=nope").status_code == 401


@pytest.mark.parametrize("query", ["limit=abc", "limit=1001", "offset=-1", "limit=%00"])
def test_bad_paging_is_rejected(world: World, query: str) -> None:
    assert call(world, "owner", "GET", f"{URL}?{query}").status_code == 422


@pytest.mark.parametrize("raw_id", ["abc", "0", "-1", "1.5", "%00", "2147483648"])
def test_malformed_path_ids_are_404(world: World, raw_id: str) -> None:
    assert call(world, "owner", "GET", f"{URL}/{raw_id}").status_code == 404


def test_get_on_the_test_route_is_not_an_id(world: World) -> None:
    assert call(world, "owner", "GET", f"{URL}/test").status_code == 404


def test_seeded_delete_is_409_and_duplicate_override_is_409(world: World) -> None:
    target = seeded(world)
    response = call(world, "root", "DELETE", f"{URL}/{target.id}{GLOBAL_Q}")
    assert response.status_code == 409
    assert response.json() == {"detail": t("api.rules.error.seeded_delete", "en")}
    make(world, seed_key=SEED_KEY)
    response = call(world, "owner", "POST", URL, json=rule(seed_key=SEED_KEY))
    assert response.status_code == 409
    assert response.json() == {"detail": t("api.rules.error.seed_key_taken", "en")}


# --- seed sync and the next analysis -------------------------------------------------------------


def test_api_edit_survives_the_seed_sync(world: World) -> None:
    target = seeded(world)
    response = call(world, "root", "PATCH", f"{URL}/{target.id}{GLOBAL_Q}", json={"weight": 88})
    assert response.status_code == 200
    assert response.json()["locally_modified"] is True
    sync_content_rules(world.db)
    world.db.commit()
    assert seeded(world).weight == 88


def _analyze(world: World) -> list[dict[str, Any]]:
    response = call(world, "owner", "POST", "/api/v1/content/analyze", json={"text": CAPS_TEXT})
    assert response.status_code == 200, response.text
    results: list[dict[str, Any]] = response.json()["rules"]["facts"]["results"]
    return results


def _matched(world: World, *, seed_key: str | None = None, name: str | None = None) -> bool:
    return any(
        r["status"] == "matched"
        and (seed_key is None or r["seed_key"] == seed_key)
        and (name is None or r["name"] == name)
        for r in _analyze(world)
    )


def test_global_change_takes_effect_on_the_next_analysis(world: World) -> None:
    target = seeded(world)
    assert target.enabled is False
    assert not _matched(world, seed_key=SEED_KEY)
    item = f"{URL}/{target.id}{GLOBAL_Q}"
    assert call(world, "root", "PATCH", item, json={"enabled": True}).status_code == 200
    assert _matched(world, seed_key=SEED_KEY)
    assert call(world, "root", "PATCH", item, json={"enabled": False}).status_code == 200
    assert not _matched(world, seed_key=SEED_KEY)


def test_tenant_rule_takes_effect_on_the_next_analysis(world: World) -> None:
    created = make(world, name="Shouting", pattern="SHOUTING")
    assert _matched(world, name="Shouting")
    item = f"{URL}/{created['id']}"
    assert call(world, "owner", "PATCH", item, json={"pattern": "absent"}).status_code == 200
    assert not _matched(world, name="Shouting")
    assert call(world, "owner", "DELETE", item).status_code == 204
    assert not _matched(world, name="Shouting")


# --- POST /rules/test ----------------------------------------------------------------------------

TEST_URL = f"{URL}/test"


def sample_body(**overrides: Any) -> dict[str, Any]:
    return {"kind": "regex", "pattern": "wor", "sample": "hello world", **overrides}


@pytest.mark.parametrize(
    ("who", "query", "status"),
    [
        ("anon", "", 401),
        ("owner", "", 200),
        ("admin", "", 200),
        ("analyst", "", 403),
        ("viewer", "", 403),
        ("root", "", 404),
        ("owner", GLOBAL_Q, 403),
        ("admin", GLOBAL_Q, 403),
        ("analyst", GLOBAL_Q, 403),
        ("viewer", GLOBAL_Q, 403),
        ("root", GLOBAL_Q, 200),
    ],
)
def test_sample_test_authorization(world: World, who: str, query: str, status: int) -> None:
    response = call(world, who, "POST", TEST_URL + query, json=sample_body())
    assert response.status_code == status, response.text


def test_sample_test_wire_format(world: World) -> None:
    response = call(world, "owner", "POST", TEST_URL, json=sample_body())
    assert response.json() == {
        "outcome": "matched",
        "timed_out": False,
        "truncated": False,
        "matches": [{"start": 6, "end": 9, "snippet": "hello world"}],
        "reason": None,
        "key": None,
        "message": None,
    }


def test_sample_test_no_match(world: World) -> None:
    body = call(world, "owner", "POST", TEST_URL, json=sample_body(pattern="zzz")).json()
    assert (body["outcome"], body["timed_out"], body["matches"]) == ("no_match", False, [])


def test_sample_test_invalid_pattern_does_not_echo(world: World) -> None:
    response = call(world, "owner", "POST", TEST_URL, json=sample_body(pattern=f"({SECRET}"))
    assert response.status_code == 200
    body = response.json()
    assert (body["outcome"], body["reason"]) == ("invalid", "invalid_syntax")
    assert body["key"] == "api.rules.error.invalid_pattern"
    assert body["message"] == t("api.rules.error.invalid_pattern", "en")
    assert SECRET not in response.text


def test_catastrophic_pattern_reports_timed_out(world: World) -> None:
    body = call(
        world,
        "owner",
        "POST",
        TEST_URL,
        json=sample_body(pattern="(a+)+$", sample="a" * 40 + "!"),
    ).json()
    assert body["outcome"] == "timed_out"
    assert body["timed_out"] is True
    assert body["matches"] == []
    assert body["message"] == t("api.rules.error.timed_out", "en")


@pytest.mark.parametrize(
    ("failure", "outcome"),
    [(SearchFailure.BUSY, "busy"), (SearchFailure.WORKER_FAILED, "error")],
)
def test_no_verdict_outcomes_are_200_and_not_timed_out(
    world: World, monkeypatch: pytest.MonkeyPatch, failure: SearchFailure, outcome: str
) -> None:
    result = MatchResult((), False, False, failure)
    monkeypatch.setattr(admin, "search_all", lambda *_a, **_k: result)
    response = call(world, "owner", "POST", TEST_URL, json=sample_body())
    assert response.status_code == 200
    body = response.json()
    assert (body["outcome"], body["timed_out"], body["matches"]) == (outcome, False, [])
    assert body["message"]


def test_sample_over_the_cap_is_a_422(world: World) -> None:
    response = call(
        world, "owner", "POST", TEST_URL, json=sample_body(sample="x" * (32 * 1024 + 1))
    )
    assert_problem(response, 422, "api.rules.error.sample_too_large", "sample", "too_long")


def test_body_over_the_limit_is_a_413(world: World) -> None:
    response = call(
        world, "owner", "POST", TEST_URL, json=sample_body(sample="x" * (MAX_BODY_BYTES + 1))
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    ("raw", "field", "reason"),
    [
        (b'{"kind":"regex","pattern":"a","sample":"a\\u0000"}', "sample", "nul"),
        (b'{"kind":"regex","pattern":"a","sample":"\\ud800"}', "sample", "surrogate"),
        (b'{"kind":"regex","pattern":"a","sample":"a","scope":"global"}', "body", "unknown_field"),
    ],
)
def test_sample_test_rejects_bad_text(world: World, raw: bytes, field: str, reason: str) -> None:
    response = call(world, "owner", "POST", TEST_URL, content=raw)
    assert_problem(response, 422, "api.rules.error.invalid_field", field, reason)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"kind":"regex","pattern":"a\\u0000","sample":"a"}',
        b'{"kind":"regex","pattern":"\\ud800","sample":"a"}',
    ],
)
def test_sample_test_pattern_with_bad_text_is_invalid(world: World, raw: bytes) -> None:
    response = call(world, "owner", "POST", TEST_URL, content=raw)
    assert response.status_code == 200
    assert response.json()["outcome"] == "invalid"


def test_sample_test_stores_nothing(world: World) -> None:
    before = rows(world.db)
    assert call(world, "owner", "POST", TEST_URL, json=sample_body()).status_code == 200
    assert rows(world.db) == before
