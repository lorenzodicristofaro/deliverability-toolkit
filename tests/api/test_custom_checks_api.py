"""M5-23 `/api/v1/custom-checks` and the custom checks of a domain run, through the real app and
middleware.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role, per-verb and per-scope tables,
error bodies, the dry run, the domain run wiring and the byte-equal regression of a built-in-only
run against the M3 acceptance fixtures. The resolver is a recorded zone with a query log
(tests/checks/test_acceptance_m3.py); no network.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from functools import partial
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.v1 import checks as api_checks
from app.api.v1 import custom_checks as custom_api
from app.checks.models import CheckContext
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.main import create_app
from app.models import CustomCheck, User
from app.services import custom_checks_admin as admin
from tests.api.test_domains import KEY, World, _seed, call
from tests.checks.test_acceptance_m3 import (
    REGISTERED,
    Make,
    Scripted,
    clock,
    healthy,
    maker,
    via_service,
)
from tests.dns.conftest import _no_network_in_dns_tests  # noqa: F401

URL = "/api/v1/custom-checks"
GLOBAL_Q = "?scope=global"
TEXT = {"en": "Publish the record.", "it": "Pubblica il record."}
D = "assigned.example"
WIRE_KEYS = {"check_id", "target", "status", "findings", "data", "started_at", "duration_ms"}


def check(**overrides: Any) -> dict[str, Any]:
    return {
        "check_key": "acme.verify",
        "name": "Verification record",
        "kind": "dns_exists",
        "definition": {"name": "_acme.{domain}", "rrtype": "TXT"},
        "severity": "medium",
        "remediation_text": dict(TEXT),
        **overrides,
    }


class Rig:
    def __init__(self, world: World) -> None:
        self.world = world
        self.make: Make = maker("healthy")
        self.made: list[Scripted] = []

    def resolver(self) -> Scripted:
        r = self.make()
        self.made.append(r)
        return r

    @property
    def queries(self) -> list[Any]:
        return [q for r in self.made for q in r.queries]


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def rig(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Rig]:
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
    holder: list[Rig] = []
    application.dependency_overrides[api_checks._resolver] = lambda: holder[0].resolver()
    monkeypatch.setattr(api_checks, "CheckContext", partial(CheckContext, clock=clock))
    monkeypatch.setattr(custom_api, "CheckContext", partial(CheckContext, clock=clock))
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            r = Rig(World(client, db, settings, tenant_a, tenant_b, users, domains))
            holder.append(r)
            yield r
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def rows(w: World) -> int:
    w.db.expire_all()
    w.db.rollback()
    count = int(w.db.scalar(select(func.count()).select_from(CustomCheck)) or 0)
    w.db.rollback()
    return count


def make(w: World, who: str = "owner", tenant: str = "a", query: str = "", **kw: Any) -> Any:
    response = call(w, who, "POST", URL + query, json=check(**kw), tenant=tenant)
    assert response.status_code == 201, response.text
    return response.json()


def assert_problem(response: Any, key: str, field: str, reason: str) -> None:
    assert response.status_code == 422, response.text
    assert response.json()["detail"] == {
        "key": key,
        "message": t(key, "en"),
        "field": field,
        "reason": reason,
    }


NOT_FOUND = {"detail": t("api.custom_checks.error.not_found", "en")}


# --- roles, verbs, scopes ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 200),
        ("admin", 200),
        ("analyst", 200),
        ("viewer", 403),
        ("root", 404),
    ],
)
def test_tenant_list_per_role(rig: Rig, who: str, status: int) -> None:
    assert call(rig.world, who, "GET", URL).status_code == status


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
def test_global_list_per_role(rig: Rig, who: str, status: int) -> None:
    response = call(rig.world, who, "GET", URL + GLOBAL_Q)
    assert response.status_code == status


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
def test_tenant_create_per_role(rig: Rig, who: str, status: int) -> None:
    response = call(rig.world, who, "POST", URL, json=check())
    assert response.status_code == status, response.text
    assert rows(rig.world) == (1 if status == 201 else 0)
    if status == 201:
        body = response.json()
        assert (body["scope"], body["kind"]) == ("tenant", "dns_exists")
        assert "tenant_id" not in body and "created_by" not in body


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
def test_global_create_per_role(rig: Rig, who: str, status: int) -> None:
    response = call(rig.world, who, "POST", URL + GLOBAL_Q, json=check())
    assert response.status_code == status
    assert rows(rig.world) == (1 if status == 201 else 0)


@pytest.mark.parametrize(
    ("method", "who", "status"),
    [
        ("GET", "anon", 401),
        ("GET", "owner", 200),
        ("GET", "admin", 200),
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
def test_tenant_item_per_role_and_verb(rig: Rig, method: str, who: str, status: int) -> None:
    w = rig.world
    target = make(w)
    tenant = "b" if who == "b_owner" else "a"
    body = {"enabled": False} if method == "PATCH" else None
    response = call(w, who, method, f"{URL}/{target['id']}", json=body, tenant=tenant)
    assert response.status_code == status, response.text
    if status == 404 and who != "anon":
        assert response.json() == NOT_FOUND
    assert rows(w) == (0 if status == 204 else 1)


@pytest.mark.parametrize(("method", "status"), [("GET", 200), ("PATCH", 200), ("DELETE", 204)])
@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer", "root"])
def test_global_item_per_role_and_verb(rig: Rig, method: str, who: str, status: int) -> None:
    w = rig.world
    target = make(w, "root", query=GLOBAL_Q)
    body = {"enabled": False} if method == "PATCH" else None
    response = call(w, who, method, f"{URL}/{target['id']}{GLOBAL_Q}", json=body)
    assert response.status_code == (status if who == "root" else 403)


@pytest.mark.parametrize("method", ["PATCH", "DELETE"])
def test_tenant_path_cannot_change_a_global_check(rig: Rig, method: str) -> None:
    w = rig.world
    target = make(w, "root", query=GLOBAL_Q)
    body = {"enabled": False} if method == "PATCH" else None
    response = call(w, "owner", method, f"{URL}/{target['id']}", json=body)
    assert response.status_code == 403
    assert call(w, "owner", "GET", f"{URL}/{target['id']}").json() == target


@pytest.mark.parametrize("method", ["GET", "PATCH", "DELETE"])
def test_foreign_unknown_and_out_of_range_ids_answer_alike(rig: Rig, method: str) -> None:
    w = rig.world
    foreign = make(w, "b_owner", tenant="b", name="Secret B check")
    body = {"enabled": True} if method == "PATCH" else None
    answers = [
        call(w, "owner", method, f"{URL}/{target}", json=body)
        for target in (foreign["id"], 999_999_999, 2**31, "abc", "0")
    ]
    assert {r.status_code for r in answers} == {404}
    assert all(r.json() == NOT_FOUND for r in answers)
    assert "Secret B" not in "".join(r.text for r in answers)
    assert call(w, "b_owner", "GET", f"{URL}/{foreign['id']}", tenant="b").json() == foreign


def test_list_never_shows_another_tenant(rig: Rig) -> None:
    w = rig.world
    own = make(w)
    shared = make(w, "root", query=GLOBAL_Q, check_key="shared")
    make(w, "b_owner", tenant="b", check_key="b.secret", name="Secret B check")
    response = call(w, "analyst", "GET", URL)
    assert [i["id"] for i in response.json()["items"]] == [own["id"], shared["id"]]
    assert "Secret B" not in response.text


# --- errors --------------------------------------------------------------------------------------

KEYS = "api.custom_checks.error."


@pytest.mark.parametrize(
    ("body", "key", "field", "reason"),
    [
        (
            check(kind="http_fetch", definition={"url": "https://x.example"}),
            "kind_unavailable",
            "kind",
            "kind_unavailable",
        ),
        (check(name="n" * 201), "name_too_long", "name", "too_long"),
        (
            check(definition={"name": "{domain}.evil.example", "rrtype": "TXT"}),
            "invalid_definition",
            "definition.name",
            "placeholder_position",
        ),
        (check(severity="critical"), "invalid_definition", "severity", "invalid_choice"),
        (check(tenant_id=1), "invalid_definition", "body", "unknown_field"),
        (
            check(remediation_key="api.rules.error.not_found", remediation_text=None),
            "invalid_definition",
            "body",
            "unknown_field",
        ),
        ({}, "invalid_definition", "body", "empty"),
    ],
)
def test_invalid_body_is_422_without_the_value(
    rig: Rig, body: dict[str, Any], key: str, field: str, reason: str
) -> None:
    response = call(rig.world, "owner", "POST", URL, json=body)
    assert_problem(response, KEYS + key, field, reason)
    assert "evil" not in response.text
    assert rows(rig.world) == 0


def test_http_fetch_update_is_422_kind_unavailable(rig: Rig) -> None:
    target = make(rig.world)
    response = call(
        rig.world, "owner", "PATCH", f"{URL}/{target['id']}", json={"kind": "http_fetch"}
    )
    assert_problem(response, KEYS + "kind_unavailable", "kind", "kind_unavailable")


@pytest.mark.parametrize("raw", [b"{", b"[1]", b'{"a": 1, "a": 2}', b'{"x": NaN}'])
def test_malformed_json_is_422(rig: Rig, raw: bytes) -> None:
    response = call(rig.world, "owner", "POST", URL, content=raw)
    assert response.status_code == 422
    assert response.json()["detail"]["key"] == KEYS + "invalid_definition"


def test_non_json_is_415(rig: Rig) -> None:
    headers = {"Content-Type": "text/plain"}
    response = call(rig.world, "owner", "POST", URL, content=b"{}", headers=headers)
    assert response.status_code == 415


def test_invalid_scope_is_422(rig: Rig) -> None:
    response = call(rig.world, "owner", "GET", URL + "?scope=Global")
    assert_problem(response, KEYS + "invalid_definition", "scope", "invalid_choice")


def test_duplicate_key_is_409(rig: Rig) -> None:
    make(rig.world)
    response = call(rig.world, "owner", "POST", URL, json=check())
    assert response.status_code == 409
    assert response.json() == {"detail": t(KEYS + "duplicate", "en")}


def test_denied_caller_gets_403_before_body_validation(rig: Rig) -> None:
    response = call(rig.world, "analyst", "POST", URL, content=b"not json")
    assert response.status_code == 403
    assert response.json() == {"detail": t(KEYS + "scope_forbidden", "en")}


def test_global_key_only_check_round_trips(rig: Rig) -> None:
    body = check(remediation_text=None, remediation_key="api.rules.error.not_found")
    response = call(rig.world, "root", "POST", URL + GLOBAL_Q, json=body)
    assert response.status_code == 201, response.text
    assert response.json()["remediation_key"] == "api.rules.error.not_found"
    unknown = check(remediation_text=None, remediation_key="custom_check.nope.fix", check_key="b")
    response = call(rig.world, "root", "POST", URL + GLOBAL_Q, json=unknown)
    assert_problem(response, KEYS + "invalid_definition", "remediation_key", "unknown_key")


# --- dry run -------------------------------------------------------------------------------------

TEST_URL = URL + "/test"


def dry(w: World, which: str = "assigned", **overrides: Any) -> dict[str, Any]:
    return {
        "domain_id": w.domains[which],
        "kind": "dns_matches",
        "definition": {"name": "{domain}", "rrtype": "TXT", "pattern": "^v=spf1"},
        **overrides,
    }


@pytest.fixture
def evaluator_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    built: list[str] = []
    real = admin.CustomDnsCheck

    def spy(*args: Any, **kwargs: Any) -> Any:
        built.append(kwargs.get("check_key", "?"))
        return real(*args, **kwargs)

    monkeypatch.setattr(admin, "CustomDnsCheck", spy)
    return built


@pytest.mark.parametrize(
    ("who", "status"),
    [
        ("anon", 401),
        ("owner", 200),
        ("admin", 200),
        ("analyst", 200),
        ("viewer", 403),
        ("root", 404),
    ],
)
def test_dry_run_per_role(rig: Rig, evaluator_spy: list[str], who: str, status: int) -> None:
    response = call(rig.world, who, "POST", TEST_URL, json=dry(rig.world))
    assert response.status_code == status, response.text
    if status == 200:
        body = response.json()
        assert set(body) == WIRE_KEYS
        assert (body["check_id"], body["target"], body["status"]) == (
            "custom:tenant:dry-run",
            D,
            "ok",
        )
        assert len(rig.queries) == 1
    else:
        assert evaluator_spy == [] and rig.queries == []
    assert rows(rig.world) == 0


def test_dry_run_is_the_runner_wire_json(rig: Rig) -> None:
    response = call(rig.world, "analyst", "POST", TEST_URL, json=dry(rig.world))
    assert response.headers["content-type"] == "application/json"
    result = json.loads(response.text)
    assert result["started_at"] == "2026-01-01T00:00:00Z" and result["duration_ms"] == 0


@pytest.mark.parametrize("state", ["servfail", "timeout", "refused"])
def test_dry_run_dns_failure_is_error_never_ok(rig: Rig, state: str) -> None:
    rig.make = lambda: Scripted({"default": healthy()}, everywhere=state)
    response = call(rig.world, "owner", "POST", TEST_URL, json=dry(rig.world))
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert body["data"]["reason"] == f"dns_{state}"


def test_dry_run_reports_no_match(rig: Rig) -> None:
    body = dry(rig.world, definition={"name": "{domain}", "rrtype": "TXT", "pattern": "^nope"})
    response = call(rig.world, "owner", "POST", TEST_URL, json=body)
    assert response.json()["status"] == "warn"


@pytest.mark.parametrize("domain_id", ["other", 999_999_999, 2**31, 2**63, True, "1", None])
def test_dry_run_on_an_invisible_domain_is_404_without_dns(
    rig: Rig, evaluator_spy: list[str], domain_id: Any
) -> None:
    w = rig.world
    value = w.domains["other"] if domain_id == "other" else domain_id
    response = call(w, "owner", "POST", TEST_URL, json={**dry(w), "domain_id": value})
    assert response.status_code == 404
    assert response.json() == {"detail": t("api.error.not_found", "en")}
    assert evaluator_spy == [] and rig.queries == []


def test_dry_run_viewer_is_403_even_on_an_assigned_domain(
    rig: Rig, evaluator_spy: list[str]
) -> None:
    response = call(rig.world, "viewer", "POST", TEST_URL, content=b"not even json")
    assert response.status_code == 403
    assert evaluator_spy == [] and rig.queries == []


def test_dry_run_foreign_active_tenant_is_404(rig: Rig, evaluator_spy: list[str]) -> None:
    response = call(rig.world, "analyst", "POST", TEST_URL, json=dry(rig.world), tenant="b")
    assert response.status_code == 404
    assert evaluator_spy == [] and rig.queries == []


@pytest.mark.parametrize(
    ("overrides", "key", "field"),
    [
        ({"kind": "http_fetch", "definition": {}}, "kind_unavailable", "kind"),
        (
            {"definition": {"name": "evil.example", "rrtype": "TXT", "pattern": "x"}},
            "invalid_definition",
            "definition.name",
        ),
        ({"check_key": "x"}, "invalid_definition", "body"),
    ],
)
def test_dry_run_invalid_definition_is_422_without_dns(
    rig: Rig, overrides: dict[str, Any], key: str, field: str
) -> None:
    response = call(rig.world, "owner", "POST", TEST_URL, json=dry(rig.world, **overrides))
    assert response.status_code == 422
    assert (response.json()["detail"]["key"], response.json()["detail"]["field"]) == (
        KEYS + key,
        field,
    )
    assert rig.queries == []


# --- the domain run ------------------------------------------------------------------------------


def run_all(w: World, who: str = "analyst", which: str = "assigned", tenant: str = "a") -> Any:
    response = call(w, who, "POST", f"/api/v1/domains/{w.domains[which]}/checks/all", tenant=tenant)
    assert response.status_code == 200, response.text[:200]
    return response


def test_built_in_only_run_is_byte_equal_to_m3(rig: Rig) -> None:
    expected = via_service(maker("healthy"), REGISTERED, single=False)
    assert run_all(rig.world).text == expected


def test_other_tenants_and_disabled_checks_leave_the_run_byte_equal(rig: Rig) -> None:
    w = rig.world
    make(w, "b_owner", tenant="b", check_key="b.secret", name="Secret B check")
    make(w, check_key="off", enabled=False)
    make(w, "root", query=GLOBAL_Q, check_key="global.off", enabled=False)
    expected = via_service(maker("healthy"), REGISTERED, single=False)
    response = run_all(w)
    assert response.text == expected
    assert "b.secret" not in response.text


def test_run_adds_global_and_own_checks_after_the_built_ins(rig: Rig) -> None:
    w = rig.world
    make(w, "root", query=GLOBAL_Q, check_key="shared")
    make(w, check_key="own", definition={"name": "{domain}", "rrtype": "TXT"})
    make(w, "b_owner", tenant="b", check_key="b.secret")
    results = run_all(w).json()
    assert [r["check_id"] for r in results] == [
        *REGISTERED,
        "custom:global:shared",
        "custom:tenant:own",
    ]
    built_in = json.loads(via_service(maker("healthy"), REGISTERED, single=False))
    assert results[: len(REGISTERED)] == built_in
    by_id = {r["check_id"]: r for r in results}
    assert by_id["custom:global:shared"]["status"] == "warn"  # _acme.assigned.example: nxdomain
    assert by_id["custom:tenant:own"]["status"] == "ok"  # assigned.example has a TXT record


def test_tenant_b_run_has_its_own_checks_only(rig: Rig) -> None:
    w = rig.world
    make(w, check_key="a.secret")
    make(w, "b_owner", tenant="b", check_key="b.own")
    ids = [r["check_id"] for r in run_all(w, "b_owner", "other", "b").json()]
    assert ids == [*REGISTERED, "custom:tenant:b.own"]


def test_viewer_run_on_an_assigned_domain_includes_custom_results(rig: Rig) -> None:
    w = rig.world
    make(w, check_key="own")
    ids = [r["check_id"] for r in run_all(w, "viewer").json()]
    assert ids[-1] == "custom:tenant:own"


def test_custom_check_dns_failure_in_a_run_is_error(rig: Rig) -> None:
    w = rig.world
    make(w, check_key="own")
    zones = {"default": healthy()}
    rig.make = lambda: Scripted(zones, fail={(f"_acme.{D}", "TXT"): "servfail"})
    result = run_all(w).json()[-1]
    assert (result["check_id"], result["status"]) == ("custom:tenant:own", "error")


def test_single_custom_id_is_not_addressable(rig: Rig) -> None:
    w = rig.world
    make(w, check_key="own")
    path = f"/api/v1/domains/{w.domains['assigned']}/checks/custom:tenant:own"
    assert call(w, "owner", "POST", path).status_code == 422
