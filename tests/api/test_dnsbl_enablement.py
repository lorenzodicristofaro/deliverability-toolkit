"""M7-05c DNSBL list enablement: `/api/v1/dnsbl-lists`, the `/dnsbl-lists` admin page, and the
enabled ids reaching the `dnsbl` check on the API (domain and free routes) and the CLI.

Through the real app and middleware. Instance-admin only: every tenant role (owner, admin, analyst,
client viewer) gets 403 on list/enable/disable, anonymous 401 (303 for a page load). The routes are
also in the M1-20 tenancy matrix. Run-path tests use the invented lists of
tests/checks/fixtures/dnsbl_test_lists.yaml and a fake DNS backend; no network.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape
from sqlalchemy import select
from typer.testing import CliRunner

from app.api.v1._common import MAX_BODY_BYTES
from app.api.v1.dns_tools import dns_backend
from app.checks.dnsbl import DnsblCheck
from app.checks.dnsbl_schema import DnsblList, load_dnsbl_lists, read_dnsbl_lists
from app.checks.registry import CheckRegistry, load_builtin_checks
from app.cli import check as cli_check
from app.cli.main import app as cli_app
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.dns.types import Resolver
from app.main import create_app
from app.models import DnsblListEnablement, User
from app.repositories import DnsblEnablementRepository
from app.services import checks as checks_service
from app.services import dnsbl_admin
from tests.api.test_domains import KEY, World, _seed, call
from tests.support.dns_backend import fake_backend
from tests.support.dns_zones import FakeServerSet, parse_zones

URL = "/api/v1/dnsbl-lists"
PAGE = "/dnsbl-lists"
TENANT_ROLES = ("owner", "admin", "analyst", "viewer")
HTML = {"Accept": "text/html"}
FORM = {"Content-Type": "application/x-www-form-urlencoded"}
SEED = {x.id: x for x in load_dnsbl_lists()}
FIXTURE = Path(__file__).parent.parent / "checks" / "fixtures" / "dnsbl_test_lists.yaml"
TEST_LISTS = {x.id: x for x in read_dnsbl_lists(FIXTURE, date(2026, 11, 13))}
HOSTILE = '<script>alert("x")</script> "><img src=x onerror=alert(1)>'
ACK = {"policy_acknowledged": True}
BOTH = {"policy_acknowledged": True, "unverified_confirmed": True}
runner = CliRunner()


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_real_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> Resolver:
        raise AssertionError("real resolver requested in a unit test")

    monkeypatch.setattr(cli_check, "resolver_factory", boom)
    monkeypatch.setattr(checks_service, "_default_registry", None)


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
            client.follow_redirects = False
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def rows(w: World) -> list[tuple[Any, ...]]:
    w.db.expire_all()
    w.db.rollback()
    found = w.db.execute(
        select(
            DnsblListEnablement.list_id,
            DnsblListEnablement.enabled_by,
            DnsblListEnablement.policy_acknowledged,
            DnsblListEnablement.unverified_confirmed,
        ).order_by(DnsblListEnablement.list_id)
    ).all()
    w.db.rollback()
    return [tuple(r) for r in found]


def shown(key: str, lang: str = "en") -> str:
    """The translation as it appears in an autoescaped page."""
    return str(escape(t(key, lang)))


def detail(key: str, lang: str = "en") -> dict[str, str]:
    return {"detail": t(key, lang)}


def use_lists(monkeypatch: pytest.MonkeyPatch, *lists: DnsblList) -> None:
    """The admin service and the registered check both see `lists` instead of the seed."""
    monkeypatch.setattr(dnsbl_admin, "load_dnsbl_lists", lambda: lists)
    registry = load_builtin_checks().replacing(DnsblCheck(lists))
    monkeypatch.setattr(checks_service, "_default_registry", registry)


def opt_in(list_id: str, **over: Any) -> DnsblList:
    return dataclasses.replace(TEST_LISTS[list_id], default_enabled=False, **over)


def form_post(w: World, who: str, path: str, fields: dict[str, str], **kw: Any) -> Any:
    headers = {**FORM, **kw.pop("headers", {})}
    return call(w, who, "POST", path, content=urlencode(fields), headers=headers, **kw)


# --- API: roles ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "tenant", "status"),
    [
        ("anon", "a", 401),
        *[(role, "a", 403) for role in TENANT_ROLES],
        ("owner", "b", 403),  # a session in a foreign tenant: still no instance permission
        ("root", "a", 200),
        ("root", "b", 200),  # instance-level: the active tenant plays no part
    ],
)
def test_list_per_role(world: World, who: str, tenant: str, status: int) -> None:
    response = call(world, who, "GET", URL, tenant=tenant)
    assert response.status_code == status
    if status == 403:
        assert response.json() == detail("api.dnsbl_lists.error.forbidden")


@pytest.mark.parametrize("who", ["anon", *TENANT_ROLES])
@pytest.mark.parametrize("verb", ["enable", "disable"])
def test_writes_denied_to_every_tenant_role(world: World, who: str, verb: str) -> None:
    DnsblEnablementRepository(world.db).enable(
        "uribl-multi",
        actor=None,
        policy_acknowledged=True,
        unverified_confirmed=True,
        now=dnsbl_admin._now(),
    )
    world.db.commit()
    before = rows(world)
    response = call(world, who, "POST", f"{URL}/surbl-multi/{verb}", json=BOTH)
    assert response.status_code == (401 if who == "anon" else 403)
    for target in ("uribl-multi", "no-such-list"):
        assert call(world, who, "POST", f"{URL}/{target}/{verb}", json=BOTH).status_code in (
            401,
            403,
        )
    assert rows(world) == before


def test_denied_caller_gets_403_whatever_the_body(world: World) -> None:
    response = call(world, "owner", "POST", f"{URL}/surbl-multi/enable", content=b"{not json")
    assert response.status_code == 403
    assert rows(world) == []


def test_mutation_without_csrf_is_refused(world: World) -> None:
    response = call(world, "root", "POST", f"{URL}/surbl-multi/enable", json=BOTH, csrf=False)
    assert response.status_code == 403
    assert rows(world) == []


# --- API: content and round trip -----------------------------------------------------------------


def test_list_shows_the_seed_data_verbatim(world: World) -> None:
    items = call(world, "root", "GET", URL).json()["items"]
    assert [i["id"] for i in items] == sorted(SEED)
    for item in items:
        lst = SEED[item["id"]]
        assert item["name"] == lst.name and item["zone"] == lst.zone and item["kind"] == lst.kind
        assert item["usage_policy"] == lst.usage_policy  # from seeds/dnsbl.yaml, not code
        assert item["sources"] == list(lst.sources)
        assert item["status"] == lst.status
        assert item["unverified_fields"] == sorted(lst.unverified_fields)
        assert item["verified_on"] == lst.verified_on.isoformat()
        assert item["default_enabled"] is False and item["enabled"] is False
        assert item["enablement"] is None


def test_round_trip(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.dnsbl_lists")
    response = call(world, "root", "POST", f"{URL}/surbl-multi/enable", json=BOTH)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["enabled"] is True and body["id"] == "surbl-multi"
    assert body["enablement"]["enabled_by"] == world.users["root"]
    assert body["enablement"]["policy_acknowledged"] is True
    assert body["enablement"]["unverified_confirmed"] is True
    assert body["enablement"]["enabled_at"] == body["enablement"]["policy_acknowledged_at"]
    assert rows(world) == [("surbl-multi", world.users["root"], True, True)]
    listed = {i["id"]: i["enabled"] for i in call(world, "root", "GET", URL).json()["items"]}
    assert listed == {"spamcop-bl": False, "surbl-multi": True, "uribl-multi": False}
    # re-enabling is accepted and keeps one row
    assert call(world, "root", "POST", f"{URL}/surbl-multi/enable", json=BOTH).status_code == 200
    assert len(rows(world)) == 1
    response = call(world, "root", "POST", f"{URL}/surbl-multi/disable")
    assert response.status_code == 200
    assert response.json()["enabled"] is False and response.json()["enablement"] is None
    assert rows(world) == []
    # disabling what is not enabled succeeds and changes nothing
    assert call(world, "root", "POST", f"{URL}/surbl-multi/disable").status_code == 200
    events = [(r.event, r.actor, r.list_id) for r in caplog.records if hasattr(r, "event")]
    root = world.users["root"]
    assert events == [
        ("dnsbl_lists.enabled", root, "surbl-multi"),
        ("dnsbl_lists.enabled", root, "surbl-multi"),
        ("dnsbl_lists.disabled", root, "surbl-multi"),
    ]


# --- API: acknowledgements and errors ------------------------------------------------------------

ENABLE_REFUSALS = [
    ("no_ack", {}, "api.dnsbl_lists.error.policy_not_acknowledged"),
    ("ack_false", {"policy_acknowledged": False}, "api.dnsbl_lists.error.policy_not_acknowledged"),
    (
        "confirm_without_ack",
        {"unverified_confirmed": True},
        "api.dnsbl_lists.error.policy_not_acknowledged",
    ),
    ("ack_only_unverified", ACK, "api.dnsbl_lists.error.unverified_not_confirmed"),
    (
        "confirm_false",
        {"policy_acknowledged": True, "unverified_confirmed": False},
        "api.dnsbl_lists.error.unverified_not_confirmed",
    ),
]


@pytest.mark.parametrize(
    ("case", "body", "key"), ENABLE_REFUSALS, ids=[c[0] for c in ENABLE_REFUSALS]
)
def test_enable_needs_explicit_acknowledgements(
    world: World, case: str, body: dict[str, Any], key: str
) -> None:
    response = call(world, "root", "POST", f"{URL}/spamcop-bl/enable", json=body)
    assert response.status_code == 422
    assert response.json() == detail(key)
    assert rows(world) == []


def test_verified_list_needs_no_second_confirmation(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_lists(monkeypatch, opt_in("dom"))
    response = call(world, "root", "POST", f"{URL}/dom/enable", json=ACK)
    assert response.status_code == 200
    assert rows(world) == [("dom", world.users["root"], True, False)]


def test_unverified_flag_is_not_stored_for_a_verified_list(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_lists(monkeypatch, opt_in("dom"))
    assert call(world, "root", "POST", f"{URL}/dom/enable", json=BOTH).status_code == 200
    assert rows(world) == [("dom", world.users["root"], True, False)]


MALFORMED = [
    ("not_json", b"{not json", "application/json", 422),
    ("array", b"[]", "application/json", 422),
    ("string_true", b'{"policy_acknowledged": "true"}', "application/json", 422),
    ("int_true", b'{"policy_acknowledged": 1}', "application/json", 422),
    ("unknown_field", b'{"policy_acknowledged": true, "tenant_id": 1}', "application/json", 422),
    ("duplicate_key", b'{"policy_acknowledged": false, "policy_acknowledged": true}', None, 422),
    ("nan", b'{"policy_acknowledged": NaN}', None, 422),
    ("bad_utf8", b'{"policy_acknowledged": "\xff"}', None, 422),
    ("form", b"policy_acknowledged=1", "application/x-www-form-urlencoded", 415),
]


@pytest.mark.parametrize(
    ("case", "raw", "ctype", "status"), MALFORMED, ids=[c[0] for c in MALFORMED]
)
def test_malformed_bodies(
    world: World, case: str, raw: bytes, ctype: str | None, status: int
) -> None:
    headers = {"Content-Type": ctype or "application/json"}
    response = call(world, "root", "POST", f"{URL}/spamcop-bl/enable", content=raw, headers=headers)
    assert response.status_code == status
    assert response.json() == detail("api.error.invalid_request")
    assert rows(world) == []


def test_oversized_body_is_413(world: World) -> None:
    raw = b'{"policy_acknowledged": true, "x": "' + b"a" * MAX_BODY_BYTES + b'"}'
    response = call(world, "root", "POST", f"{URL}/spamcop-bl/enable", content=raw)
    assert response.status_code == 413
    assert rows(world) == []


@pytest.mark.parametrize(
    "list_id", ["no-such-list", "SURBL-MULTI", "surbl-multi%00", "a" * 41, "%2e%2e", "-"]
)
@pytest.mark.parametrize("verb", ["enable", "disable"])
def test_unknown_or_malformed_list_is_404_after_the_permission(
    world: World, list_id: str, verb: str
) -> None:
    response = call(world, "root", "POST", f"{URL}/{list_id}/{verb}", content=b"{not json")
    assert response.status_code == 404
    assert response.json() == detail("api.dnsbl_lists.error.not_found")
    assert call(world, "analyst", "POST", f"{URL}/{list_id}/{verb}", json=BOTH).status_code == 403
    assert rows(world) == []


def test_default_enabled_list_cannot_be_toggled(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    use_lists(monkeypatch, TEST_LISTS["dom"])  # default_enabled is true
    for verb in ("enable", "disable"):
        response = call(world, "root", "POST", f"{URL}/dom/{verb}", json=ACK)
        assert response.status_code == 409
        assert response.json() == detail("api.dnsbl_lists.error.always_enabled")
    item = call(world, "root", "GET", URL).json()["items"][0]
    assert item["default_enabled"] is True and item["enabled"] is True
    assert rows(world) == []


def test_list_without_policy_text_says_so(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    use_lists(monkeypatch, opt_in("ip-v4only"))
    assert TEST_LISTS["ip-v4only"].usage_policy is None
    assert call(world, "root", "GET", URL).json()["items"][0]["usage_policy"] is None
    page = call(world, "root", "GET", PAGE, headers=HTML)
    assert 'data-testid="dnsbl-no-policy"' in page.text
    assert shown("web.dnsbl_lists.no_policy") in page.text


def test_unloadable_list_data_is_503(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> tuple[DnsblList, ...]:
        raise dnsbl_admin.DnsblSchemaError("bad file")

    monkeypatch.setattr(dnsbl_admin, "load_dnsbl_lists", broken)
    response = call(world, "root", "GET", URL)
    assert response.status_code == 503
    assert response.json() == detail("api.dnsbl_lists.error.unavailable")
    assert call(world, "root", "POST", f"{URL}/surbl-multi/enable", json=BOTH).status_code == 503
    assert call(world, "owner", "GET", URL).status_code == 403  # permission still first
    page = call(world, "root", "GET", PAGE, headers=HTML)
    assert page.status_code == 503 and shown("api.dnsbl_lists.error.unavailable") in page.text


@pytest.mark.parametrize("lang", ["en", "it"])
def test_error_keys_exist_in_both_languages(lang: str) -> None:
    for exc in (
        dnsbl_admin.ListsForbidden,
        dnsbl_admin.ListNotFound,
        dnsbl_admin.PolicyNotAcknowledged,
        dnsbl_admin.UnverifiedNotConfirmed,
        dnsbl_admin.AlwaysEnabled,
        dnsbl_admin.ListsUnavailable,
    ):
        assert t(exc.key, lang) != exc.key


def test_italian_error_body(world: World) -> None:
    response = call(
        world,
        "root",
        "POST",
        f"{URL}/spamcop-bl/enable",
        json={},
        headers={"Accept-Language": "it"},
    )
    assert response.json() == detail("api.dnsbl_lists.error.policy_not_acknowledged", "it")


# --- admin page ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("who", "status"), [("anon", 303), *[(r, 403) for r in TENANT_ROLES], ("root", 200)]
)
def test_page_per_role(world: World, who: str, status: int) -> None:
    response = call(world, who, "GET", PAGE, headers=HTML)
    assert response.status_code == status
    if status == 303:
        assert response.headers["location"].startswith("/login?next=")
    if status == 403:
        assert 'data-testid="forbidden"' in response.text
        assert "spamcop" not in response.text
    if status == 200:
        assert response.headers["cache-control"] == "no-store"


def test_page_shows_policy_sources_and_unverified_state(world: World) -> None:
    html = call(world, "root", "GET", PAGE, headers=HTML).text
    for lst in SEED.values():
        assert f'data-list="{lst.id}"' in html
        assert lst.zone in html
        for source in lst.sources:
            assert source in html
    assert html.count('data-testid="badge-unverified"') == len(SEED)
    assert html.count('data-testid="dnsbl-confirm-unverified"') == len(SEED)
    assert html.count('data-testid="dnsbl-policy"') == len(SEED)
    assert "Free use of" in html  # SURBL policy text from the seed (quotes are escaped)


def test_page_escapes_list_data(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    use_lists(monkeypatch, opt_in("ip-both", name=HOSTILE, usage_policy=HOSTILE))
    html = call(world, "root", "GET", PAGE, headers=HTML).text
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("who", TENANT_ROLES)
@pytest.mark.parametrize("verb", ["enable", "disable"])
def test_page_writes_denied_to_tenant_roles(world: World, who: str, verb: str) -> None:
    fields = {"policy_acknowledged": "1", "unverified_confirmed": "1"}
    response = form_post(world, who, f"{PAGE}/surbl-multi/{verb}", fields, headers=HTML)
    assert response.status_code == 403
    assert 'data-testid="forbidden"' in response.text
    assert rows(world) == []


def test_page_anonymous_post_is_401(world: World) -> None:
    response = form_post(world, "anon", f"{PAGE}/surbl-multi/enable", {"policy_acknowledged": "1"})
    assert response.status_code == 401
    assert rows(world) == []


PAGE_REFUSALS = [
    ("nothing", {}, "api.dnsbl_lists.error.policy_not_acknowledged"),
    ("ack_zero", {"policy_acknowledged": "0"}, "api.dnsbl_lists.error.policy_not_acknowledged"),
    ("ack_on", {"policy_acknowledged": "on"}, "api.dnsbl_lists.error.policy_not_acknowledged"),
    ("ack_only", {"policy_acknowledged": "1"}, "api.dnsbl_lists.error.unverified_not_confirmed"),
]


@pytest.mark.parametrize(
    ("case", "fields", "key"), PAGE_REFUSALS, ids=[c[0] for c in PAGE_REFUSALS]
)
def test_page_enable_refusals(world: World, case: str, fields: dict[str, str], key: str) -> None:
    response = form_post(world, "root", f"{PAGE}/surbl-multi/enable", fields, headers=HTML)
    assert response.status_code == 422
    assert shown(key) in response.text
    assert rows(world) == []


def test_page_malformed_forms(world: World) -> None:
    path = f"{PAGE}/surbl-multi/enable"
    repeated = "policy_acknowledged=1&policy_acknowledged=1&unverified_confirmed=1"
    for raw in (repeated, "policy_acknowledged=%ff", "&".join(f"f{i}=1" for i in range(20))):
        response = call(world, "root", "POST", path, content=raw, headers={**FORM, **HTML})
        assert response.status_code == 422, raw
        assert shown("web.dnsbl_lists.error.invalid_form") in response.text
    big = "policy_acknowledged=1&x=" + "a" * 5000
    response = call(world, "root", "POST", path, content=big, headers={**FORM, **HTML})
    assert response.status_code in (403, 413)  # the CSRF form cap may refuse it first
    assert rows(world) == []


def test_page_unknown_list_is_404(world: World) -> None:
    for verb in ("enable", "disable"):
        response = form_post(world, "root", f"{PAGE}/no-such-list/{verb}", {}, headers=HTML)
        assert response.status_code == 404


def test_page_round_trip(world: World) -> None:
    fields = {"policy_acknowledged": "1", "unverified_confirmed": "1"}
    response = form_post(world, "root", f"{PAGE}/uribl-multi/enable", fields)
    assert response.status_code == 303
    assert response.headers["location"] == "/dnsbl-lists?notice=enabled"
    assert rows(world) == [("uribl-multi", world.users["root"], True, True)]
    html = call(world, "root", "GET", f"{PAGE}?notice=enabled", headers=HTML).text
    assert shown("web.dnsbl_lists.flash.enabled") in html
    assert html.count('data-testid="dnsbl-disable"') == 1
    response = form_post(world, "root", f"{PAGE}/uribl-multi/disable", {})
    assert response.status_code == 303
    assert response.headers["location"] == "/dnsbl-lists?notice=disabled"
    assert rows(world) == []


def test_page_is_translated(world: World) -> None:
    html = call(world, "root", "GET", PAGE, headers={**HTML, "Accept-Language": "it"}).text
    assert shown("web.dnsbl_lists.title", "it") in html
    assert shown("web.dnsbl_lists.ack.unverified", "it") in html


# --- run paths: enabled ids reach the check ------------------------------------------------------

RUN_ZONES: dict[str, list[dict[str, Any]]] = {
    "default": [
        {
            "name": "assigned.example.dbl.example.net",
            "type": "A",
            "ttl": 60,
            "rdata": ["127.0.1.2"],
        },
        {"name": "8.8.8.8.bl.example.com", "type": "A", "ttl": 60, "rdata": ["127.0.0.2"]},
    ]
}


@pytest.fixture
def servers(world: World, monkeypatch: pytest.MonkeyPatch) -> FakeServerSet:
    use_lists(monkeypatch, opt_in("ip-both"), opt_in("dom"))
    backend, fake = fake_backend(RUN_ZONES)
    world.client.app.dependency_overrides[dns_backend] = lambda: backend  # type: ignore[attr-defined]
    return fake


def _questions(servers: FakeServerSet) -> list[str]:
    """The DNSBL queries only (`all` also runs SPF, DMARC, DKIM and ESP detection)."""
    zones = (".dbl.example.net", ".bl.example.com")
    return [q.name for q in servers.resolver("default").questions if q.name.endswith(zones)]


def _dnsbl(results: Any) -> dict[str, Any]:
    items = results if isinstance(results, list) else [results]
    return next(r for r in items if r["check_id"] == "dnsbl")


def _codes(result: dict[str, Any]) -> list[str]:
    return [f["code"] for f in result["findings"]]


def _api_runs(w: World) -> list[dict[str, Any]]:
    base = f"/api/v1/domains/{w.domains['assigned']}/checks"
    responses = [
        call(w, "viewer", "POST", f"{base}/dnsbl"),
        call(w, "analyst", "POST", f"{base}/all"),
        call(w, "owner", "POST", base, json={"ids": ["dnsbl"]}),
        call(
            w, "analyst", "POST", "/api/v1/checks/free", json={"name": "8.8.8.8", "ids": ["dnsbl"]}
        ),
    ]
    assert [r.status_code for r in responses] == [200] * 4, [r.text[:200] for r in responses]
    return [_dnsbl(r.json()) for r in responses]


def test_disabled_lists_send_no_query_on_any_api_route(
    world: World, servers: FakeServerSet
) -> None:
    for result in _api_runs(world):
        assert _codes(result) == ["DNSBL_NO_LISTS_APPLICABLE"]
        assert {x["reason"] for x in result["data"]["lists"]} == {"list_disabled"}
    assert _questions(servers) == []


def test_enabled_list_is_queried_per_request(world: World, servers: FakeServerSet) -> None:
    assert call(world, "root", "POST", f"{URL}/dom/enable", json=ACK).status_code == 200
    assert call(world, "root", "POST", f"{URL}/ip-both/enable", json=ACK).status_code == 200
    for result in _api_runs(world):
        assert _codes(result) == ["DNSBL_LISTED"]
    assert "assigned.example.dbl.example.net" in _questions(servers)
    assert "8.8.8.8.bl.example.com" in _questions(servers)
    # disabled again: the next request reads the new state, no query is sent
    assert call(world, "root", "POST", f"{URL}/dom/disable").status_code == 200
    assert call(world, "root", "POST", f"{URL}/ip-both/disable").status_code == 200
    servers.resolver("default").questions.clear()
    for result in _api_runs(world):
        assert _codes(result) == ["DNSBL_NO_LISTS_APPLICABLE"]
    assert _questions(servers) == []


def _cli(monkeypatch: pytest.MonkeyPatch, target: str) -> Any:
    resolver = parse_zones({"zones": RUN_ZONES}).resolver()
    monkeypatch.setattr(cli_check, "resolver_factory", lambda: resolver)
    result = runner.invoke(cli_app, ["check", target, "--only", "dnsbl", "--format", "json"])
    return result, resolver


def test_cli_reads_the_instance_enablement(
    world: World, servers: FakeServerSet, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real loader: DATABASE_URL points at the world's database (fixture env)."""
    result, resolver = _cli(monkeypatch, "8.8.8.8")
    assert result.exit_code == 0 and resolver.questions == []
    assert call(world, "root", "POST", f"{URL}/ip-both/enable", json=ACK).status_code == 200
    result, resolver = _cli(monkeypatch, "8.8.8.8")
    assert result.exit_code == 1, result.output
    assert _codes(json.loads(result.stdout)) == ["DNSBL_LISTED"]
    assert [q.name for q in resolver.questions] == ["8.8.8.8.bl.example.com"]
    assert t("cli.check.notice.dnsbl_enablement_unavailable", "en") not in result.output


def test_cli_without_readable_database_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No fallback: the dnsbl result is `error` (enablement_unavailable), no query, exit 2."""
    use_lists(monkeypatch, opt_in("ip-both"))
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")  # no schema
    result, resolver = _cli(monkeypatch, "8.8.8.8")
    assert result.exit_code == 2
    assert resolver.questions == []
    body = json.loads(result.stdout)
    assert body["status"] == "error"
    assert _codes(body) == ["DNSBL_ENABLEMENT_UNAVAILABLE"]
    assert body["findings"][0]["params"]["reason"] == "enablement_unavailable"
    assert body["data"] == {"lists": [], "reason": "enablement_unavailable"}
    assert t("cli.check.notice.dnsbl_enablement_unavailable", "en") in result.stderr
    assert t("cli.check.notice.dnsbl_enablement_unavailable", "en") not in result.stdout


@pytest.mark.parametrize("loaded", [None, frozenset(), frozenset({"ip-both"})])
def test_cli_loader_seam(monkeypatch: pytest.MonkeyPatch, loaded: frozenset[str] | None) -> None:
    use_lists(monkeypatch, opt_in("ip-both"))
    monkeypatch.setattr(cli_check, "dnsbl_enablement_loader", lambda: loaded)
    result, resolver = _cli(monkeypatch, "8.8.8.8")
    queried = bool(loaded)
    assert [q.name for q in resolver.questions] == (["8.8.8.8.bl.example.com"] if queried else [])
    expected = {None: (2, "error", ["DNSBL_ENABLEMENT_UNAVAILABLE"])}.get(
        loaded,
        (1, "warn", ["DNSBL_LISTED"]) if queried else (0, "info", ["DNSBL_NO_LISTS_APPLICABLE"]),
    )
    body = json.loads(result.stdout)
    assert (result.exit_code, body["status"], _codes(body)) == expected
    assert (t("cli.check.notice.dnsbl_enablement_unavailable", "en") in result.stderr) is (
        loaded is None
    )


def test_cli_unreadable_enablement_leaves_other_checks_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_check, "dnsbl_enablement_loader", lambda: None)
    resolver = parse_zones(
        {
            "zones": {
                "default": [
                    {"name": "example.com", "type": "TXT", "ttl": 60, "rdata": ["v=spf1 -all"]}
                ]
            }
        }
    ).resolver()
    monkeypatch.setattr(cli_check, "resolver_factory", lambda: resolver)
    args = ["check", "example.com", "--only", "spf,dnsbl", "--format", "json"]
    result = runner.invoke(cli_app, args)
    statuses = {r["check_id"]: r["status"] for r in json.loads(result.stdout)}
    assert statuses["dnsbl"] == "error" and statuses["spf"] != "error"
    assert result.exit_code == 2


def test_cli_does_not_read_the_database_without_dnsbl(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> frozenset[str] | None:
        raise AssertionError("enablement read without the dnsbl check")

    monkeypatch.setattr(cli_check, "dnsbl_enablement_loader", boom)
    resolver = parse_zones({"zones": {"default": []}}).resolver()
    monkeypatch.setattr(cli_check, "resolver_factory", lambda: resolver)
    result = runner.invoke(cli_app, ["check", "example.com", "--only", "spf", "--format", "json"])
    assert result.exit_code in (0, 1, 2)


# --- shared helpers (no database) ----------------------------------------------------------------

IP_TARGETS: list[tuple[str, list[str], str | None]] = [
    ("8.8.8.8", ["dnsbl"], "8.8.8.8"),
    ("2001:4860:4860::8888", ["dnsbl"], "2001:4860:4860::8888"),
    ("8.8.8.8", [], None),
    ("8.8.8.8", ["spf"], None),
    ("8.8.8.8", ["dnsbl", "spf"], None),
    ("example.com", ["dnsbl"], None),
    ("1.2.3", ["dnsbl"], None),
    ("8.8.8.08", ["dnsbl"], None),
    ("8.8.8.8%eth0", ["dnsbl"], None),
    ("", ["dnsbl"], None),
    ("\x00", ["dnsbl"], None),
]


@pytest.mark.parametrize(("name", "ids", "expected"), IP_TARGETS)
def test_ip_dnsbl_target(name: str, ids: list[str], expected: str | None) -> None:
    assert checks_service.ip_dnsbl_target(name, ids) == expected


def test_with_dnsbl_enabled_keeps_lists_and_leaves_the_registry_unchanged() -> None:
    base = load_builtin_checks().replacing(DnsblCheck((opt_in("dom"),)))
    configured = checks_service.with_dnsbl_enabled(base, {"dom"})
    assert configured is not base and configured.all_ids() == base.all_ids()
    original, copy = base.get("dnsbl"), configured.get("dnsbl")
    assert isinstance(original, DnsblCheck) and isinstance(copy, DnsblCheck)
    assert copy._lists == original._lists
    assert copy._enabled == frozenset({"dom"}) and original._enabled == frozenset()
    for check_id in base.all_ids():
        if check_id != "dnsbl":
            assert configured.get(check_id) is base.get(check_id)
    without = CheckRegistry()
    for check_id in base.all_ids():
        if check_id != "dnsbl":
            without.register(base.get(check_id))
    assert checks_service.with_dnsbl_enabled(without, {"dom"}) is without
    with pytest.raises(KeyError):
        without.replacing(DnsblCheck(()))
