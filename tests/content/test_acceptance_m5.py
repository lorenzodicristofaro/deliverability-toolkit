"""M5 acceptance (M5-25): content analysis, rules admin and custom checks across the surfaces.

Everything here is offline: sockets are blocked (only the test database is reachable), every
attempted connection is recorded and must be empty, and DNS is a recorded zone whose query log
must stay empty for content analysis. Timing assertions are deliberately generous: they bound a
hung run, they never assert speed. Corpus facts: the three seeded content rules are all disabled
(seeds/content_rules.yaml), so a rule that matches here is the one the test created.
"""

from __future__ import annotations

import json
import re
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from app.api.v1 import checks as api_checks
from app.api.v1.domain_esps import esp_profiles
from app.cli import content as cli_content
from app.cli.main import app as cli_app
from app.core import i18n
from app.core.config import Settings
from app.core.custom_check_schema import KindUnavailable, parse_definition
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import CustomCheck, User
from app.services.content_analysis import ContentAnalysis, ContentInput, analyze_content
from tests.api.test_domains import KEY, World, _seed, call
from tests.checks.test_acceptance_m3 import DOMAIN_ALL, Scripted, healthy, no_esp_profiles, txt
from tests.support.socket_guard import db_endpoint, install, resolved_addresses

RULES = "/api/v1/rules"
GLOBAL_Q = "?scope=global"
ANALYZE = "/api/v1/content/analyze"
CUSTOM = "/api/v1/custom-checks"
D = "assigned.example"
runner = CliRunner()

# A pattern that backtracks exponentially on `"a" * 40 + "!"` (the M5-03 guard's reference case).
CATASTROPHIC = "(a+)+$"
CATASTROPHIC_TEXT = "a" * 40 + "!"
# Far above the 1 s per-rule timeout and the 10 s rules budget: it only catches a hung run.
GENEROUS_WALL_S = 60.0


# --- fixtures ------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def attempts(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Block sockets (except the test database); record every connect, resolve or send."""
    install(monkeypatch, "the M5 acceptance suite", db_endpoint())
    endpoint = db_endpoint()
    allowed = resolved_addresses(endpoint)
    seen: list[Any] = []

    def is_db_address(address: Any) -> bool:
        return (
            isinstance(address, tuple)
            and len(address) >= 2
            and (str(address[0]).lower(), address[1]) in allowed
        )

    def is_db_host(host: Any) -> bool:
        return endpoint is not None and isinstance(host, str) and host.lower() == endpoint[0]

    def recording(name: str, original: Any, is_db: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not is_db(args):
                seen.append((name, args[1:] if name != "getaddrinfo" else args))
            return original(*args, **kwargs)  # the guard still refuses it

        return wrapper

    def address_at_1(args: Any) -> bool:
        return len(args) > 1 and is_db_address(args[1])

    for method in ("connect", "connect_ex", "sendto"):
        original = getattr(socket.socket, method)
        monkeypatch.setattr(
            socket.socket,
            method,
            recording(method, original, address_at_1 if method != "sendto" else lambda a: False),
        )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        recording("getaddrinfo", socket.getaddrinfo, lambda a: bool(a) and is_db_host(a[0])),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        recording("gethostbyname", socket.gethostbyname, lambda a: bool(a) and is_db_host(a[0])),
    )
    return seen


class Zone:
    """The resolver of the app under test: a recorded zone with a query log."""

    def __init__(self) -> None:
        self.zones: dict[str, list[dict[str, Any]]] = {}
        self.fail: dict[tuple[str, str], str] | None = None
        self.made: list[Scripted] = []
        self.reset()

    def reset(self, extra: list[dict[str, Any]] | None = None) -> None:
        self.zones = {"default": [*healthy(), *(extra or [])]}

    def resolver(self) -> Scripted:
        r = Scripted(self.zones, self.fail)
        self.made.append(r)
        return r

    @property
    def queries(self) -> list[Any]:
        return [q for r in self.made for q in r.queries]


@pytest.fixture
def zone() -> Zone:
    return Zone()


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, zone: Zone) -> Iterator[World]:
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
    application.dependency_overrides[api_checks._resolver] = zone.resolver
    application.dependency_overrides[esp_profiles] = no_esp_profiles
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- helpers -------------------------------------------------------------------------------------


def rule(**overrides: Any) -> dict[str, Any]:
    return {
        "name": "Acceptance rule",
        "kind": "keyword",
        "pattern": "zebraword",
        "weight": 10,
        "category": "spam",
        "severity": "low",
        "title": "A title",
        **overrides,
    }


def make_rule(
    w: World, who: str = "owner", tenant: str = "a", query: str = "", **overrides: Any
) -> dict[str, Any]:
    response = call(w, who, "POST", RULES + query, json=rule(**overrides), tenant=tenant)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def analyze(w: World, who: str = "owner", tenant: str = "a", **body: Any) -> dict[str, Any]:
    response = call(
        w, who, "POST", ANALYZE, json=body or {"text": "get zebraword now"}, tenant=tenant
    )
    assert response.status_code == 200, response.text
    parsed: dict[str, Any] = response.json()
    return parsed


def matched(analysis: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["name"]: r for r in analysis["rules"]["facts"]["results"] if r["status"] == "matched"}


def score(analysis: dict[str, Any]) -> int:
    value: int = analysis["rules"]["facts"]["score"]
    return value


# --- 1. rules are editable without a redeploy ----------------------------------------------------


def test_tenant_rule_create_edit_weight_disable_without_restart(world: World) -> None:
    assert matched(analyze(world)) == {}  # nothing enabled matches yet

    created = make_rule(world, "admin")  # a tenant admin, not only the owner
    found = analyze(world)
    assert set(matched(found)) == {"Acceptance rule"}
    assert score(found) == 10

    item = f"{RULES}/{created['id']}"
    assert call(world, "admin", "PATCH", item, json={"weight": 40}).status_code == 200
    assert score(analyze(world)) == 40

    assert call(world, "admin", "PATCH", item, json={"enabled": False}).status_code == 200
    gone = analyze(world)
    assert matched(gone) == {}
    assert score(gone) == 0

    assert call(world, "admin", "PATCH", item, json={"enabled": True}).status_code == 200
    assert score(analyze(world)) == 40  # back, still no restart or re-seed between steps


def test_global_rule_is_visible_to_two_tenants_and_a_tenant_rule_to_one(world: World) -> None:
    shared = make_rule(world, "root", query=GLOBAL_Q, name="Shared rule", pattern="zebraword")
    own = make_rule(world, "owner", name="Tenant A only", pattern="zebraword", weight=7)

    a = matched(analyze(world, "owner", "a"))
    b = matched(analyze(world, "b_owner", "b"))
    assert set(a) == {"Shared rule", "Tenant A only"}
    assert set(b) == {"Shared rule"}  # the tenant A rule is invisible to tenant B

    # tenant B cannot see, read or change tenant A's rule by id either
    foreign = f"{RULES}/{own['id']}"
    assert call(world, "b_owner", "GET", foreign, tenant="b").status_code == 404
    assert (
        call(world, "b_owner", "PATCH", foreign, json={"weight": 1}, tenant="b").status_code == 404
    )
    listing = call(world, "b_owner", "GET", RULES, tenant="b").json()
    assert "Tenant A only" not in json.dumps(listing)

    # and the other way round: a tenant B rule never reaches tenant A
    theirs = make_rule(
        world, "b_owner", tenant="b", name="Tenant B only", pattern="zebraword", weight=0
    )
    assert "Tenant B only" in matched(analyze(world, "b_owner", "b"))
    assert "Tenant B only" not in matched(analyze(world, "owner", "a"))
    assert call(world, "owner", "GET", f"{RULES}/{theirs['id']}").status_code == 404

    # a global edit by the instance admin reaches both tenants on their next analysis
    item = f"{RULES}/{shared['id']}{GLOBAL_Q}"
    assert call(world, "root", "PATCH", item, json={"weight": 55}).status_code == 200
    assert score(analyze(world, "b_owner", "b")) == 55
    assert call(world, "root", "PATCH", item, json={"enabled": False}).status_code == 200
    assert set(matched(analyze(world, "owner", "a"))) == {"Tenant A only"}
    assert set(matched(analyze(world, "b_owner", "b"))) == {"Tenant B only"}

    # a tenant admin cannot write the global scope
    denied = call(world, "owner", "POST", RULES + GLOBAL_Q, json=rule(name="No"))
    assert denied.status_code == 403


# --- 2. the regex timeout is enforced ------------------------------------------------------------


def test_catastrophic_rule_is_cut_off_in_the_sample_tester(world: World) -> None:
    started = time.monotonic()
    response = call(
        world,
        "owner",
        "POST",
        f"{RULES}/test",
        json={"kind": "regex", "pattern": CATASTROPHIC, "sample": CATASTROPHIC_TEXT},
    )
    assert time.monotonic() - started < GENEROUS_WALL_S
    body = response.json()
    assert response.status_code == 200
    assert (body["outcome"], body["timed_out"], body["matches"]) == ("timed_out", True, [])
    assert body["message"] == t("api.rules.error.timed_out", "en")


def test_catastrophic_rule_in_a_full_analysis_is_an_error_and_the_rest_still_ran(
    world: World,
) -> None:
    make_rule(world, name="Keyword", pattern="zebraword", weight=20)
    make_rule(world, name="Catastrophic", kind="regex", pattern=CATASTROPHIC, weight=90)
    make_rule(world, name="Plain regex", kind="regex", pattern="zeb+raword", weight=5)

    started = time.monotonic()
    found = analyze(world, text=CATASTROPHIC_TEXT + " zebraword")
    assert time.monotonic() - started < GENEROUS_WALL_S

    by_name = {r["name"]: r for r in found["rules"]["facts"]["results"]}
    assert (by_name["Catastrophic"]["status"], by_name["Catastrophic"]["issue"]) == (
        "error",
        "timeout",
    )
    assert by_name["Keyword"]["status"] == "matched"
    assert by_name["Plain regex"]["status"] == "matched"  # a fresh worker ran the rest
    assert found["rules"]["status"] == "error"
    assert found["status"] == "error"  # never ok when a rule could not be evaluated
    assert found["complete"] is False
    assert found["rules"]["facts"]["error_rules"] == 1
    assert any(f["code"] == "CONTENT_RULE_ERROR" for f in found["findings"])


# --- 3. the surfaces are equal, and content analysis is offline ----------------------------------

HTML = (
    "<p>zebraword <a href='http://bit.ly/abc'>https://paypal.example/login</a> "
    "<a href='http://203.0.113.9/x'>click</a> <a href='https://news.example/'>news</a></p>"
)
EML = (
    "From: Alice <alice@example.com>\r\nTo: bob@example.net\r\nSubject: zebraword offer\r\n"
    "Message-ID: <m1@example.com>\r\nMIME-Version: 1.0\r\n"
    "List-Unsubscribe: <https://example.com/u/1>, <mailto:u@example.com>\r\n"
    "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    "Content-Type: text/html; charset=utf-8\r\n\r\n"
    "<p>zebraword <a href='http://bit.ly/abc'>go</a></p>\r\n"
)
CASES = {
    "json": {"html": HTML, "text": "zebraword plain text", "subject": "FREE!!! zebraword"},
    "eml": {"eml": EML},
}


def _service(w: World, who: str, content: ContentInput) -> str:
    w.db.rollback()
    return analyze_content(TenantContext(w.tenant_a, w.users[who]), w.db, content).model_dump_json()


def _cli(w: World, who: str, case: str, tmp_path: Path) -> Any:
    args = ["content", "--tenant-id", str(w.tenant_a), "--user-id", str(w.users[who]), "--json"]
    for name, value in CASES[case].items():
        if name == "subject":  # a literal, unlike the others, which are file paths
            args += ["--subject", value]
            continue
        path = tmp_path / f"{case}.{name}"
        path.write_bytes(value.encode())
        args += [f"--{name}", str(path)]
    return runner.invoke(cli_app, args)


def _content_input(case: str) -> ContentInput:
    data = CASES[case]
    return ContentInput(
        html=data.get("html"),
        text=data.get("text"),
        subject=data.get("subject"),
        eml=data["eml"].encode() if "eml" in data else None,
    )


def _ui(w: World, who: str, case: str) -> str:
    response = call(
        w,
        who,
        "POST",
        "/tools/content",
        content=urlencode(CASES[case]).encode(),
        headers={"Accept": "text/html", "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200, response.text[:300]
    return response.text


@pytest.mark.parametrize("case", ["json", "eml"])
def test_service_api_cli_are_byte_equal_and_the_ui_shows_the_same_status_and_codes(
    world: World, zone: Zone, attempts: list[Any], tmp_path: Path, case: str
) -> None:
    make_rule(world, name="Keyword", pattern="zebraword")
    if case == "eml":
        api = call(
            world,
            "analyst",
            "POST",
            ANALYZE,
            content=EML.encode(),
            headers={"Content-Type": "message/rfc822"},
        )
    else:
        api = call(world, "analyst", "POST", ANALYZE, json=CASES[case])
    assert api.status_code == 200, api.text

    service = _service(world, "analyst", _content_input(case))
    cli = _cli(world, "analyst", case, tmp_path)
    assert api.content == service.encode()
    assert cli.stdout_bytes == api.content + b"\n"
    analysis = ContentAnalysis.model_validate_json(api.content)
    assert cli.exit_code == cli_content.exit_code(analysis)

    page = _ui(world, "analyst", case)
    ui_status = re.search(r'data-testid="content-result" data-status="([a-z_]+)"', page)
    assert ui_status is not None and ui_status.group(1) == analysis.status
    assert re.findall(r'<li data-code="([A-Z_]+)"', page) == [f.code for f in analysis.findings]
    sections = dict(re.findall(r'<tr data-section="([a-z]+)" data-status="([a-z_]+)"', page))
    expected = {
        key: sec.status
        for key in ("message", "body", "links", "subject", "unsubscribe", "rules")
        if (sec := getattr(analysis, key)) is not None
    }
    assert sections == expected

    # the analysis really looked at links and rules, and still touched no DNS and no socket
    codes = {f.code for f in analysis.findings}
    assert "CONTENT_URL_SHORTENER" in codes
    assert "CONTENT_RULE_MATCH" in codes
    assert zone.queries == []
    assert attempts == []


def test_a_run_without_eml_cannot_evaluate_list_unsubscribe(
    world: World, attempts: list[Any]
) -> None:
    found = analyze(world, text="zebraword", subject="hello")
    assert found["unsubscribe"]["status"] == "not_evaluated"
    assert found["complete"] is False
    assert "unsubscribe" in found["not_evaluated_sections"]
    assert attempts == []


def test_the_guard_itself_blocks_connections(attempts: list[Any]) -> None:
    with pytest.raises(AssertionError, match="network access"):
        socket.create_connection(("192.0.2.1", 80), timeout=1)


# --- 4. custom checks: DNS kinds end to end, http_fetch refused everywhere -----------------------


def make_check(w: World, who: str = "owner", tenant: str = "a", **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "check_key": "acme.verify",
        "name": "Verification record",
        "kind": "dns_exists",
        "definition": {"name": "_acme.{domain}", "rrtype": "TXT"},
        "severity": "medium",
        "remediation_text": {"en": "Publish the record.", "it": "Pubblica il record."},
        **overrides,
    }
    response = call(w, who, "POST", CUSTOM, json=body, tenant=tenant)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def run_all(w: World, who: str = "analyst") -> dict[str, dict[str, Any]]:
    response = call(w, who, "POST", f"/api/v1/domains/{w.domains['assigned']}/checks/all")
    assert response.status_code == 200, response.text[:300]
    results: list[dict[str, Any]] = response.json()
    assert [r["check_id"] for r in results[: len(DOMAIN_ALL)]] == list(DOMAIN_ALL)
    return {r["check_id"]: r for r in results[len(DOMAIN_ALL) :]}


DNS_CASES = [
    ("exists_ok", "dns_exists", {"name": "_acme.{domain}", "rrtype": "TXT"}, "ok", None),
    (
        "exists_missing",
        "dns_exists",
        {"name": "_nope.{domain}", "rrtype": "TXT"},
        "warn",
        "nxdomain",
    ),
    (
        "matches_ok",
        "dns_matches",
        {"name": "_acme.{domain}", "rrtype": "TXT", "pattern": "^verify=[a-z]+$"},
        "ok",
        None,
    ),
    (
        "matches_no",
        "dns_matches",
        {"name": "_acme.{domain}", "rrtype": "TXT", "pattern": "^verify=[0-9]+$"},
        "warn",
        "no_match",
    ),
    (
        "range_ok",
        "dns_value_range",
        {"name": "_limit.{domain}", "rrtype": "TXT", "min": 1, "max": 10},
        "ok",
        None,
    ),
    (
        "range_out",
        "dns_value_range",
        {"name": "_limit.{domain}", "rrtype": "TXT", "min": 1, "max": 5},
        "warn",
        "out_of_range",
    ),
]


@pytest.mark.parametrize(
    ("key", "kind", "definition", "status", "reason"),
    DNS_CASES,
    ids=[c[0] for c in DNS_CASES],
)
def test_dns_kinds_end_to_end_with_a_fake_dns_backend(
    world: World,
    zone: Zone,
    key: str,
    kind: str,
    definition: dict[str, Any],
    status: str,
    reason: str | None,
) -> None:
    zone.reset([txt(f"_acme.{D}", "verify=abc"), txt(f"_limit.{D}", "7")])
    make_check(world, check_key=key, kind=kind, definition=definition)
    result = run_all(world)[f"custom:tenant:{key}"]
    assert result["status"] == status
    if reason is None:
        assert result["findings"] == []
    else:
        (found,) = result["findings"]
        assert found["code"] == "CUSTOM_CHECK_FAILED"
        assert found["params"]["reason"] == reason
        assert found["params"]["remediation_text"]["en"] == "Publish the record."
    assert zone.queries  # it went through the fake backend


@pytest.mark.parametrize("state", ["servfail", "timeout", "refused"])
def test_dns_failure_in_a_custom_check_is_error_never_ok(
    world: World, zone: Zone, state: str
) -> None:
    zone.reset([txt(f"_acme.{D}", "verify=abc")])
    zone.fail = {(f"_acme.{D}", "TXT"): state}
    make_check(world, check_key="own")
    result = run_all(world)["custom:tenant:own"]
    assert result["status"] == "error"
    assert result["data"]["reason"] == f"dns_{state}"


def test_viewer_sees_custom_results_but_never_the_pattern_or_range(
    world: World, zone: Zone
) -> None:
    zone.reset([txt(f"_acme.{D}", "verify=abc"), txt(f"_limit.{D}", "7")])
    make_check(
        world,
        check_key="secret.pattern",
        kind="dns_matches",
        definition={"name": "_acme.{domain}", "rrtype": "TXT", "pattern": "^SECRETPAT[0-9]+$"},
    )
    make_check(
        world,
        check_key="secret.range",
        kind="dns_value_range",
        definition={"name": "_limit.{domain}", "rrtype": "TXT", "min": 11111, "max": 22222},
    )
    response = call(
        world, "viewer", "POST", f"/api/v1/domains/{world.domains['assigned']}/checks/all"
    )
    assert response.status_code == 200
    ids = [r["check_id"] for r in response.json()]
    assert {"custom:tenant:secret.pattern", "custom:tenant:secret.range"} <= set(ids)
    for needle in ("SECRETPAT", "11111", "22222"):
        assert needle not in response.text
    # and the definitions themselves are not readable by a client viewer
    assert call(world, "viewer", "GET", CUSTOM).status_code == 403


def _custom_rows(w: World) -> int:
    w.db.expire_all()
    w.db.rollback()
    count = int(w.db.scalar(select(func.count()).select_from(CustomCheck)) or 0)
    w.db.rollback()
    return count


def test_http_fetch_is_rejected_at_schema_api_and_ui(world: World, zone: Zone) -> None:
    # schema
    with pytest.raises(KindUnavailable) as raised:
        parse_definition("http_fetch", {"url": "https://x.example"})
    assert (raised.value.field, raised.value.reason) == ("kind", "kind_unavailable")

    # API: create (tenant and global) and the dry run
    body = {
        "check_key": "http.one",
        "name": "Fetch",
        "kind": "http_fetch",
        "definition": {"url": "https://x.example"},
        "severity": "low",
        "remediation_text": {"en": "x", "it": "y"},
    }
    for who, query in (("owner", ""), ("root", GLOBAL_Q)):
        response = call(world, who, "POST", CUSTOM + query, json=body)
        assert response.status_code == 422
        assert response.json()["detail"]["key"] == "api.custom_checks.error.kind_unavailable"
    dry = call(
        world,
        "owner",
        "POST",
        f"{CUSTOM}/test",
        json={
            "domain_id": world.domains["assigned"],
            "kind": "http_fetch",
            "definition": {"url": "https://x.example"},
        },
    )
    assert dry.status_code == 422

    # UI: the option is disabled and a posted form is refused
    html = {"Accept": "text/html"}
    page = call(world, "owner", "GET", "/custom-checks/new", headers=html).text
    option = re.search(r'<option value="http_fetch"[^>]*>', page)
    assert option is not None and "disabled" in option.group(0)
    posted = call(
        world,
        "owner",
        "POST",
        "/custom-checks?scope=tenant",
        content=urlencode(
            {
                "check_key": "http.ui",
                "name": "Fetch",
                "kind": "http_fetch",
                "rrtype": "TXT",
                "name_template": "{domain}",
                "severity": "low",
                "remediation_en": "x",
                "remediation_it": "y",
                "enabled": "1",
            }
        ).encode(),
        headers={**html, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert posted.status_code == 422
    assert t("api.custom_checks.error.kind_unavailable", "en") in posted.text

    assert _custom_rows(world) == 0
    assert zone.queries == []  # no DNS for a refused kind
