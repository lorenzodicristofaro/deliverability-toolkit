"""M5-20 the DKIM selector list on every surface, through the real app and middleware.

Domain checks (REST and SSE) use the database list; free checks and the CLI stay on the seed. The
startup seed sync runs here, so a database holding only the synced seed is the starting point and
the M3 acceptance zones are the regression baseline. No network.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from functools import partial
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, event, select

from app.api.v1 import checks as api_checks
from app.checks import dkim as dkim_mod
from app.checks.dkim import seed_providers
from app.checks.dkim_selectors import KnowledgeError, list_selectors
from app.checks.models import CheckContext
from app.cli import check as cli_check
from app.core.config import Settings
from app.core.csrf import CSRF_HEADER, session_csrf_token
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.security import SESSION_COOKIE_NAME, unsign_session_token
from app.core.tenancy import TenantContext
from app.dns.types import DnsQuestion, DnsResult
from app.main import create_app
from app.models import User
from app.models.dkim_selector import DkimSelector
from app.repositories import GlobalDkimSelectorRepository, repo_for
from app.services import dkim_probe_selectors as probe
from app.services.auth import SessionPolicy, create_session
from app.services.dkim_probe_selectors import MAX_PROBE_SELECTORS
from app.web import checks_stream
from tests.api.test_domains import KEY, World, _seed, call
from tests.checks import test_acceptance_m3 as m3
from tests.support.socket_guard import db_endpoint, install
from tests.web.test_checks_stream import parse as parse_sse

D = m3.D
SEED = [s.name for s in list_selectors()]
STREAM = {"Accept": "text/event-stream"}
DONE_STATUS = re.compile(r'data-complete="([01])" data-status="([a-z]+)"')
ROW = re.compile(r'data-selector="([^"]*)" data-state="([^"]*)"')
DEADLINE_TEXT = t("checks.dkim.deadline", "en")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "dkim selector wiring", db_endpoint())


@pytest.fixture
def rig(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[m3.Rig]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=migrated_db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    holder: list[m3.Rig] = []
    application.dependency_overrides[api_checks._resolver] = lambda: holder[0].resolver()
    monkeypatch.setattr(api_checks, "CheckContext", partial(CheckContext, clock=m3.clock))
    monkeypatch.setattr(cli_check, "CheckContext", partial(CheckContext, clock=m3.clock))
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            r = m3.Rig(World(client, db, settings, tenant_a, tenant_b, users, domains))
            holder.append(r)
            yield r
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- helpers -------------------------------------------------------------------------------------


def api(rig: m3.Rig, who: str = "analyst", domain: str = "assigned", tenant: str = "a") -> Any:
    w = rig.world
    path = f"/api/v1/domains/{w.domains[domain]}/checks/dkim"
    response = call(w, who, "POST", path, tenant=tenant)
    assert response.status_code == 200, response.text[:300]
    return response.json()


def stream_path(rig: m3.Rig, domain: str = "assigned") -> str:
    return f"/domains/{rig.world.domains[domain]}/authentication/dkim/stream"


def stream(
    rig: m3.Rig, who: str = "analyst", domain: str = "assigned", tenant: str = "a"
) -> tuple[dict[str, str], str]:
    response = call(rig.world, who, "GET", stream_path(rig, domain), headers=STREAM, tenant=tenant)
    assert response.status_code == 200, response.text[:300]
    events = parse_sse(response.text)
    assert events[-1][0] == "done"
    rows = {m[1]: m[2] for _, data in events[:-1] if (m := ROW.search(data))}
    return rows, events[-1][1]


def tenant_row(rig: m3.Rig, selector: str, tenant: str = "a", **values: Any) -> None:
    w = rig.world
    ctx = (
        TenantContext(w.tenant_a, w.users["owner"])
        if tenant == "a"
        else TenantContext(w.tenant_b, w.users["b_owner"])
    )
    repo_for(ctx, w.db).dkim_selectors.create({"selector": selector, **values})
    w.db.commit()


def disable_all_global(rig: m3.Rig) -> None:
    store = GlobalDkimSelectorRepository(rig.world.db)
    for row in store.list(limit=1000):
        store.update(row.id, {"enabled": False})
    rig.world.db.commit()


def probed(rig: m3.Rig) -> set[str]:
    """Selector names that reached the resolver."""
    suffix = f"._domainkey.{D}"
    return {q.name.removesuffix(suffix) for q in rig.queries if q.name.endswith(suffix)}


def names(doc: Any) -> list[str]:
    return [s["selector"] for s in doc["data"]["selectors"]]


def codes(doc: Any) -> set[str]:
    return {f["code"] for f in doc["findings"]}


def statements_on(rig: m3.Rig) -> list[str]:
    seen: list[str] = []

    def record(_c: Any, _cur: Any, statement: str, _p: Any, _ctx: Any, _many: Any) -> None:
        seen.append(statement)

    event.listen(rig.world.client.app.state.db_engine, "before_cursor_execute", record)  # type: ignore[attr-defined]
    return seen


# --- byte-equal regression -----------------------------------------------------------------------


@pytest.mark.parametrize("scenario", list(m3.scenario_zones()))
def test_only_the_seed_is_byte_equal_to_the_seed_list_on_rest(rig: m3.Rig, scenario: str) -> None:
    make = m3.maker(scenario)
    rig.make = make
    assert m3.via_api(rig, "analyst", ["dkim"], mode="single") == m3.via_service(
        make, ["dkim"], single=True
    )


@pytest.mark.parametrize("scenario", list(m3.scenario_zones()))
def test_only_the_seed_is_byte_equal_to_the_seed_list_on_sse(rig: m3.Rig, scenario: str) -> None:
    rig.make = m3.maker(scenario)
    w = rig.world
    domain = call(w, "analyst", "GET", stream_path(rig), headers=STREAM)
    free = call(w, "analyst", "GET", f"/tools/dkim/stream?name={D}", headers=STREAM)
    assert domain.status_code == free.status_code == 200
    # Rows arrive in completion order; the frames themselves must be identical.
    assert sorted(parse_sse(domain.text)) == sorted(parse_sse(free.text))


def test_rest_preserves_the_seed_order(rig: m3.Rig) -> None:
    assert names(api(rig)) == SEED


# --- the database list is really used ------------------------------------------------------------


def test_tenant_row_is_probed_on_rest_and_sse(rig: m3.Rig) -> None:
    tenant_row(rig, "mine")
    expected = sorted({*SEED, "mine"})
    assert names(api(rig)) == expected
    assert "mine" in probed(rig)
    rows, _ = stream(rig)
    assert sorted(rows) == expected


def test_every_domain_route_uses_the_list(rig: m3.Rig) -> None:
    tenant_row(rig, "mine")
    w = rig.world
    base = f"/api/v1/domains/{w.domains['assigned']}/checks"
    one = call(w, "analyst", "POST", f"{base}/all").json()
    two = call(w, "analyst", "POST", base, json={"ids": ["spf", "dkim"]}).json()
    assert "mine" in names(next(d for d in one if d["check_id"] == "dkim"))
    assert "mine" in names(next(d for d in two if d["check_id"] == "dkim"))


def test_tenants_never_see_each_others_selectors(rig: m3.Rig) -> None:
    tenant_row(rig, "a-private")
    tenant_row(rig, "b-private", tenant="b")

    b_doc = api(rig, "b_owner", "other", "b")
    b_rows, _ = stream(rig, "b_owner", "other", "b")
    assert "b-private" in names(b_doc) and "a-private" not in names(b_doc)
    assert "b-private" in b_rows and "a-private" not in b_rows

    a_doc = api(rig)
    a_rows, _ = stream(rig)
    assert "a-private" in names(a_doc) and "b-private" not in names(a_doc)
    assert "a-private" in a_rows and "b-private" not in a_rows


def test_foreign_selector_never_reaches_dns(rig: m3.Rig) -> None:
    tenant_row(rig, "b-private", tenant="b")
    api(rig)
    stream(rig)
    assert "b-private" not in probed(rig)


# --- tenant-less surfaces ------------------------------------------------------------------------


def test_free_rest_stays_on_the_seed(rig: m3.Rig) -> None:
    tenant_row(rig, "mine")
    disable_all_global(rig)
    doc = json.loads(m3.via_free(rig, ["dkim"]))[0]
    assert names(doc) == SEED


def test_free_stream_stays_on_the_seed(rig: m3.Rig) -> None:
    tenant_row(rig, "mine")
    disable_all_global(rig)
    response = call(rig.world, "analyst", "GET", f"/tools/dkim/stream?name={D}", headers=STREAM)
    rows = {m[1] for _, data in parse_sse(response.text)[:-1] if (m := ROW.search(data))}
    assert sorted(rows) == SEED


def test_cli_stays_on_the_seed(rig: m3.Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_row(rig, "mine")
    disable_all_global(rig)
    result = m3.via_cli(monkeypatch, m3.maker("healthy"), ["dkim"], mode="single")
    assert names(json.loads(result.stdout)) == SEED


# --- fallback and empty list ---------------------------------------------------------------------


def test_empty_global_table_falls_back_on_rest_and_sse(rig: m3.Rig) -> None:
    w = rig.world
    w.db.execute(delete(DkimSelector).where(DkimSelector.scope == "global"))
    w.db.commit()
    assert names(api(rig)) == SEED
    rows, _ = stream(rig)
    assert sorted(rows) == SEED


def test_all_disabled_says_nothing_was_probed_on_rest(rig: m3.Rig) -> None:
    disable_all_global(rig)
    doc = api(rig)
    assert doc["status"] == "error"
    assert codes(doc) == {"DKIM_NO_SELECTORS_PROBED"}
    assert doc["data"]["probed"] == 0
    assert probed(rig) == set()


def test_all_disabled_says_nothing_was_probed_on_sse(rig: m3.Rig) -> None:
    disable_all_global(rig)
    rows, done = stream(rig)
    assert rows == {}
    match = DONE_STATUS.search(done)
    assert match is not None and match[2] == "error"
    assert 'data-code="DKIM_NO_SELECTORS_PROBED"' in done
    assert "DKIM_NO_SELECTOR_FOUND" not in done
    assert probed(rig) == set()


# --- probe cap -----------------------------------------------------------------------------------


def over_cap(rig: m3.Rig, over: int) -> list[str]:
    """Rows added straight through the repository, as racing creates could leave them."""
    store = GlobalDkimSelectorRepository(rig.world.db)
    extra = [f"r{n:04d}" for n in range(MAX_PROBE_SELECTORS + over - len(SEED))]
    for name in extra:
        store.create({"selector": name}, actor=None)
    rig.world.db.commit()
    return sorted({*SEED, *extra})


def test_over_cap_is_incomplete_and_the_same_on_rest_and_sse(rig: m3.Rig) -> None:
    every = over_cap(rig, 2)
    kept, cut = every[:MAX_PROBE_SELECTORS], every[MAX_PROBE_SELECTORS:]

    doc = api(rig)
    assert doc["status"] == "error"
    assert names(doc) == kept
    assert doc["data"]["dropped"] == 2
    assert "DKIM_SELECTORS_CAPPED" in codes(doc)
    assert "DKIM_NO_SELECTOR_FOUND" not in codes(doc)
    assert not set(cut) & probed(rig)

    rows, done = stream(rig)
    assert sorted(rows) == kept
    match = DONE_STATUS.search(done)
    assert match is not None and (match[1], match[2]) == ("0", "error")
    assert 'data-code="DKIM_SELECTORS_CAPPED"' in done
    assert DEADLINE_TEXT not in done  # the cap is not a timeout
    assert not set(cut) & probed(rig)


def test_at_the_cap_nothing_is_dropped(rig: m3.Rig) -> None:
    every = over_cap(rig, 0)
    doc = api(rig)
    assert names(doc) == every
    assert "dropped" not in doc["data"]
    assert "DKIM_SELECTORS_CAPPED" not in codes(doc)
    _, done = stream(rig)
    match = DONE_STATUS.search(done)
    assert match is not None and match[1] == "1"


# --- database use --------------------------------------------------------------------------------


class Watched(m3.Scripted):
    """Records how many connections the app holds while a DNS query is answered."""

    held: list[int]
    outstanding: list[int]

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.held.append(self.outstanding[0])
        return await super().resolve(question)


@pytest.mark.parametrize(
    "request_kind",
    ["rest_dkim", "rest_all", "rest_ids", "rest_spf", "sse", "free_rest", "free_sse"],
)
def test_no_connection_is_held_during_dns(rig: m3.Rig, request_kind: str) -> None:
    w = rig.world
    engine = w.client.app.state.db_engine  # type: ignore[attr-defined]
    outstanding = [0]
    held: list[int] = []

    def checkout(*_a: Any) -> None:
        outstanding[0] += 1

    def checkin(*_a: Any) -> None:
        outstanding[0] -= 1

    event.listen(engine, "checkout", checkout)
    event.listen(engine, "checkin", checkin)

    def make() -> Watched:
        resolver = Watched(m3.scenario_zones()["healthy"])
        resolver.held, resolver.outstanding = held, outstanding
        return resolver

    rig.make = make
    base = f"/api/v1/domains/{w.domains['assigned']}/checks"
    response = {
        "rest_dkim": lambda: call(w, "analyst", "POST", f"{base}/dkim"),
        "rest_all": lambda: call(w, "analyst", "POST", f"{base}/all"),
        "rest_ids": lambda: call(w, "analyst", "POST", base, json={"ids": ["dkim"]}),
        "rest_spf": lambda: call(w, "analyst", "POST", f"{base}/spf"),
        "sse": lambda: call(w, "analyst", "GET", stream_path(rig), headers=STREAM),
        "free_rest": lambda: call(
            w, "analyst", "POST", "/api/v1/checks/free", json={"name": D, "ids": ["dkim"]}
        ),
        "free_sse": lambda: call(
            w, "analyst", "GET", f"/tools/dkim/stream?name={D}", headers=STREAM
        ),
    }[request_kind]()
    assert response.status_code == 200, response.text[:300]
    assert held, "no DNS query was made"
    assert set(held) == {0}


def test_a_run_without_dkim_does_not_read_the_table(rig: m3.Rig) -> None:
    seen = statements_on(rig)
    w = rig.world
    call(w, "analyst", "POST", f"/api/v1/domains/{w.domains['assigned']}/checks/spf")
    assert not [s for s in seen if "dkim_selectors" in s]


@pytest.mark.parametrize(
    ("who", "domain", "status"),
    [("viewer", "unassigned", 404), ("owner", "other", 404)],
)
def test_denied_caller_never_reads_the_table(
    rig: m3.Rig, who: str, domain: str, status: int
) -> None:
    seen = statements_on(rig)
    w = rig.world
    response = call(w, who, "POST", f"/api/v1/domains/{w.domains[domain]}/checks/dkim")
    assert response.status_code == status
    assert call(w, who, "GET", stream_path(rig, domain), headers=STREAM).status_code == status
    assert not [s for s in seen if "dkim_selectors" in s]
    assert rig.queries == []


# --- what a result shows, and an unreadable seed -------------------------------------------------


TENANT_NOTE = "SECRET-TENANT-NOTE"
GLOBAL_NOTE = "SECRET-GLOBAL-NOTE"
SEED_PROVIDERS = seed_providers()
WITH_PROVIDER = next(n for n in SEED if n in SEED_PROVIDERS)
WITHOUT_PROVIDER = next(n for n in SEED if n not in SEED_PROVIDERS)
PROVIDER_SPAN = re.compile(r'data-testid="dkim-provider">([^<]*)<')


def note_on_global(rig: m3.Rig, name: str, notes: str) -> None:
    store = GlobalDkimSelectorRepository(rig.world.db)
    row = next(r for r in store.list(limit=1000) if r.selector == name)
    store.update(row.id, {"notes": notes})
    rig.world.db.commit()


def rest_providers(doc: Any) -> dict[str, str | None]:
    return {s["selector"]: s["provider"] for s in doc["data"]["selectors"]}


def sse_providers(text: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name, data in parse_sse(text):
        if name == "selector" and (m := ROW.search(data)):
            p = PROVIDER_SPAN.search(data)
            out[m[1]] = None if p is None else p[1]
    return out


def no_tenant_cookie(rig: m3.Rig, who: str) -> str:
    w = rig.world
    user = w.db.scalars(select(User).where(User.id == w.users[who])).one()
    issued = create_session(
        w.db,
        user,
        w.settings.secret_key,
        active_tenant_id=None,
        policy=SessionPolicy.from_settings(w.settings),
    )
    w.db.commit()
    return issued.cookie_value


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_every_role_sees_name_and_provider_never_notes(rig: m3.Rig, who: str) -> None:
    tenant_row(rig, "mine", provider="tenant-prov", notes=TENANT_NOTE)
    tenant_row(rig, "bare", notes=TENANT_NOTE)
    note_on_global(rig, WITH_PROVIDER, GLOBAL_NOTE)
    expected = {
        **{n: SEED_PROVIDERS.get(n) for n in SEED},
        "mine": "tenant-prov",
        "bare": None,
    }
    w = rig.world
    rest = call(w, who, "POST", f"/api/v1/domains/{w.domains['assigned']}/checks/dkim")
    sse = call(w, who, "GET", stream_path(rig), headers=STREAM)
    assert rest.status_code == sse.status_code == 200, rest.text[:300]
    assert rest_providers(rest.json()) == expected
    assert sse_providers(sse.text) == expected
    for response in (rest, sse):
        assert TENANT_NOTE not in response.text and GLOBAL_NOTE not in response.text
        assert '"notes"' not in response.text


def test_a_selector_without_provider_renders_no_label(rig: m3.Rig) -> None:
    sse = call(rig.world, "viewer", "GET", stream_path(rig), headers=STREAM)
    label = t("checks.dkim.row.provider", "en")
    for name, data in parse_sse(sse.text):
        m = ROW.search(data)
        if name == "selector" and m and m[1] == WITHOUT_PROVIDER:
            assert "dkim-provider" not in data and label not in data
            break
    else:
        pytest.fail("row missing")


def test_same_name_in_two_tenants_never_leaks_the_other_provider(rig: m3.Rig) -> None:
    tenant_row(rig, "shared", provider="a-prov", notes=TENANT_NOTE)
    tenant_row(rig, "shared", tenant="b", provider="b-prov", notes=TENANT_NOTE)
    tenant_row(rig, "a-only", provider="a-only-prov")
    tenant_row(rig, "b-only", tenant="b", provider="b-only-prov")
    w = rig.world
    a_path = f"/api/v1/domains/{w.domains['assigned']}/checks/dkim"
    b_path = f"/api/v1/domains/{w.domains['other']}/checks/dkim"
    for who in ("viewer", "owner"):
        rest = call(w, who, "POST", a_path)
        sse = call(w, who, "GET", stream_path(rig), headers=STREAM)
        assert rest_providers(rest.json())["shared"] == "a-prov"
        assert sse_providers(sse.text)["shared"] == "a-prov"
        for response in (rest, sse):
            assert "b-prov" not in response.text and "b-only" not in response.text
    for who in ("b_viewer", "b_owner"):
        rest = call(w, who, "POST", b_path, tenant="b")
        sse = call(w, who, "GET", stream_path(rig, "other"), headers=STREAM, tenant="b")
        assert rest_providers(rest.json())["shared"] == "b-prov"
        assert sse_providers(sse.text)["shared"] == "b-prov"
        for response in (rest, sse):
            assert "a-prov" not in response.text and "a-only" not in response.text
            assert TENANT_NOTE not in response.text


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"provider": "mine-wins"}, "mine-wins"),  # tenant non-empty provider wins
        ({}, None),  # NULL tenant provider: the global one
        ({"provider": "off-prov", "enabled": False}, None),  # disabled: the global one
    ],
    ids=["tenant-wins", "empty-falls-back", "disabled-ignored"],
)
def test_tenant_row_over_a_global_row_of_the_same_name(
    rig: m3.Rig, values: dict[str, Any], expected: str | None
) -> None:
    tenant_row(rig, WITH_PROVIDER, **values)
    want = expected or SEED_PROVIDERS[WITH_PROVIDER]
    w = rig.world
    rest = call(w, "viewer", "POST", f"/api/v1/domains/{w.domains['assigned']}/checks/dkim")
    sse = call(w, "viewer", "GET", stream_path(rig), headers=STREAM)
    assert rest_providers(rest.json())[WITH_PROVIDER] == want
    assert sse_providers(sse.text)[WITH_PROVIDER] == want
    # Tenant B keeps the global provider.
    b_doc = api(rig, "b_owner", "other", "b")
    assert rest_providers(b_doc)[WITH_PROVIDER] == SEED_PROVIDERS[WITH_PROVIDER]


@pytest.mark.parametrize(
    ("who", "domain", "tenant"),
    [
        ("viewer", "unassigned", "a"),
        ("owner", "other", "a"),
        ("analyst", "assigned", "b"),
        ("b_viewer", "assigned", "b"),
    ],
    ids=["viewer-unassigned", "foreign-domain", "foreign-active-tenant", "foreign-viewer"],
)
def test_denied_callers_get_404_and_no_provider(
    rig: m3.Rig, who: str, domain: str, tenant: str
) -> None:
    tenant_row(rig, "mine", provider="tenant-prov", notes=TENANT_NOTE)
    w = rig.world
    rest = call(w, who, "POST", f"/api/v1/domains/{w.domains[domain]}/checks/dkim", tenant=tenant)
    sse = call(w, who, "GET", stream_path(rig, domain), headers=STREAM, tenant=tenant)
    for response in (rest, sse):
        assert response.status_code == 404
        assert "tenant-prov" not in response.text and TENANT_NOTE not in response.text
    assert rig.queries == []


@pytest.mark.parametrize("who", ["viewer", "analyst"])
def test_no_active_tenant_is_404_on_rest_and_sse(rig: m3.Rig, who: str) -> None:
    tenant_row(rig, "mine", provider="tenant-prov")
    w = rig.world
    w.client.cookies.clear()
    cookie = no_tenant_cookie(rig, who)
    w.client.cookies.set(SESSION_COOKIE_NAME, cookie)
    token = unsign_session_token(cookie, w.settings.secret_key)
    assert token is not None
    csrf = {CSRF_HEADER: session_csrf_token(token, w.settings.secret_key)}
    rest = w.client.post(f"/api/v1/domains/{w.domains['assigned']}/checks/dkim", headers=csrf)
    sse = w.client.get(stream_path(rig), headers=STREAM)
    for response in (rest, sse):
        assert response.status_code == 404, response.text[:200]
        assert "tenant-prov" not in response.text
    assert rig.queries == []


def test_free_surfaces_show_seed_providers_and_never_tenant_ones(
    rig: m3.Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_row(rig, WITH_PROVIDER, provider="tenant-prov", notes=TENANT_NOTE)
    expected = {n: SEED_PROVIDERS.get(n) for n in SEED}
    free = json.loads(m3.via_free(rig, ["dkim"]))[0]
    assert rest_providers(free) == expected
    response = call(rig.world, "analyst", "GET", f"/tools/dkim/stream?name={D}", headers=STREAM)
    assert sse_providers(response.text) == expected
    cli = m3.via_cli(monkeypatch, m3.maker("healthy"), ["dkim"], mode="single")
    assert rest_providers(json.loads(cli.stdout)) == expected
    for text in (json.dumps(free), response.text, cli.stdout):
        assert "tenant-prov" not in text and TENANT_NOTE not in text


def _break_seed(rig: m3.Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> Any:
        raise KnowledgeError("seed unreadable")

    for module in (probe, checks_stream, dkim_mod):
        monkeypatch.setattr(module, "list_selectors", broken)
    w = rig.world
    w.db.execute(delete(DkimSelector).where(DkimSelector.scope == "global"))
    w.db.commit()


@pytest.mark.parametrize("route", ["domain", "free"])
def test_unreadable_seed_ends_the_stream_with_an_error_verdict(
    rig: m3.Rig, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    _break_seed(rig, monkeypatch)
    path = stream_path(rig) if route == "domain" else f"/tools/dkim/stream?name={D}"
    response = call(rig.world, "analyst", "GET", path, headers=STREAM)
    assert response.status_code == 200
    events = parse_sse(response.text)
    assert [name for name, _ in events] == ["done"]
    match = DONE_STATUS.search(events[0][1])
    assert match is not None and (match[1], match[2]) == ("0", "error")
    assert 'data-code="CHECK_INTERNAL_ERROR"' in events[0][1]
    assert DEADLINE_TEXT not in events[0][1]
    assert rig.queries == []


def test_unreadable_seed_is_an_error_on_rest_too(
    rig: m3.Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    _break_seed(rig, monkeypatch)
    doc = api(rig)
    assert doc["status"] == "error"
    assert codes(doc) == {"CHECK_INTERNAL_ERROR"}
