"""M3 acceptance (TODO.md / M3-19), asserted through every surface: the service, the REST API
(domain-bound and free), the CLI, the DKIM SSE stream and the Authentication tab.

Zones are in-memory recorded fixtures (tests/support/dns_zones.py); `Scripted` adds per-lookup
failure injection and a query log. A fixed clock makes `started_at`/`duration_ms` equal too, so
the comparison is on the raw bytes of the wire JSON. No network: the loopback-only socket guard of
tests/dns/conftest.py is active for this whole module (also covering the API/web/CLI tests below).
"""

from __future__ import annotations

import ast
import asyncio
import json
import re
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

import pytest
import yaml
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select
from typer.testing import CliRunner

import app.checks.dkim as dkim_mod
import app.checks.dmarc as dmarc_mod
import app.checks.dmarc_external as dmarc_ext_mod
import app.checks.spf as spf_mod
import app.services.checks as service_mod
from app.api.v1 import checks as api_checks
from app.checks.dkim_selectors import list_selectors
from app.checks.models import CODE_RE, CheckContext, CheckResult
from app.cli import check as cli_check
from app.cli.main import app as cli_app
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.dns.types import DnsQuestion, DnsResult, ResultState
from app.main import create_app
from app.models import Membership
from app.services.checks import default_registry, run_check, run_checks
from tests.api.test_domains import KEY, ROOT, World, _seed, call
from tests.dns.conftest import _no_network_in_dns_tests  # noqa: F401
from tests.support.dns_zones import parse_zones
from tests.tenancy.test_matrix import LEAVES, MATRIX
from tests.web.test_checks_stream import parse as parse_sse

D = "assigned.example"
CLOCK_NOW = datetime(2026, 1, 1, tzinfo=UTC)
ZONES_DIR = Path(__file__).parent.parent / "fixtures" / "zones"
runner = CliRunner()
Zones = dict[str, list[dict[str, Any]]]
HTML = {"Accept": "text/html"}
STREAM = {"Accept": "text/event-stream"}


def clock() -> datetime:
    return CLOCK_NOW


def _rsa_key() -> str:
    data = yaml.safe_load((ZONES_DIR / "dkim_cases.yaml").read_text(encoding="utf-8"))
    for e in data["zones"]["default"]:
        if e["name"] == "sel._domainkey.d2048.example.com":
            return str(e["rdata"][0])
    raise AssertionError("fixture key not found")


KEY2048 = _rsa_key()
SELECTOR_NAMES = [s.name for s in list_selectors()]


# --- the recorded world ----------------------------------------------------------------------


def txt(name: str, *rdata: str) -> dict[str, Any]:
    return {"name": name, "type": "TXT", "ttl": 300, "rdata": list(rdata)}


def failing(name: str, state: str, rtype: str = "TXT") -> dict[str, Any]:
    entry: dict[str, Any] = {"name": name, "type": rtype, "state": state}
    if state == "servfail":
        entry["rcode"] = 2
    return entry


def healthy() -> list[dict[str, Any]]:
    return [
        txt(D, "v=spf1 -all"),
        txt(f"_dmarc.{D}", f"v=DMARC1; p=reject; rua=mailto:r@{D}"),
        txt(f"default._domainkey.{D}", KEY2048),
    ]


def scenario_zones() -> dict[str, Zones]:
    over = [txt(D, "v=spf1 " + " ".join(f"include:i{n}.{D}" for n in range(1, 12)) + " -all")]
    over += [txt(f"i{n}.{D}", "v=spf1 -all") for n in range(1, 12)]
    loop = [
        txt(D, f"v=spf1 include:a.{D} -all"),
        txt(f"a.{D}", f"v=spf1 include:b.{D} -all"),
        txt(f"b.{D}", f"v=spf1 include:a.{D} -all"),
    ]
    ext = [txt(f"_dmarc.{D}", "v=DMARC1; p=reject; rua=mailto:r@ext.example.net")]
    other = [n for n in SELECTOR_NAMES if n not in ("default", "google", "k1")][:2]
    mix = [
        txt(f"default._domainkey.{D}", KEY2048),
        failing(f"google._domainkey.{D}", "servfail"),
        failing(f"k1._domainkey.{D}", "timeout"),
        txt(f"{other[0]}._domainkey.{D}", "v=DKIM1; p=!!!notbase64"),
        txt(f"{other[1]}._domainkey.{D}", "v=DKIM1; k=rsa; p="),
    ]
    return {
        "healthy": {"default": healthy()},
        "spf_over_limit": {"default": [*over, *healthy()[1:]]},
        "spf_loop": {"default": [*loop, *healthy()[1:]]},
        "dmarc_external_unauthorized": {"default": [healthy()[0], *ext, healthy()[2]]},
        "dkim_mix": {"default": [*healthy()[:2], *mix]},
        "servfail_everywhere": {"default": healthy()},  # replaced by Scripted(everywhere=...)
    }


class Scripted:
    """A recorded zone plus failure injection (`fail`: (name, type) -> state; `everywhere`: one
    state for every query) and a log of every query it received."""

    identity = "scripted"

    def __init__(
        self,
        zones: Zones,
        fail: dict[tuple[str, str], str] | None = None,
        everywhere: str | None = None,
    ) -> None:
        self.inner = parse_zones({"zones": zones}).resolver()
        self.fail = fail or {}
        self.everywhere = everywhere
        self.queries: list[DnsQuestion] = []

    async def resolve(self, question: DnsQuestion) -> DnsResult:
        self.queries.append(question)
        state = self.everywhere or self.fail.get((question.name, question.rdtype))
        if state is not None:
            return DnsResult(question=question, state=ResultState(state), server=self.identity)
        return await self.inner.resolve(question)


Make = Callable[[], Scripted]


def maker(name: str) -> Make:
    zones = scenario_zones()[name]
    everywhere = {"servfail_everywhere": "servfail"}.get(name)
    return lambda: Scripted(zones, everywhere=everywhere)


# --- surfaces ------------------------------------------------------------------------------------


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
    def queries(self) -> list[DnsQuestion]:
        return [q for r in self.made for q in r.queries]


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def rig(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Rig]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    holder: list[Rig] = []
    application.dependency_overrides[api_checks._resolver] = lambda: holder[0].resolver()
    monkeypatch.setattr(api_checks, "CheckContext", partial(CheckContext, clock=clock))
    monkeypatch.setattr(cli_check, "CheckContext", partial(CheckContext, clock=clock))
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


def _many(results: Sequence[CheckResult]) -> str:
    return "[" + ",".join(r.model_dump_json() for r in results) + "]"


def via_service(make: Make, ids: Sequence[str], *, single: bool) -> str:
    ctx = CheckContext(resolver=make(), clock=clock)
    if single:
        return asyncio.run(run_check(ids[0], D, ctx)).model_dump_json()
    return _many(asyncio.run(run_checks(list(ids), D, ctx)))


def via_api(rig: Rig, who: str, ids: Sequence[str], *, mode: str) -> str:
    w = rig.world
    base = f"/api/v1/domains/{w.domains['assigned']}/checks"
    if mode == "single":
        r = call(w, who, "POST", f"{base}/{ids[0]}")
    elif mode == "all":
        r = call(w, who, "POST", f"{base}/all")
    else:
        r = call(w, who, "POST", base, json={"ids": list(ids)})
    assert r.status_code == 200, r.text[:200]
    return str(r.text)


def via_free(rig: Rig, ids: Sequence[str]) -> str:
    r = call(rig.world, "analyst", "POST", "/api/v1/checks/free", json={"name": D, "ids": ids})
    assert r.status_code == 200, r.text[:200]
    return str(r.text)


def via_cli(monkeypatch: pytest.MonkeyPatch, make: Make, ids: Sequence[str], *, mode: str) -> Any:
    monkeypatch.setattr(cli_check, "resolver_factory", make)
    args = ["check", D, "--format", "json"]
    if mode != "all":
        args += ["--only", ",".join(ids)]
    return runner.invoke(cli_app, args)


def all_surfaces(
    rig: Rig, mp: pytest.MonkeyPatch, make: Make, ids: Sequence[str], *, mode: str
) -> tuple[str, int]:
    """Run one request on every surface; assert the bytes are equal; return (json, cli exit)."""
    rig.make = make
    ids = default_registry().all_ids() if mode == "all" else list(ids)
    single = mode == "single"
    expected = via_service(make, ids, single=single)
    assert via_api(rig, "analyst", ids, mode=mode) == expected
    cli = via_cli(mp, make, ids, mode=mode)
    assert cli.stdout.endswith("\n") and not cli.stdout.endswith("\n\n"), cli.output
    assert cli.stdout[:-1] == expected, cli.output
    assert via_free(rig, ids) == (f"[{expected}]" if single else expected)
    return expected, int(cli.exit_code)


# --- identical results ---------------------------------------------------------------------------

REGISTERED = ("dkim", "dmarc", "spf")


def test_registered_ids() -> None:
    assert default_registry().all_ids() == list(REGISTERED)


@pytest.mark.parametrize("scenario", list(scenario_zones()))
def test_service_api_cli_byte_equal(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    make = maker(scenario)
    docs: dict[str, dict[str, Any]] = {}
    for check_id in ("spf", "dmarc", "dkim"):
        text, _ = all_surfaces(rig, monkeypatch, make, [check_id], mode="single")
        docs[check_id] = json.loads(text)
    assert_ui_equals(rig, docs)  # the Authentication tab, same zone
    ids = ["spf", "dmarc", "dkim"]  # request order, not sorted
    listed, _ = all_surfaces(rig, monkeypatch, make, ids, mode="list")
    assert [d["check_id"] for d in json.loads(listed)] == ids
    everything, code = all_surfaces(rig, monkeypatch, make, ids, mode="all")
    assert [d["check_id"] for d in json.loads(everything)] == sorted(REGISTERED)
    assert all(
        d["started_at"] == "2026-01-01T00:00:00Z" and d["duration_ms"] == 0 for d in docs.values()
    )
    statuses = {c: d["status"] for c, d in docs.items()}
    codes = {c: {f["code"] for f in d["findings"]} for c, d in docs.items()}
    expected_exit = (
        2 if "error" in statuses.values() else 1 if set(statuses.values()) & {"warn", "fail"} else 0
    )
    assert code == expected_exit
    if scenario == "healthy":
        assert set(statuses.values()) <= {"ok", "info"}
    elif scenario == "spf_over_limit":
        assert "SPF_TOO_MANY_LOOKUPS" in codes["spf"]
    elif scenario == "spf_loop":
        assert "SPF_INCLUDE_LOOP" in codes["spf"]
    elif scenario == "dmarc_external_unauthorized":
        assert "DMARC_EXTERNAL_UNAUTHORIZED" in codes["dmarc"]
        assert docs["dmarc"]["data"]["report_destinations"]
    elif scenario == "dkim_mix":
        assert statuses["dkim"] != "error"  # one selector found: the status follows the findings
        assert "DKIM_PROBE_ERRORS" in codes["dkim"]
    else:
        assert set(statuses.values()) == {"error"}


SECTION = re.compile(
    r'<section class="check-result" data-testid="check-(\w+)" data-status="(\w+)">(.*?)</section>',
    re.S,
)
FINDING = re.compile(r'<li data-code="([A-Z0-9_]+)" data-severity="(\w+)">')


UI_CHECKS = ("spf", "dmarc")  # rendered server-side; DKIM arrives over SSE (tested below)


def compare_ui(html: str, docs: dict[str, dict[str, Any]]) -> None:
    """Each UI check has exactly one section whose data-status and ordered (data-code,
    data-severity) pairs equal the service result. Service findings need a non-empty UI list."""
    found: dict[str, list[re.Match[str]]] = {}
    for m in SECTION.finditer(html):
        found.setdefault(m.group(1), []).append(m)
    for check_id in UI_CHECKS:
        sections = found.get(check_id, [])
        assert len(sections) == 1, (check_id, "expected exactly one section", len(sections))
        status, body = sections[0].group(2), sections[0].group(3)
        assert status == docs[check_id]["status"], (check_id, status)
        ui = FINDING.findall(body)
        expected = [(f["code"], f["severity"]) for f in docs[check_id]["findings"]]
        if expected:
            assert ui, (check_id, "service has findings, UI list is empty")
        assert ui == expected, check_id


def assert_ui_equals(rig: Rig, docs: dict[str, dict[str, Any]]) -> None:
    """The Authentication tab shows the same status and (code, severity) list as the service."""
    w = rig.world
    r = call(w, "analyst", "GET", f"/domains/{w.domains['assigned']}/authentication", headers=HTML)
    assert r.status_code == 200, r.status_code
    compare_ui(r.text, docs)


_UI_DOCS: dict[str, dict[str, Any]] = {
    "spf": {"status": "fail", "findings": [{"code": "SPF_MISSING", "severity": "high"}]},
    "dmarc": {"status": "ok", "findings": []},
}
_UI_SPF = (
    '<section class="check-result" data-testid="check-spf" data-status="fail">'
    '<ul><li data-code="SPF_MISSING" data-severity="high">x</li></ul></section>'
)
_UI_DMARC = '<section class="check-result" data-testid="check-dmarc" data-status="ok"></section>'
_UI_OK = _UI_SPF + _UI_DMARC


@pytest.mark.parametrize(
    "html",
    [
        pytest.param(_UI_SPF, id="no-dmarc"),
        pytest.param(_UI_DMARC, id="no-spf"),
        pytest.param("", id="empty-page"),
        pytest.param("<section", id="truncated"),
        pytest.param(_UI_OK + _UI_DMARC, id="duplicate-section"),
        pytest.param(_UI_OK.replace('"fail"', '"warn"'), id="wrong-status"),
        pytest.param(_UI_OK.replace('"high"', '"low"'), id="wrong-severity"),
        pytest.param(_UI_OK.replace("SPF_MISSING", "SPF_OTHER"), id="wrong-code"),
        pytest.param(re.sub(r"<li.*?</li>", "", _UI_OK), id="findings-dropped"),
        pytest.param(_UI_OK.replace("check-dmarc", "check-dmarcx"), id="malformed-testid"),
    ],
)
def test_ui_comparison_rejects_mismatch(html: str) -> None:
    """Non-vacuity of compare_ui: missing, duplicated or differing sections fail."""
    compare_ui(_UI_OK, _UI_DOCS)  # the baseline passes
    with pytest.raises(AssertionError):
        compare_ui(html, _UI_DOCS)


# --- errors are errors ---------------------------------------------------------------------------

POINTS_ZONE: Zones = {
    "default": [
        txt(D, f"v=spf1 include:inc.{D} -all"),
        txt(f"inc.{D}", "v=spf1 -all"),
        txt(f"_dmarc.{D}", "v=DMARC1; p=reject; rua=mailto:r@ext.example.net"),
        {"name": f"default._domainkey.{D}", "type": "A", "ttl": 300, "rdata": ["192.0.2.1"]},
    ]
}
# (check, name, type): every lookup a check depends on, incl. the DMARC external authorization.
POINTS = [
    ("spf", D, "TXT"),
    ("spf", f"inc.{D}", "TXT"),
    ("dmarc", f"_dmarc.{D}", "TXT"),
    ("dmarc", f"{D}._report._dmarc.ext.example.net", "TXT"),
    ("dkim", f"default._domainkey.{D}", "TXT"),
    ("dkim", f"default._domainkey.{D}", "CNAME"),
]
ABSENCE = {"nxdomain", "nodata"}


@pytest.mark.parametrize("state", [s.value for s in ResultState if s is not ResultState.ok])
@pytest.mark.parametrize(("check_id", "name", "rtype"), POINTS)
def test_failed_lookup_is_error_never_missing(
    state: str, check_id: str, name: str, rtype: str
) -> None:
    make = lambda: Scripted(POINTS_ZONE, fail={(name, rtype): state})  # noqa: E731
    result = json.loads(via_service(make, [check_id], single=True))
    codes = {f["code"] for f in result["findings"]}
    if state in ABSENCE:
        assert result["status"] != "error"
    else:
        assert result["status"] == "error"
        assert not codes & {"SPF_MISSING", "DMARC_MISSING", "DKIM_NO_SELECTOR_FOUND"}
        assert not codes & {"DMARC_EXTERNAL_UNAUTHORIZED", "SPF_INCLUDE_NOT_FOUND"}


@pytest.mark.parametrize("state", ["servfail", "timeout"])
def test_failed_lookup_is_error_on_every_surface(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    for check_id, name, rtype in POINTS:
        make = lambda: Scripted(POINTS_ZONE, fail={(name, rtype): state})  # noqa: E731, B023
        text, _ = all_surfaces(rig, monkeypatch, make, [check_id], mode="single")
        assert json.loads(text)["status"] == "error", (check_id, name, rtype)


@pytest.mark.parametrize("state", ["servfail", "timeout"])
def test_every_registered_check_errors_on_every_surface(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    make = lambda: Scripted(POINTS_ZONE, everywhere=state)  # noqa: E731
    for check_id in default_registry().all_ids():
        text, code = all_surfaces(rig, monkeypatch, make, [check_id], mode="single")
        assert json.loads(text)["status"] == "error", check_id
        assert code == 2
    text, code = all_surfaces(rig, monkeypatch, make, [], mode="all")
    assert {d["status"] for d in json.loads(text)} == {"error"} and code == 2


# --- SSE equals REST -----------------------------------------------------------------------------


def test_sse_selector_states_equal_rest(rig: Rig) -> None:
    rig.make = maker("dkim_mix")
    w = rig.world
    rest = call(w, "analyst", "POST", f"/api/v1/domains/{w.domains['assigned']}/checks/dkim")
    sse = call(
        w,
        "analyst",
        "GET",
        f"/domains/{w.domains['assigned']}/authentication/dkim/stream",
        headers={"Accept": "text/event-stream"},
    )
    assert sse.status_code == 200
    streamed = {
        m.group(1): m.group(2)
        for _, d in parse_sse(sse.text)[:-1]
        if (m := re.search(r'data-selector="([^"]*)" data-state="([^"]*)"', d))
    }
    assert streamed == {s["selector"]: s["state"] for s in rest.json()["data"]["selectors"]}
    assert {"found", "not_found", "error"} <= set(streamed.values())


# --- zero DNS queries for every denied request ---------------------------------------------------


def _toggle(w: World, user: str, toggles: dict[str, bool]) -> None:
    membership = w.db.scalars(select(Membership).where(Membership.user_id == w.users[user])).one()
    membership.feature_toggles = toggles
    w.db.commit()


def _requests(w: World, which: str) -> list[tuple[str, str, dict[str, Any]]]:
    """Domain-bound routes for the domain `which` (REST single/all/ids, SSE, tab)."""
    d = w.domains[which]
    api = f"/api/v1/domains/{d}/checks"
    return [
        ("POST", f"{api}/spf", {}),
        ("POST", f"{api}/all", {}),
        ("POST", api, {"json": {"ids": ["spf", "dkim"]}}),
        ("GET", f"/domains/{d}/authentication/dkim/stream", {"headers": STREAM}),
        ("GET", f"/domains/{d}/authentication", {"headers": HTML}),
    ]


FREE: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", "/api/v1/checks/free", {"json": {"name": D, "ids": ["spf", "dkim"]}}),
    ("GET", f"/tools/dkim/stream?name={D}", {"headers": STREAM}),
]


def _denied(rig: Rig, who: str, reqs: list[tuple[str, str, dict[str, Any]]], **kw: Any) -> None:
    for method, path, extra in reqs:
        r = call(rig.world, who, method, path, **extra, **kw)
        assert r.status_code in (401, 403, 404), (who, method, path, r.status_code)
        assert "event:" not in r.text
    assert rig.queries == []


def test_allowed_requests_do_query_dns(rig: Rig) -> None:
    """Non-vacuity: the same requests, permitted, do reach the resolver."""
    for method, path, extra in [*_requests(rig.world, "assigned"), *FREE]:
        before = len(rig.queries)
        r = call(rig.world, "analyst", method, path, **extra)
        assert r.status_code == 200, (path, r.status_code)
        assert len(rig.queries) > before, path


def test_anonymous_zero_queries(rig: Rig) -> None:
    w = rig.world
    for method, path, extra in [*_requests(w, "assigned"), *FREE]:
        w.client.cookies.clear()
        if method == "GET":
            r = w.client.get(path, headers=extra["headers"], follow_redirects=False)
            assert r.status_code in (303, 401), path
        else:
            r = call(w, "anon", method, path, **extra)
            assert r.status_code == 401, path
    assert rig.queries == []


def test_foreign_tenant_zero_queries(rig: Rig) -> None:
    for who in ("owner", "admin", "analyst", "viewer"):
        _denied(rig, who, _requests(rig.world, "other"))  # tenant B's domain
    _denied(rig, "analyst", _requests(rig.world, "assigned"), tenant="b")  # foreign active tenant
    _denied(rig, "analyst", FREE, tenant="b")


def test_unassigned_client_viewer_zero_queries(rig: Rig) -> None:
    _denied(rig, "viewer", _requests(rig.world, "unassigned"))
    _denied(rig, "viewer", FREE)  # a client viewer has no dns.tools


def test_check_run_false_zero_queries(rig: Rig) -> None:
    for who in ("owner", "admin", "analyst", "viewer"):
        _toggle(rig.world, who, {"check.run": False})
        _denied(rig, who, _requests(rig.world, "assigned"))


def test_dns_tools_false_zero_queries(rig: Rig) -> None:
    _toggle(rig.world, "analyst", {"dns.tools": False})
    _denied(rig, "analyst", FREE)


# --- tenancy sweep -------------------------------------------------------------------------------

M3_MODULES = ("app.api.v1.checks", "app.web.checks_stream", "app.web.authentication")


def test_every_m3_route_is_in_the_tenancy_matrix() -> None:
    m3 = [
        leaf
        for leaf in LEAVES
        if getattr(leaf.route, "endpoint", None) is not None
        and leaf.route.endpoint.__module__ in M3_MODULES
    ]
    assert {leaf.key for leaf in m3} == {
        ("POST", "/api/v1/domains/{domain_id}/checks/{check_id}"),
        ("POST", "/api/v1/domains/{domain_id}/checks"),
        ("POST", "/api/v1/checks/free"),
        ("GET", "/domains/{domain_id}/authentication/dkim/stream"),
        ("GET", "/tools/dkim/stream"),
        ("GET", "/domains/{domain_id}/authentication"),
    }
    assert [leaf.key for leaf in m3 if leaf.key not in MATRIX] == []


# --- i18n and hardcoded strings ------------------------------------------------------------------

CODE_MODULES = {
    "spf": spf_mod,
    "dmarc": dmarc_mod,
    "dmarc_external": dmarc_ext_mod,
    "dkim": dkim_mod,
    "service": service_mod,
}
ALL_CODES = sorted({c for m in CODE_MODULES.values() for c in m.CODES})
NO_REMEDIATION = {"CHECK_INTERNAL_ERROR", "CHECK_TIMEOUT"}  # emitted with remediation=False


def test_codes_are_well_formed_and_unique_per_module() -> None:
    for name, module in CODE_MODULES.items():
        assert len(set(module.CODES)) == len(module.CODES), name
        assert all(CODE_RE.fullmatch(c) for c in module.CODES), name
    assert len(ALL_CODES) >= 40


@pytest.mark.parametrize("code", ALL_CODES)
def test_every_code_has_en_and_it_text(code: str) -> None:
    parts = ["title", "detail"] + ([] if code in NO_REMEDIATION else ["remediation"])
    en, it = i18n.load_catalogue("en"), i18n.load_catalogue("it")
    for part in parts:
        key = f"finding.{code}.{part}"
        assert en.get(key, "").strip(), key
        assert it.get(key, "").strip(), key
        assert i18n.placeholders(en[key]) == i18n.placeholders(it[key]), key


def test_cli_has_no_hardcoded_user_strings() -> None:
    tree = ast.parse(Path(cli_check.__file__).read_text(encoding="utf-8"))
    bad: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        values = list(node.args) if name == "echo" else []
        values += [k.value for k in node.keywords if k.arg == "help"]
        bad += [
            v.lineno
            for v in values
            if isinstance(v, ast.Constant)
            and isinstance(v.value, str)
            and re.search("[A-Za-z]", v.value)
        ]
    assert bad == []


TEMPLATES = Path(cli_check.__file__).parents[1] / "web" / "templates"


@pytest.mark.parametrize(
    "template",
    [*sorted((TEMPLATES / "checks").glob("*.html")), TEMPLATES / "domains/authentication.html"],
)
def test_templates_have_no_literal_text(template: Path) -> None:
    src = template.read_text(encoding="utf-8")
    src = re.sub(r"\{#.*?#\}|\{\{.*?\}\}|\{%.*?%\}", "", src, flags=re.S)
    literal_attrs = re.findall(
        r'\b(?:title|aria-label|alt|placeholder)="([^"]*[A-Za-z][^"]*)"', src
    )
    text = re.sub(r"<[^>]*>", "", src)
    assert literal_attrs == []
    assert not re.search(r"[A-Za-z]{2,}", text), template.name
