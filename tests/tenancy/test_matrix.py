"""M1-20 tenancy matrix, generated from the FastAPI route table.

Every leaf route of `app.main.create_app()` (method x path) must be either an entry of `MATRIX`
or an explicit exemption in `EXEMPT` (documented in docs/TESTING.md); the guard test fails
otherwise, so a new endpoint cannot ship without tenancy coverage. Each matrix entry declares its
kind; the cases are generated as route x role x target:

- anonymous: 401 (API and non-GET) or 303 to /login (browser GET);
- every role of tenant A (owner, admin, analyst, client viewer, instance admin) addressing a
  tenant B domain, or using a session whose active tenant is B (a tenant they do not belong to):
  404 on every verb, UI and API, and nothing changes in either tenant;
- client viewer addressing an unassigned domain of its own tenant: 404;
- list responses (JSON and the landing page HTML) never include tenant B or, for the client
  viewer, unassigned domains;
- switching to a non-member tenant fails (404, no new session cookie).
Every case also checks that the response (body, headers) and the captured log records contain no
tenant B string (tenant name, slug, domain names in both forms, user emails).

Route enumeration uses `fastapi.routing.iter_route_contexts`: FastAPI 0.162 keeps included
routers as wrapper routes, so `app.routes` does not list the leaf routes. The enumeration is
self-tested against a nested synthetic app and against the routers declared in `app.web` and
`app.api`, so it cannot silently return nothing or skip a router.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.routing import APIRoute, iter_route_contexts
from starlette.routing import Mount, Route

import app.api
import app.web
from app.core.i18n import t
from app.core.security import SESSION_COOKIE_NAME
from app.core.tenancy import TenantContext
from app.main import create_app
from app.repositories import repo_for
from app.repositories.base import MAX_LIMIT
from app.repositories.content_rules import ContentRuleRecord
from app.web import deps
from tests.tenancy.conftest import (
    B_TENANT_NAME,
    ROLES,
    World,
    WorldMutated,
    assert_pristine,
    leaks,
)

ROOT = Path(__file__).resolve().parents[2]
TESTING_DOC = ROOT / "docs" / "TESTING.md"
ROW = re.compile(r'<tr data-domain-id="(\d+)">')
MOUNT = "*"  # the "method" of a Mount leaf


# --- route enumeration -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Leaf:
    method: str
    path: str
    name: str | None
    route: Any  # the original APIRoute / Mount

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.path)


def leaf_routes(application: FastAPI) -> list[Leaf]:
    """Every leaf route with its full path, one Leaf per method (Mounts: method "*"). HTTP
    routes are FastAPI APIRoutes or plain Starlette Routes; anything else (e.g. a websocket) is
    returned with method "?" so the guard fails until the matrix learns about it."""
    leaves: list[Leaf] = []
    for ctx in iter_route_contexts(application.routes):
        original = ctx.original_route
        path = ctx.path
        assert isinstance(path, str), f"leaf without a path: {original!r}"
        if isinstance(original, Route):
            leaves.extend(Leaf(m, path, ctx.name, original) for m in sorted(ctx.methods or ()))
        elif isinstance(original, Mount):
            leaves.append(Leaf(MOUNT, path, ctx.name, original))
        else:
            leaves.append(Leaf("?", path, ctx.name, original))
    return leaves


def declared_endpoints() -> set[Callable[..., Any]]:
    """Endpoints of every APIRouter defined in app.web.* and app.api.* modules (independent of
    how the app includes them)."""
    found: set[Callable[..., Any]] = set()
    for package in (app.web, app.api):
        for info in pkgutil.walk_packages(package.__path__, f"{package.__name__}."):
            module = importlib.import_module(info.name)
            for value in vars(module).values():
                if isinstance(value, APIRouter):
                    found |= {r.endpoint for r in value.routes if isinstance(r, APIRoute)}
    return found


def depends_on(route: APIRoute, target: Callable[..., Any]) -> bool:
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is target:
            return True
        stack.extend(dep.dependencies)
    return False


_APP = create_app()
LEAVES = leaf_routes(_APP)


# --- matrix ------------------------------------------------------------------------------------


class Kind(Enum):
    DOMAIN = "domain"  # addresses one domain by id
    COLLECTION = "collection"  # the active tenant's domain collection (list / create)
    LANDING = "landing"  # the tenant landing page (lists domains)
    SESSION = "session"  # session only, no tenant data (logout)
    SWITCH = "switch"  # changes the active tenant
    DNS = "dns"  # raw DNS tools: tenant-level `dns.tools`, no tenant data (M2-12)
    RULE = "rule"  # addresses one content rule by id (M5-18); `own` is the status on tenant B's


Body = Callable[[World, str], Any]


@dataclass(frozen=True)
class Entry:
    kind: Kind
    body: Body | None = None
    own: Mapping[str, int] = field(default_factory=dict)  # role -> status, target "own"
    smuggle: Mapping[str, int] = field(default_factory=dict)  # role -> status, "smuggle"
    # (role, target) -> reason: a known isolation bug, reported as a ticket and NOT fixed here.
    # The case is marked xfail(strict=True), so it fails again once the bug is fixed.
    xfail: Mapping[tuple[str, str], str] = field(default_factory=dict)
    not_found: str = "api.error.not_found"  # i18n key of the route's 404 body


def _by_role(writers: int, readers: int) -> dict[str, int]:
    """Owner, admin and instance admin (owner of A) may write; analyst and viewer may not."""
    return {role: (readers if role in ("analyst", "viewer") else writers) for role in ROLES}


def _rename(_w: World, role: str) -> dict[str, str]:
    return {"name": f"probe-{role.replace('_', '-')}.example"}


def _access(w: World, _role: str) -> dict[str, list[int]]:
    return {"user_ids": [w.users["b_viewer"], w.users["viewer"]]}


def _smuggle_json(w: World, role: str) -> dict[str, Any]:
    return {**_rename(w, role), "tenant_id": w.tenants["b"]}


def _smuggle_form(w: World, role: str) -> dict[str, str]:
    return {**_rename(w, role), "tenant_id": str(w.tenants["b"])}


def _switch_to_b(w: World, _role: str) -> dict[str, str]:
    return {"tenant_id": str(w.tenants["b"]), "next": "/"}


def _dns_lookup(_w: World, _role: str) -> dict[str, Any]:
    return {"name": "example.com", "type": "A"}


def _dns_reverse(_w: World, _role: str) -> dict[str, Any]:
    return {"ip": "192.0.2.10"}


def _dns_propagation(_w: World, _role: str) -> dict[str, Any]:
    return {"name": "example.com", "type": "A", "resolver_ids": ["google"]}


def _dns_propagation_form(_w: World, _role: str) -> dict[str, Any]:
    return {"name": "example.com", "type": "A", "resolver_ids": "google"}


def _message_form(_w: World, _role: str) -> dict[str, Any]:
    return {"raw": "Subject: probe\r\nFrom: a@example.com\r\n\r\nbody"}


def _content_form(_w: World, _role: str) -> dict[str, Any]:
    return {"text": "probe text", "subject": "probe"}


def _content_empty(_w: World, _role: str) -> dict[str, Any]:
    return {"subject": "probe"}


def _check_ids(_w: World, _role: str) -> dict[str, Any]:
    return {"ids": ["spf"]}


def _check_free(_w: World, _role: str) -> dict[str, Any]:
    return {"name": "example.com", "ids": ["spf"]}


_DNS_OWN = {**_by_role(200, 200), "viewer": 403}  # client viewers never get raw DNS tools

_MSG_OWN = {**_by_role(415, 415), "viewer": 403}  # client viewers never analyse messages

_CONTENT_OWN = {**_by_role(422, 422), "viewer": 403}  # client viewers never analyse content

_RULES_404 = "api.rules.error.not_found"
_RULES_READ = {**_by_role(200, 200), "viewer": 403}  # client viewers never see rule configuration
# Addressing a rule of tenant B: permission first (403), then the row is simply not there (404).
_RULE_READ_ON_B = {**_by_role(404, 404), "viewer": 403}
_RULE_WRITE_ON_B = _by_role(404, 403)


def _rule_sample(_w: World, _role: str) -> dict[str, Any]:
    return {"kind": "keyword", "pattern": "probe", "sample": "probe text"}


def _rule_form(_w: World, _role: str) -> dict[str, Any]:
    return {
        "name": "probe"
    }  # incomplete on purpose: a permitted role gets a 422, nothing is stored


def _toggle(_w: World, _role: str) -> dict[str, Any]:
    return {"enabled": "0"}


MATRIX: dict[tuple[str, str], Entry] = {
    # session / tenant switch (app.web.auth)
    ("POST", "/logout"): Entry(Kind.SESSION),
    ("POST", "/tenants/switch"): Entry(Kind.SWITCH, body=_switch_to_b),
    # landing (app.web.landing)
    ("GET", "/"): Entry(Kind.LANDING),
    # domain UI (app.web.domains)
    ("GET", "/domains/new"): Entry(Kind.COLLECTION, own=_by_role(200, 403)),
    ("POST", "/domains"): Entry(Kind.COLLECTION, body=_smuggle_form, smuggle=_by_role(303, 403)),
    ("GET", "/domains/{domain_id}"): Entry(Kind.DOMAIN),
    ("GET", "/domains/{domain_id}/rename"): Entry(Kind.DOMAIN),
    ("POST", "/domains/{domain_id}/rename"): Entry(Kind.DOMAIN, body=_rename),
    ("GET", "/domains/{domain_id}/delete"): Entry(Kind.DOMAIN),
    ("POST", "/domains/{domain_id}/delete"): Entry(Kind.DOMAIN),
    # domain API (app.api.v1.domains)
    ("GET", "/api/v1/domains"): Entry(Kind.COLLECTION, own=_by_role(200, 200)),
    ("POST", "/api/v1/domains"): Entry(
        Kind.COLLECTION, body=_smuggle_json, smuggle=_by_role(422, 403)
    ),
    ("GET", "/api/v1/domains/{domain_id}"): Entry(Kind.DOMAIN),
    ("PATCH", "/api/v1/domains/{domain_id}"): Entry(Kind.DOMAIN, body=_rename),
    ("DELETE", "/api/v1/domains/{domain_id}"): Entry(Kind.DOMAIN),
    ("PUT", "/api/v1/domains/{domain_id}/access"): Entry(Kind.DOMAIN, body=_access),
    # DNS tools UI (app.web.dns_tools)
    ("GET", "/tools/dns"): Entry(Kind.DNS, own=_DNS_OWN),
    ("POST", "/tools/dns/lookup"): Entry(Kind.DNS, body=_dns_lookup, own=_DNS_OWN),
    ("POST", "/tools/dns/reverse"): Entry(Kind.DNS, body=_dns_reverse, own=_DNS_OWN),
    ("GET", "/tools/dns/trace"): Entry(Kind.DNS, own=_DNS_OWN),
    ("POST", "/tools/dns/trace"): Entry(Kind.DNS, body=_dns_lookup, own=_DNS_OWN),
    ("GET", "/tools/dns/propagation"): Entry(Kind.DNS, own=_DNS_OWN),
    ("POST", "/tools/dns/propagation"): Entry(Kind.DNS, body=_dns_propagation_form, own=_DNS_OWN),
    # message analysis UI (app.web.message): tenant-level `message.analyze`
    ("GET", "/tools/message"): Entry(Kind.DNS, own=_DNS_OWN),
    ("POST", "/tools/message"): Entry(Kind.DNS, body=_message_form, own=_DNS_OWN),
    # content analysis UI (app.web.content): tenant-level `content.analyze`
    ("GET", "/tools/content"): Entry(Kind.DNS, own=_DNS_OWN),
    ("POST", "/tools/content"): Entry(Kind.DNS, body=_content_form, own=_DNS_OWN),
    # DNS tools API (app.api.v1.dns_tools)
    ("POST", "/api/v1/dns/lookup"): Entry(Kind.DNS, body=_dns_lookup, own=_DNS_OWN),
    ("POST", "/api/v1/dns/reverse"): Entry(Kind.DNS, body=_dns_reverse, own=_DNS_OWN),
    ("POST", "/api/v1/dns/trace"): Entry(Kind.DNS, body=_dns_lookup, own=_DNS_OWN),
    ("POST", "/api/v1/dns/propagation"): Entry(Kind.DNS, body=_dns_propagation, own=_DNS_OWN),
    # checks API (app.api.v1.checks): domain-bound (check.run) and free (dns.tools)
    ("POST", "/api/v1/domains/{domain_id}/checks/{check_id}"): Entry(Kind.DOMAIN),
    ("POST", "/api/v1/domains/{domain_id}/checks"): Entry(Kind.DOMAIN, body=_check_ids),
    ("POST", "/api/v1/checks/free"): Entry(Kind.DNS, body=_check_free, own=_DNS_OWN),
    # message analysis API (app.api.v1.message): tenant-level `message.analyze`. The matrix sends
    # JSON, so permitted roles stop at 415 (the content type is checked after the permission);
    # the 200 path is covered by tests/api/test_message_analyze.py.
    ("POST", "/api/v1/message/analyze"): Entry(Kind.DNS, body=_dns_lookup, own=_MSG_OWN),
    # content analysis API (app.api.v1.content): tenant-level `content.analyze`. The matrix sends
    # a JSON body with no html/text, so permitted roles stop at 422 (decided before the analyzer);
    # the 200 path is covered by tests/api/test_content_analyze.py.
    ("POST", "/api/v1/content/analyze"): Entry(Kind.DNS, body=_content_empty, own=_CONTENT_OWN),
    # content rules API (app.api.v1.rules), tenant path. The global path needs no tenant, so it is
    # covered per role and verb by tests/api/test_rules_api.py.
    ("GET", "/api/v1/rules"): Entry(Kind.COLLECTION, own=_RULES_READ, not_found=_RULES_404),
    ("POST", "/api/v1/rules"): Entry(
        Kind.COLLECTION, body=_smuggle_json, smuggle=_by_role(422, 403), not_found=_RULES_404
    ),
    ("POST", "/api/v1/rules/test"): Entry(
        Kind.DNS, body=_rule_sample, own=_by_role(200, 403), not_found=_RULES_404
    ),
    ("GET", "/api/v1/rules/{rule_id}"): Entry(Kind.RULE, own=_RULE_READ_ON_B, not_found=_RULES_404),
    ("PATCH", "/api/v1/rules/{rule_id}"): Entry(
        Kind.RULE, body=_rename, own=_RULE_WRITE_ON_B, not_found=_RULES_404
    ),
    ("DELETE", "/api/v1/rules/{rule_id}"): Entry(
        Kind.RULE, own=_RULE_WRITE_ON_B, not_found=_RULES_404
    ),
    # content rules UI (app.web.rules). Reads need `rules.read`, every other route `rules.manage`
    # on the tenant path; the global tab is covered by tests/web/test_rules_ui.py. `POST /rules`
    # (create) and `/rules/test` take no rule id; the permitted roles stop at 422 / 200.
    ("GET", "/rules"): Entry(Kind.COLLECTION, own=_RULES_READ),
    ("GET", "/rules/new"): Entry(Kind.COLLECTION, own=_by_role(200, 403)),
    ("POST", "/rules"): Entry(Kind.DNS, body=_rule_form, own=_by_role(422, 403)),
    ("POST", "/rules/{rule_id}/edit"): Entry(Kind.RULE, body=_rule_form, own=_RULE_WRITE_ON_B),
    ("GET", "/rules/test"): Entry(Kind.DNS, own=_by_role(200, 403)),
    ("POST", "/rules/test"): Entry(Kind.DNS, body=_rule_sample, own=_by_role(200, 403)),
    ("GET", "/rules/{rule_id}/edit"): Entry(Kind.RULE, own=_RULE_WRITE_ON_B),
    ("POST", "/rules/{rule_id}/toggle"): Entry(Kind.RULE, body=_toggle, own=_RULE_WRITE_ON_B),
    ("POST", "/rules/{rule_id}/delete"): Entry(Kind.RULE, own=_RULE_WRITE_ON_B),
    # DKIM SSE streams (app.web.checks_stream): check.run on the domain / dns.tools (free).
    # The free route needs `?name=`; without it permitted roles get 422 (decided before streaming).
    ("GET", "/domains/{domain_id}/authentication"): Entry(Kind.DOMAIN),
    ("GET", "/domains/{domain_id}/authentication/dkim/stream"): Entry(Kind.DOMAIN),
    ("GET", "/tools/dkim/stream"): Entry(Kind.DNS, own={**_by_role(422, 422), "viewer": 403}),
}

# Public routes by (method, path): a new method on an exempt path is NOT exempt. Keep this
# minimal: each needs a reason here AND a row in docs/TESTING.md.
_HEALTH = "liveness probe for orchestrators; no session, no tenant data"
_LOGIN = "pre-session login; resolves no tenant context (tests/web/test_auth_endpoints)"
_SETUP = "first-run wizard, 404 once any user exists (tests/web/test_setup)"
EXEMPT: dict[tuple[str, str], str] = {
    ("GET", "/healthz"): _HEALTH,
    ("HEAD", "/healthz"): _HEALTH,
    ("GET", "/login"): _LOGIN,
    ("POST", "/login"): _LOGIN,
    ("GET", "/setup"): _SETUP,
    ("POST", "/setup"): _SETUP,
    (MOUNT, "/static"): "packaged CSS/JS (StaticFiles mount); no session, no data",
    ("POST", "/language"): "sets the language cookie only; no session or tenant data",
}

# Targets per kind (besides "anon"). The viewer additionally gets "unassigned" on DOMAIN routes.
TARGETS: dict[Kind, tuple[str, ...]] = {
    Kind.DOMAIN: ("b_domain", "b_session", "b_session_own"),
    Kind.COLLECTION: ("own", "b_session"),
    Kind.LANDING: ("own", "b_session"),
    Kind.SESSION: ("own", "b_session"),
    Kind.SWITCH: ("own", "b_session"),
    Kind.DNS: ("own", "b_session"),
    Kind.RULE: ("b_rule", "b_session"),
}


@dataclass(frozen=True)
class Case:
    leaf: Leaf
    entry: Entry | None
    role: str
    target: str

    @property
    def id(self) -> str:
        return f"{self.leaf.method} {self.leaf.path} [{self.role}/{self.target}]"


def uncovered(leaves: list[Leaf]) -> list[str]:
    """Leaf routes that are neither a MATRIX entry nor an EXEMPT (method, path)."""
    return sorted(
        f"{leaf.method} {leaf.path}"
        for leaf in leaves
        if leaf.key not in EXEMPT and leaf.key not in MATRIX
    )


def generate_cases(leaves: list[Leaf]) -> Iterator[Case]:
    for leaf in leaves:
        if leaf.key in EXEMPT:
            continue
        entry = MATRIX.get(leaf.key)
        if entry is None:  # uncovered route: one failing case (and the guard test fails)
            yield Case(leaf, None, "-", "uncovered")
            continue
        yield Case(leaf, entry, "anon", "-")
        for role in ROLES:
            targets = TARGETS[entry.kind]
            if entry.kind is Kind.COLLECTION:
                own = "own" if leaf.method == "GET" else "smuggle"
                targets = tuple(own if t == "own" else t for t in targets)
            for target in targets:
                yield Case(leaf, entry, role, target)
        if entry.kind is Kind.DOMAIN:
            yield Case(leaf, entry, "viewer", "unassigned")


CASES = list(generate_cases(LEAVES))


def _param(case: Case) -> Any:
    reason = case.entry.xfail.get((case.role, case.target)) if case.entry else None
    marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
    return pytest.param(case, id=case.id, marks=marks)


# --- route-table guard -------------------------------------------------------------------------


def test_enumeration_resolves_nested_routers() -> None:
    inner = APIRouter(prefix="/inner")

    @inner.get("/{item}")
    def leaf_get(item: str) -> str:
        return item

    @inner.api_route("/x", methods=["PUT", "DELETE"])
    def leaf_multi() -> None:
        return None

    outer = APIRouter(prefix="/outer")
    outer.include_router(inner)
    synthetic = FastAPI()
    synthetic.include_router(outer, prefix="/v9")
    synthetic.mount("/files", app=FastAPI(), name="files")

    async def plain(_request: Request) -> Response:
        return Response()

    synthetic.add_route("/plain", plain, methods=["POST"])
    keys = {leaf.key for leaf in leaf_routes(synthetic)}
    assert keys == {
        ("GET", "/v9/outer/inner/{item}"),
        ("PUT", "/v9/outer/inner/x"),
        ("DELETE", "/v9/outer/inner/x"),
        (MOUNT, "/files"),
        ("POST", "/plain"),
        # FastAPI's own docs routes are plain Starlette routes: they are enumerated too.
        ("GET", "/openapi.json"),
        ("HEAD", "/openapi.json"),
        ("GET", "/docs"),
        ("HEAD", "/docs"),
        ("GET", "/docs/oauth2-redirect"),
        ("HEAD", "/docs/oauth2-redirect"),
        ("GET", "/redoc"),
        ("HEAD", "/redoc"),
    }


def test_enumeration_finds_the_app_routes() -> None:
    names = {leaf.name for leaf in LEAVES}
    assert len(LEAVES) > 0
    assert {"landing", "healthz", "list_domains", "put_domain_access", "static"} <= names
    assert ("GET", "/") in {leaf.key for leaf in LEAVES}
    assert ("PUT", "/api/v1/domains/{domain_id}/access") in {leaf.key for leaf in LEAVES}
    # Independent source: every APIRoute declared on a router in app.web / app.api is reached.
    reached = {leaf.route.endpoint for leaf in LEAVES if isinstance(leaf.route, APIRoute)}
    missing = {f"{e.__module__}.{e.__qualname__}" for e in declared_endpoints() - reached}
    assert missing == set()


def test_every_route_is_in_the_matrix_or_exempt() -> None:
    unknown = [leaf for leaf in LEAVES if leaf.method == "?"]
    assert unknown == [], "unsupported route type: extend leaf_routes and the matrix"
    assert uncovered(LEAVES) == [], "add a MATRIX entry (or a documented EXEMPT reason)"


def test_exemption_is_per_method() -> None:
    """A new verb on an exempt path (e.g. DELETE /login) is not exempt by inheritance."""
    login = next(leaf for leaf in LEAVES if leaf.key == ("POST", "/login"))
    added = [
        Leaf("DELETE", "/login", "delete_login", login.route),
        Leaf("PUT", "/healthz", "put_health", login.route),
        Leaf("GET", "/static", "static_get", login.route),
    ]
    assert uncovered([*LEAVES, *added]) == ["DELETE /login", "GET /static", "PUT /healthz"]
    generated = [c for c in generate_cases([*LEAVES, *added]) if c.target == "uncovered"]
    assert sorted(c.id for c in generated) == [
        "DELETE /login [-/uncovered]",
        "GET /static [-/uncovered]",
        "PUT /healthz [-/uncovered]",
    ]


def test_matrix_and_exemptions_have_no_stale_entries() -> None:
    keys = {leaf.key for leaf in LEAVES}
    assert sorted(set(MATRIX) - keys) == []
    assert sorted(set(EXEMPT) - keys) == []
    assert not set(MATRIX) & set(EXEMPT)
    assert not {p for _, p in MATRIX} & {p for _, p in EXEMPT}


def test_exemptions_are_documented() -> None:
    doc = TESTING_DOC.read_text(encoding="utf-8")
    for (method, path), reason in EXEMPT.items():
        assert reason
        assert f"`{method} {path}`" in doc, f"{method} {path} is not documented in TESTING.md"


def test_matrix_routes_require_a_session_and_exempt_ones_no_tenant() -> None:
    """Covered routes all depend on `current_session`; exempt routes never build a
    TenantContext or a permission check through the request dependencies."""
    for leaf in LEAVES:
        if not isinstance(leaf.route, APIRoute):
            assert leaf.key not in MATRIX, f"cannot verify dependencies of {leaf.key}"
            continue
        if leaf.key in MATRIX:
            assert depends_on(leaf.route, deps.current_session), leaf.key
        elif leaf.key in EXEMPT:
            assert not depends_on(leaf.route, deps.current_session), leaf.key
            assert not depends_on(leaf.route, deps.tenant_ctx), leaf.key


def test_matrix_size() -> None:
    covered = [c for c in CASES if c.entry is not None]
    assert len({c.leaf.key for c in covered}) == len(MATRIX)
    assert len(covered) >= len(MATRIX) * (1 + 2 * len(ROLES))


# --- generated matrix --------------------------------------------------------------------------


def _expected(case: Case) -> int:
    entry, method, api = case.entry, case.leaf.method, case.leaf.path.startswith("/api/")
    assert entry is not None
    if case.role == "anon":
        return 303 if method == "GET" and not api else 401
    if entry.kind is Kind.DOMAIN:
        return 404  # every role, every verb, every cross-tenant or unassigned target
    if entry.kind is Kind.COLLECTION:
        if case.target == "b_session":
            return 404
        table = entry.own if case.target == "own" else entry.smuggle
        return table[case.role]
    if entry.kind in (Kind.DNS, Kind.RULE):
        return 404 if case.target == "b_session" else entry.own[case.role]
    if entry.kind is Kind.LANDING:
        return 200
    if entry.kind is Kind.SESSION:
        return 303
    return 404  # SWITCH: tenant B is not a membership of any tenant A user


def b_rule(w: World) -> ContentRuleRecord:
    """Tenant B's private content rule, created on first use. Its name holds a tenant B secret, so
    `leaks` catches it in any response or log line. The world baseline does not cover rules."""
    w.db.expire_all()
    repository = repo_for(TenantContext(w.tenants["b"], w.users["b_owner"]), w.db).content_rules
    for existing in repository.list(limit=MAX_LIMIT):
        if existing.scope == "tenant":
            return existing
    created = repository.create(
        {
            "name": f"{B_TENANT_NAME} private rule",
            "kind": "keyword",
            "pattern": "b-private-pattern",
            "weight": 1,
            "category": "spam",
            "severity": "low",
            "title": "B private title",
        }
    )
    w.db.commit()
    return created


def _path(w: World, case: Case) -> str:
    if "{rule_id}" in case.leaf.path:
        return case.leaf.path.replace("{rule_id}", str(b_rule(w).id))
    target_domain = {
        "b_domain": "secret",
        "b_session": "secret",
        "b_session_own": "assigned",
        "unassigned": "unassigned",
        "-": "secret",
    }.get(case.target, "secret")
    return case.leaf.path.replace("{domain_id}", str(w.domains[target_domain]))


def _listed_ids(case: Case, response: Any) -> set[int]:
    if case.leaf.path.startswith("/api/"):
        return {item["id"] for item in response.json()["items"]}
    return {int(m) for m in ROW.findall(response.text)}


def _remove_probe(w: World, role: str) -> None:
    """Delete the domain a successful "smuggle" create added to tenant A (restores the
    baseline for the next case)."""
    domains = repo_for(TenantContext(w.tenants["a"], None), w.db).domains
    probe = domains.get_by_name(_rename(w, role)["name"])
    if probe is not None:
        domains.delete(probe.id)
        w.db.commit()


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
def test_matrix(world: World, logs: pytest.LogCaptureFixture, case: Case) -> None:
    assert case.entry is not None, f"route not covered by the tenancy matrix: {case.id}"
    try:
        _check_case(world, logs, case)
    finally:
        if case.target == "smuggle":
            _remove_probe(world, case.role)


def _check_case(world: World, logs: pytest.LogCaptureFixture, case: Case) -> None:
    entry = case.entry
    assert entry is not None
    before_a, before_b = world.state("a"), world.state("b")
    rule_before = b_rule(world) if case.leaf.path.startswith(("/api/v1/rules", "/rules")) else None
    tenant = "b" if case.target.startswith("b_session") else "a"
    fresh = entry.kind in (Kind.SESSION, Kind.SWITCH)  # these consume/rotate the session
    body = entry.body(world, case.role) if entry.body is not None else None
    api = case.leaf.path.startswith("/api/")
    response = world.send(
        case.role,
        case.leaf.method,
        _path(world, case),
        tenant=tenant,
        fresh=fresh,
        form=None if api else body,
        json=body if api else None,
    )

    assert response.status_code == _expected(case), response.text[:300]
    assert leaks(world, response, logs) == []
    if case.role == "anon" and response.status_code == 303:
        assert response.headers["location"].startswith("/login?next=")
    if api and response.status_code == 404:
        assert response.json() == {"detail": t(entry.not_found, "en")}

    after_b = world.state("b")
    assert after_b == before_b, "tenant B changed"
    if rule_before is not None:
        assert b_rule(world) == rule_before, "tenant B's rule changed"
    after_a = world.state("a")
    if case.target == "smuggle" and response.status_code == 303:
        # The UI create ignores the smuggled tenant_id: the domain lands in tenant A only.
        added = set(after_a[4]) - set(before_a[4])
        assert {name for _, name in added} == {_rename(world, case.role)["name"]}
        assert after_a[:4] == before_a[:4]
    else:
        assert after_a == before_a, "tenant A changed"

    if entry.kind is Kind.SWITCH:
        assert SESSION_COOKIE_NAME not in response.headers.get("set-cookie", "")
    if entry.kind is Kind.LANDING and case.target == "b_session":
        assert 'data-testid="no-tenant"' in response.text
        assert ROW.findall(response.text) == []
    listing = (entry.kind is Kind.LANDING and case.target == "own") or (
        case.leaf.key == ("GET", "/api/v1/domains") and case.target == "own"
    )
    if listing:
        ids = _listed_ids(case, response)
        b_ids = {world.domains["secret"], world.domains["idn"]}
        a_ids = {d_id for d_id, _ in after_a[4]}
        assert not ids & b_ids
        assert ids <= a_ids
        if case.role == "viewer":
            assert ids == {world.domains["assigned"]}
        else:
            assert {world.domains["assigned"], world.domains["unassigned"]} <= ids


# Exempt routes requested below as every role. POST /login and POST /setup are not: they are
# covered by tests/web/test_auth_endpoints.py and tests/web/test_setup.py (docs/TESTING.md).
EXEMPT_PROBES: tuple[tuple[str, str, int], ...] = (
    ("GET", "/healthz", 200),
    ("HEAD", "/healthz", 200),
    ("GET", "/login", 200),
    ("GET", "/setup", 404),
    ("GET", "/static/app.css", 200),
)


@pytest.mark.parametrize("who", ["anon", *ROLES])
def test_exempt_routes_leak_nothing(world: World, logs: pytest.LogCaptureFixture, who: str) -> None:
    for method, path, status in EXEMPT_PROBES:
        response = world.send(who, method, path)
        assert response.status_code == status, (method, path)
        assert leaks(world, response, logs) == [], (method, path)
    response = world.send(who, "POST", "/language", form={"lang": "it", "next": "/"})
    assert response.status_code == 303
    assert leaks(world, response, logs) == []


def test_mutated_world_is_detected(seeded_world: World) -> None:
    """Self-test of the baseline guard: a change to either tenant makes the next test's `world`
    fixture fail loudly instead of letting later cases pass vacuously."""
    assert_pristine(seeded_world)
    b_domains = repo_for(TenantContext(seeded_world.tenants["b"], None), seeded_world.db).domains
    secret = seeded_world.domains["secret"]
    original = b_domains.get(secret)
    assert original is not None
    original_name = original.name
    b_domains.rename(secret, "renamed-by-a-buggy-case.example")
    seeded_world.db.commit()
    try:
        with pytest.raises(WorldMutated, match=r"tenants \['b'\]"):
            assert_pristine(seeded_world)
    finally:
        b_domains.rename(secret, original_name)
        seeded_world.db.commit()
    assert_pristine(seeded_world)
    a_domains = repo_for(TenantContext(seeded_world.tenants["a"], None), seeded_world.db).domains
    extra = a_domains.create("left-behind.example")
    seeded_world.db.commit()
    try:
        with pytest.raises(WorldMutated, match=r"tenants \['a'\]"):
            assert_pristine(seeded_world)
    finally:
        a_domains.delete(extra.id)
        seeded_world.db.commit()
    assert_pristine(seeded_world)
