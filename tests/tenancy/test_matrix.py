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
from app.main import create_app
from app.web import deps
from tests.tenancy.conftest import ROLES, World, leaks

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


Body = Callable[[World, str], Any]


@dataclass(frozen=True)
class Entry:
    kind: Kind
    body: Body | None = None
    own: Mapping[str, int] = field(default_factory=dict)  # role -> status, target "own"
    smuggle: Mapping[str, int] = field(default_factory=dict)  # role -> status, "smuggle"


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
}

# Public routes, all methods. Keep this minimal: each needs a reason here AND in docs/TESTING.md.
EXEMPT: dict[str, str] = {
    "/healthz": "liveness probe for orchestrators; no session, no tenant data",
    "/login": "pre-session login form; resolves no tenant context (tests/web/test_auth_endpoints)",
    "/setup": "first-run wizard, 404 once any user exists (tests/web/test_setup)",
    "/static": "packaged CSS/JS (StaticFiles mount); no session, no data",
    "/language": "sets the language cookie only; no session or tenant data",
}

# Targets per kind (besides "anon"). The viewer additionally gets "unassigned" on DOMAIN routes.
TARGETS: dict[Kind, tuple[str, ...]] = {
    Kind.DOMAIN: ("b_domain", "b_session", "b_session_own"),
    Kind.COLLECTION: ("own", "b_session"),
    Kind.LANDING: ("own", "b_session"),
    Kind.SESSION: ("own", "b_session"),
    Kind.SWITCH: ("own", "b_session"),
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


def generate_cases(leaves: list[Leaf]) -> Iterator[Case]:
    for leaf in leaves:
        if leaf.path in EXEMPT:
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
    uncovered = sorted(
        f"{leaf.method} {leaf.path}"
        for leaf in LEAVES
        if leaf.path not in EXEMPT and leaf.key not in MATRIX
    )
    assert uncovered == [], "add a MATRIX entry (or a documented EXEMPT reason) for each"


def test_matrix_and_exemptions_have_no_stale_entries() -> None:
    keys = {leaf.key for leaf in LEAVES}
    paths = {leaf.path for leaf in LEAVES}
    assert sorted(set(MATRIX) - keys) == []
    assert sorted(set(EXEMPT) - paths) == []
    assert not {p for _, p in MATRIX} & set(EXEMPT)


def test_exemptions_are_documented() -> None:
    doc = TESTING_DOC.read_text(encoding="utf-8")
    for path, reason in EXEMPT.items():
        assert reason
        assert f"`{path}`" in doc, f"{path} exemption is not documented in docs/TESTING.md"


def test_matrix_routes_require_a_session_and_exempt_ones_no_tenant() -> None:
    """Covered routes all depend on `current_session`; exempt routes never build a
    TenantContext or a permission check through the request dependencies."""
    for leaf in LEAVES:
        if not isinstance(leaf.route, APIRoute):
            assert leaf.key not in MATRIX, f"cannot verify dependencies of {leaf.key}"
            continue
        if leaf.key in MATRIX:
            assert depends_on(leaf.route, deps.current_session), leaf.key
        else:
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
    if entry.kind is Kind.LANDING:
        return 200
    if entry.kind is Kind.SESSION:
        return 303
    return 404  # SWITCH: tenant B is not a membership of any tenant A user


def _path(w: World, case: Case) -> str:
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


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_matrix(world: World, logs: pytest.LogCaptureFixture, case: Case) -> None:
    assert case.entry is not None, f"route not covered by the tenancy matrix: {case.id}"
    entry = case.entry
    before_a, before_b = world.state("a"), world.state("b")
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
        assert response.json() == {"detail": t("api.error.not_found", "en")}

    after_b = world.state("b")
    assert after_b == before_b, "tenant B changed"
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


@pytest.mark.parametrize("who", ["anon", *ROLES])
def test_exempt_routes_leak_nothing(world: World, logs: pytest.LogCaptureFixture, who: str) -> None:
    for method, path in (("GET", "/healthz"), ("GET", "/login"), ("GET", "/setup")):
        response = world.send(who, method, path)
        assert response.status_code in (200, 303, 404), path
        assert leaks(world, response, logs) == [], path
    response = world.send(who, "POST", "/language", form={"lang": "it", "next": "/"})
    assert response.status_code == 303
    assert leaks(world, response, logs) == []
