"""M1-18 `/api/v1/domains` through the real app and middleware (CSRF, sessions, i18n).

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url`
fixture); the schema is built by Alembic. Sessions are created directly with
`app.services.auth.create_session` (no password hashing). No network.

The tenancy matrix covers EVERY endpoint x role (anonymous, owner, admin, analyst, client viewer)
x target (own tenant, other tenant, and a session whose active tenant is one the user does not
belong to). Expected statuses are written out explicitly in `EXPECTED`, not derived from code.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import i18n
from app.core.config import Settings
from app.core.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER,
    new_double_submit_token,
    session_csrf_token,
)
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.security import SESSION_COOKIE_NAME, unsign_session_token
from app.main import create_app
from app.models import Domain, DomainAccess, Membership, MembershipRole, Tenant, User
from app.repositories.domain import DomainRepository
from app.services.auth import SessionPolicy, create_session

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
BASE = "/api/v1/domains"
# Data of tenant B that must never appear in any response made in tenant A.
B_SECRET_NAME = "tenantb-secret.example"
B_TENANT_NAME = "Secret Agency B"
ROLES = ("anon", "owner", "admin", "analyst", "viewer")


@dataclass
class World:
    client: TestClient
    db: Session
    settings: Settings
    tenant_a: int
    tenant_b: int
    users: dict[str, int]
    domains: dict[str, int]  # "assigned", "unassigned" (A), "other" (B)
    cookies: dict[tuple[str, str], str] = field(default_factory=dict)

    def tenant_id(self, which: str) -> int:
        return self.tenant_a if which == "a" else self.tenant_b


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


def _seed(db: Session) -> tuple[int, int, dict[str, int], dict[str, int]]:
    a = Tenant(name="Agency A", slug="agency-a")
    b = Tenant(name=B_TENANT_NAME, slug="agency-b")
    users = {n: User(email=f"{n}@example.com") for n in (*ROLES[1:], "b_owner", "b_viewer")}
    db.add_all([a, b, *users.values()])
    db.flush()
    role = MembershipRole
    members = {
        "owner": Membership(user_id=users["owner"].id, tenant_id=a.id, role=role.OWNER),
        "admin": Membership(user_id=users["admin"].id, tenant_id=a.id, role=role.ADMIN),
        "analyst": Membership(user_id=users["analyst"].id, tenant_id=a.id, role=role.ANALYST),
        "viewer": Membership(user_id=users["viewer"].id, tenant_id=a.id, role=role.CLIENT_VIEWER),
        "b_owner": Membership(user_id=users["b_owner"].id, tenant_id=b.id, role=role.OWNER),
        "b_viewer": Membership(
            user_id=users["b_viewer"].id, tenant_id=b.id, role=role.CLIENT_VIEWER
        ),
    }
    domains = {
        "assigned": Domain(tenant_id=a.id, name="assigned.example"),
        "unassigned": Domain(tenant_id=a.id, name="unassigned.example"),
        "other": Domain(tenant_id=b.id, name=B_SECRET_NAME),
    }
    db.add_all([*members.values(), *domains.values()])
    db.flush()
    db.add_all(
        [
            DomainAccess(
                membership_id=members["viewer"].id,
                domain_id=domains["assigned"].id,
                tenant_id=a.id,
            ),
            DomainAccess(
                membership_id=members["b_viewer"].id,
                domain_id=domains["other"].id,
                tenant_id=b.id,
            ),
        ]
    )
    db.commit()
    return a.id, b.id, {k: u.id for k, u in users.items()}, {k: d.id for k, d in domains.items()}


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
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


# --- request helpers --------------------------------------------------------------------------


def _cookie(w: World, who: str, tenant: str) -> str:
    """A live session cookie for `who` whose active tenant is `tenant` ("a" or "b")."""
    if (who, tenant) not in w.cookies:
        user = w.db.scalars(select(User).where(User.id == w.users[who])).one()
        issued = create_session(
            w.db,
            user,
            w.settings.secret_key,
            active_tenant_id=w.tenant_id(tenant),
            policy=SessionPolicy.from_settings(w.settings),
        )
        w.db.commit()
        w.cookies[(who, tenant)] = issued.cookie_value
    return w.cookies[(who, tenant)]


def call(
    w: World,
    who: str,
    method: str,
    path: str,
    *,
    json: Any = None,
    content: Any = None,
    tenant: str = "a",
    csrf: bool = True,
    headers: dict[str, str] | None = None,
) -> Any:
    """Send a request as `who` (a seeded user or "anon"). Mutations carry a valid CSRF token
    unless `csrf=False`: the session-bound token, or for "anon" a double-submit pair."""
    w.client.cookies.clear()
    sent = dict(headers or {})
    if who == "anon":
        if csrf:
            token = new_double_submit_token(w.settings.secret_key)
            w.client.cookies.set(CSRF_COOKIE_NAME, token)
            sent[CSRF_HEADER] = token
    else:
        cookie = _cookie(w, who, tenant)
        w.client.cookies.set(SESSION_COOKIE_NAME, cookie)
        if csrf:
            session_token = unsign_session_token(cookie, w.settings.secret_key)
            assert session_token is not None
            sent[CSRF_HEADER] = session_csrf_token(session_token, w.settings.secret_key)
    if content is not None:
        sent.setdefault("Content-Type", "application/json")
        return w.client.request(method, path, content=content, headers=sent)
    return w.client.request(method, path, json=json, headers=sent)


def snapshot(w: World) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    """Ground truth: every domain and domain_access row (all tenants)."""
    w.db.expire_all()
    domains = w.db.execute(
        select(Domain.id, Domain.tenant_id, Domain.name).order_by(Domain.id)
    ).all()
    access = w.db.execute(
        select(DomainAccess.membership_id, DomainAccess.domain_id).order_by(
            DomainAccess.membership_id, DomainAccess.domain_id
        )
    ).all()
    return [tuple(r) for r in domains], [tuple(r) for r in access]


def detail(key: str, lang: str = "en") -> dict[str, str]:
    return {"detail": t(key, lang)}


ERROR_KEYS = {
    401: "auth.required",
    403: "api.error.forbidden",
    404: "api.error.not_found",
    409: "api.error.conflict",
}


# --- tenancy / permission matrix --------------------------------------------------------------

# Endpoints: (method, path template, body). `{id}` is the target domain id.
ENDPOINTS: dict[str, tuple[str, str, Any]] = {
    "list": ("GET", BASE, None),
    "create": ("POST", BASE, {"name": "created.example"}),
    "get": ("GET", BASE + "/{id}", None),
    "patch": ("PATCH", BASE + "/{id}", {"name": "renamed.example"}),
    "delete": ("DELETE", BASE + "/{id}", None),
    "access": ("PUT", BASE + "/{id}/access", "VIEWER"),
}
COLLECTION = {"list", "create"}
# Targets: "assigned"/"unassigned" are tenant A domains (assigned to the A viewer or not),
# "other" is a tenant B domain, "foreign_session" is the assigned A domain requested from a
# session whose active tenant is B, where none of these users is a member.
ID_TARGETS = ("assigned", "unassigned", "other", "foreign_session")
COLLECTION_TARGETS = ("own", "foreign_session")

_ANON = {"anon": 401}
_ALL_404 = {"owner": 404, "admin": 404, "analyst": 404, "viewer": 404}
EXPECTED: dict[tuple[str, str], dict[str, int]] = {
    ("list", "own"): {**_ANON, "owner": 200, "admin": 200, "analyst": 200, "viewer": 200},
    ("create", "own"): {**_ANON, "owner": 201, "admin": 201, "analyst": 403, "viewer": 403},
    ("get", "assigned"): {**_ANON, "owner": 200, "admin": 200, "analyst": 200, "viewer": 200},
    ("get", "unassigned"): {**_ANON, "owner": 200, "admin": 200, "analyst": 200, "viewer": 404},
    ("patch", "assigned"): {**_ANON, "owner": 200, "admin": 200, "analyst": 403, "viewer": 403},
    ("patch", "unassigned"): {**_ANON, "owner": 200, "admin": 200, "analyst": 403, "viewer": 404},
    ("delete", "assigned"): {**_ANON, "owner": 204, "admin": 204, "analyst": 403, "viewer": 403},
    ("delete", "unassigned"): {
        **_ANON,
        "owner": 204,
        "admin": 204,
        "analyst": 403,
        "viewer": 404,
    },
    ("access", "assigned"): {**_ANON, "owner": 200, "admin": 200, "analyst": 403, "viewer": 403},
    ("access", "unassigned"): {
        **_ANON,
        "owner": 200,
        "admin": 200,
        "analyst": 403,
        "viewer": 404,
    },
}
for _endpoint in ENDPOINTS:
    for _target in ("other", "foreign_session"):
        if _endpoint in COLLECTION and _target == "other":
            continue
        EXPECTED[(_endpoint, _target)] = {**_ANON, **_ALL_404}

MATRIX = [
    pytest.param(endpoint, role, target, id=f"{endpoint}-{role}-{target}")
    for endpoint in ENDPOINTS
    for target in (COLLECTION_TARGETS if endpoint in COLLECTION else ID_TARGETS)
    for role in ROLES
]


def test_matrix_is_complete() -> None:
    combos = {(e, tgt) for e, _r, tgt in (p.values for p in MATRIX)}
    assert combos == set(EXPECTED)
    assert all(set(EXPECTED[c]) == set(ROLES) for c in EXPECTED)
    assert len(MATRIX) == (2 * 2 + 4 * 4) * len(ROLES)  # 100 cases


@pytest.mark.parametrize(("endpoint", "role", "target"), MATRIX)
def test_tenancy_matrix(world: World, endpoint: str, role: str, target: str) -> None:
    method, template, body = ENDPOINTS[endpoint]
    domain_key = "assigned" if target in ("own", "foreign_session") else target
    path = template.format(id=world.domains[domain_key])
    if body == "VIEWER":
        body = {"user_ids": [world.users["viewer"]]}
    tenant = "b" if target == "foreign_session" else "a"
    before = snapshot(world)

    response = call(world, role, method, path, json=body, tenant=tenant)

    expected = EXPECTED[(endpoint, target)][role]
    assert response.status_code == expected, response.text
    assert B_SECRET_NAME not in response.text and B_TENANT_NAME not in response.text
    if expected >= 400:
        assert response.json() == detail(ERROR_KEYS[expected])
        assert snapshot(world) == before  # a denied request changes nothing
    elif method == "GET" and endpoint == "list":
        names = {item["name"] for item in response.json()["items"]}
        if role == "viewer":
            assert names == {"assigned.example"}
        else:
            assert names == {"assigned.example", "unassigned.example"}
    elif endpoint == "access":
        assert response.json()["user_ids"] == [world.users["viewer"]]
    elif method != "GET":
        assert snapshot(world) != before


# --- anonymous and CSRF -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", BASE), ("PATCH", BASE + "/1"), ("DELETE", BASE + "/1"), ("PUT", BASE + "/1/access")],
)
def test_anonymous_mutation_without_csrf_is_refused_by_csrf(
    world: World, method: str, path: str
) -> None:
    response = call(world, "anon", method, path, json={"name": "x.example"}, csrf=False)
    assert response.status_code == 403
    assert response.json() == detail("csrf.invalid")


@pytest.mark.parametrize(
    ("method", "path_key", "body"),
    [
        ("POST", None, {"name": "new.example"}),
        ("PATCH", "unassigned", {"name": "new.example"}),
        ("DELETE", "unassigned", None),
        ("PUT", "unassigned", {"user_ids": []}),
    ],
)
@pytest.mark.parametrize("token", [None, "", "x", "a" * 43])
def test_cookie_authenticated_mutations_require_csrf(
    world: World, method: str, path_key: str | None, body: Any, token: str | None
) -> None:
    path = BASE if path_key is None else f"{BASE}/{world.domains[path_key]}"
    if path_key is not None and method == "PUT":
        path += "/access"
    before = snapshot(world)
    headers = {} if token is None else {CSRF_HEADER: token}
    response = call(world, "owner", method, path, json=body, csrf=False, headers=headers)
    assert response.status_code == 403
    assert response.json() == detail("csrf.invalid")
    assert snapshot(world) == before


# --- create / duplicates ----------------------------------------------------------------------


def test_create_converts_idn_to_a_label(world: World) -> None:
    response = call(world, "owner", "POST", BASE, json={"name": "MÜNCHEN.de."})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "xn--mnchen-3ya.de"
    assert body["display_name"] == "münchen.de"
    assert set(body) == {"id", "name", "display_name", "created_at"}
    got = call(world, "owner", "GET", f"{BASE}/{body['id']}")
    assert got.json()["name"] == "xn--mnchen-3ya.de"


@pytest.mark.parametrize("name", ["assigned.example", "ASSIGNED.example.", "Assigned.Example"])
def test_duplicate_in_same_tenant_is_409(world: World, name: str) -> None:
    before = snapshot(world)
    response = call(world, "owner", "POST", BASE, json={"name": name})
    assert response.status_code == 409
    assert response.json() == detail("api.error.conflict")
    assert snapshot(world) == before


def test_duplicate_idn_and_a_label_conflict(world: World) -> None:
    assert call(world, "owner", "POST", BASE, json={"name": "münchen.de"}).status_code == 201
    again = call(world, "owner", "POST", BASE, json={"name": "xn--mnchen-3ya.de"})
    assert again.status_code == 409


def test_same_name_in_another_tenant_is_allowed(world: World) -> None:
    response = call(world, "b_owner", "POST", BASE, json={"name": "assigned.example"}, tenant="b")
    assert response.status_code == 201
    # ...and tenant B's own existing name is a 409 there, without echoing anything
    dup = call(world, "b_owner", "POST", BASE, json={"name": B_SECRET_NAME}, tenant="b")
    assert dup.status_code == 409 and B_SECRET_NAME not in dup.text
    # creating B's name in A is allowed and reveals nothing about B
    in_a = call(world, "owner", "POST", BASE, json={"name": B_SECRET_NAME})
    assert in_a.status_code == 201


def test_rename_to_existing_name_is_409(world: World) -> None:
    path = f"{BASE}/{world.domains['assigned']}"
    response = call(world, "owner", "PATCH", path, json={"name": "unassigned.example"})
    assert response.status_code == 409
    assert response.json() == detail("api.error.conflict")
    same = call(world, "owner", "PATCH", path, json={"name": "assigned.example"})
    assert same.status_code == 200


def test_rename_to_name_of_other_tenant_is_allowed(world: World) -> None:
    path = f"{BASE}/{world.domains['assigned']}"
    response = call(world, "owner", "PATCH", path, json={"name": B_SECRET_NAME})
    assert response.status_code == 200


# --- malformed input --------------------------------------------------------------------------

INVALID_NAMES = [
    "",
    " ",
    "exa mple.com",
    "example.com\u0000",
    "\u0000",
    "exa\u0000mple.com",
    "example.com\u0001",
    "example.com\u001f",
    "\u0085example.com",
    "example.com\u000b",
    "example\u001f.com",
    "example.com\u007f",
    "example\u0085.com",
    "example .com",
    "192.0.2.1",
    "[::1]",
    "2001:db8::1",
    "localhost",
    "example..com",
    "-example.com",
    "_dmarc.example.com",
    "*.example.com",
    "a" * 64 + ".com",
    ".".join(["a" * 63] * 4) + ".com",
    "x" * 2000,
    "http://example.com",
    "user@example.com",
    "♥.com",
]


@pytest.mark.parametrize(
    "name", [" example.com", "example.com ", "example.com\n", " \texample.com\r\n"]
)
@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_surrounding_whitespace_is_trimmed(world: World, name: str, method: str) -> None:
    path = BASE if method == "POST" else f"{BASE}/{world.domains['assigned']}"
    response = call(world, "owner", method, path, json={"name": name})
    assert response.status_code in (200, 201), response.text
    assert response.json()["name"] == "example.com"


@pytest.mark.parametrize("name", INVALID_NAMES)
@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_invalid_names_are_422_before_any_write(world: World, name: str, method: str) -> None:
    path = BASE if method == "POST" else f"{BASE}/{world.domains['assigned']}"
    before = snapshot(world)
    response = call(world, "owner", method, path, json={"name": name})
    assert response.status_code == 422, response.text
    assert response.json() == detail("domain.error.invalid_name")
    assert snapshot(world) == before


ESCAPED_INVALID_NAMES: list[bytes] = [
    b'{"name": "\\ud800.com"}',  # lone surrogate (cannot be sent as a Python str)
    b'{"name": "a.com\\udfff"}',
    b'{"name": "exa\\u0000mple.com"}',
    b'{"name": "example.com\\u0000"}',
    b'{"name": "\\u001b[31mexample.com"}',  # ANSI escape
    b'{"name": "' + b"x" * (1024 + 1) + b'.com"}',  # over MAX_INPUT_LENGTH
]


@pytest.mark.parametrize("body", ESCAPED_INVALID_NAMES)
@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_escaped_invalid_names_are_422(world: World, body: bytes, method: str) -> None:
    path = BASE if method == "POST" else f"{BASE}/{world.domains['assigned']}"
    before = snapshot(world)
    response = call(world, "owner", method, path, content=body)
    assert response.status_code == 422, response.text
    assert response.json() == detail("domain.error.invalid_name")
    assert snapshot(world) == before


MALFORMED_BODIES: list[bytes] = [
    b"",
    b"not json",
    b"{",
    b"[]",
    b'"example.com"',
    b"null",
    b"{}",
    b'{"name": 1}',
    b'{"name": null}',
    b'{"name": ["example.com"]}',
    b'{"name": {"x": 1}}',
    b'{"name": true}',
    b'{"name": "a.example", "tenant_id": 2}',  # extra field (no tenant override)
    b'{"name": "a.example", "id": 1}',
    b'{"name": "a.example", "name": "b.example"}',  # duplicate key
    b'{"name\\u0000": "a.example"}',  # NUL in a key
    b'{"name": NaN}',
    b'{"name": Infinity}',
    b'{"name": "a.example"} trailing',
    b'{"name": "\xff\xfe"}',  # invalid UTF-8
    b"\xef\xbb\xbf{}",  # BOM
    b"[" * 20000 + b"]" * 20000,  # deep nesting
]


@pytest.mark.parametrize("body", MALFORMED_BODIES)
@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_malformed_name_bodies_are_422(world: World, body: bytes, method: str) -> None:
    path = BASE if method == "POST" else f"{BASE}/{world.domains['assigned']}"
    before = snapshot(world)
    response = call(world, "owner", method, path, content=body)
    assert response.status_code == 422, response.text
    assert response.json() == detail("api.error.invalid_request")
    assert snapshot(world) == before


MALFORMED_ACCESS: list[bytes] = [
    b"{}",
    b"[]",
    b'{"user_ids": null}',
    b'{"user_ids": 1}',
    b'{"user_ids": ["1"]}',
    b'{"user_ids": [true]}',
    b'{"user_ids": [1.0]}',
    b'{"user_ids": [null]}',
    b'{"user_ids": [], "extra": 1}',
    b'{"user_ids": [], "user_ids": []}',
    b'{"user_ids": "\\u0000"}',
    b'{"user_ids": [' + b",".join([b"1"] * 1001) + b"]}",  # over MAX_ASSIGNMENTS
]


@pytest.mark.parametrize("body", MALFORMED_ACCESS)
def test_malformed_access_bodies_are_422(world: World, body: bytes) -> None:
    before = snapshot(world)
    path = f"{BASE}/{world.domains['assigned']}/access"
    response = call(world, "owner", "PUT", path, content=body)
    assert response.status_code == 422, response.text
    assert response.json() == detail("api.error.invalid_request")
    assert snapshot(world) == before


@pytest.mark.parametrize(
    ("method", "path_key"), [("POST", None), ("PATCH", "assigned"), ("PUT", "assigned")]
)
def test_over_long_bodies_are_413(world: World, method: str, path_key: str | None) -> None:
    path = BASE if path_key is None else f"{BASE}/{world.domains[path_key]}"
    if method == "PUT":
        path += "/access"
    before = snapshot(world)
    big = b'{"name": "' + b"a" * (70 * 1024) + b'"}'
    response = call(world, "owner", method, path, content=big)
    assert response.status_code == 413
    assert response.json() == detail("api.error.payload_too_large")

    def chunks() -> Iterator[bytes]:  # no Content-Length: the streaming limit applies
        yield b'{"name": "'
        for _ in range(70):
            yield b"a" * 1024
        yield b'"}'

    streamed = call(world, "owner", method, path, content=chunks())
    assert streamed.status_code == 413
    assert snapshot(world) == before


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded"])
def test_non_json_content_type_is_415(world: World, content_type: str) -> None:
    before = snapshot(world)
    response = call(
        world,
        "owner",
        "POST",
        BASE,
        content=b'{"name": "a.example"}',
        headers={"Content-Type": content_type},
    )
    assert response.status_code == 415
    assert response.json() == detail("api.error.invalid_request")
    assert snapshot(world) == before


def test_denied_caller_gets_403_whatever_the_body(world: World) -> None:
    response = call(world, "viewer", "POST", BASE, content=b"not json")
    assert response.status_code == 403
    patch = call(world, "analyst", "PATCH", f"{BASE}/{world.domains['assigned']}", content=b"{bad")
    assert patch.status_code == 403


MALFORMED_IDS = ["abc", "0", "-1", "1.0", "1e3", "99999999999999999999", "9" * 40, "%00", "1%20"]


@pytest.mark.parametrize("bad_id", MALFORMED_IDS)
@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("GET", "", None),
        ("PATCH", "", {"name": "x.example"}),
        ("DELETE", "", None),
        ("PUT", "/access", {"user_ids": []}),
    ],
)
def test_malformed_path_ids_are_404(
    world: World, bad_id: str, method: str, suffix: str, body: Any
) -> None:
    before = snapshot(world)
    response = call(world, "owner", method, f"{BASE}/{bad_id}{suffix}", json=body)
    assert response.status_code == 404
    assert response.json() == detail("api.error.not_found")
    assert snapshot(world) == before


@pytest.mark.parametrize(
    "query",
    [
        "limit=abc",
        "limit=-1",
        "limit=1001",
        "offset=-1",
        "offset=x",
        "limit=1.5",
        "offset=9999999999999999999",  # over 2**63 - 1 (would be a DB error)
        "offset=%00",
        "limit=%EF%BC%91",  # full-width digit one
    ],
)
def test_bad_pagination_is_422(world: World, query: str) -> None:
    response = call(world, "owner", "GET", f"{BASE}?{query}")
    assert response.status_code == 422
    assert response.json() == detail("api.error.invalid_request")


def test_pagination(world: World) -> None:
    first = call(world, "owner", "GET", f"{BASE}?limit=1").json()["items"]
    second = call(world, "owner", "GET", f"{BASE}?limit=1&offset=1").json()["items"]
    assert [d["name"] for d in first + second] == ["assigned.example", "unassigned.example"]
    assert call(world, "owner", "GET", f"{BASE}?limit=0").json() == {"items": []}


# --- domain access ----------------------------------------------------------------------------


def test_access_assign_and_unassign_changes_viewer_visibility(world: World) -> None:
    target = world.domains["unassigned"]
    assert call(world, "viewer", "GET", f"{BASE}/{target}").status_code == 404
    viewer = world.users["viewer"]
    put = call(world, "admin", "PUT", f"{BASE}/{target}/access", json={"user_ids": [viewer]})
    assert put.status_code == 200
    assert put.json() == {"domain_id": target, "user_ids": [viewer]}
    assert call(world, "viewer", "GET", f"{BASE}/{target}").status_code == 200
    listed = call(world, "viewer", "GET", BASE).json()["items"]
    assert {d["name"] for d in listed} == {"assigned.example", "unassigned.example"}
    cleared = call(world, "owner", "PUT", f"{BASE}/{target}/access", json={"user_ids": []})
    assert cleared.json() == {"domain_id": target, "user_ids": []}
    assert call(world, "viewer", "GET", f"{BASE}/{target}").status_code == 404


@pytest.mark.parametrize(
    ("user_key", "status", "key"),
    [
        ("b_viewer", 404, "api.error.not_found"),  # member of another tenant only
        ("b_owner", 404, "api.error.not_found"),
        ("analyst", 422, "api.error.invalid_request"),  # member, but not a client viewer
        ("owner", 422, "api.error.invalid_request"),
    ],
)
def test_access_rejects_non_viewers_and_foreign_users(
    world: World, user_key: str, status: int, key: str
) -> None:
    before = snapshot(world)
    path = f"{BASE}/{world.domains['unassigned']}/access"
    response = call(world, "owner", "PUT", path, json={"user_ids": [world.users[user_key]]})
    assert response.status_code == status
    assert response.json() == detail(key)
    assert snapshot(world) == before


@pytest.mark.parametrize("user_id", [0, -1, 10**9, 2**63, 2**70])
def test_access_unknown_user_ids_are_404(world: World, user_id: int) -> None:
    path = f"{BASE}/{world.domains['unassigned']}/access"
    response = call(world, "owner", "PUT", path, json={"user_ids": [user_id]})
    assert response.status_code == 404


def test_delete_removes_access_rows(world: World) -> None:
    target = world.domains["assigned"]
    assert call(world, "owner", "DELETE", f"{BASE}/{target}").status_code == 204
    _domains, access = snapshot(world)
    assert all(domain_id != target for _m, domain_id in access)
    assert call(world, "viewer", "GET", BASE).json() == {"items": []}


# --- i18n -------------------------------------------------------------------------------------


def test_errors_are_translated(world: World) -> None:
    headers = {"Accept-Language": "it"}
    other = f"{BASE}/{world.domains['other']}"
    assert call(world, "owner", "GET", other, headers=headers).json() == detail(
        "api.error.not_found", "it"
    )
    denied = call(world, "viewer", "POST", BASE, json={"name": "x.example"}, headers=headers)
    assert denied.json() == detail("api.error.forbidden", "it")
    bad = call(world, "owner", "POST", BASE, json={"name": "bad name"}, headers=headers)
    assert bad.json() == detail("domain.error.invalid_name", "it")
    assert detail("api.error.not_found", "it") != detail("api.error.not_found", "en")


@pytest.mark.parametrize("method", ["POST", "PATCH"])
def test_db_enforced_duplicate_is_409(
    world: World, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    """The repository pre-check is bypassed (as in a concurrent insert): the unique constraint
    still yields a 409, and the session stays usable for the next request."""
    monkeypatch.setattr(DomainRepository, "get_by_name", lambda self, name: None)
    path = BASE if method == "POST" else f"{BASE}/{world.domains['unassigned']}"
    before = snapshot(world)
    response = call(world, "owner", method, path, json={"name": "assigned.example"})
    assert response.status_code == 409
    assert response.json() == detail("api.error.conflict")
    assert snapshot(world) == before
    assert call(world, "owner", "GET", BASE).status_code == 200
