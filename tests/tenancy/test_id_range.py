"""M5-17b: an id outside the INTEGER range behaves exactly like an unknown id.

PostgreSQL binds ids as INTEGER, so a larger value used to raise DataError and give a 500 (SQLite
just missed). The bound is `app.repositories.base.MAX_ID`, enforced by `coerce_id` and `parse_id`.

- behaviour: every route with a numeric id, on SQLite and PostgreSQL (shared tenancy world). An
  out-of-range id gets the same status, content type and body as an unknown id and as a domain of
  another tenant;
- schema: every key column really is INTEGER, in the models and in the migrated database;
- guards, from the route table and the source: every path parameter is either parsed by the
  shared parser or declared non-numeric; every route with a numeric path id has a behaviour row;
  every integer id field of a JSON body is registered; every `int()` in the web and API layers is
  a known one, so an id read by hand from a form cannot appear unnoticed. No network.

Limits of the guards. They are name-based: outside the path, an id is recognised by a name or alias
ending in `id` or `ids`, so a numeric id called `target` with no such alias is not seen. The `int()`
allowlist works per top-level function, so another `int()` added to a listed function is not
noticed. Only direct `int(...)` calls are seen, not `map(int, ...)` or a renamed `int`.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Annotated, Any, get_args

import pytest
from fastapi import Body, FastAPI, Query
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field
from sqlalchemy import BigInteger, Integer
from sqlalchemy import inspect as sa_inspect
from starlette.convertors import IntegerConvertor
from starlette.routing import Route

from app.api.v1.domains import _domain_id as api_domain_id
from app.cli.tenant_scope import MAX_OPERATOR_ID
from app.core.tenancy import TenantContext
from app.models.base import Base
from app.repositories import UserMembershipsRepository, repo_for
from app.repositories.base import MAX_ID, coerce_id, parse_id
from app.services.auth import revoke_all_sessions, revoke_session
from app.web.domains import _domain_id as web_domain_id
from tests.tenancy.conftest import World, assert_pristine, leaks
from tests.tenancy.test_matrix import (
    LEAVES,
    Leaf,
    b_custom_check,
    b_rule,
    b_selector,
    leaf_routes,
)

ROOT = Path(__file__).resolve().parents[2]
UNKNOWN_ID = 999_999_999  # in range, and no seeded row has it
BOUNDARY_IDS = (2147483647, 2147483648, 2**63 - 1)
BOUNDARY_PARAMS = pytest.mark.parametrize("value", BOUNDARY_IDS, ids=["max", "max+1", "2^63-1"])
LIMIT_HINTS = ("2147483647", "out of range", "integer", "overflow")
_CSRF_INPUT = re.compile(r'name="csrf_token" value="[^"]*"')


# --- behaviour ---------------------------------------------------------------------------------


def _name(_w: World) -> dict[str, str]:
    return {"name": "probe-range.example"}


def _access(w: World) -> dict[str, list[int]]:
    return {"user_ids": [w.users["viewer"]]}


def _check_ids(_w: World) -> dict[str, list[str]]:
    return {"ids": ["spf"]}


Payload = Callable[[World], Any] | None

# (method, route path) -> request payload. Must list every route with a numeric path id.
ID_ROUTES: dict[tuple[str, str], Payload] = {
    ("GET", "/domains/{domain_id}"): None,
    ("GET", "/domains/{domain_id}/rename"): None,
    ("POST", "/domains/{domain_id}/rename"): _name,
    ("GET", "/domains/{domain_id}/delete"): None,
    ("POST", "/domains/{domain_id}/delete"): None,
    ("GET", "/domains/{domain_id}/authentication"): None,
    ("GET", "/domains/{domain_id}/authentication/dkim/stream"): None,
    ("GET", "/api/v1/domains/{domain_id}"): None,
    ("PATCH", "/api/v1/domains/{domain_id}"): _name,
    ("DELETE", "/api/v1/domains/{domain_id}"): None,
    ("PUT", "/api/v1/domains/{domain_id}/access"): _access,
    ("POST", "/api/v1/domains/{domain_id}/checks"): _check_ids,
    ("POST", "/api/v1/domains/{domain_id}/checks/{check_id}"): None,
}


def _outcome(response: Any) -> tuple[int, str | None, str]:
    """What the client can compare. HTML pages echo the request's own path (language form `next`)
    and carry the per-session CSRF token; everything else must match byte for byte."""
    body = response.text.replace(response.request.url.path, "<request-path>")
    body = _CSRF_INPUT.sub("<csrf>", body)
    return response.status_code, response.headers.get("content-type"), body


def _call(world: World, who: str, key: tuple[str, str], domain_id: int) -> Any:
    method, template = key
    path = template.replace("{domain_id}", str(domain_id)).replace("{check_id}", "all")
    payload = ID_ROUTES[key]
    body = None if payload is None else payload(world)
    if path.startswith("/api/"):
        return world.send(who, method, path, json=body)
    return world.send(who, method, path, form=body)


@BOUNDARY_PARAMS
@pytest.mark.parametrize("who", ["owner", "viewer"])
@pytest.mark.parametrize("key", list(ID_ROUTES), ids=" ".join)
def test_out_of_range_path_id_is_an_unknown_id(
    world: World,
    logs: pytest.LogCaptureFixture,
    key: tuple[str, str],
    who: str,
    value: int,
) -> None:
    unknown = _outcome(_call(world, who, key, UNKNOWN_ID))
    foreign = _outcome(_call(world, who, key, world.domains["secret"]))
    response = _call(world, who, key, value)
    assert _outcome(response) == unknown == foreign
    assert response.status_code == 404
    if value > MAX_ID:
        assert not [hint for hint in LIMIT_HINTS if hint in response.text.casefold()]
    assert not leaks(world, response, logs)
    assert_pristine(world)


@BOUNDARY_PARAMS
@pytest.mark.parametrize("shape", ["alone", "after_valid"])
def test_out_of_range_user_id_in_access_body_is_an_unknown_user(
    world: World, logs: pytest.LogCaptureFixture, shape: str, value: int
) -> None:
    path = f"/api/v1/domains/{world.domains['assigned']}/access"
    prefix = [] if shape == "alone" else [world.users["viewer"]]

    def put(user_id: int) -> Any:
        return world.send("owner", "PUT", path, json={"user_ids": [*prefix, user_id]})

    unknown = _outcome(put(UNKNOWN_ID))
    foreign = _outcome(put(world.users["b_viewer"]))
    response = put(value)
    assert _outcome(response) == unknown == foreign
    assert response.status_code == 404
    if value > MAX_ID:
        assert not [hint for hint in LIMIT_HINTS if hint in response.text.casefold()]
    assert not leaks(world, response, logs)
    assert_pristine(world)


# Content rule routes (M5-18). Their own table: a client viewer has no `rules.read`, so it is
# refused (403) before any id is looked at, the same answer for every id.
RULE_ID_ROUTES: dict[tuple[str, str], Any] = {
    ("GET", "/api/v1/rules/{rule_id}"): None,
    ("PATCH", "/api/v1/rules/{rule_id}"): {"name": "probe"},
    ("DELETE", "/api/v1/rules/{rule_id}"): None,
    ("GET", "/rules/{rule_id}/edit"): None,
    ("POST", "/rules/{rule_id}/edit"): {"name": "probe"},
    ("POST", "/rules/{rule_id}/toggle"): {"enabled": "0"},
    ("POST", "/rules/{rule_id}/delete"): None,
}


@BOUNDARY_PARAMS
@pytest.mark.parametrize(("who", "status"), [("owner", 404), ("viewer", 403)])
@pytest.mark.parametrize("key", list(RULE_ID_ROUTES), ids=" ".join)
def test_out_of_range_rule_id_is_an_unknown_rule(
    world: World,
    logs: pytest.LogCaptureFixture,
    key: tuple[str, str],
    who: str,
    status: int,
    value: int,
) -> None:
    method, template = key

    def send(rule_id: int) -> Any:
        path = template.replace("{rule_id}", str(rule_id))
        payload = RULE_ID_ROUTES[key]
        if path.startswith("/api/"):
            return world.send(who, method, path, json=payload)
        return world.send(who, method, path, form=payload)

    foreign = b_rule(world)
    unknown_outcome = _outcome(send(UNKNOWN_ID))
    foreign_outcome = _outcome(send(foreign.id))
    response = send(value)
    assert _outcome(response) == unknown_outcome == foreign_outcome
    assert response.status_code == status
    if value > MAX_ID:
        assert not [hint for hint in LIMIT_HINTS if hint in response.text.casefold()]
    assert not leaks(world, response, logs)
    assert b_rule(world) == foreign
    assert_pristine(world)


# DKIM selector routes (M5-20): same permissions as the content rules, so the same two answers.
SELECTOR_ID_ROUTES: dict[tuple[str, str], Any] = {
    ("GET", "/api/v1/dkim-selectors/{selector_id}"): None,
    ("PATCH", "/api/v1/dkim-selectors/{selector_id}"): {"notes": "probe"},
    ("DELETE", "/api/v1/dkim-selectors/{selector_id}"): None,
    ("GET", "/dkim-selectors/{selector_id}/edit"): None,
    ("POST", "/dkim-selectors/{selector_id}/edit"): {"notes": "probe"},
    ("POST", "/dkim-selectors/{selector_id}/toggle"): {"enabled": "0"},
    ("POST", "/dkim-selectors/{selector_id}/delete"): None,
}


@BOUNDARY_PARAMS
@pytest.mark.parametrize(("who", "status"), [("owner", 404), ("viewer", 403)])
@pytest.mark.parametrize("key", list(SELECTOR_ID_ROUTES), ids=" ".join)
def test_out_of_range_selector_id_is_an_unknown_selector(
    world: World,
    logs: pytest.LogCaptureFixture,
    key: tuple[str, str],
    who: str,
    status: int,
    value: int,
) -> None:
    method, template = key

    def send(selector_id: int) -> Any:
        path = template.replace("{selector_id}", str(selector_id))
        payload = SELECTOR_ID_ROUTES[key]
        if path.startswith("/api/"):
            return world.send(who, method, path, json=payload)
        return world.send(who, method, path, form=payload)

    foreign = b_selector(world)
    unknown_outcome = _outcome(send(UNKNOWN_ID))
    foreign_outcome = _outcome(send(foreign.id))
    response = send(value)
    assert _outcome(response) == unknown_outcome == foreign_outcome
    assert response.status_code == status
    if value > MAX_ID:
        assert not [hint for hint in LIMIT_HINTS if hint in response.text.casefold()]
    assert not leaks(world, response, logs)
    assert b_selector(world) == foreign
    assert_pristine(world)


# Custom check routes (M5-23): the content rules' table shape (no `rules.read` for a viewer).
CUSTOM_CHECK_ID_ROUTES: dict[tuple[str, str], Any] = {
    ("GET", "/api/v1/custom-checks/{custom_check_id}"): None,
    ("PATCH", "/api/v1/custom-checks/{custom_check_id}"): {"name": "probe"},
    ("DELETE", "/api/v1/custom-checks/{custom_check_id}"): None,
    ("GET", "/custom-checks/{custom_check_id}/edit"): None,
    ("POST", "/custom-checks/{custom_check_id}/edit"): {"name": "probe"},
    ("POST", "/custom-checks/{custom_check_id}/toggle"): {"enabled": "0"},
    ("POST", "/custom-checks/{custom_check_id}/delete"): None,
}


@BOUNDARY_PARAMS
@pytest.mark.parametrize(("who", "status"), [("owner", 404), ("viewer", 403)])
@pytest.mark.parametrize("key", list(CUSTOM_CHECK_ID_ROUTES), ids=" ".join)
def test_out_of_range_custom_check_id_is_an_unknown_check(
    world: World,
    logs: pytest.LogCaptureFixture,
    key: tuple[str, str],
    who: str,
    status: int,
    value: int,
) -> None:
    method, template = key

    def send(check_id: int) -> Any:
        path = template.replace("{custom_check_id}", str(check_id))
        return world.send(who, method, path, json=CUSTOM_CHECK_ID_ROUTES[key])

    foreign = b_custom_check(world)
    unknown_outcome = _outcome(send(UNKNOWN_ID))
    foreign_outcome = _outcome(send(foreign.id))
    response = send(value)
    assert _outcome(response) == unknown_outcome == foreign_outcome
    assert response.status_code == status
    if value > MAX_ID:
        assert not [hint for hint in LIMIT_HINTS if hint in response.text.casefold()]
    assert not leaks(world, response, logs)
    assert b_custom_check(world) == foreign
    assert_pristine(world)


@BOUNDARY_PARAMS
def test_out_of_range_domain_in_custom_check_dry_run_is_an_unknown_domain(
    world: World, logs: pytest.LogCaptureFixture, value: int
) -> None:
    """`domain_id` of the dry-run body is read as JSON and goes through `coerce_id`."""

    def send(domain_id: int) -> Any:
        body = {
            "domain_id": domain_id,
            "kind": "dns_exists",
            "definition": {"name": "{domain}", "rrtype": "A"},
        }
        return world.send("owner", "POST", "/api/v1/custom-checks/test", json=body)

    unknown = _outcome(send(UNKNOWN_ID))
    foreign = _outcome(send(world.domains["secret"]))
    response = send(value)
    assert _outcome(response) == unknown == foreign
    assert response.status_code == 404
    assert not leaks(world, response, logs)
    assert_pristine(world)


@BOUNDARY_PARAMS
def test_out_of_range_tenant_in_switch_form_is_an_unknown_tenant(
    world: World, logs: pytest.LogCaptureFixture, value: int
) -> None:
    def switch(tenant_id: int) -> Any:
        form = {"tenant_id": str(tenant_id), "next": "/"}
        return world.send("owner", "POST", "/tenants/switch", fresh=True, form=form)

    unknown = _outcome(switch(UNKNOWN_ID))
    foreign = _outcome(switch(world.tenants["b"]))
    response = switch(value)
    assert _outcome(response) == unknown == foreign
    assert response.status_code == 404
    assert "set-cookie" not in response.headers
    if value > MAX_ID:
        assert not [hint for hint in LIMIT_HINTS if hint in response.text.casefold()]
    assert not leaks(world, response, logs)
    assert_pristine(world)


@BOUNDARY_PARAMS
def test_out_of_range_ids_reach_no_query_outside_the_routes(world: World, value: int) -> None:
    """The non-route callers of `coerce_id`: on PostgreSQL an unchecked bind would raise."""
    ctx = TenantContext(world.tenants["a"], world.users["owner"])
    repos = repo_for(ctx, world.db)
    memberships = UserMembershipsRepository(world.db, world.users["owner"])
    assert repos.domains.get(value) is None
    assert repos.memberships.get_by_user(value) is None
    assert repos.domain_access.domain_ids_for_user(value) == frozenset()
    assert repos.domain_esps.list_for_domain(value) == []
    assert repos.domain_esps.add(value, "esp") is None
    assert repos.domain_esps.remove(value, "esp") is False
    assert memberships.get_for_tenant(value) is None
    assert revoke_session(world.db, value) is False
    assert revoke_all_sessions(world.db, value) == 0


# --- parsers -----------------------------------------------------------------------------------


def test_boundary_is_the_integer_column_maximum() -> None:
    assert MAX_ID == 2147483647
    assert MAX_OPERATOR_ID == MAX_ID  # the CLI keeps its own constant: the two must not drift


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, 1),
        (MAX_ID, MAX_ID),
        (MAX_ID + 1, None),
        (2**63 - 1, None),
        (2**63, None),
        (0, None),
        (-1, None),
        (True, None),
        ("1", None),
        (1.0, None),
        (None, None),
    ],
    ids=repr,
)
def test_coerce_id_bounds(value: Any, expected: int | None) -> None:
    assert coerce_id(value) == expected


@pytest.mark.parametrize("parser", [parse_id, web_domain_id, api_domain_id])
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", 1),
        ("2147483647", 2147483647),
        ("0000000000000000001", 1),  # 19 characters: zero-padding is still accepted
        ("2147483648", None),
        (str(2**63 - 1), None),
        (str(2**63), None),
        ("00000000000000000001", None),  # 20 characters
        ("9" * 5000, None),  # over the int() digit limit: must not raise
        ("0", None),
        ("-1", None),
        ("+1", None),
        ("", None),
        (" 1", None),
        ("1\n", None),
        ("1_000", None),
        ("1.0", None),
        ("0x10", None),
        ("abc", None),
        ("١٢٣", None),  # non-ASCII digits
        ("²", None),
    ],
    ids=repr,
)
def test_parse_id(parser: Callable[[str], int | None], raw: str, expected: int | None) -> None:
    assert parser(raw) == expected


# --- schema ------------------------------------------------------------------------------------

# Id columns that are neither `*_id` nor declared keys in every model.
_EXTRA_ID_COLUMNS = {"created_by"}
# `*_id` columns that are not row ids, with the reason (keys are (table, column)).
_TEXT_ID_COLUMNS = {
    ("domain_esps", "esp_id"): "ESP profile slug; profiles live in YAML, not in a table",
}


def _id_columns() -> Iterator[tuple[str, Any]]:
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            exempt = (table.name, column.name) in _TEXT_ID_COLUMNS
            if exempt and not column.primary_key and not column.foreign_keys:
                continue
            if (
                column.primary_key
                or column.foreign_keys
                or column.name.endswith("_id")
                or column.name in _EXTRA_ID_COLUMNS
            ):
                yield table.name, column


def test_every_id_column_of_the_models_is_integer() -> None:
    columns = list(_id_columns())
    assert len(columns) >= 10  # the walk really found the schema
    wrong = [f"{t}.{c.name}: {c.type!r}" for t, c in columns if type(c.type) is not Integer]
    assert not wrong


def test_every_id_column_of_the_migrated_schema_is_integer(world: World) -> None:
    inspector = sa_inspect(world.db.get_bind())
    reflected = {
        (table, column["name"]): column["type"]
        for table in inspector.get_table_names()
        for column in inspector.get_columns(table)
    }
    wrong = []
    for table, column in _id_columns():
        kind = reflected[(table, column.name)]
        if not isinstance(kind, Integer) or isinstance(kind, BigInteger):
            wrong.append(f"{table}.{column.name}: {kind!r}")
    assert not wrong


# --- guards ------------------------------------------------------------------------------------

# Path parameters that are not database ids, with the reason. Anything else must be parsed.
NON_NUMERIC_PATH_PARAMS = {"check_id": "name of a registered check ('spf', 'all'), never a row"}
# The functions that apply MAX_ID to text. `_domain_id` delegates to `parse_id` in both layers
# (test_parse_id runs them through the same table).
ID_PARSERS = {"parse_id", "_domain_id"}
# Integer id fields of JSON bodies, each proven to end in `coerce_id` by a behaviour test above.
INT_BODY_FIELDS = {("AccessIn", "user_ids")}
# Every `int()` of the web and API layers: none of them handles an id.
KNOWN_INT_CALLS = {
    ("app/api/v1/_common.py", "_raw_body"),  # Content-Length
    ("app/api/v1/content.py", "_read_capped"),  # Content-Length
    ("app/api/v1/domains.py", "_page_value"),  # limit / offset
    ("app/api/v1/message.py", "_read_capped"),  # Content-Length
    ("app/web/checks_stream.py", "dkim_events"),  # duration in ms
    ("app/web/content.py", "_read_capped"),  # Content-Length
    ("app/web/custom_checks.py", "_read_capped"),  # Content-Length
    ("app/web/dkim_selectors.py", "_read_capped"),  # Content-Length
    ("app/web/message.py", "_read_capped"),  # Content-Length
    ("app/web/rules.py", "_read_capped"),  # Content-Length
    ("app/web/rules.py", "_weight"),  # rule weight, 0 to 100
}


def _dependants(route: APIRoute) -> Iterator[Any]:
    stack = [route.dependant]
    while stack:
        dependant = stack.pop()
        yield dependant
        stack.extend(dependant.dependencies)


def _is_id_name(name: object) -> bool:
    """True for a name or alias of an id. Header aliases use hyphens; a missing alias is None."""
    if not isinstance(name, str):
        return False
    normal = name.replace("-", "_").casefold()
    return normal in ("id", "ids") or normal.endswith(("_id", "_ids"))


def _holds_int(annotation: Any) -> bool:
    return annotation is int or any(_holds_int(arg) for arg in get_args(annotation))


def _parses(call: Callable[..., Any] | None, param: str) -> bool:
    """True if the source of `call` passes `param` to one of the shared id parsers."""
    if call is None:
        return False
    tree = ast.parse(inspect.getsource(inspect.unwrap(call)).lstrip())
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ID_PARSERS
        and any(isinstance(arg, ast.Name) and arg.id == param for arg in node.args)
        for node in ast.walk(tree)
    )


def route_violations(leaves: list[Leaf]) -> list[str]:
    """Routes that could hand an unchecked id to the database."""
    found: list[str] = []
    for leaf in leaves:
        label = f"{leaf.method} {leaf.path}"
        if isinstance(leaf.route, Route) and not isinstance(leaf.route, APIRoute):
            if "{" in leaf.path:
                found.append(f"{label}: plain route with a path parameter")
            continue
        if not isinstance(leaf.route, APIRoute):
            continue
        for name, convertor in leaf.route.param_convertors.items():
            if isinstance(convertor, IntegerConvertor):
                found.append(f"{label}: {name} uses the :int convertor")
        dependants = list(_dependants(leaf.route))
        for dependant in dependants:
            for param in dependant.path_params:
                if param.name in NON_NUMERIC_PATH_PARAMS:
                    continue
                if param.field_info.annotation is not str:
                    found.append(f"{label}: path parameter {param.name} must be declared str")
                if not any(_parses(d.call, param.name) for d in dependants):
                    found.append(f"{label}: path parameter {param.name} skips the id parser")
            others = (
                *dependant.query_params,
                *dependant.header_params,
                *dependant.cookie_params,
                *dependant.body_params,
            )
            for param in others:
                if _is_id_name(param.name) or _is_id_name(param.alias):
                    found.append(f"{label}: {param.name} is an id outside the path")
    return found


def int_id_fields(model: type[BaseModel]) -> set[tuple[str, str]]:
    """The fields of `model` holding integers under the name or an alias of an id."""
    return {
        (model.__name__, name)
        for name, field in model.model_fields.items()
        if _holds_int(field.annotation)
        and (_is_id_name(name) or _is_id_name(field.alias) or _is_id_name(field.validation_alias))
    }


def numeric_id_routes(leaves: list[Leaf]) -> set[tuple[str, str]]:
    return {
        leaf.key
        for leaf in leaves
        if isinstance(leaf.route, APIRoute)
        and any(
            param.name not in NON_NUMERIC_PATH_PARAMS
            for dependant in _dependants(leaf.route)
            for param in dependant.path_params
        )
    }


def int_calls(source: str) -> set[str]:
    """Names of the top-level functions of `source` that call `int()` ("" for module level)."""
    tree = ast.parse(source)
    found = set()
    for node in tree.body:
        name = getattr(node, "name", "")
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "int"
            ):
                found.add(name)
    return found


def _app_modules() -> Iterator[Any]:
    """Every module of the web and API layers, found on disk: `pkgutil` skips folders without an
    `__init__.py`, such as app/api/v1."""
    for folder in ("app/web", "app/api"):
        for path in (ROOT / folder).rglob("*.py"):
            parts = path.relative_to(ROOT).with_suffix("").parts
            yield importlib.import_module(".".join(parts).removesuffix(".__init__"))


def test_every_path_parameter_goes_through_the_shared_parser() -> None:
    assert not route_violations(LEAVES)


def test_every_numeric_id_route_has_a_behaviour_row() -> None:
    assert numeric_id_routes(LEAVES) == (
        set(ID_ROUTES) | set(RULE_ID_ROUTES) | set(SELECTOR_ID_ROUTES) | set(CUSTOM_CHECK_ID_ROUTES)
    )


def test_every_integer_id_field_of_a_json_body_is_registered() -> None:
    found = set()
    for module in _app_modules():
        for value in vars(module).values():
            if not (
                inspect.isclass(value)
                and issubclass(value, BaseModel)
                and value.__module__.startswith("app.")
            ):
                continue
            found |= int_id_fields(value)
    assert found == INT_BODY_FIELDS


def test_every_int_call_of_the_web_and_api_layers_is_known() -> None:
    found = {
        (path.relative_to(ROOT).as_posix(), name)
        for folder in ("app/web", "app/api")
        for path in (ROOT / folder).rglob("*.py")
        for name in int_calls(path.read_text(encoding="utf-8"))
    }
    assert found == KNOWN_INT_CALLS


# --- the guards detect what they claim to --------------------------------------------------------


def _ok(domain_id: str) -> Any:
    return parse_id(domain_id)


def _unparsed(domain_id: str) -> Any:
    return domain_id


def _typed_int(domain_id: int) -> Any:
    return domain_id


def _in_query(domain_id: str, tenant_id: str = "1") -> Any:
    return parse_id(domain_id), tenant_id


def _query_alias(domain_id: str, target: Annotated[str, Query(alias="tenant_id")] = "1") -> Any:
    return parse_id(domain_id), target


def _body_embedded(domain_id: str, tenant_id: Annotated[int, Body(embed=True)]) -> Any:
    return parse_id(domain_id), tenant_id


def _body_list(domain_id: str, user_ids: Annotated[list[int], Body()]) -> Any:
    return parse_id(domain_id), user_ids


def _body_alias(domain_id: str, target: Annotated[int, Body(alias="tenant_id", embed=True)]) -> Any:
    return parse_id(domain_id), target


def _body_not_id(domain_id: str, count: Annotated[int, Body(embed=True)]) -> Any:
    return parse_id(domain_id), count


@pytest.mark.parametrize(
    ("path", "endpoint", "expected"),
    [
        ("/x/{domain_id}", _ok, None),
        ("/x/{domain_id}", _unparsed, "skips the id parser"),
        ("/x/{domain_id}", _typed_int, "must be declared str"),
        ("/x/{domain_id:int}", _ok, ":int convertor"),
        ("/x/{domain_id}", _in_query, "tenant_id is an id outside the path"),
        ("/x/{domain_id}", _query_alias, "target is an id outside the path"),
        ("/x/{domain_id}", _body_embedded, "tenant_id is an id outside the path"),
        ("/x/{domain_id}", _body_list, "user_ids is an id outside the path"),
        ("/x/{domain_id}", _body_alias, "target is an id outside the path"),
        ("/x/{domain_id}", _body_not_id, None),
    ],
    ids=[
        "parsed",
        "unparsed",
        "int-annotation",
        "int-convertor",
        "query-id",
        "query-alias",
        "body-embedded",
        "body-list",
        "body-alias",
        "body-not-id",
    ],
)
def test_route_guard_detects_violations(
    path: str, endpoint: Callable[..., Any], expected: str | None
) -> None:
    application = FastAPI()
    application.add_api_route(path, endpoint, methods=["POST"])
    found = route_violations([x for x in leaf_routes(application) if "/x/" in x.path])
    if expected is None:
        assert not found
    else:
        assert any(expected in item for item in found), found


class _ModelAlias(BaseModel):
    target: int = Field(alias="domain_id")


class _ModelValidationAlias(BaseModel):
    target: int = Field(validation_alias="domain_id")


class _ModelName(BaseModel):
    user_ids: list[int]


class _ModelNotId(BaseModel):
    count: int


class _ModelStringId(BaseModel):
    check_id: str


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        (_ModelAlias, {("_ModelAlias", "target")}),
        (_ModelValidationAlias, {("_ModelValidationAlias", "target")}),
        (_ModelName, {("_ModelName", "user_ids")}),
        (_ModelNotId, set()),
        (_ModelStringId, set()),
    ],
    ids=["alias", "validation-alias", "name", "not-an-id", "string-id"],
)
def test_body_field_scan_detects_ids(
    model: type[BaseModel], expected: set[tuple[str, str]]
) -> None:
    assert int_id_fields(model) == expected


def test_int_call_scan_detects_a_new_conversion() -> None:
    source = "def read(form):\n    return int(form['tenant_id'])\n"
    assert int_calls(source) == {"read"}
    assert int_calls("def read(form):\n    return form['tenant_id']\n") == set()
