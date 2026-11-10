"""`/api/v1/custom-checks`: administration of custom checks (M5-23).

`?scope=tenant` (default) addresses the active tenant's path, `?scope=global` the global rows; the
rules and semantics are in `app.services.custom_checks_admin`. The request never names a tenant.

Status codes (401, 403, 404, 409, 413 and 415 bodies are `{"detail": <i18n>}`):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 the principal lacks the permission for that scope, or a tenant-path write to a global
  check; on `/test`, no `rules.read` (client viewers) or no `check.run` on the domain;
- 404 no active tenant on the tenant path, a check that is missing/foreign/malformed id, or on
  `/test` a domain that is missing, foreign, unassigned or out of range;
- 409 duplicate check_key in the scope; 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 `{key, message, field, reason}`, never echoing the rejected value; `http_fetch` is
  `api.custom_checks.error.kind_unavailable`.

`POST /test` body: `domain_id`, `kind`, `definition`, optional `severity` (default medium) and
`remediation_text`. It answers 200 with the `CheckResult` wire JSON of the check runner, exactly
as a domain run would print it; a DNS failure is DATA (status `error`), never `ok`. Nothing is
stored.

Permission is decided before the body is read, so a denied caller gets 403 whatever it sent.
Dependencies are solved in parameter order: `ManageScope` / `TestAccess` must stay before `Body`.
On PATCH the raw body is read (and size-limited) before the check's visibility is checked, and
parsed only after it. `/test` releases the database connection before any DNS work.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import Body, RawBody, _error, _no_constant, _no_duplicate_keys
from app.api.v1.checks import ResolverDep
from app.api.v1.domains import _MAX_OFFSET, _page_value
from app.checks.models import CheckContext
from app.checks.registry import CheckRegistry
from app.core.i18n import t
from app.core.permissions import RuleScope
from app.core.tenancy import TenantContext
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, parse_id
from app.repositories.custom_checks import CustomCheckRecord
from app.services.checks import run_check
from app.services.custom_checks_admin import (
    INVALID_DEFINITION_KEY,
    CustomCheckFieldInvalid,
    CustomChecksAdminError,
    CustomChecksAdminService,
    DryRun,
)
from app.web.deps import CurrentSession, DbDep
from app.web.templating import request_language

router = APIRouter(prefix="/custom-checks", tags=["custom-checks"])


# --- errors -------------------------------------------------------------------------------------


def _problem(request: Request, key: str, field: str, reason: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "key": key,
            "message": t(key, request_language(request.scope)),
            "field": field,
            "reason": reason,
        },
    )


def _raise(request: Request, exc: CustomChecksAdminError) -> NoReturn:
    if isinstance(exc, CustomCheckFieldInvalid):
        raise _problem(request, exc.key, exc.field, exc.reason) from None
    raise _error(request, exc.status, exc.key) from None


# --- dependencies -------------------------------------------------------------------------------


def _service(db: DbDep, auth: CurrentSession) -> CustomChecksAdminService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return CustomChecksAdminService(db, ctx, auth.principal)


Service = Annotated[CustomChecksAdminService, Depends(_service)]


def _scope(request: Request, _auth: Service, scope: str | None = None) -> RuleScope:
    """Authentication first (via `Service`), so an anonymous caller gets 401, not 422."""
    if scope is None:
        return RuleScope.TENANT
    if scope not in (RuleScope.TENANT.value, RuleScope.GLOBAL.value):
        raise _problem(request, INVALID_DEFINITION_KEY, "scope", "invalid_choice")
    return RuleScope(scope)


Scope = Annotated[RuleScope, Depends(_scope)]


def _manage(request: Request, service: Service, scope: Scope) -> RuleScope:
    try:
        service.check_manage(scope)
    except CustomChecksAdminError as exc:
        _raise(request, exc)
    return scope


ManageScope = Annotated[RuleScope, Depends(_manage)]


def _test_access(request: Request, service: Service) -> None:
    try:
        service.check_test()
    except CustomChecksAdminError as exc:
        _raise(request, exc)


TestAccess = Annotated[None, Depends(_test_access)]


def _json_object(request: Request, body: RawBody) -> dict[str, Any]:
    """Strict JSON (no duplicate keys, no NaN/Infinity). The field checks are the service's."""
    if not body.is_json:
        raise _error(request, 415, "api.error.invalid_request")
    try:
        data = json.loads(
            body.data.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_constant,
        )
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
        raise _problem(request, INVALID_DEFINITION_KEY, "body", "malformed_json") from None
    if not isinstance(data, dict):
        raise _problem(request, INVALID_DEFINITION_KEY, "body", "not_an_object")
    return data


# --- responses ----------------------------------------------------------------------------------


def _thaw(value: Any) -> Any:
    """The record's read-only definition as plain JSON values."""
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(v) for v in value]
    return value


def _check_json(record: CustomCheckRecord) -> dict[str, Any]:
    """The owning tenant and author stay out: a check's reader needs neither."""
    text = record.remediation_text
    return {
        "id": record.id,
        "scope": record.scope,
        "check_key": record.check_key,
        "name": record.name,
        "description": record.description,
        "kind": record.kind,
        "definition": _thaw(record.definition),
        "severity": record.severity,
        "remediation_key": record.remediation_key,
        "remediation_text": None if text is None else text.as_dict(),
        "enabled": record.enabled,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


# --- routes -------------------------------------------------------------------------------------


@router.get("")
def list_custom_checks(
    request: Request,
    service: Service,
    scope: Scope,
    limit: str | None = None,
    offset: str | None = None,
) -> dict[str, Any]:
    page_limit = _page_value(request, limit, DEFAULT_LIMIT, MAX_LIMIT)
    page_offset = _page_value(request, offset, 0, _MAX_OFFSET)
    try:
        records = service.list_checks(scope, limit=page_limit, offset=page_offset)
    except CustomChecksAdminError as exc:
        _raise(request, exc)
    return {"items": [_check_json(r) for r in records]}


@router.post("", status_code=201)
def create_custom_check(
    request: Request, scope: ManageScope, service: Service, body: Body
) -> dict[str, Any]:
    data = _json_object(request, body)
    try:
        return _check_json(service.create(scope, data))
    except CustomChecksAdminError as exc:
        _raise(request, exc)


# Declared before the `{custom_check_id}` routes so "test" is never read as an id.
@router.post("/test", response_class=Response)
async def test_custom_check(
    request: Request,
    _access: TestAccess,
    service: Service,
    db: DbDep,
    body: Body,
    resolver: ResolverDep,
) -> Response:
    data = _json_object(request, body)

    def prepare() -> DryRun:
        try:
            return service.prepare_test(data)
        finally:
            db.rollback()  # no connection is held during the DNS work

    try:
        dry = await run_in_threadpool(prepare)
    except CustomChecksAdminError as exc:
        _raise(request, exc)
    ctx = CheckContext(
        resolver=resolver, tenant_id=str(dry.tenant_id), domain_id=str(dry.domain_id)
    )
    registry = CheckRegistry()
    registry.register(dry.check)
    result = await run_check(dry.check.id, dry.domain_name, ctx, registry=registry)
    return Response(content=result.model_dump_json(), media_type="application/json")


@router.get("/{custom_check_id}")
def get_custom_check(
    request: Request, service: Service, scope: Scope, custom_check_id: str
) -> dict[str, Any]:
    try:
        return _check_json(service.get_check(scope, parse_id(custom_check_id)))
    except CustomChecksAdminError as exc:
        _raise(request, exc)


@router.patch("/{custom_check_id}")
def update_custom_check(
    request: Request, scope: ManageScope, service: Service, body: Body, custom_check_id: str
) -> dict[str, Any]:
    target = parse_id(custom_check_id)
    try:
        service.check_write(scope, target)
        return _check_json(service.update(scope, target, _json_object(request, body)))
    except CustomChecksAdminError as exc:
        _raise(request, exc)


@router.delete("/{custom_check_id}", status_code=204)
def delete_custom_check(
    request: Request, scope: ManageScope, service: Service, custom_check_id: str
) -> Response:
    try:
        service.delete(scope, parse_id(custom_check_id))
    except CustomChecksAdminError as exc:
        _raise(request, exc)
    return Response(status_code=204)
