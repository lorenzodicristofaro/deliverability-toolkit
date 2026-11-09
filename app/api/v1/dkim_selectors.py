"""`/api/v1/dkim-selectors`: administration of DKIM selectors (M5-20).

`?scope=tenant` (default) addresses the active tenant's path, `?scope=global` the global rows; the
rules and semantics are in `app.services.dkim_selectors_admin`. The request never names a tenant.

Status codes (401, 403, 404, 409, 413 and 415 bodies are `{"detail": <i18n>}`):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 the principal lacks the permission for that scope, or a tenant-path write to a global row;
- 404 no active tenant on the tenant path, or a selector that is missing/foreign/malformed id;
- 409 duplicate selector in the scope, or deleting a seeded global selector (disable it instead);
- 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 `{key, message, field, reason}`, never echoing the rejected value.

Permission is decided before the body is read, so a denied caller gets 403 whatever it sent.
Dependencies are solved in parameter order: `ManageScope` must stay before `Body`. On PATCH the
raw body is read (and size-limited) before the selector's visibility is checked, and parsed only
after it: a missing or foreign id with a malformed body is a 404.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.api.v1._common import Body, RawBody, _error, _no_constant, _no_duplicate_keys
from app.api.v1.domains import _MAX_OFFSET, _page_value
from app.core.i18n import t
from app.core.permissions import RuleScope
from app.core.tenancy import TenantContext
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, parse_id
from app.repositories.dkim_selectors import DkimSelectorRecord
from app.services.dkim_selectors_admin import (
    INVALID_FIELD_KEY,
    DkimSelectorsAdminError,
    DkimSelectorsAdminService,
    SelectorFieldInvalid,
)
from app.web.deps import CurrentSession, DbDep
from app.web.templating import request_language

router = APIRouter(prefix="/dkim-selectors", tags=["dkim-selectors"])


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


def _raise(request: Request, exc: DkimSelectorsAdminError) -> NoReturn:
    if isinstance(exc, SelectorFieldInvalid):
        raise _problem(request, exc.key, exc.field, exc.reason) from None
    raise _error(request, exc.status, exc.key) from None


# --- dependencies -------------------------------------------------------------------------------


def _service(db: DbDep, auth: CurrentSession) -> DkimSelectorsAdminService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return DkimSelectorsAdminService(db, ctx, auth.principal)


Service = Annotated[DkimSelectorsAdminService, Depends(_service)]


def _scope(request: Request, _auth: Service, scope: str | None = None) -> RuleScope:
    """Authentication first (via `Service`), so an anonymous caller gets 401, not 422."""
    if scope is None:
        return RuleScope.TENANT
    if scope not in (RuleScope.TENANT.value, RuleScope.GLOBAL.value):
        raise _problem(request, INVALID_FIELD_KEY, "scope", "invalid_choice")
    return RuleScope(scope)


Scope = Annotated[RuleScope, Depends(_scope)]


def _manage(request: Request, service: Service, scope: Scope) -> RuleScope:
    try:
        service.check_manage(scope)
    except DkimSelectorsAdminError as exc:
        _raise(request, exc)
    return scope


ManageScope = Annotated[RuleScope, Depends(_manage)]


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
        raise _problem(request, INVALID_FIELD_KEY, "body", "malformed_json") from None
    if not isinstance(data, dict):
        raise _problem(request, INVALID_FIELD_KEY, "body", "not_an_object")
    return data


# --- responses ----------------------------------------------------------------------------------


def _selector_json(record: DkimSelectorRecord) -> dict[str, Any]:
    """The owning tenant and author stay out: a selector's reader needs neither."""
    return {
        "id": record.id,
        "scope": record.scope,
        "selector": record.selector,
        "provider": record.provider,
        "record_type": record.record_type,
        "notes": record.notes,
        "enabled": record.enabled,
        "sources": None if record.sources is None else list(record.sources),
        "verified_on": None if record.verified_on is None else record.verified_on.isoformat(),
        "status": record.status,
        "seed_key": record.seed_key,
        "locally_modified": record.locally_modified,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


# --- routes -------------------------------------------------------------------------------------


@router.get("")
def list_selectors(
    request: Request,
    service: Service,
    scope: Scope,
    limit: str | None = None,
    offset: str | None = None,
) -> dict[str, Any]:
    page_limit = _page_value(request, limit, DEFAULT_LIMIT, MAX_LIMIT)
    page_offset = _page_value(request, offset, 0, _MAX_OFFSET)
    try:
        records = service.list_selectors(scope, limit=page_limit, offset=page_offset)
    except DkimSelectorsAdminError as exc:
        _raise(request, exc)
    return {"items": [_selector_json(r) for r in records]}


@router.post("", status_code=201)
def create_selector(
    request: Request, scope: ManageScope, service: Service, body: Body
) -> dict[str, Any]:
    data = _json_object(request, body)
    try:
        return _selector_json(service.create(scope, data))
    except DkimSelectorsAdminError as exc:
        _raise(request, exc)


@router.get("/{selector_id}")
def get_selector(
    request: Request, service: Service, scope: Scope, selector_id: str
) -> dict[str, Any]:
    try:
        return _selector_json(service.get_selector(scope, parse_id(selector_id)))
    except DkimSelectorsAdminError as exc:
        _raise(request, exc)


@router.patch("/{selector_id}")
def update_selector(
    request: Request, scope: ManageScope, service: Service, body: Body, selector_id: str
) -> dict[str, Any]:
    target = parse_id(selector_id)
    try:
        service.check_write(scope, target)
        return _selector_json(service.update(scope, target, _json_object(request, body)))
    except DkimSelectorsAdminError as exc:
        _raise(request, exc)


@router.delete("/{selector_id}", status_code=204)
def delete_selector(
    request: Request, scope: ManageScope, service: Service, selector_id: str
) -> Response:
    try:
        service.delete(scope, parse_id(selector_id))
    except DkimSelectorsAdminError as exc:
        _raise(request, exc)
    return Response(status_code=204)
