"""`/api/v1/domains`: domains of the session's active tenant (M1-18, GM decision Q7).

Status codes (never echoing user input or other-tenant data; bodies are `{"detail": <i18n>}`):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 404 no active tenant, a domain that is missing/foreign/malformed id/unassigned (client viewer);
- 403 a visible domain or the tenant the principal may not change (e.g. client viewer, analyst);
- 409 duplicate name in the tenant; 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 malformed JSON/body (duplicate keys, NaN, extra fields, wrong types) or invalid name.

Bodies are read with a hard size limit and parsed here (strict JSON, then strict pydantic) so the
framework's default 422 body, which echoes the input, is never produced.
"""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, StrictInt, StrictStr

from app.api.v1._common import Body, _error, _parse, _Strict
from app.core.permissions import Principal
from app.core.tenancy import TenantContext
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, parse_id
from app.repositories.domain_access import MAX_ASSIGNMENTS
from app.services.domains import (
    DomainAccessView,
    DomainService,
    DomainServiceError,
    DomainView,
)
from app.web.deps import CurrentSession, DbDep, current_principal, tenant_ctx

router = APIRouter(prefix="/domains", tags=["domains"])

_MAX_PAGE_DIGITS = 19  # limit / offset: 2**63 - 1 has 19 digits
_MAX_OFFSET = 2**63 - 1  # SQL OFFSET is a signed 64-bit value on PostgreSQL and SQLite


# --- errors -------------------------------------------------------------------------------------


def _raise(request: Request, exc: DomainServiceError) -> NoReturn:
    raise _error(request, exc.status, exc.key) from None


# --- dependencies -------------------------------------------------------------------------------


def _ctx(request: Request, auth: CurrentSession) -> TenantContext:
    """`tenant_ctx`, with the translated 404 body when there is no active tenant."""
    try:
        return tenant_ctx(auth)
    except HTTPException as exc:
        raise _error(request, exc.status_code, "api.error.not_found") from None


def _service(
    db: DbDep,
    ctx: Annotated[TenantContext, Depends(_ctx)],
    principal: Annotated[Principal, Depends(current_principal)],
) -> DomainService:
    return DomainService(db, ctx, principal)


# Dependencies are solved in parameter order: the service (401 anonymous, 404 no active tenant)
# always comes before the body.
Service = Annotated[DomainService, Depends(_service)]
# --- payloads -----------------------------------------------------------------------------------


class DomainIn(_Strict):
    # Length and characters are checked by to_ascii_domain (-> domain.error.invalid_name); the
    # body size limit bounds the raw string.
    name: StrictStr


class AccessIn(_Strict):
    user_ids: list[StrictInt] = Field(max_length=MAX_ASSIGNMENTS)


def _domain_id(value: str) -> int | None:
    """Path id as a positive int; anything else is None (answered as 404, like a missing id)."""
    return parse_id(value)


def _page_value(request: Request, raw: str | None, default: int, maximum: int | None) -> int:
    if raw is None:
        return default
    if not raw.isascii() or not raw.isdigit() or len(raw) > _MAX_PAGE_DIGITS:
        raise _error(request, 422, "api.error.invalid_request")
    value = int(raw)
    if maximum is not None and value > maximum:
        raise _error(request, 422, "api.error.invalid_request")
    return value


def _domain_json(view: DomainView) -> dict[str, Any]:
    return {
        "id": view.id,
        "name": view.name,
        "display_name": view.display_name,
        "created_at": view.created_at.isoformat(),
    }


def _access_json(view: DomainAccessView) -> dict[str, Any]:
    return {"domain_id": view.domain_id, "user_ids": list(view.user_ids)}


# --- routes -------------------------------------------------------------------------------------


@router.get("")
def list_domains(
    request: Request, service: Service, limit: str | None = None, offset: str | None = None
) -> dict[str, Any]:
    page_limit = _page_value(request, limit, DEFAULT_LIMIT, MAX_LIMIT)
    page_offset = _page_value(request, offset, 0, _MAX_OFFSET)
    try:
        views = service.list(limit=page_limit, offset=page_offset)
    except DomainServiceError as exc:
        _raise(request, exc)
    return {"items": [_domain_json(v) for v in views]}


@router.post("", status_code=201)
def create_domain(request: Request, service: Service, body: Body) -> dict[str, Any]:
    try:
        service.check_create()  # permission first: 403 whatever the body contains
        payload = _parse(request, DomainIn, body)
        return _domain_json(service.create(payload.name))
    except DomainServiceError as exc:
        _raise(request, exc)


@router.get("/{domain_id}")
def get_domain(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        return _domain_json(service.get(_domain_id(domain_id)))
    except DomainServiceError as exc:
        _raise(request, exc)


@router.patch("/{domain_id}")
def update_domain(request: Request, service: Service, body: Body, domain_id: str) -> dict[str, Any]:
    try:
        target = _domain_id(domain_id)
        service.check_update(target)
        payload = _parse(request, DomainIn, body)
        view = service.rename(target, payload.name)
        return {
            **_domain_json(view),
            "esp_hosts_rewritten": view.esp_hosts_rewritten,
            "esp_hosts_unmatched": view.esp_hosts_unmatched,
        }
    except DomainServiceError as exc:
        _raise(request, exc)


@router.delete("/{domain_id}", status_code=204)
def delete_domain(request: Request, service: Service, domain_id: str) -> Response:
    try:
        service.delete(_domain_id(domain_id))
    except DomainServiceError as exc:
        _raise(request, exc)
    return Response(status_code=204)


@router.put("/{domain_id}/access")
def put_domain_access(
    request: Request, service: Service, body: Body, domain_id: str
) -> dict[str, Any]:
    try:
        target = _domain_id(domain_id)
        service.check_set_access(target)
        payload = _parse(request, AccessIn, body)
        return _access_json(service.set_access(target, payload.user_ids))
    except DomainServiceError as exc:
        _raise(request, exc)
