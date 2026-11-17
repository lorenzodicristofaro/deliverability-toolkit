"""Monitor target routes (M7-11): a domain's scheduled checks.

- `GET /api/v1/monitors`: the active tenant's targets on the domains the caller may read
  (client viewers: assigned domains only), ordered by id;
- `GET /api/v1/domains/{domain_id}/monitor`: the domain's target;
- `POST /api/v1/domains/{domain_id}/monitor`: create it, body
  `{"check_ids": [...], "interval_seconds": N, "enabled": true}` (`enabled` optional, default
  true); 201. The first run is due at once (`next_run_at` = now);
- `PATCH /api/v1/domains/{domain_id}/monitor`: change any of those three fields; 200;
- `DELETE /api/v1/domains/{domain_id}/monitor`: 204.

The rules are in `app.services.monitors`. Status codes (401, 403, 404, 409, 413, 415 bodies are
`{"detail": <i18n>}`):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 a readable domain without `monitor.read`, or a write without `monitor.manage` (client
  viewers, toggled-off users); the list without `domain.list`;
- 404 no active tenant; a domain that is missing, foreign, malformed, unassigned (client viewer)
  or not readable; a domain without a target (GET, PATCH, DELETE);
- 409 `monitor.error.exists`: the domain already has a target (POST);
- 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 a malformed body (`{"detail": <i18n>}`, as the domains API: wrong types, unknown or null
  fields, duplicate keys), or a rejected field as `{key, message, field, reason}` (`check_ids`
  unknown/empty/duplicate, `interval_seconds` not in the allowed set, `target` limit_reached for
  the per-tenant cap), never echoing the rejected value.

The body is read (size-limited) before the permission and domain checks and parsed only after
them, so a denied caller or a missing domain gets 403/404 whatever it sent.
"""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import Field, StrictBool, StrictInt, StrictStr

from app.api.v1._common import Body, _error, _parse, _Strict
from app.api.v1.domains import _domain_id
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.repositories.monitor_targets import MonitorTargetRecord
from app.services.clock import Clock, SystemClock
from app.services.monitors import MonitorError, MonitorFieldInvalid, MonitorService
from app.web.deps import CurrentSession, DbDep, SettingsDep
from app.web.templating import request_language

router = APIRouter(tags=["monitors"])

# Far above the number of built-in checks; the repository rejects unknown ids anyway.
MAX_CHECK_IDS = 64


# --- errors -------------------------------------------------------------------------------------


def _raise(request: Request, exc: MonitorError) -> NoReturn:
    if isinstance(exc, MonitorFieldInvalid):
        raise HTTPException(
            status_code=422,
            detail={
                "key": exc.key,
                "message": t(exc.key, request_language(request.scope)),
                "field": exc.field,
                "reason": exc.reason,
            },
        ) from None
    raise _error(request, exc.status, exc.key) from None


# --- dependencies -------------------------------------------------------------------------------


def monitor_clock() -> Clock:
    """The clock for the first `next_run_at`; overridden in tests."""
    return SystemClock()


def _service(
    db: DbDep,
    auth: CurrentSession,
    settings: SettingsDep,
    clock: Annotated[Clock, Depends(monitor_clock)],
) -> MonitorService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return MonitorService(
        db,
        ctx,
        auth.principal,
        max_targets=settings.monitor_max_targets_per_tenant,
        clock=clock,
    )


# Dependencies are solved in parameter order: the service (401 anonymous) comes before the body.
Service = Annotated[MonitorService, Depends(_service)]


# --- payloads -----------------------------------------------------------------------------------


class MonitorIn(_Strict):
    check_ids: list[StrictStr] = Field(max_length=MAX_CHECK_IDS)
    interval_seconds: StrictInt
    enabled: StrictBool = True


class MonitorPatch(_Strict):
    # None means "not sent"; an explicit null is rejected in `_patch_fields`.
    check_ids: list[StrictStr] | None = Field(default=None, max_length=MAX_CHECK_IDS)
    interval_seconds: StrictInt | None = None
    enabled: StrictBool | None = None


def _patch_fields(request: Request, payload: MonitorPatch) -> dict[str, object]:
    fields = {name: getattr(payload, name) for name in payload.model_fields_set}
    if any(value is None for value in fields.values()):
        raise _error(request, 422, "api.error.invalid_request")
    return fields


# --- responses ----------------------------------------------------------------------------------


def _target_json(record: MonitorTargetRecord) -> dict[str, Any]:
    """The owning tenant stays out."""
    return {
        "id": record.id,
        "domain_id": record.domain_id,
        "check_ids": list(record.check_ids),
        "interval_seconds": record.interval_seconds,
        "enabled": record.enabled,
        "next_run_at": record.next_run_at.isoformat(),
        "last_run_at": None if record.last_run_at is None else record.last_run_at.isoformat(),
        "last_status": record.last_status,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


# --- routes -------------------------------------------------------------------------------------


@router.get("/monitors")
def list_monitors(request: Request, service: Service) -> dict[str, Any]:
    try:
        records = service.list_targets()
    except MonitorError as exc:
        _raise(request, exc)
    return {"items": [_target_json(r) for r in records]}


@router.get("/domains/{domain_id}/monitor")
def get_monitor(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        record = service.get(_domain_id(domain_id))
    except MonitorError as exc:
        _raise(request, exc)
    return _target_json(record)


@router.post("/domains/{domain_id}/monitor")
def create_monitor(request: Request, service: Service, body: Body, domain_id: str) -> Response:
    try:
        target = service.check_manage(_domain_id(domain_id))
        payload = _parse(request, MonitorIn, body)
        record = service.create(
            target,
            check_ids=payload.check_ids,
            interval_seconds=payload.interval_seconds,
            enabled=payload.enabled,
        )
    except MonitorError as exc:
        _raise(request, exc)
    return JSONResponse(_target_json(record), status_code=201)


@router.patch("/domains/{domain_id}/monitor")
def update_monitor(
    request: Request, service: Service, body: Body, domain_id: str
) -> dict[str, Any]:
    try:
        target = service.check_manage(_domain_id(domain_id))
        fields = _patch_fields(request, _parse(request, MonitorPatch, body))
        record = service.update(target, **fields)
    except MonitorError as exc:
        _raise(request, exc)
    return _target_json(record)


@router.delete("/domains/{domain_id}/monitor", status_code=204)
def delete_monitor(request: Request, service: Service, domain_id: str) -> Response:
    try:
        service.delete(_domain_id(domain_id))
    except MonitorError as exc:
        _raise(request, exc)
    return Response(status_code=204)
