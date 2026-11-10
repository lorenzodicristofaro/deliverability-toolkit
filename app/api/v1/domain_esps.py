"""ESP routes (M6-03): the profile catalogue and a domain's ESP assignments.

- `GET /api/v1/esp-profiles`: the loaded ESP profiles (id, name, homepage, status, verified_on,
  sources), read-only, from `app.esp.profile`;
- `GET /api/v1/domains/{domain_id}/esps`: the domain's assignments, ordered by esp_id;
- `PUT /api/v1/domains/{domain_id}/esps/{esp_id}`: assign, body optional
  `{"return_path_host": ..., "tracking_host": ...}` (both default to null). 201 when the pair is
  new, 200 when it existed (its hosts set to the given ones; resending changes nothing);
- `DELETE /api/v1/domains/{domain_id}/esps/{esp_id}`: 204.

The rules are in `app.services.domain_esps`. Status codes (401, 403, 404, 409, 413 and 415 bodies
are `{"detail": <i18n>}`):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 client viewers on every route, and readers without `domain.update` on writes;
- 404 no active tenant; a domain that is missing, foreign, malformed or (viewer) unassigned; an
  assignment that does not exist (DELETE);
- 413 body over MAX_BODY_BYTES; 415 a non-empty body that is not `application/json`;
- 503 `api.domain_esps.error.profiles_unavailable` when the ESP profiles cannot be loaded (broken
  profile directory, logged as a warning) on the catalogue, the list and PUT, after the
  permission and domain checks; DELETE does not need the profiles;
- 422 a malformed body (`{"detail": <i18n>}`, as the domains API), or a rejected field as
  `{key, message, field, reason}` (unknown esp_id, invalid host, host outside the domain, too
  many ESPs), never echoing the rejected value.

The body is read (size-limited) before the permission and domain checks and parsed only after
them, so a denied caller or a missing domain gets 403/404 whatever it sent. The profile source is
the `esp_profiles` dependency (tests override it with a fixture directory).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import StrictStr

from app.api.v1._common import Body, RawBody, _error, _parse, _Strict
from app.api.v1.domains import _domain_id
from app.core.i18n import t
from app.core.tenancy import TenantContext
from app.esp.profile import EspProfile, load_esp_profiles
from app.repositories.domain_esps import DomainEspRecord
from app.services.domain_esps import (
    DomainEspError,
    DomainEspService,
    EspFieldInvalid,
    ProfileSource,
)
from app.web.deps import CurrentSession, DbDep
from app.web.templating import request_language

router = APIRouter(tags=["esps"])


# --- errors -------------------------------------------------------------------------------------


def _raise(request: Request, exc: DomainEspError) -> NoReturn:
    if isinstance(exc, EspFieldInvalid):
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


def esp_profiles() -> ProfileSource:
    """The ESP profile source; overridden in tests."""
    return load_esp_profiles


def _service(
    db: DbDep, auth: CurrentSession, profiles: Annotated[ProfileSource, Depends(esp_profiles)]
) -> DomainEspService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return DomainEspService(db, ctx, auth.principal, profiles)


# Dependencies are solved in parameter order: the service (401 anonymous) comes before the body.
Service = Annotated[DomainEspService, Depends(_service)]


# --- payloads -----------------------------------------------------------------------------------


class AssignIn(_Strict):
    # Length and characters are checked by the repository (-> invalid_host / host_outside_domain);
    # the body size limit bounds the raw strings.
    return_path_host: StrictStr | None = None
    tracking_host: StrictStr | None = None


def _assign_payload(request: Request, body: RawBody) -> AssignIn:
    """An empty body means no hosts; anything else is strict JSON."""
    if not body.data:
        return AssignIn()
    return _parse(request, AssignIn, body)


# --- responses ----------------------------------------------------------------------------------


def _profile_json(profile: EspProfile) -> dict[str, Any]:
    return {
        "id": profile.id,
        "name": profile.name,
        "homepage": profile.homepage,
        "status": profile.status,
        "verified_on": profile.verified_on.isoformat(),
        "sources": list(profile.sources),
    }


def _assignment_json(record: DomainEspRecord, names: dict[str, str]) -> dict[str, Any]:
    """The owning tenant stays out. `name` is null when the profile is no longer loaded."""
    return {
        "domain_id": record.domain_id,
        "esp_id": record.esp_id,
        "name": names.get(record.esp_id),
        "return_path_host": record.return_path_host,
        "tracking_host": record.tracking_host,
        "created_at": record.created_at.isoformat(),
    }


def _items(records: Sequence[DomainEspRecord], names: dict[str, str]) -> dict[str, Any]:
    return {"items": [_assignment_json(r, names) for r in records]}


# --- routes -------------------------------------------------------------------------------------


@router.get("/esp-profiles")
def list_esp_profiles(request: Request, service: Service) -> dict[str, Any]:
    try:
        profiles = service.catalogue()
    except DomainEspError as exc:
        _raise(request, exc)
    return {"items": [_profile_json(p) for p in profiles]}


@router.get("/domains/{domain_id}/esps")
def list_domain_esps(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        records = service.list_for_domain(_domain_id(domain_id))
        names = service.profile_names()
    except DomainEspError as exc:
        _raise(request, exc)
    return _items(records, names)


@router.put("/domains/{domain_id}/esps/{esp_id}")
def put_domain_esp(
    request: Request, service: Service, body: Body, domain_id: str, esp_id: str
) -> Response:
    try:
        target = service.check_write(_domain_id(domain_id))
        payload = _assign_payload(request, body)
        result = service.assign(
            target,
            esp_id,
            return_path_host=payload.return_path_host,
            tracking_host=payload.tracking_host,
        )
        # The profiles were just loaded by `assign` (a successful load is cached).
        names = service.profile_names()
    except DomainEspError as exc:
        _raise(request, exc)
    content = _assignment_json(result.record, names)
    return JSONResponse(content, status_code=201 if result.created else 200)


@router.delete("/domains/{domain_id}/esps/{esp_id}", status_code=204)
def delete_domain_esp(request: Request, service: Service, domain_id: str, esp_id: str) -> Response:
    try:
        service.remove(_domain_id(domain_id), esp_id)
    except DomainEspError as exc:
        _raise(request, exc)
    return Response(status_code=204)
