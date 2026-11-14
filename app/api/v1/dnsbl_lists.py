"""`/api/v1/dnsbl-lists`: DNSBL list enablement by the instance admin (M7-05c).

Routes (rules in `app.services.dnsbl_admin`):
- `GET  /dnsbl-lists`                    every list of `seeds/dnsbl.yaml` with its usage policy
                                         text, sources, verification status and enabled state;
- `POST /dnsbl-lists/{list_id}/enable`   body `{"policy_acknowledged": true}`, plus
                                         `"unverified_confirmed": true` for an unverified list;
- `POST /dnsbl-lists/{list_id}/disable`  no body needed.

Instance-level: the request never names a tenant and the active tenant plays no part.

Status codes (bodies are `{"detail": <i18n>}`, never echoing user input):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 any principal without the instance admin flag, every tenant role included;
- 404 a list id that is not in the seed file (after the permission);
- 409 enable/disable of a `default_enabled` list (it always runs);
- 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 malformed body, missing policy acknowledgement or missing unverified confirmation;
- 503 the list data cannot be loaded.

The permission is decided before the body is read, and the list id before the body is parsed.
"""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, Request
from pydantic import StrictBool

from app.api.v1._common import Body, _error, _parse, _Strict
from app.services.dnsbl_admin import DnsblAdminError, DnsblAdminService, DnsblListView
from app.web.deps import CurrentSession, DbDep

router = APIRouter(prefix="/dnsbl-lists", tags=["dnsbl-lists"])


class EnableIn(_Strict):
    policy_acknowledged: StrictBool = False
    unverified_confirmed: StrictBool = False


def _raise(request: Request, exc: DnsblAdminError) -> NoReturn:
    raise _error(request, exc.status, exc.key) from None


def _service(db: DbDep, auth: CurrentSession) -> DnsblAdminService:
    return DnsblAdminService(db, auth.principal)


Service = Annotated[DnsblAdminService, Depends(_service)]


def _manage(request: Request, service: Service) -> DnsblAdminService:
    try:
        service.check_manage()
    except DnsblAdminError as exc:
        _raise(request, exc)
    return service


Manager = Annotated[DnsblAdminService, Depends(_manage)]


def view_json(view: DnsblListView) -> dict[str, Any]:
    lst, record = view.entry, view.record
    return {
        "id": lst.id,
        "name": lst.name,
        "zone": lst.zone,
        "kind": lst.kind,
        "status": lst.status,
        "unverified_fields": sorted(lst.unverified_fields),
        "verified_on": lst.verified_on.isoformat(),
        "sources": list(lst.sources),
        "usage_policy": lst.usage_policy,
        "default_enabled": lst.default_enabled,
        "enabled": view.enabled,
        "enablement": None
        if record is None
        else {
            "enabled_by": record.enabled_by,
            "enabled_at": record.enabled_at.isoformat(),
            "policy_acknowledged": record.policy_acknowledged,
            "policy_acknowledged_at": record.policy_acknowledged_at.isoformat(),
            "unverified_confirmed": record.unverified_confirmed,
        },
    }


@router.get("")
def list_dnsbl_lists(request: Request, service: Manager) -> dict[str, Any]:
    try:
        return {"items": [view_json(v) for v in service.views()]}
    except DnsblAdminError as exc:
        _raise(request, exc)


@router.post("/{list_id}/enable")
def enable_dnsbl_list(
    request: Request, service: Manager, body: Body, list_id: str
) -> dict[str, Any]:
    try:
        service.find(list_id)
        payload = _parse(request, EnableIn, body)
        view = service.enable(
            list_id,
            policy_acknowledged=payload.policy_acknowledged,
            unverified_confirmed=payload.unverified_confirmed,
        )
    except DnsblAdminError as exc:
        _raise(request, exc)
    return view_json(view)


@router.post("/{list_id}/disable")
def disable_dnsbl_list(request: Request, service: Manager, list_id: str) -> dict[str, Any]:
    try:
        return view_json(service.disable(list_id))
    except DnsblAdminError as exc:
        _raise(request, exc)
