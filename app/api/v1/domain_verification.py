"""Domain ownership verification routes (M7-21a); the rules are in
`app.services.domain_verification`.

- `GET /api/v1/domains/{domain_id}/verification`: the status (`domain.read`);
- `POST /api/v1/domains/{domain_id}/verification`: start, i.e. issue a new token (`domain.verify`);
  201 with the record to publish. This response is the only place the token ever appears; it is
  sent with `Cache-Control: no-store`;
- `POST /api/v1/domains/{domain_id}/verification/check`: look the record up now
  (`domain.verify`); 200 with `outcome` (`verified`, `not_found`, `expired`, `not_started`,
  `error`) and the status. A DNS failure is data (`outcome: error` with `dns_state`), never a
  verified domain.

No request body is read. Status codes (bodies are `{"detail": <i18n>}`, never echoing input):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 404 no active tenant; a domain that is missing, foreign, malformed or unassigned (client
  viewer);
- 403 a visible domain without `domain.verify` (analyst, client viewer, toggled-off user).

The resolver is the checks' (`dns_backend`, faked in tests); the clock is a dependency so tests
fix "now".
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import _error
from app.api.v1.checks import ResolverDep
from app.api.v1.domains import _domain_id
from app.core.permissions import Principal
from app.core.tenancy import TenantContext
from app.services.clock import Clock, SystemClock
from app.services.domain_verification import (
    DomainVerificationService,
    StartResult,
    VerificationState,
    VerifyResult,
    verify,
)
from app.services.domains import DomainServiceError
from app.web.deps import CurrentSession, DbDep, SettingsDep, current_principal, tenant_ctx

router = APIRouter(prefix="/domains", tags=["domains"])

NO_STORE = {"Cache-Control": "no-store"}


def verification_clock() -> Clock:
    """The clock for token expiry; overridden in tests."""
    return SystemClock()


def _raise(request: Request, exc: DomainServiceError) -> NoReturn:
    raise _error(request, exc.status, exc.key) from None


def _ctx(request: Request, auth: CurrentSession) -> TenantContext:
    try:
        return tenant_ctx(auth)
    except HTTPException as exc:
        raise _error(request, exc.status_code, "api.error.not_found") from None


def verification_service(
    db: DbDep,
    ctx: Annotated[TenantContext, Depends(_ctx)],
    principal: Annotated[Principal, Depends(current_principal)],
    settings: SettingsDep,
    clock: Annotated[Clock, Depends(verification_clock)],
) -> DomainVerificationService:
    ttl = timedelta(hours=settings.domain_verify_token_ttl_hours)
    return DomainVerificationService(db, ctx, principal, clock, ttl)


Service = Annotated[DomainVerificationService, Depends(verification_service)]


def _when(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def state_json(state: VerificationState) -> dict[str, Any]:
    return {
        "domain_id": state.domain_id,
        "status": state.status,
        "method": state.method,
        "verified_at": _when(state.verified_at),
        "pending": state.pending,
        "token_expires_at": _when(state.token_expires_at),
        "record_name": state.record_name,
    }


def _start_json(result: StartResult) -> dict[str, Any]:
    return {
        "record_type": result.record_type,
        "record_name": result.record_name,
        "record_value": result.record_value,
        "verification": state_json(result.state),
    }


def _verify_json(result: VerifyResult) -> dict[str, Any]:
    return {
        "outcome": str(result.outcome),
        "dns_state": result.dns_state,
        "verification": state_json(result.state),
    }


@router.get("/{domain_id}/verification")
def get_verification(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        return state_json(service.status(_domain_id(domain_id)))
    except DomainServiceError as exc:
        _raise(request, exc)


@router.post("/{domain_id}/verification", status_code=201)
def start_verification(request: Request, service: Service, domain_id: str) -> JSONResponse:
    try:
        result = service.start(_domain_id(domain_id))
    except DomainServiceError as exc:
        _raise(request, exc)
    return JSONResponse(_start_json(result), status_code=201, headers=NO_STORE)


@router.post("/{domain_id}/verification/check")
async def check_verification(
    request: Request, service: Service, resolver: ResolverDep, domain_id: str
) -> dict[str, Any]:
    target = _domain_id(domain_id)
    try:
        await run_in_threadpool(service.check_verify, target)
        result = await verify(service, resolver, target)
    except DomainServiceError as exc:
        _raise(request, exc)
    return _verify_json(result)
