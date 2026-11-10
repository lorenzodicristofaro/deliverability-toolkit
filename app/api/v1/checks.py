"""`/api/v1` check endpoints (M3-15). Checks run live; nothing is persisted in M3.

Routes (all POST, so the CSRF rules are those of `/api/v1/domains`):
- `/domains/{domain_id}/checks/{check_id}`: one check, or `all` (every registered check, then the
  enabled custom checks of the active tenant and the global ones, M5-23);
  the domain routes also know `esp` (M6-06, `app.services.domain_esps.resolve_esp_run`): the
  domain's assigned ESPs, read through the tenant repository. It is part of `all` only when the
  domain has an assignment (sorted among the built-ins); requested by id with no assignment it is
  the `ESP_NONE_ASSIGNED` info result. Every role that may run checks on the domain gets the
  full `esp` result, client viewers on their assigned domains included (M6-06c). The free route
  does not know `esp`;
- `/domains/{domain_id}/checks`: body `{"ids": [...]}`;
- `/checks/free`: body `{"name": ..., "ids": [...]}`, no tenant data.

The response body is the `CheckResult` wire JSON of the M3-02 service, byte for byte
(`model_dump_json`), so the API and the CLI print the same thing. A single check answers with one
object; `all` and `ids` answer with an array of objects in request order (`all`: the built-in
checks sorted by id, then the custom checks in creation order; with no enabled custom check and no
assigned ESP it is exactly the pre-M5 answer).

Status codes (bodies are `{"detail": <i18n>}`, never echoing user input):
- 401 anonymous (mutations first need a valid CSRF token, else the middleware answers 403);
- 404 no active tenant; a domain that is missing, foreign, malformed or (client viewer) unassigned;
- 403 the principal lacks `check.run` on a visible domain, or `dns.tools` on the free route;
- 413 body over MAX_BODY_BYTES; 415 not `application/json`;
- 422 malformed body, unknown or duplicate check id, too many ids, invalid domain name;
- 200 whenever the checks ran: a DNS failure is DATA (status `error`) in the body.

The resolver comes from the `dns_backend` dependency (tests override it with a fake; no network).
Domain routes probe the DKIM selectors of the global table plus the active tenant's
(`app.services.dkim_probe_selectors`); the free route stays on the seed list. The database
connection is released before any DNS work.
Caps: `MAX_IDS` checks per request, the service's per-request concurrency bound and
`MAX_PROBE_SELECTORS`. There is no per-user rate limiting yet, so one request can still fan out
many DNS queries (DKIM probe).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import Field, StrictStr
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import Body, _error, _parse, _Strict
from app.api.v1.dns_tools import Backend
from app.api.v1.domain_esps import esp_profiles
from app.api.v1.domains import _domain_id
from app.checks.dkim import DkimCheck
from app.checks.models import CheckContext, CheckResult
from app.checks.registry import CheckRegistry
from app.core.domain_names import InvalidDomainName, to_dns_name
from app.core.permissions import Action, DomainResource, TenantResource, can
from app.core.tenancy import TenantContext
from app.dns.types import Resolver
from app.services.checks import (
    InvalidTarget,
    UnknownCheck,
    default_registry,
    run_check,
    run_checks,
)
from app.services.custom_checks_admin import run_checks_for
from app.services.dkim_probe_selectors import registry_for, resolve_probe_selectors
from app.services.domain_esps import ESP_CHECK_ID, ProfileSource, resolve_esp_run
from app.services.domains import DomainService, DomainServiceError, DomainView
from app.web.deps import CurrentSession, DbDep, tenant_ctx

router = APIRouter(tags=["checks"])

MAX_IDS = 8
MAX_NAME_LEN = 1024  # raw input; the validator enforces the real DNS limits
ALL = "all"

_Ids = Annotated[
    list[Annotated[StrictStr, Field(max_length=64)]], Field(min_length=1, max_length=MAX_IDS)
]


class IdsIn(_Strict):
    ids: _Ids


class FreeIn(_Strict):
    name: Annotated[StrictStr, Field(max_length=MAX_NAME_LEN)]
    ids: _Ids


def _resolver(backend: Backend) -> Resolver:
    """The resolver checks use; overridden in tests through `dns_backend`."""
    return backend.default


ResolverDep = Annotated[Resolver, Depends(_resolver)]
ProfilesDep = Annotated[ProfileSource, Depends(esp_profiles)]


# --- access -------------------------------------------------------------------------------------


class _CheckTarget:
    __slots__ = ("ctx", "view")

    def __init__(self, ctx: TenantContext, view: DomainView) -> None:
        self.ctx = ctx
        self.view = view


def _check_target(
    request: Request, auth: CurrentSession, db: DbDep, domain_id: str
) -> _CheckTarget:
    """401 anonymous, 404 no tenant / invisible domain, 403 without `check.run` on it."""
    try:
        ctx = tenant_ctx(auth)
    except HTTPException:
        raise _error(request, 404, "api.error.not_found") from None
    try:
        view = DomainService(db, ctx, auth.principal).get(_domain_id(domain_id))
    except DomainServiceError as exc:
        raise _error(request, exc.status, exc.key) from None
    if not can(auth.principal, Action.CHECK_RUN, DomainResource(ctx.tenant_id, view.id)):
        raise _error(request, 403, "api.error.forbidden")
    return _CheckTarget(ctx, view)


CheckTarget = Annotated[_CheckTarget, Depends(_check_target)]


def _free_access(request: Request, auth: CurrentSession) -> TenantContext:
    """401 anonymous, 404 no active tenant, 403 without `dns.tools`."""
    try:
        ctx = tenant_ctx(auth)
    except HTTPException:
        raise _error(request, 404, "api.error.not_found") from None
    if not can(auth.principal, Action.DNS_TOOLS, TenantResource(ctx.tenant_id)):
        raise _error(request, 403, "api.error.forbidden")
    return ctx


FreeAccess = Annotated[TenantContext, Depends(_free_access)]


# --- helpers ------------------------------------------------------------------------------------


def _invalid(request: Request) -> HTTPException:
    return _error(request, 422, "api.error.invalid_request")


def _json(results: Sequence[CheckResult], *, many: bool) -> Response:
    """The service's own wire JSON, not reshaped."""
    bodies = [r.model_dump_json() for r in results]
    content = "[" + ",".join(bodies) + "]" if many else bodies[0]
    return Response(content=content, media_type="application/json")


def _validate_ids(request: Request, ids: Sequence[str], *, esp: bool = False) -> list[str]:
    known = set(default_registry().all_ids())
    if esp:
        known.add(ESP_CHECK_ID)
    if len(set(ids)) != len(ids) or any(i not in known for i in ids):
        raise _invalid(request)
    return list(ids)


_MANY: dict[int | str, dict[str, Any]] = {200: {"model": list[CheckResult]}}


def _body_doc(model: type[_Strict]) -> dict[str, Any]:
    schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}


def _context(
    resolver: Resolver, tenant_id: int | None = None, domain_id: int | None = None
) -> CheckContext:
    return CheckContext(
        resolver=resolver,
        tenant_id=None if tenant_id is None else str(tenant_id),
        domain_id=None if domain_id is None else str(domain_id),
    )


def _prepare(
    access: _CheckTarget, db: Session, ids: Sequence[str], profiles: ProfileSource
) -> CheckRegistry | None:
    """The registry of a domain run (None: no DKIM and no ESP, the default one); ends the
    transaction."""
    try:
        registry = None
        if DkimCheck.id in ids:
            registry = registry_for(resolve_probe_selectors(access.ctx, db))
        if ESP_CHECK_ID in ids:
            esp = resolve_esp_run(access.ctx, db, access.view.id, profiles)
            registry = (registry or default_registry()).with_checks([esp.check])
    finally:
        db.rollback()
    return registry


def _prepare_all(
    access: _CheckTarget, db: Session, profiles: ProfileSource
) -> tuple[CheckRegistry, list[str]]:
    """The registry and ids of `all`: built-ins (DKIM on the tenant's selectors, `esp` when the
    domain has an assigned ESP) plus the tenant's custom checks; ends
    the transaction. The ESP assignments are read last, so a failure there cannot affect the
    other reads."""
    try:
        registry = registry_for(resolve_probe_selectors(access.ctx, db))
        custom = run_checks_for(access.ctx, db)
        esp = resolve_esp_run(access.ctx, db, access.view.id, profiles)
        if esp.assigned:
            registry = registry.with_checks([esp.check])
    finally:
        db.rollback()
    return registry.with_checks(custom), [*registry.all_ids(), *(c.id for c in custom)]


async def _run_many(
    request: Request,
    ids: list[str],
    name: str,
    ctx: CheckContext,
    registry: CheckRegistry | None = None,
) -> Response:
    try:
        results = await run_checks(ids, name, ctx, registry=registry)
    except (UnknownCheck, InvalidTarget):
        raise _invalid(request) from None
    return _json(results, many=True)


# --- routes -------------------------------------------------------------------------------------


@router.post(
    "/domains/{domain_id}/checks/{check_id}",
    response_class=Response,
    responses={200: {"model": CheckResult | list[CheckResult]}},
)
async def run_domain_check(
    request: Request,
    access: CheckTarget,
    db: DbDep,
    resolver: ResolverDep,
    profiles: ProfilesDep,
    check_id: str,
) -> Response:
    ctx = _context(resolver, access.ctx.tenant_id, access.view.id)
    if check_id == ALL:
        everything, ids = await run_in_threadpool(_prepare_all, access, db, profiles)
        return await _run_many(request, ids, access.view.name, ctx, everything)
    registry = await run_in_threadpool(_prepare, access, db, [check_id], profiles)
    try:
        result = await run_check(check_id, access.view.name, ctx, registry=registry)
    except (UnknownCheck, InvalidTarget):
        raise _invalid(request) from None
    return _json([result], many=False)


@router.post(
    "/domains/{domain_id}/checks",
    response_class=Response,
    responses=_MANY,
    openapi_extra=_body_doc(IdsIn),
)
async def run_domain_checks(
    request: Request,
    access: CheckTarget,
    db: DbDep,
    body: Body,
    resolver: ResolverDep,
    profiles: ProfilesDep,
) -> Response:
    payload = _parse(request, IdsIn, body)
    ids = _validate_ids(request, payload.ids, esp=True)
    ctx = _context(resolver, access.ctx.tenant_id, access.view.id)
    registry = await run_in_threadpool(_prepare, access, db, ids, profiles)
    return await _run_many(request, ids, access.view.name, ctx, registry)


@router.post(
    "/checks/free",
    response_class=Response,
    responses=_MANY,
    openapi_extra=_body_doc(FreeIn),
)
async def run_free_checks(
    request: Request, _ctx: FreeAccess, db: DbDep, body: Body, resolver: ResolverDep
) -> Response:
    payload = _parse(request, FreeIn, body)
    ids = _validate_ids(request, payload.ids)
    try:
        to_dns_name(payload.name, allow_underscore=False)
    except InvalidDomainName:
        raise _invalid(request) from None
    await run_in_threadpool(db.rollback)  # no tenant rows here: just hold no transaction during DNS
    return await _run_many(request, ids, payload.name, _context(resolver))
