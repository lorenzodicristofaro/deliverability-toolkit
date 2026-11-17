"""History read API (M7-12), all `GET`, read-only, under `/api/v1/domains/{domain_id}/history`:

- `/runs`: check runs, newest first. Query: `check_id`, `since`, `until` (ISO 8601 with offset),
  `limit` (1..200, default 50), `cursor` (opaque, from `next_cursor`);
- `/trend`: server-side bucketed series. Query: `check_id`, `since`, `until`, `bucket`
  (`hour`|`day`, default `day`); at most 500 buckets;
- `/snapshots`: DNS snapshots, newest first. Query: `limit`, `cursor`;
- `/snapshots/diff`: changes between two snapshots of the domain. Query: `from`, `to` (ids).

Rules, bounds, cursor format and bucket rules are in `app.services.history`. Status codes
(bodies are `{"detail": <i18n>}`): 401 anonymous; 403 a readable domain without `monitor.read`;
404 no active tenant, or a domain/snapshot that is missing, foreign, malformed, of another domain,
unassigned (client viewer) or not readable; 409 a stored snapshot that cannot be read; 422 a
malformed, repeated, unknown or out-of-range query parameter.

The query string is read raw and parsed only after the permission and domain checks, so a denied
caller or a missing domain gets 403/404 whatever it sent.
"""

from __future__ import annotations

from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, Request

from app.api.v1._common import _error
from app.api.v1.domains import _domain_id
from app.core.tenancy import TenantContext
from app.services.clock import Clock, SystemClock
from app.services.history import HistoryInvalid, HistoryService
from app.services.monitors import MonitorError
from app.web.deps import CurrentSession, DbDep
from app.web.templating import request_language

router = APIRouter(tags=["history"])


def history_clock() -> Clock:
    """The clock for the default trend window; overridden in tests."""
    return SystemClock()


def _raise(request: Request, exc: MonitorError) -> NoReturn:
    raise _error(request, exc.status, exc.key) from None


def _service(
    db: DbDep, auth: CurrentSession, clock: Annotated[Clock, Depends(history_clock)]
) -> HistoryService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return HistoryService(db, ctx, auth.principal, clock=clock)


Service = Annotated[HistoryService, Depends(_service)]


def _query(request: Request) -> dict[str, str]:
    """The query parameters by name; a repeated name is malformed."""
    pairs = request.query_params.multi_items()
    found = dict(pairs)
    if len(found) != len(pairs):
        raise HistoryInvalid
    return found


@router.get("/domains/{domain_id}/history/runs")
def list_runs(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        did = service.check_read(_domain_id(domain_id))
        return service.runs(did, _query(request), request_language(request.scope))
    except MonitorError as exc:
        _raise(request, exc)


@router.get("/domains/{domain_id}/history/trend")
def trend(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        did = service.check_read(_domain_id(domain_id))
        return service.trend(did, _query(request))
    except MonitorError as exc:
        _raise(request, exc)


@router.get("/domains/{domain_id}/history/snapshots")
def list_snapshots(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        did = service.check_read(_domain_id(domain_id))
        return service.snapshots(did, _query(request))
    except MonitorError as exc:
        _raise(request, exc)


@router.get("/domains/{domain_id}/history/snapshots/diff")
def diff_snapshots(request: Request, service: Service, domain_id: str) -> dict[str, Any]:
    try:
        did = service.check_read(_domain_id(domain_id))
        return service.diff(did, _query(request))
    except MonitorError as exc:
        _raise(request, exc)
