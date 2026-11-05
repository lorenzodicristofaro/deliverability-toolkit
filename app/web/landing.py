"""Tenant landing page `/` (M1-19): the domains of the active tenant visible to the user.

- Anonymous: 303 to /login?next=/ (browser) via `current_session`; while setup is pending the
  setup gate sends every request to /setup first. Setup redirects here after creating the admin.
- Authenticated without an active tenant (e.g. an instance admin created without a first
  tenant): 200 with a "no tenant" message and no tenant data.
- Otherwise: one row per domain the principal may read (client viewers: assigned ones only),
  the tenant name, and a tenant switcher when the user has several memberships. The last-check
  column is an empty state until checks exist (M3+).

Memberships come from `UserMembershipsRepository` (user-scoped), domains from `DomainService`.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.repositories import UserMembershipsRepository
from app.repositories.base import MAX_LIMIT
from app.services.domains import DomainService, DomainServiceError
from app.web.deps import CurrentSession, DbDep, tenant_ctx
from app.web.domains import DomainRow, can_create, domain_row
from app.web.templating import render

router = APIRouter()


@router.get("/", include_in_schema=False)
def landing(request: Request, auth: CurrentSession, db: DbDep) -> HTMLResponse:
    memberships = UserMembershipsRepository(db, auth.user.id).list()
    tenant_id = auth.active_tenant_id
    active = next((m for m in memberships if m.tenant_id == tenant_id), None)
    rows: list[DomainRow] | None = None
    may_create = False
    if tenant_id is not None and active is not None:
        service = DomainService(db, tenant_ctx(auth), auth.principal)
        try:
            views = service.list(limit=MAX_LIMIT)
        except DomainServiceError:
            views = None  # e.g. a feature toggle denies listing: no domain section
        if views is not None:
            rows = [domain_row(v, service.principal, tenant_id) for v in views]
        may_create = can_create(service.principal, tenant_id)
    return render(
        request,
        "landing.html",
        logged_in=True,
        tenant=active,
        memberships=memberships,
        rows=rows,
        may_create=may_create,
    )
