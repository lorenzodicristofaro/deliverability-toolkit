"""Domain page "ESPs" tab (M6-07): `/domains/{domain_id}/esps`.

Everything goes through `DomainEspService` (M6-03): this module holds no repository and repeats no
authorization except the display decisions (`can()` for the controls and the `esp` run).

Routes (anonymous GET -> 303 /login, anonymous POST -> 401):
- GET  /domains/{domain_id}/esps                 the tab: assigned ESPs (name, profile status,
                                                 `verified_on`, sources), the attach form and remove
                                                 controls (only with `domain.update`), and, with
                                                 `check.run`, the `esp` check run on load (the
                                                 "Run again" link reloads it), its findings grouped
                                                 per ESP, and the ESPs detected in DNS but not
                                                 assigned in their own section (M6-13);
- POST /domains/{domain_id}/esps                 attach (`esp_id`, optional `return_path_host`,
                                                 `tracking_host`); re-attaching an ESP replaces its
                                                 hosts (the service's PUT semantics);
- POST /domains/{domain_id}/esps/{esp_id}/remove remove.

Client viewers read the tab on their assigned domains and never get a control; a direct POST gets
the 403 page. No tenant, a missing, foreign, malformed or (viewer) unassigned domain: 404. The
permission and the domain are decided before the body is read. Everything derived from profiles,
hosts or DNS is autoescaped (no `|safe`) and shown through `visible`; source links are https only.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.api.v1.checks import ResolverDep
from app.api.v1.domain_esps import esp_profiles
from app.checks.models import CheckContext, CheckResult, Finding
from app.core.permissions import Action, DomainResource, can
from app.esp.profile import EspProfile
from app.repositories.domain_esps import DomainEspRecord
from app.services.checks import default_registry, run_checks
from app.services.domain_esps import (
    ESP_CHECK_ID,
    DomainEspError,
    DomainEspService,
    EspFieldInvalid,
    ProfileSource,
    resolve_esp_run,
)
from app.services.domains import DomainServiceError
from app.web.authentication import finding_params  # noqa: F401  registers the filter and test
from app.web.deps import DbDep
from app.web.dns_tools import visible
from app.web.domains import Web, WebDep, _domain_id
from app.web.templating import read_form, render

router = APIRouter()

_NO_STORE: Final = {"Cache-Control": "no-store"}
INVALID_FORM_KEY: Final = "web.domain.esps.error.invalid_form"
DETECTED_CODE: Final = "ESP_DETECTED_NOT_ASSIGNED"
_NOTICES: Final = {
    "attached": "web.domain.esps.flash.attached",
    "removed": "web.domain.esps.flash.removed",
}
_CONTROL_CATEGORIES: Final = frozenset({"Cc", "Cs"})

__all__ = ["router", "visible"]

Profiles = Annotated[ProfileSource, Depends(esp_profiles)]


# --- view model ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EspRow:
    record: DomainEspRecord
    profile: EspProfile | None  # None: the profile is no longer loaded
    findings: tuple[Finding, ...] = ()


@dataclass(slots=True)
class Tab:
    rows: list[EspRow] = field(default_factory=list)
    general: list[Finding] = field(default_factory=list)
    detected: list[Finding] = field(default_factory=list)
    result: CheckResult | None = None
    catalogue: Sequence[EspProfile] = ()
    notes: list[str] = field(default_factory=list)  # i18n keys of non-fatal problems


def group_findings(
    rows: Sequence[tuple[DomainEspRecord, EspProfile | None]], result: CheckResult | None
) -> Tab:
    """Findings per assigned ESP (by the profile name, or the stored id when the profile is no
    longer loaded, in the finding's `esp` param); detected-not-assigned findings in their own
    list; everything else (no ESP assigned, combined SPF limit, detection truncated, ...) as
    general."""
    tab = Tab()
    findings = list(result.findings) if result is not None else []
    detected = [f for f in findings if f.code == DETECTED_CODE]
    rest = [f for f in findings if f.code != DETECTED_CODE]
    taken: set[int] = set()
    for record, profile in rows:
        label = profile.name if profile is not None else record.esp_id
        mine = [(i, f) for i, f in enumerate(rest) if f.params.get("esp") == label]
        taken.update(i for i, _ in mine)
        tab.rows.append(EspRow(record, profile, tuple(f for _, f in mine)))
    tab.general = [f for i, f in enumerate(rest) if i not in taken]
    tab.detected = detected
    tab.result = result
    return tab


# --- helpers ------------------------------------------------------------------------------------


def _service(web: Web, db: DbDep, profiles: ProfileSource) -> DomainEspService:
    return DomainEspService(db, web.ctx, web.service.principal, profiles)


def _respond(request: Request, template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    response = render(request, template, status_code=status_code, logged_in=True, **ctx)
    response.headers.update(_NO_STORE)
    return response


def _failure(request: Request, exc: DomainEspError) -> HTMLResponse:
    """404 -> the translated 404 page (exception handler); 403 -> the denied page."""
    if exc.status == 404:
        raise HTTPException(status_code=404)
    if exc.status == 403:
        return _respond(request, "domains/denied.html", 403)
    raise exc


def _clean(form: dict[str, list[str]], name: str) -> str | None:
    """The single value of `name` (blank when absent), or None if repeated or with control
    characters (NUL included): such input never reaches the service."""
    values = form.get(name, [""])
    if len(values) != 1:
        return None
    if any(unicodedata.category(c) in _CONTROL_CATEGORIES for c in values[0]):
        return None
    return values[0]


async def _page(
    request: Request,
    web: Web,
    db: DbDep,
    resolver: Any,
    profiles: ProfileSource,
    domain_id: int | None,
    *,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
    run: bool = True,
    form: dict[str, str] | None = None,
) -> Response:
    service = _service(web, db, profiles)
    try:
        records = service.list_for_domain(domain_id)
        view = web.service.get(domain_id)
    except DomainEspError as exc:
        return _failure(request, exc)
    except DomainServiceError:
        raise HTTPException(status_code=404) from None
    principal = web.service.principal
    resource = DomainResource(web.ctx.tenant_id, view.id)
    can_write = can(principal, Action.DOMAIN_UPDATE, resource)
    can_run = can(principal, Action.CHECK_RUN, resource)
    notes: list[str] = []
    catalogue: Sequence[EspProfile] = ()
    try:
        catalogue = service.catalogue()
    except DomainEspError as exc:
        notes.append(exc.key)
    by_id = {p.id: p for p in catalogue}
    result: CheckResult | None = None
    if can_run and run:
        try:
            esp = resolve_esp_run(web.ctx, db, view.id, profiles)
        finally:
            db.rollback()  # no pooled connection is held during DNS
        ctx = CheckContext(
            resolver=resolver, tenant_id=str(web.ctx.tenant_id), domain_id=str(view.id)
        )
        registry = default_registry().with_checks([esp.check])
        result = (await run_checks([ESP_CHECK_ID], view.name, ctx, registry=registry))[0]
    tab = group_findings([(r, by_id.get(r.esp_id)) for r in records], result)
    tab.notes = notes
    tab.catalogue = catalogue
    return _respond(
        request,
        "domains/esps.html",
        status_code,
        domain_id=view.id,
        display_name=view.display_name,
        tab=tab,
        can_write=can_write,
        can_run=can_run,
        error=error,
        flash=_NOTICES.get(notice or ""),
        form=form or {"esp_id": "", "return_path_host": "", "tracking_host": ""},
    )


# --- routes -------------------------------------------------------------------------------------


@router.get("/domains/{domain_id}/esps", include_in_schema=False)
async def esps_tab(
    request: Request,
    web: WebDep,
    db: DbDep,
    resolver: ResolverDep,
    profiles: Profiles,
    domain_id: str,
    notice: str | None = None,
) -> Response:
    return await _page(request, web, db, resolver, profiles, _domain_id(domain_id), notice=notice)


@router.post("/domains/{domain_id}/esps", include_in_schema=False)
async def esps_attach(
    request: Request,
    web: WebDep,
    db: DbDep,
    resolver: ResolverDep,
    profiles: Profiles,
    domain_id: str,
) -> Response:
    service = _service(web, db, profiles)
    try:  # permission and domain first: a denied caller never has its body read
        did = service.check_write(_domain_id(domain_id))
    except DomainEspError as exc:
        return _failure(request, exc)
    db.rollback()
    raw = await read_form(request)

    async def again(status: int, key: str, echo: dict[str, str] | None = None) -> Response:
        return await _page(
            request,
            web,
            db,
            resolver,
            profiles,
            did,
            status_code=status,
            error=key,
            run=False,
            form=echo,
        )

    if raw is None:
        return await again(413, INVALID_FORM_KEY)
    esp_id, rp, tr = (_clean(raw, n) for n in ("esp_id", "return_path_host", "tracking_host"))
    if esp_id is None or rp is None or tr is None:
        return await again(422, INVALID_FORM_KEY)
    echo = {"esp_id": esp_id, "return_path_host": rp, "tracking_host": tr}
    try:
        service.assign(
            did, esp_id, return_path_host=rp.strip() or None, tracking_host=tr.strip() or None
        )
    except EspFieldInvalid as exc:
        return await again(422, exc.key, echo)
    except DomainEspError as exc:
        if exc.status in (404, 403):
            return _failure(request, exc)
        return await again(exc.status, exc.key, echo)
    return RedirectResponse(f"/domains/{did}/esps?notice=attached", status_code=303)


@router.post("/domains/{domain_id}/esps/{esp_id}/remove", include_in_schema=False)
async def esps_remove(
    request: Request,
    web: WebDep,
    db: DbDep,
    resolver: ResolverDep,
    profiles: Profiles,
    domain_id: str,
    esp_id: str,
) -> Response:
    service = _service(web, db, profiles)
    did = _domain_id(domain_id)
    try:
        did = service.check_write(did)
        service.remove(did, esp_id)
    except DomainEspError as exc:
        if exc.status in (404, 403):
            return _failure(request, exc)
        return await _page(
            request, web, db, resolver, profiles, did, status_code=exc.status, error=exc.key,
            run=False,
        )  # fmt: skip
    return RedirectResponse(f"/domains/{did}/esps?notice=removed", status_code=303)
