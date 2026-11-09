"""DKIM selectors admin UI (M5-21): `/dkim-selectors`, list, create, edit, enable/disable, delete.

Every operation goes through `DkimSelectorsAdminService` (M5-20), the same service as the REST API:
this module holds no repository and repeats no authorization. The scope is the `?scope=` query
(`tenant`, the default, or `global`), never a form field, so the permission is decided before the
body is read. A denied principal gets a 403 page (404 for a missing tenant, a foreign or malformed
selector id), and the service is not reached with the body.

Routes (all need a session; anonymous GET -> 303 /login, anonymous POST -> 401):
- GET  /dkim-selectors                        list (tenant tab: the tenant's rows, then global rows
                                              read-only; `?page=`; a session with no tenant defaults
                                              to the global tab if its user may manage it)
- GET  /dkim-selectors/new                    create form
- POST /dkim-selectors                        create
- GET  /dkim-selectors/{selector_id}/edit     edit form
- POST /dkim-selectors/{selector_id}/edit     update
- POST /dkim-selectors/{selector_id}/toggle   enable / disable (`enabled=1|0`)
- POST /dkim-selectors/{selector_id}/delete   delete (a seeded global row answers 409)

Bodies are urlencoded and size-capped by `_read_capped`. NUL and lone surrogates are refused before
the service and never echoed. A browser submits textarea newlines as CRLF: `_lf` turns them back
into LF. On a seeded row selector, provider and record_type are read-only (the service refuses a
change with `seed_managed`) and the delete control is not shown. Everything derived from stored
rows is autoescaped (no `|safe`) and shown through `visible`. Every response is
`Cache-Control: no-store`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.core.permissions import RuleScope
from app.core.tenancy import TenantContext
from app.models.dkim_selector import RECORD_TYPES
from app.repositories.base import MAX_LIMIT, parse_id
from app.repositories.dkim_selectors import DkimSelectorRecord
from app.services.dkim_selectors_admin import (
    DkimSelectorsAdminError,
    DkimSelectorsAdminService,
    SeededSelectorNotDeletable,
    SelectorConflict,
    SelectorFieldInvalid,
)
from app.web.deps import AuthSession, CurrentSession, DbDep
from app.web.dns_tools import visible  # registers the `visible` filter
from app.web.templating import render

router = APIRouter(prefix="/dkim-selectors")

_NO_STORE: Final = {"Cache-Control": "no-store"}
_FORM_OVERHEAD_BYTES: Final = 4096
# Worst case of the text fields (4 bytes per character), percent-encoded (3x).
MAX_SAVE_BYTES: Final = 3 * 4 * 1000 + _FORM_OVERHEAD_BYTES
_MAX_FIELDS: Final = 20
PAGE_SIZE: Final = 200
_TEXT_FIELDS: Final = ("selector", "provider", "record_type", "notes")

_FLASH: Final = {
    "created": "web.dkim_selectors.flash.created",
    "updated": "web.dkim_selectors.flash.updated",
    "deleted": "web.dkim_selectors.flash.deleted",
    "enabled": "web.dkim_selectors.flash.enabled",
    "disabled": "web.dkim_selectors.flash.disabled",
}
_FIELD_LABELS: Final = {
    "selector": "web.dkim_selectors.field.selector",
    "provider": "web.dkim_selectors.field.provider",
    "record_type": "web.dkim_selectors.field.record_type",
    "notes": "web.dkim_selectors.field.notes",
    "enabled": "web.dkim_selectors.field.enabled",
}
INVALID_FORM_KEY: Final = "web.dkim_selectors.error.invalid_form"
INVALID_CHARS_KEY: Final = "web.dkim_selectors.error.invalid_chars"
TOO_LARGE_KEY: Final = "web.dkim_selectors.error.too_large"
SEED_MANAGED_KEY: Final = "web.dkim_selectors.error.seed_managed"

__all__ = ["MAX_SAVE_BYTES", "PAGE_SIZE", "router", "visible"]


# --- helpers ------------------------------------------------------------------------------------


def _service(db: Session, auth: AuthSession) -> DkimSelectorsAdminService:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return DkimSelectorsAdminService(db, ctx, auth.principal)


def _parse_scope(value: str | None) -> RuleScope | None:
    if value is None:
        return RuleScope.TENANT
    if value in (RuleScope.TENANT.value, RuleScope.GLOBAL.value):
        return RuleScope(value)
    return None


def _parse_page(value: str | None) -> int | None:
    return 1 if value is None else parse_id(value)


def _respond(
    request: Request, template: str, status_code: int = 200, **context: Any
) -> HTMLResponse:
    response = render(request, template, status_code=status_code, logged_in=True, **context)
    response.headers.update(_NO_STORE)
    return response


def _not_found(request: Request) -> HTMLResponse:
    response = render(request, "errors/404.html", status_code=404, logged_in=True)
    response.headers.update(_NO_STORE)
    return response


def _failure(request: Request, exc: DkimSelectorsAdminError) -> Response:
    """The page for a refused operation: 404 (missing, foreign, malformed or stale, or no tenant)
    or the 403 denied page. Any other error is a bug and is raised."""
    if exc.status == 404:
        return _not_found(request)
    if exc.status == 403:
        return _respond(request, "dkim_selectors/denied.html", 403)
    raise exc


def _allowed(check: Callable[[RuleScope], None], scope: RuleScope) -> bool:
    try:
        check(scope)
    except DkimSelectorsAdminError:
        return False
    return True


def _redirect(scope: RuleScope, notice: str) -> Response:
    return RedirectResponse(f"/dkim-selectors?scope={scope.value}&notice={notice}", status_code=303)


class _BodyTooLarge(Exception):
    pass


async def _read_capped(request: Request, cap: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (
        not (declared.isascii() and declared.isdigit()) or int(declared) > cap
    ):
        raise _BodyTooLarge
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > cap:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _form(body: bytes) -> dict[str, list[str]] | None:
    """The urlencoded fields, or None if the body is not valid UTF-8 or has too many fields."""
    try:
        return parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            max_num_fields=_MAX_FIELDS,
            errors="strict",  # an invalid percent-encoded UTF-8 sequence is refused, not replaced
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _single(form: dict[str, list[str]], name: str) -> str | None:
    """The one value of `name` ("" if absent); None if the field is repeated."""
    values = form.get(name, [""])
    return values[0] if len(values) == 1 else None


def _lf(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _bad_chars(value: str) -> bool:
    return "\x00" in value or any("\ud800" <= ch <= "\udfff" for ch in value)


@dataclass(frozen=True, slots=True)
class _Row:
    record: DkimSelectorRecord
    can_edit: bool
    can_delete: bool
    also_tenant: bool = False  # a global row whose name a row of this tenant also uses


def _form_values(record: DkimSelectorRecord | None) -> dict[str, Any]:
    if record is None:
        return {
            "selector": "",
            "provider": "",
            "record_type": "either",
            "notes": "",
            "enabled": True,
        }
    return {
        "selector": record.selector,
        "provider": record.provider or "",
        "record_type": record.record_type,
        "notes": record.notes or "",
        "enabled": record.enabled,
    }


def _field_error(exc: SelectorFieldInvalid) -> dict[str, str | None]:
    key = SEED_MANAGED_KEY if exc.reason == "seed_managed" else exc.key
    return {"key": key, "field_label": _FIELD_LABELS.get(exc.field)}


# --- list ---------------------------------------------------------------------------------------


def _all_records(service: DkimSelectorsAdminService, scope: RuleScope) -> list[DkimSelectorRecord]:
    """Every row visible in `scope`, read in batches until a short one, so nothing is cut off and
    the duplicate markers see all of the tenant's rows wherever the page being shown falls."""
    records: list[DkimSelectorRecord] = []
    while True:
        batch = service.list_selectors(scope, limit=MAX_LIMIT, offset=len(records))
        records.extend(batch)
        if len(batch) < MAX_LIMIT:
            return records


def _list_page(
    request: Request,
    service: DkimSelectorsAdminService,
    scope: RuleScope,
    *,
    page: int = 1,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    try:
        records = _all_records(service, scope)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    can_manage = {s: _allowed(service.check_manage, s) for s in RuleScope}
    own = [r for r in records if r.scope == RuleScope.TENANT.value]
    shared = [r for r in records if r.scope == RuleScope.GLOBAL.value]
    own_names = {r.selector for r in own}
    last_page = max(1, (len(records) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, last_page)
    rows = [
        _Row(
            record,
            can_edit=record.scope == scope.value and can_manage[scope],
            can_delete=(
                record.scope == scope.value and can_manage[scope] and record.seed_key is None
            ),
            also_tenant=record.scope == RuleScope.GLOBAL.value and record.selector in own_names,
        )
        for record in [*own, *shared][(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    ]
    return _respond(
        request,
        "dkim_selectors/index.html",
        status_code,
        scope=scope.value,
        tenant_rows=[r for r in rows if r.record.scope == RuleScope.TENANT.value],
        global_rows=[r for r in rows if r.record.scope == RuleScope.GLOBAL.value],
        has_tenant_rows=bool(own),
        has_global_rows=bool(shared),
        page=page,
        last_page=last_page,
        show_tenant_tab=_allowed(service.check_read, RuleScope.TENANT),
        show_global_tab=can_manage[RuleScope.GLOBAL],
        can_manage=can_manage[scope],
        error=error,
        flash=_FLASH.get(notice or ""),
    )


@router.get("", include_in_schema=False)
def selectors_index(
    request: Request,
    auth: CurrentSession,
    db: DbDep,
    scope: str | None = None,
    notice: str | None = None,
    page: str | None = None,
) -> Response:
    parsed = _parse_scope(scope)
    page_number = _parse_page(page)
    if parsed is None or page_number is None:
        return _not_found(request)
    service = _service(db, auth)
    if (
        scope is None
        and auth.active_tenant_id is None
        and _allowed(service.check_manage, RuleScope.GLOBAL)
    ):
        parsed = RuleScope.GLOBAL
    return _list_page(request, service, parsed, page=page_number, notice=notice)


# --- create / edit ------------------------------------------------------------------------------


def _form_page(
    request: Request,
    service: DkimSelectorsAdminService,
    scope: RuleScope,
    selector_id: int | None,
    *,
    values: dict[str, Any] | None = None,
    status_code: int = 200,
    error: dict[str, str | None] | None = None,
    plain_error: str | None = None,
) -> Response:
    record = None
    if selector_id is not None:
        try:
            record = service.get_selector(scope, selector_id)
        except DkimSelectorsAdminError as exc:
            return _failure(request, exc)
    return _respond(
        request,
        "dkim_selectors/form.html",
        status_code,
        scope=scope.value,
        record=record,
        form=values if values is not None else _form_values(record),
        record_types=RECORD_TYPES,
        seeded=record is not None and record.seed_key is not None,
        error=error,
        plain_error=plain_error,
    )


@router.get("/new", include_in_schema=False)
def selectors_new(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:
        service.check_manage(parsed)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return _form_page(request, service, parsed, None)


@router.get("/{selector_id}/edit", include_in_schema=False)
def selectors_edit(
    request: Request, auth: CurrentSession, db: DbDep, selector_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(selector_id)
    try:
        service.check_write(parsed, target)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return _form_page(request, service, parsed, target)


def _save_data(form: dict[str, list[str]]) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    """(service data, echo values, error key). The data holds every field of the form."""
    echo = _form_values(None)
    texts: dict[str, str] = {}
    for name in _TEXT_FIELDS:
        value = _single(form, name)
        if value is None:
            return {}, echo, INVALID_FORM_KEY
        texts[name] = _lf(value)
    enabled = _single(form, "enabled")
    if enabled is None:
        return {}, echo, INVALID_FORM_KEY
    if any(_bad_chars(v) for v in (*texts.values(), enabled)):
        return {}, echo, INVALID_CHARS_KEY
    echo.update({**texts, "enabled": enabled == "1"})
    data: dict[str, Any] = {
        "selector": texts["selector"].strip(),
        "provider": texts["provider"].strip() or None,
        "record_type": texts["record_type"],
        "notes": texts["notes"].strip() or None,
        "enabled": enabled == "1",
    }
    return data, echo, None


async def _save(
    request: Request,
    service: DkimSelectorsAdminService,
    db: Session,
    scope: RuleScope,
    target: int | None,
) -> Response:
    """Create (`target` None) or update a selector from the form. The caller has already checked the
    permission (and the row's visibility), so the body is read only for an allowed caller."""
    db.rollback()  # no pooled connection is held while the body is read
    try:
        body = await _read_capped(request, MAX_SAVE_BYTES)
    except _BodyTooLarge:
        return _form_page(
            request, service, scope, target, status_code=413, plain_error=TOO_LARGE_KEY
        )
    form = _form(body)
    del body
    if form is None:
        return _form_page(
            request, service, scope, target, status_code=422, plain_error=INVALID_FORM_KEY
        )
    data, echo, problem = _save_data(form)
    del form
    if problem is not None:
        values = None if problem == INVALID_CHARS_KEY else echo  # never echo a NUL
        return _form_page(
            request, service, scope, target, values=values, status_code=422, plain_error=problem
        )
    try:
        if target is None:
            service.create(scope, data)
        else:
            service.update(scope, target, data)
    except SelectorFieldInvalid as exc:
        return _form_page(
            request, service, scope, target, values=echo, status_code=422, error=_field_error(exc)
        )
    except SelectorConflict as exc:
        return _form_page(
            request,
            service,
            scope,
            target,
            values=echo,
            status_code=409,
            error={"key": exc.key, "field_label": _FIELD_LABELS["selector"]},
        )
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return _redirect(scope, "created" if target is None else "updated")


@router.post("", include_in_schema=False)
async def selectors_create(
    request: Request, auth: CurrentSession, db: DbDep, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    try:  # permission first: a denied caller never has its body read
        service.check_manage(parsed)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return await _save(request, service, db, parsed, None)


@router.post("/{selector_id}/edit", include_in_schema=False)
async def selectors_update(
    request: Request, auth: CurrentSession, db: DbDep, selector_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(selector_id)
    try:  # permission and visibility of the row first
        service.check_write(parsed, target)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return await _save(request, service, db, parsed, target)


# --- toggle / delete ----------------------------------------------------------------------------


@router.post("/{selector_id}/toggle", include_in_schema=False)
async def selectors_toggle(
    request: Request, auth: CurrentSession, db: DbDep, selector_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(selector_id)
    try:
        service.check_write(parsed, target)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    db.rollback()
    try:
        body = await _read_capped(request, _FORM_OVERHEAD_BYTES)
    except _BodyTooLarge:
        return _list_page(request, service, parsed, status_code=413, error=TOO_LARGE_KEY)
    form = _form(body)
    enabled = None if form is None else _single(form, "enabled")
    if enabled not in ("0", "1"):
        return _list_page(request, service, parsed, status_code=422, error=INVALID_FORM_KEY)
    try:
        service.update(parsed, target, {"enabled": enabled == "1"})
    except SelectorFieldInvalid as exc:
        return _list_page(request, service, parsed, status_code=422, error=exc.key)
    except SelectorConflict as exc:
        return _list_page(request, service, parsed, status_code=409, error=exc.key)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return _redirect(parsed, "enabled" if enabled == "1" else "disabled")


@router.post("/{selector_id}/delete", include_in_schema=False)
async def selectors_delete(
    request: Request, auth: CurrentSession, db: DbDep, selector_id: str, scope: str | None = None
) -> Response:
    parsed = _parse_scope(scope)
    if parsed is None:
        return _not_found(request)
    service = _service(db, auth)
    target = parse_id(selector_id)
    try:
        service.check_write(parsed, target)
        db.rollback()
        service.delete(parsed, target)
    except SeededSelectorNotDeletable as exc:
        return _list_page(request, service, parsed, status_code=409, error=exc.key)
    except DkimSelectorsAdminError as exc:
        return _failure(request, exc)
    return _redirect(parsed, "deleted")
