"""Domain management UI (M1-19): add, rename, delete forms and the domain page stub.

Every operation goes through the M1-18 `DomainService` (tenant repositories + `can()`); the
buttons a role lacks are not rendered, and the routes enforce the same checks:
- anonymous: GET -> 303 to /login (browser), POST -> 401 (after the CSRF middleware);
- no active tenant, or a domain that is missing/foreign/malformed id/unassigned -> 404 page;
- a visible domain (or the tenant) the role may not change -> 403 page;
- form errors re-render the form: 422 invalid name or form, 409 duplicate name; 413 oversized.

Forms are urlencoded and parsed with `read_form` (no python-multipart). A field that is missing,
repeated, over-long or contains control characters (NUL included) is refused here, before the
service or the database, and is never echoed back. Templates autoescape everything.

Lookalikes: `mixed_script` is a minimal offline MIXED-SCRIPT HEURISTIC inspired by UTS #39
section 5.2 ("Highly Restrictive"); it is NOT a conformant UTS #39 implementation (no confusable
skeletons, no Script_Extensions data). The script of a letter is taken from the first word of
its Unicode character name (`unicodedata.name`), which matches the script for the common
alphabets (LATIN, CYRILLIC, GREEK, ARABIC, HEBREW, ...). No third-party library is used.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.core.domain_names import MAX_INPUT_LENGTH
from app.core.permissions import Action, DomainResource, Principal, TenantResource, can
from app.core.tenancy import TenantContext
from app.repositories.base import parse_id
from app.services.domains import (
    DomainService,
    DomainServiceError,
    DomainView,
    Forbidden,
    InvalidRequest,
    NotFound,
)
from app.web.deps import CurrentSession, DbDep, tenant_ctx
from app.web.templating import payload_too_large, read_form, render

router = APIRouter()

_CONTROL_CATEGORIES: Final = frozenset({"Cc", "Cs"})
NAME_FIELD: Final = "name"

# --- mixed-script heuristic ---------------------------------------------------------------------

# Character-name prefixes that are not the script name itself.
_SCRIPT_ALIASES: Final = {
    "CJK": "HAN",
    "IDEOGRAPHIC": "HAN",
    "KATAKANA-HIRAGANA": "KATAKANA",
    "ARABIC-INDIC": "ARABIC",
    "EXTENDED": "ARABIC",  # EXTENDED ARABIC-INDIC DIGIT ...
}
# UTS #39 section 5.2: besides a single script, these combinations are "Highly Restrictive".
_ALLOWED_COMBINATIONS: Final = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
)


def _script(char: str) -> str | None:
    """Heuristic script of `char`; None for script-neutral characters (ASCII digits, hyphen,
    dot, combining marks). Unnamed characters count as their own "UNKNOWN" script."""
    if char in "-." or ("0" <= char <= "9"):
        return None
    if unicodedata.category(char).startswith("M"):
        return None  # combining marks inherit the script of their base
    name = unicodedata.name(char, "")
    if not name:
        return "UNKNOWN"
    first = name.split(" ", 1)[0]
    return _SCRIPT_ALIASES.get(first, first)


def scripts_of(name: str) -> frozenset[str]:
    return frozenset(s for s in (_script(c) for c in name) if s is not None)


def mixed_script(name: str) -> bool:
    """True if a label of `name` (Unicode display form) mixes scripts outside the UTS #39
    "Highly Restrictive" combinations, e.g. Latin + Cyrillic ("pаypal" with a Cyrillic "а")."""
    for label in name.split("."):
        found = scripts_of(label)
        if len(found) > 1 and not any(found <= allowed for allowed in _ALLOWED_COMBINATIONS):
            return True
    return False


# --- view model ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DomainRow:
    """What the templates show for one domain (and which actions the principal may take)."""

    id: int
    display_name: str
    ascii_name: str | None  # the A-label form, only when it differs from the display name
    mixed_script: bool
    can_rename: bool
    can_delete: bool
    can_check: bool = False


def domain_row(view: DomainView, principal: Principal, tenant_id: int) -> DomainRow:
    resource = DomainResource(tenant_id, view.id)
    return DomainRow(
        id=view.id,
        display_name=view.display_name,
        ascii_name=view.name if view.name != view.display_name else None,
        mixed_script=mixed_script(view.display_name),
        can_rename=can(principal, Action.DOMAIN_UPDATE, resource),
        can_delete=can(principal, Action.DOMAIN_DELETE, resource),
        can_check=can(principal, Action.CHECK_RUN, resource),
    )


def can_create(principal: Principal, tenant_id: int) -> bool:
    return can(principal, Action.DOMAIN_CREATE, TenantResource(tenant_id))


# --- helpers ------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Web:
    service: DomainService
    ctx: TenantContext


def _web(
    db: DbDep, auth: CurrentSession, ctx: Annotated[TenantContext, Depends(tenant_ctx)]
) -> Web:
    return Web(DomainService(db, ctx, auth.principal), ctx)


WebDep = Annotated[Web, Depends(_web)]


def _domain_id(value: str) -> int | None:
    """Path id as a positive int; anything else is None (answered as 404, like a missing id)."""
    return parse_id(value)


def clean_field(form: dict[str, list[str]], field: str) -> str | None:
    """The single value of `field`, or None if it is missing, repeated, over-long or contains
    control characters (NUL included): such input never reaches the service or the DB."""
    values = form.get(field)
    if values is None or len(values) != 1:
        return None
    value = values[0]
    if len(value) > MAX_INPUT_LENGTH:
        return None
    if any(unicodedata.category(c) in _CONTROL_CATEGORIES for c in value):
        return None
    return value


def _denied(request: Request, exc: DomainServiceError) -> HTMLResponse:
    """404 -> the translated 404 page (exception handler); 403 -> the denied page."""
    if isinstance(exc, NotFound):
        raise HTTPException(status_code=404)
    if isinstance(exc, Forbidden):
        return render(request, "domains/denied.html", status_code=403, logged_in=True)
    raise exc


def _form_page(
    request: Request,
    *,
    mode: str,
    status_code: int = 200,
    row: DomainRow | None = None,
    name: str = "",
    error: str | None = None,
) -> HTMLResponse:
    return render(
        request,
        "domains/form.html",
        status_code=status_code,
        logged_in=True,
        mode=mode,
        row=row,
        name=name,
        error=error,
    )


def _row(web: Web, domain_id: int | None) -> DomainRow:
    view = web.service.get(domain_id)
    return domain_row(view, web.service.principal, web.ctx.tenant_id)


# --- routes -------------------------------------------------------------------------------------


@router.get("/domains/new", include_in_schema=False)
def new_domain_form(request: Request, web: WebDep) -> Response:
    try:
        web.service.check_create()
    except DomainServiceError as exc:
        return _denied(request, exc)
    return _form_page(request, mode="add")


@router.post("/domains", include_in_schema=False)
async def create_domain(request: Request, web: WebDep) -> Response:
    try:
        web.service.check_create()  # permission first: 403 whatever the body contains
    except DomainServiceError as exc:
        return _denied(request, exc)
    form = await read_form(request)
    if form is None:
        return payload_too_large(request)
    name = clean_field(form, NAME_FIELD)
    if name is None:
        return _form_page(request, mode="add", status_code=422, error=InvalidRequest.key)
    try:
        web.service.create(name)
    except DomainServiceError as exc:
        if exc.status in (409, 422):
            return _form_page(request, mode="add", status_code=exc.status, name=name, error=exc.key)
        return _denied(request, exc)
    return RedirectResponse("/", status_code=303)


def _count_param(request: Request, name: str) -> str:
    """A small count from the query string (the rename notice), as digits for the message;
    empty (no notice) for zero, anything else that is not 1 to 4 ASCII digits."""
    raw = request.query_params.get(name, "")
    return raw.lstrip("0") if raw.isascii() and raw.isdigit() and len(raw) <= 4 else ""


@router.get("/domains/{domain_id}", include_in_schema=False)
def domain_detail(request: Request, web: WebDep, domain_id: str) -> Response:
    try:
        row = _row(web, _domain_id(domain_id))
    except DomainServiceError as exc:
        return _denied(request, exc)
    access_count: int | None = None
    try:
        web.service.check_set_access(row.id)
    except Forbidden:
        pass  # analysts and client viewers do not see who has access
    else:
        access_count = len(web.service.access_of(row.id).user_ids)
    return render(
        request,
        "domains/detail.html",
        logged_in=True,
        row=row,
        access_count=access_count,
        esp_hosts_rewritten=_count_param(request, "esp_hosts"),
        esp_hosts_unmatched=_count_param(request, "esp_unmatched"),
    )


@router.get("/domains/{domain_id}/rename", include_in_schema=False)
def rename_domain_form(request: Request, web: WebDep, domain_id: str) -> Response:
    try:
        target = _domain_id(domain_id)
        web.service.check_update(target)
        row = _row(web, target)
    except DomainServiceError as exc:
        return _denied(request, exc)
    return _form_page(request, mode="rename", row=row, name=row.display_name)


@router.post("/domains/{domain_id}/rename", include_in_schema=False)
async def rename_domain(request: Request, web: WebDep, domain_id: str) -> Response:
    try:
        target = _domain_id(domain_id)
        web.service.check_update(target)
        row = _row(web, target)
    except DomainServiceError as exc:
        return _denied(request, exc)
    form = await read_form(request)
    if form is None:
        return payload_too_large(request)
    name = clean_field(form, NAME_FIELD)
    if name is None:
        return _form_page(
            request, mode="rename", status_code=422, row=row, error=InvalidRequest.key
        )
    try:
        renamed = web.service.rename(row.id, name)
    except DomainServiceError as exc:
        if exc.status in (409, 422):
            return _form_page(
                request, mode="rename", status_code=exc.status, row=row, name=name, error=exc.key
            )
        return _denied(request, exc)
    target_url = f"/domains/{row.id}"
    if renamed.esp_hosts_rewritten or renamed.esp_hosts_unmatched:
        target_url += (
            f"?esp_hosts={renamed.esp_hosts_rewritten}&esp_unmatched={renamed.esp_hosts_unmatched}"
        )
    return RedirectResponse(target_url, status_code=303)


def _check_delete(web: Web, domain_id: int | None) -> DomainRow:
    row = _row(web, domain_id)  # NotFound before Forbidden: unseen domains stay 404
    if not row.can_delete:
        raise Forbidden
    return row


@router.get("/domains/{domain_id}/delete", include_in_schema=False)
def delete_domain_form(request: Request, web: WebDep, domain_id: str) -> Response:
    try:
        row = _check_delete(web, _domain_id(domain_id))
    except DomainServiceError as exc:
        return _denied(request, exc)
    return render(request, "domains/delete.html", logged_in=True, row=row)


@router.post("/domains/{domain_id}/delete", include_in_schema=False)
def delete_domain(request: Request, web: WebDep, domain_id: str) -> Response:
    try:
        row = _check_delete(web, _domain_id(domain_id))
        web.service.delete(row.id)
    except DomainServiceError as exc:
        return _denied(request, exc)
    return RedirectResponse("/", status_code=303)
