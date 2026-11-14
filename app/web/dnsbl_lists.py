"""DNSBL list enablement admin page (M7-05c): `/dnsbl-lists`, list, enable, disable.

Every operation goes through `DnsblAdminService`, the same service as the REST API: this module
holds no repository and repeats no authorization. Only the instance admin flag passes; every tenant
role gets the 403 page, whatever its tenant. An unknown list id is a 404; the permission is decided
before the body is read and the list id before the body is parsed.

Routes (all need a session; anonymous GET -> 303 /login, anonymous POST -> 401):
- GET  /dnsbl-lists                     every list of the seed file: usage policy text (or a note
                                        that the list data has none), sources, verification
                                        status, enabled state, enable/disable controls
- POST /dnsbl-lists/{list_id}/enable    `policy_acknowledged=1` required; an unverified list also
                                        needs `unverified_confirmed=1` (refused with 422 otherwise)
- POST /dnsbl-lists/{list_id}/disable

Bodies are urlencoded and size-capped. Everything shown comes from the seed file and the
enablement rows and is autoescaped (no `|safe`), shown through `visible`. Sources are shown as
text, not links. Every response is `Cache-Control: no-store`.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.services.dnsbl_admin import DnsblAdminError, DnsblAdminService
from app.web.deps import AuthSession, CurrentSession, DbDep
from app.web.dns_tools import visible  # registers the `visible` filter
from app.web.templating import render

router = APIRouter(prefix="/dnsbl-lists")

_NO_STORE: Final = {"Cache-Control": "no-store"}
MAX_FORM_BYTES: Final = 4096
_MAX_FIELDS: Final = 10

_FLASH: Final = {
    "enabled": "web.dnsbl_lists.flash.enabled",
    "disabled": "web.dnsbl_lists.flash.disabled",
}
INVALID_FORM_KEY: Final = "web.dnsbl_lists.error.invalid_form"
TOO_LARGE_KEY: Final = "web.dnsbl_lists.error.too_large"

__all__ = ["MAX_FORM_BYTES", "router", "visible"]


# --- helpers ------------------------------------------------------------------------------------


def _service(db: Session, auth: AuthSession) -> DnsblAdminService:
    return DnsblAdminService(db, auth.principal)


def _respond(
    request: Request, template: str, status_code: int = 200, **context: object
) -> HTMLResponse:
    response = render(request, template, status_code=status_code, logged_in=True, **context)
    response.headers.update(_NO_STORE)
    return response


def _failure(request: Request, exc: DnsblAdminError) -> Response:
    if exc.status == 404:
        return _respond(request, "errors/404.html", 404)
    if exc.status == 403:
        return _respond(request, "dnsbl_lists/denied.html", 403)
    if exc.status == 503:
        return _respond(request, "dnsbl_lists/index.html", 503, views=[], error=exc.key, flash=None)
    raise exc


def _list_page(
    request: Request,
    service: DnsblAdminService,
    *,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    try:
        views = service.views()
    except DnsblAdminError as exc:
        return _failure(request, exc)
    return _respond(
        request,
        "dnsbl_lists/index.html",
        status_code,
        views=views,
        error=error,
        flash=_FLASH.get(notice or ""),
    )


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


def _flags(body: bytes) -> tuple[bool, bool] | None:
    """(policy_acknowledged, unverified_confirmed) of the form; None if malformed or repeated."""
    try:
        form = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            max_num_fields=_MAX_FIELDS,
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError):
        return None
    values: list[bool] = []
    for name in ("policy_acknowledged", "unverified_confirmed"):
        given = form.get(name, [""])
        if len(given) != 1:
            return None
        values.append(given[0] == "1")
    return values[0], values[1]


# --- routes -------------------------------------------------------------------------------------


@router.get("", include_in_schema=False)
def dnsbl_lists_index(
    request: Request, auth: CurrentSession, db: DbDep, notice: str | None = None
) -> Response:
    return _list_page(request, _service(db, auth), notice=notice)


@router.post("/{list_id}/enable", include_in_schema=False)
async def dnsbl_lists_enable(
    request: Request, auth: CurrentSession, db: DbDep, list_id: str
) -> Response:
    service = _service(db, auth)
    try:  # permission and list id first: a denied caller never has its body read
        await run_in_threadpool(service.find, list_id)
    except DnsblAdminError as exc:
        return _failure(request, exc)
    await run_in_threadpool(db.rollback)  # no pooled connection is held while the body is read
    try:
        body = await _read_capped(request, MAX_FORM_BYTES)
    except _BodyTooLarge:
        return await run_in_threadpool(
            _list_page, request, service, status_code=413, error=TOO_LARGE_KEY
        )
    flags = _flags(body)
    if flags is None:
        return await run_in_threadpool(
            _list_page, request, service, status_code=422, error=INVALID_FORM_KEY
        )
    try:
        await run_in_threadpool(
            lambda: service.enable(
                list_id, policy_acknowledged=flags[0], unverified_confirmed=flags[1]
            )
        )
    except DnsblAdminError as exc:
        if exc.status in (409, 422):
            return await run_in_threadpool(
                _list_page, request, service, status_code=exc.status, error=exc.key
            )
        return _failure(request, exc)
    return RedirectResponse("/dnsbl-lists?notice=enabled", status_code=303)


@router.post("/{list_id}/disable", include_in_schema=False)
async def dnsbl_lists_disable(
    request: Request, auth: CurrentSession, db: DbDep, list_id: str
) -> Response:
    service = _service(db, auth)
    try:
        await run_in_threadpool(service.disable, list_id)
    except DnsblAdminError as exc:
        if exc.status == 409:
            return await run_in_threadpool(
                _list_page, request, service, status_code=409, error=exc.key
            )
        return _failure(request, exc)
    return RedirectResponse("/dnsbl-lists?notice=disabled", status_code=303)
