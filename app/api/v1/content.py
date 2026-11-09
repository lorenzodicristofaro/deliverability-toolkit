"""`/api/v1/content`: offline analysis of message content against the rules (M5-15).

`POST /analyze` takes either a JSON object `{html?, text?, subject?, language?}`
(`application/json`) or a RAW `.eml` (`message/rfc822`) and answers with the `ContentAnalysis`
JSON of `analyze_content`, byte-for-byte (`model_dump_json`). That JSON shape is frozen here.

Status codes (error bodies are `{"detail": ...}`, never echoing the input):
- 401 anonymous (mutating requests first need a valid CSRF token, else the middleware answers 403);
- 404 no active tenant (a stale or foreign one included);
- 403 the principal lacks `content.analyze` in the active tenant (client viewers);
- 415 other content type; 413 body over MAX_RAW_BYTES (declared length first, then counted while
  streaming: the rest is never buffered); 422 empty input, NUL byte, a malformed JSON body or an
  invalid language. These detail objects are `{key, message, field, reason}` with stable codes.
- 200 otherwise; content the analyzer cannot fully evaluate is data (status `error`).

Permission checks run before the body is read, so a denied caller never reaches the analyzer.
`analyze_content` is synchronous and blocks for up to about 15 s, so it runs in a worker thread
(`run_in_threadpool`). The `Session` is the request's own (the same one the auth dependency used,
cached per request); the event loop only awaits while the worker uses it, so it is never touched
by two threads at once. Nothing is stored or logged and there is no network or DNS access.
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import _error, _no_duplicate_keys
from app.core.i18n import t
from app.core.permissions import Action, TenantResource, can
from app.core.tenancy import TenantContext
from app.models.content_rule import MAX_LANGUAGE_LENGTH
from app.parsers.message import MAX_RAW_BYTES
from app.services.content_analysis import ContentInput, analyze_content
from app.web.deps import CurrentSession, DbDep, tenant_ctx
from app.web.templating import request_language

router = APIRouter(prefix="/content", tags=["content"])

_JSON_TYPE = "application/json"
_EML_TYPE = "message/rfc822"
_FIELDS = ("html", "text", "subject", "language")
# Same shape the rule repository accepts for a rule language (lowercase BCP 47-ish code).
_LANGUAGE = re.compile(r"[a-z]{2,3}(?:-[a-z0-9]{2,8})*")


def _access(request: Request, auth: CurrentSession) -> TenantContext:
    """401 anonymous (via current_session), 404 no active tenant, 403 without `content.analyze`."""
    try:
        ctx = tenant_ctx(auth)
    except HTTPException:
        raise _error(request, 404, "api.error.not_found") from None
    if not can(auth.principal, Action.CONTENT_ANALYZE, TenantResource(ctx.tenant_id)):
        raise _error(request, 403, "api.error.forbidden")
    return ctx


Access = Annotated[TenantContext, Depends(_access)]


def _problem(request: Request, status: int, key: str, field: str, reason: str) -> HTTPException:
    return HTTPException(
        status_code=status,
        detail={
            "key": key,
            "message": t(key, request_language(request.scope)),
            "field": field,
            "reason": reason,
        },
    )


def _too_large(request: Request) -> HTTPException:
    return _problem(request, 413, "api.content.error.too_large", "body", "too_large")


def _nul(request: Request, field: str) -> HTTPException:
    return _problem(request, 422, "api.content.error.nul_byte", field, "nul_byte")


def _empty(request: Request) -> HTTPException:
    return _problem(request, 422, "api.content.error.empty", "body", "empty")


def _invalid_body(request: Request, field: str, reason: str) -> HTTPException:
    return _problem(request, 422, "api.content.error.invalid_body", field, reason)


async def _read_capped(request: Request) -> bytes:
    """The body, read with a hard cap: Content-Length is checked first, then the bytes are
    counted while streaming and reading stops at the first chunk that crosses the cap."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_RAW_BYTES):
        raise _too_large(request)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_RAW_BYTES:
            raise _too_large(request)
        chunks.append(chunk)
    return b"".join(chunks)


def _no_constant(_name: str) -> NoReturn:
    raise ValueError("non-finite number")


def _parse_json(request: Request, raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_constant,
        )
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and JSONDecodeError
        raise _invalid_body(request, "body", "malformed_json") from None
    if not isinstance(data, dict):
        raise _invalid_body(request, "body", "not_an_object")
    return data


def _content_from_json(request: Request, raw: bytes) -> ContentInput:
    data = _parse_json(request, raw)
    for name in data:
        if name not in _FIELDS:
            raise _invalid_body(request, "body", "unknown_field")
    values: dict[str, str | None] = {}
    for name in _FIELDS:
        value = data.get(name)
        if value is not None and not isinstance(value, str):
            raise _invalid_body(request, name, "not_a_string")
        if value is not None and "\x00" in value:
            raise _nul(request, name)
        values[name] = value
    language = values["language"]
    if language is not None:
        language = language.lower()
        if len(language) > MAX_LANGUAGE_LENGTH or not _LANGUAGE.fullmatch(language):
            raise _problem(
                request, 422, "api.content.error.invalid_language", "language", "invalid_language"
            )
    if not values["html"] and not values["text"]:
        raise _empty(request)
    return ContentInput(
        html=values["html"] or None,
        text=values["text"] or None,
        subject=values["subject"],
        language_hint=language,
    )


@router.post("/analyze")
async def content_analyze(request: Request, ctx: Access, db: DbDep) -> Response:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in (_JSON_TYPE, _EML_TYPE):
        raise _problem(
            request,
            415,
            "api.content.error.unsupported_media_type",
            "content_type",
            "unsupported_media_type",
        )
    raw = await _read_capped(request)
    if not raw:
        raise _empty(request)
    if b"\x00" in raw:
        raise _nul(request, "body")
    content = (
        _content_from_json(request, raw) if content_type == _JSON_TYPE else ContentInput(eml=raw)
    )
    analysis = await run_in_threadpool(analyze_content, ctx, db, content)
    return Response(content=analysis.model_dump_json(), media_type="application/json")
