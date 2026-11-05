"""Helpers shared by the `/api/v1` routers: translated errors, size-limited body reading and
strict JSON parsing (moved out of `domains.py` in M2-12, no behaviour change)."""

from __future__ import annotations

import json
from typing import Annotated, Any, NoReturn

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, ValidationError

from app.core.i18n import t
from app.web.templating import request_language

MAX_BODY_BYTES = 64 * 1024
_JSON_TYPE = "application/json"


def _error(request: Request, status: int, key: str) -> HTTPException:
    return HTTPException(status_code=status, detail=t(key, request_language(request.scope)))


class RawBody:
    __slots__ = ("data", "is_json")

    def __init__(self, is_json: bool, data: bytes) -> None:
        self.is_json = is_json
        self.data = data


async def _raw_body(request: Request) -> RawBody:
    """The request body, read with a hard size limit (413 beyond MAX_BODY_BYTES). Parsed only
    after the permission checks (`_parse`), so a denied caller gets 403/404, not 415/422."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
        raise _error(request, 413, "api.error.payload_too_large")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise _error(request, 413, "api.error.payload_too_large")
        chunks.append(chunk)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    return RawBody(content_type == _JSON_TYPE, b"".join(chunks))


Body = Annotated[RawBody, Depends(_raw_body)]


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _no_constant(_name: str) -> NoReturn:
    raise ValueError("NaN/Infinity are not JSON")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _parse[M: _Strict](request: Request, model: type[M], body: RawBody) -> M:
    """Strict JSON (no duplicate keys, no NaN/Infinity) validated by a strict model; any error is
    a generic 415/422 whose body does not echo the input."""
    if not body.is_json:
        raise _error(request, 415, "api.error.invalid_request")
    try:
        data = json.loads(
            body.data.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_constant,
        )
        return model.model_validate(data)
    except (UnicodeDecodeError, ValueError, RecursionError, ValidationError):
        raise _error(request, 422, "api.error.invalid_request") from None
