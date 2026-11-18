"""Alert channel routes (M7-15): the active tenant's alert channels.

- `GET /api/v1/alert-channels`: the channels, ordered by id;
- `POST /api/v1/alert-channels`: create, body `{"kind", "name", "enabled"?, "config"?,
  "secrets"?}`; 201;
- `GET /api/v1/alert-channels/{channel_id}`: one channel;
- `PATCH /api/v1/alert-channels/{channel_id}`: change `name`, `enabled`, `config` and/or
  `secrets` (a given `secrets` object replaces every stored secret setting); `kind` is fixed;
- `DELETE /api/v1/alert-channels/{channel_id}`: 204 (its alert rules and deliveries go too);
- `POST /api/v1/alert-channels/{channel_id}/test`: send a test alert now, rate limited per
  channel; 200 `{"outcome": ok|retryable|permanent, "code", "message"}`.

Every route needs `alert.manage` on the active tenant (owner and admin; never analysts or client
viewers). Secret settings (webhook URLs, signing secrets) are encrypted before storage and never
returned: responses show `secrets` as `{name: "********"}` for the names that are set. The
settings rules are in `app.services.alert_dispatch`. Status codes (`{"detail": <i18n>}` bodies):
- 401 anonymous (mutations first need a valid CSRF token, else the CSRF middleware answers 403);
- 403 no `alert.manage` (decided before the body is parsed);
- 404 no active tenant; a channel that is missing, foreign or has a malformed id;
- 409 `alert.channel.error.name_taken`; 413 body too large; 415 not `application/json`;
- 422 malformed body (`{"detail": <i18n>}`), or a rejected field `{key, message, field, reason}`
  never echoing the value; 429 test sends over the limit (`Retry-After`);
- 503 `alert.channel.error.encryption_unavailable`: ENCRYPTION_KEY is not a usable key.
Writes log the actor, channel id and kind only (no audit table yet, as the other admin routes).
"""

from __future__ import annotations

import functools
import logging
import math
import threading
from collections.abc import Callable
from datetime import timedelta
from typing import Annotated, Any, Final, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import Field, StrictBool, StrictStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.v1._common import Body, _error, _parse, _Strict
from app.core.i18n import t
from app.core.permissions import Action, Principal, TenantResource, can
from app.core.secrets_crypto import SecretCipher, SecretsError
from app.core.tenancy import TenantContext
from app.models.alert_channel import CHANNEL_KINDS
from app.repositories import repo_for
from app.repositories.alert_channels import (
    AlertChannelInvalid,
    AlertChannelRecord,
    AlertChannelRepository,
)
from app.repositories.base import parse_id
from app.services.alert_dispatch import (
    DEFAULT_TEST_TIMEOUT,
    AlertDispatcher,
    ChannelRegistry,
    FieldError,
    TestSendLimiter,
    default_registry,
    field_key,
    seal_secrets,
    validate_config,
    validate_secrets,
)
from app.services.alerts import AlertService
from app.services.clock import Clock, SystemClock
from app.web.deps import CurrentSession, DbDep, SettingsDep, _session_factory
from app.web.templating import request_language

logger = logging.getLogger("app.alert_channels")
router = APIRouter(prefix="/alert-channels", tags=["alerts"])

NOT_FOUND_KEY: Final = "alert.channel.error.not_found"
NAME_TAKEN_KEY: Final = "alert.channel.error.name_taken"
RATE_LIMITED_KEY: Final = "alert.channel.error.rate_limited"
ENCRYPTION_KEY: Final = "alert.channel.error.encryption_unavailable"
FORBIDDEN_KEY: Final = "api.error.forbidden"
MASK: Final = "********"
MAX_CHANNELS: Final = 50  # per tenant; bounds work, not a security boundary


# --- errors -------------------------------------------------------------------------------------


class ChannelError(Exception):
    """`status` is the HTTP status, `key` the i18n key; never carries user input."""

    def __init__(self, status: int, key: str) -> None:
        super().__init__(key)
        self.status = status
        self.key = key


class ChannelFieldInvalid(ChannelError):
    def __init__(self, error: FieldError) -> None:
        super().__init__(422, field_key(error.field))
        self.field = error.field
        self.reason = error.reason


def _raise(request: Request, exc: ChannelError) -> NoReturn:
    if isinstance(exc, ChannelFieldInvalid):
        raise HTTPException(
            status_code=422,
            detail={
                "key": exc.key,
                "message": t(exc.key, request_language(request.scope)),
                "field": exc.field,
                "reason": exc.reason,
            },
        ) from None
    raise _error(request, exc.status, exc.key) from None


def _first(errors: list[FieldError]) -> None:
    if errors:
        raise ChannelFieldInvalid(errors[0])


# --- dependencies -------------------------------------------------------------------------------


def alert_channel_clock() -> Clock:
    """Timestamps and the test send limiter; overridden in tests."""
    return SystemClock()


@functools.cache
def _default_registry() -> ChannelRegistry:
    return default_registry()


def alert_registry() -> ChannelRegistry:
    """The channel implementations; overridden in tests."""
    return _default_registry()


CipherFactory = Callable[[], SecretCipher]


def alert_cipher(settings: SettingsDep) -> CipherFactory:
    """Builds the cipher from the app settings only when a secret is sealed or opened, so a bad
    ENCRYPTION_KEY affects only those requests (503)."""
    return lambda: SecretCipher(settings.encryption_key.get_secret_value())


_limiter_lock = threading.Lock()


def alert_test_limiter(
    request: Request, clock: Annotated[Clock, Depends(alert_channel_clock)]
) -> TestSendLimiter:
    """One limiter per app (in memory, per process)."""
    state = request.app.state
    with _limiter_lock:
        limiter = getattr(state, "alert_test_limiter", None)
        if limiter is None:
            limiter = TestSendLimiter(clock)
            state.alert_test_limiter = limiter
    return limiter


class ChannelsApi:
    """One request's channel operations. `ctx` is None when the session has no active tenant."""

    def __init__(
        self,
        db: Session,
        ctx: TenantContext | None,
        principal: Principal,
        clock: Clock,
        registry: ChannelRegistry,
        cipher: CipherFactory,
        allowed_ports: tuple[int, ...],
    ) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal
        self._clock = clock
        self.registry = registry
        self.cipher = cipher
        self._ports = allowed_ports

    @property
    def ctx(self) -> TenantContext:
        if self._ctx is None:
            raise ChannelError(404, NOT_FOUND_KEY)
        return self._ctx

    def check_manage(self) -> None:
        ctx = self.ctx
        if not can(self._principal, Action.ALERT_MANAGE, TenantResource(ctx.tenant_id)):
            raise ChannelError(403, FORBIDDEN_KEY)

    def _repo(self) -> AlertChannelRepository:
        return repo_for(self.ctx, self._db).alert_channels

    def list_all(self) -> list[AlertChannelRecord]:
        self.check_manage()
        return list(self._repo().list_all())

    def get(self, channel_id: int | None) -> AlertChannelRecord:
        self.check_manage()
        record = None if channel_id is None else self._repo().get(channel_id)
        if record is None:
            raise ChannelError(404, NOT_FOUND_KEY)
        assert isinstance(record, AlertChannelRecord)
        return record

    def _seal(self, secrets: dict[str, str]) -> tuple[str | None, list[str]]:
        if not secrets:
            return None, []
        try:
            return seal_secrets(self.cipher(), secrets)
        except SecretsError:
            raise ChannelError(503, ENCRYPTION_KEY) from None

    def _write(self, action: Callable[[], AlertChannelRecord | None]) -> AlertChannelRecord | None:
        """Run a repository write and commit it. A concurrent duplicate name surfaces as an
        IntegrityError at the flush or the commit: rolled back and answered 409. The error is
        dropped (`from None`, no context, nothing logged), because its message carries the SQL
        parameters, the encrypted secret token among them."""
        failed = False
        record: AlertChannelRecord | None = None
        try:
            record = action()
            self._db.commit()
        except IntegrityError:
            failed = True
        if failed:  # raised outside the handler, so the error has no __context__
            self._db.rollback()
            raise ChannelError(409, NAME_TAKEN_KEY)
        return record

    def create(self, payload: ChannelIn) -> AlertChannelRecord:
        if payload.kind not in CHANNEL_KINDS:
            raise ChannelFieldInvalid(FieldError("kind", "unknown_kind"))
        config, errors = validate_config(payload.kind, payload.config, self.registry)
        _first(errors)
        secrets, errors = validate_secrets(
            payload.kind, payload.secrets, self.registry, self._ports
        )
        _first(errors)
        repo = self._repo()
        try:
            if repo.name_taken(payload.name):
                raise ChannelError(409, NAME_TAKEN_KEY)
        except AlertChannelInvalid as exc:
            raise ChannelFieldInvalid(FieldError(exc.field, exc.reason)) from None
        if repo.count() >= MAX_CHANNELS:
            raise ChannelFieldInvalid(FieldError("channel", "limit_reached"))
        token, names = self._seal(secrets)
        record = self._write(
            lambda: repo.create(
                kind=payload.kind,
                name=payload.name,
                enabled=payload.enabled,
                config=config,
                secret_token=token,
                secret_fields=names,
                now=self._clock.now(),
            )
        )
        assert isinstance(record, AlertChannelRecord)
        self._log("alert_channels.created", record)
        return record

    def update(self, channel_id: int | None, payload: ChannelPatch) -> AlertChannelRecord:
        current = self.get(channel_id)
        sent = payload.model_fields_set
        if any(getattr(payload, name) is None for name in sent):
            raise ChannelFieldInvalid(FieldError("body", "null"))
        repo = self._repo()
        config = secret = None
        if "name" in sent:
            try:
                if repo.name_taken(payload.name, exclude_id=current.id):
                    raise ChannelError(409, NAME_TAKEN_KEY)
            except AlertChannelInvalid as exc:
                raise ChannelFieldInvalid(FieldError(exc.field, exc.reason)) from None
        if "config" in sent:
            config, errors = validate_config(current.kind, payload.config, self.registry)
            _first(errors)
        if "secrets" in sent:
            values, errors = validate_secrets(
                current.kind, payload.secrets, self.registry, self._ports
            )
            _first(errors)
            secret = self._seal(values)
        record = self._write(
            lambda: repo.update(
                current.id,
                now=self._clock.now(),
                name=payload.name if "name" in sent else None,
                enabled=payload.enabled if "enabled" in sent else None,
                config=config,
                secret=secret,
            )
        )
        if record is None:  # deleted meanwhile; nothing was written
            raise ChannelError(404, NOT_FOUND_KEY)
        self._log("alert_channels.updated", record)
        return record

    def delete(self, channel_id: int | None) -> None:
        current = self.get(channel_id)
        if not self._repo().delete(current.id):
            raise ChannelError(404, NOT_FOUND_KEY)
        self._db.commit()
        self._log("alert_channels.deleted", current)

    def _log(self, event: str, record: AlertChannelRecord) -> None:
        logger.info(
            "%s channel %d (%s)",
            event,
            record.id,
            record.kind,
            extra={"event": event, "tenant_id": self.ctx.tenant_id, "actor": self.ctx.principal},
        )


def _api(
    db: DbDep,
    auth: CurrentSession,
    settings: SettingsDep,
    clock: Annotated[Clock, Depends(alert_channel_clock)],
    registry: Annotated[ChannelRegistry, Depends(alert_registry)],
    cipher: Annotated[CipherFactory, Depends(alert_cipher)],
) -> ChannelsApi:
    ctx = (
        None
        if auth.active_tenant_id is None
        else TenantContext(tenant_id=auth.active_tenant_id, principal=auth.user.id)
    )
    return ChannelsApi(
        db, ctx, auth.principal, clock, registry, cipher, settings.outbound_http_ports()
    )


Api = Annotated[ChannelsApi, Depends(_api)]


def _manage(request: Request, api: Api) -> ChannelsApi:
    """Authentication (401) via `Api`, then tenant (404) and permission (403), before the body."""
    try:
        api.check_manage()
    except ChannelError as exc:
        _raise(request, exc)
    return api


Manage = Annotated[ChannelsApi, Depends(_manage)]


# --- payloads -----------------------------------------------------------------------------------


class ChannelIn(_Strict):
    kind: StrictStr
    name: StrictStr = Field(max_length=1000)
    enabled: StrictBool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, Any] = Field(default_factory=dict)


class ChannelPatch(_Strict):
    name: StrictStr | None = Field(default=None, max_length=1000)
    enabled: StrictBool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, Any] | None = None


# --- responses ----------------------------------------------------------------------------------


def _channel_json(record: AlertChannelRecord) -> dict[str, Any]:
    """Secret values never appear: only the names of the stored secret settings, masked."""
    return {
        "id": record.id,
        "kind": record.kind,
        "name": record.name,
        "enabled": record.enabled,
        "config": dict(record.config),
        "secrets": {name: MASK for name in record.secret_fields},
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


# --- routes -------------------------------------------------------------------------------------


@router.get("")
def list_channels(request: Request, api: Manage) -> dict[str, Any]:
    try:
        records = api.list_all()
    except ChannelError as exc:
        _raise(request, exc)
    return {"items": [_channel_json(r) for r in records]}


@router.post("")
def create_channel(request: Request, api: Manage, body: Body) -> Response:
    payload = _parse(request, ChannelIn, body)
    try:
        record = api.create(payload)
    except ChannelError as exc:
        _raise(request, exc)
    return JSONResponse(_channel_json(record), status_code=201)


@router.get("/{channel_id}")
def get_channel(request: Request, api: Manage, channel_id: str) -> dict[str, Any]:
    try:
        return _channel_json(api.get(parse_id(channel_id)))
    except ChannelError as exc:
        _raise(request, exc)


@router.patch("/{channel_id}")
def update_channel(request: Request, api: Manage, body: Body, channel_id: str) -> dict[str, Any]:
    target = parse_id(channel_id)
    try:
        api.get(target)  # a missing or foreign channel is 404 whatever the body
        return _channel_json(api.update(target, _parse(request, ChannelPatch, body)))
    except ChannelError as exc:
        _raise(request, exc)


@router.delete("/{channel_id}", status_code=204)
def delete_channel(request: Request, api: Manage, channel_id: str) -> Response:
    try:
        api.delete(parse_id(channel_id))
    except ChannelError as exc:
        _raise(request, exc)
    return Response(status_code=204)


@router.post("/{channel_id}/test")
async def test_channel(
    request: Request,
    api: Manage,
    db: DbDep,
    limiter: Annotated[TestSendLimiter, Depends(alert_test_limiter)],
    clock: Annotated[Clock, Depends(alert_channel_clock)],
    settings: SettingsDep,
    channel_id: str,
) -> dict[str, Any]:
    target = parse_id(channel_id)
    try:
        record = await run_in_threadpool(api.get, target)
    except ChannelError as exc:
        _raise(request, exc)
    await run_in_threadpool(db.rollback)  # hold no pooled connection through the send
    ctx = api.ctx
    wait = limiter.try_acquire(ctx.tenant_id, record.id)
    if wait is not None:
        error = _error(request, 429, RATE_LIMITED_KEY)
        error.headers = {"Retry-After": str(math.ceil(wait.total_seconds()))}
        raise error
    try:
        cipher = api.cipher()
    except SecretsError:
        raise _error(request, 503, ENCRYPTION_KEY) from None
    factory = _session_factory(request)
    # min(test timeout, send timeout): the email channel bounds a test send to 0.8 of the same.
    test_wait = min(DEFAULT_TEST_TIMEOUT, timedelta(seconds=settings.alert_send_timeout_seconds))
    dispatcher = AlertDispatcher(
        factory, AlertService(factory, clock), api.registry, cipher, clock, test_timeout=test_wait
    )
    result = await dispatcher.send_test(ctx, record.id)
    if result is None:  # deleted meanwhile
        raise _error(request, 404, NOT_FOUND_KEY)
    logger.info(
        "alert channel %d test send: %s (%s)",
        record.id,
        result.outcome.value,
        result.code,
        extra={"event": "alert_channels.tested", "tenant_id": ctx.tenant_id},
    )
    return {
        "outcome": result.outcome.value,
        "code": result.code,
        "message": t(f"alert.channel.test.{result.outcome.value}", request_language(request.scope)),
    }
