"""Alert channels: the Channel protocol, the registry, settings validation and the delivery loop
(M7-15). Design: ARCHITECTURE section 6 ("Alerts"); the concrete channels are M7-16..19.

Channel protocol. A channel kind (email, webhook, slack, teams) is an object with
- `kind`: its kind string;
- `validate_config(config) -> list[FieldError]`: extra checks of the NON-secret settings;
- `validate_secrets(secrets) -> list[FieldError]`: extra checks of the secret settings;
- `async send(alert, rendered, channel) -> SendResult`: deliver one alert. `alert` is the
  M7-14 `AlertMessage` (codes and params), `rendered` the text in the tenant language,
  `channel` the decrypted settings. Outcome `ok`, `retryable` or `permanent`, with a short
  stable code (`timeout`, `http_5xx`, ...); never a message, body or secret. Every outbound
  request goes through the guarded client (`app.net.guarded_http`), which validates the URL
  again at send time: the write-time check below is a convenience, not the control.
Channels are registered by kind in a `ChannelRegistry`. `default_registry()` reads the
mapping `CHANNELS` of the package `app.services.alert_channels` (M7-16..19 add their lines
there) and is empty while that package does not exist.

Base settings per kind (project choices, not vendor facts; checked before the channel's own
checks): email `config.recipients` (1..10 addresses), no secrets; webhook secret `url`
(required) and `signing_secret` (optional, 16..256 printable ASCII characters); slack and teams
secret `url`. Every URL must be https with a host and port the guarded client accepts
(`app.net.policy.parse_url`, no DNS). Unknown keys are rejected. Secret settings are sealed as one
Fernet token (`seal_secrets`, `app.core.secrets_crypto`) and opened only at send time.

Delivery loop. `AlertDispatcher.run_once()` lists the tenants with due deliveries
(`AlertDispatchRepository.tenants_with_due`) and calls M7-14's `AlertService.deliver_due` for
each with `TenantContext(tenant, principal=None)`, passing `sender` as the `Sender`. So claim,
lease, `send_timeout` (< lease), attempts, backoff and abandon are M7-14's and not repeated
here. The sender loads the channel, its secret token, the tenant language and the domain name
(in a worker thread), opens the secrets, renders the alert and calls the channel; anything but
`ok` (and a missing, disabled, unregistered or unreadable channel) becomes a `DeliveryError`
with a stable code, i.e. a failed attempt. A channel exception is caught by `deliver_due` (code
`internal_error`); an exception for one tenant is logged and the loop goes on.
`permanent` is retried like `retryable` until `max_attempts`: M7-14's delivery API has no
"abandon now" path.
`run(stop=None)` loops `run_once` every `poll_interval` until cancelled (or `stop` is set); a
cancellation mid-send leaves that delivery claimed, and it is due again when its lease ends.

`send_test(ctx, channel_id)` sends a synthetic test alert (code `ALERT_TEST`) to one channel,
enabled or not, under `test_timeout`, and returns the `SendResult` (None for no such channel).
`TestSendLimiter` bounds test sends per channel. Logs carry ids, kinds and codes only.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import importlib.util
import json
import logging
import threading
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from sqlalchemy.orm import Session, sessionmaker

from app.core.i18n import t
from app.core.secrets_crypto import SecretCipher, SecretsError
from app.core.tenancy import TenantContext
from app.models.alert_channel import CHANNEL_KINDS
from app.models.user import normalize_email
from app.net.policy import FetchError, parse_url
from app.repositories import repo_for
from app.repositories.alert_channels import AlertChannelRecord, AlertDispatchRepository
from app.repositories.alerts import error_code
from app.services.alerts import (
    DEFAULT_SEND_TIMEOUT,
    I18N_PREFIX,
    INTERNAL_ERROR,
    SEND_TIMEOUT,
    AlertMessage,
    AlertService,
    DeliveryError,
    DeliveryReport,
)
from app.services.clock import Clock

logger = logging.getLogger("app.alert_dispatch")

CHANNELS_PACKAGE: Final = "app.services.alert_channels"
MAX_RECIPIENTS: Final = 10
MIN_SIGNING_SECRET: Final = 16
MAX_SIGNING_SECRET: Final = 256
MAX_URL: Final = 2048
DEFAULT_POLL_INTERVAL: Final = timedelta(seconds=30)
DEFAULT_TENANT_BATCH: Final = 100
DEFAULT_DELIVERY_BATCH: Final = 50
DEFAULT_TEST_CAPACITY: Final = 3
DEFAULT_TEST_WINDOW: Final = timedelta(minutes=10)
TEST_CODE: Final = "ALERT_TEST"
TEST_KIND: Final = "test"

# Delivery error codes of the dispatcher itself (stored by M7-14 as `last_error`).
CHANNEL_MISSING: Final = "channel_missing"
CHANNEL_DISABLED: Final = "channel_disabled"
CHANNEL_UNAVAILABLE: Final = "channel_unavailable"
SECRET_UNREADABLE: Final = "secret_unreadable"
CONFIG_INVALID: Final = "config_invalid"
INVALID_RESULT: Final = "invalid_result"

# i18n keys of rejected settings (`field_key`).
KEY_PREFIX: Final = "alert.channel.error"
_FIELD_KEYS: Final[Mapping[str, str]] = {
    "kind": f"{KEY_PREFIX}.invalid_kind",
    "name": f"{KEY_PREFIX}.invalid_name",
    "recipients": f"{KEY_PREFIX}.invalid_recipients",
    "url": f"{KEY_PREFIX}.invalid_url",
    "signing_secret": f"{KEY_PREFIX}.invalid_signing_secret",
    "channel": f"{KEY_PREFIX}.limit_reached",
}
INVALID_SETTINGS_KEY: Final = f"{KEY_PREFIX}.invalid_settings"


def field_key(field_name: str) -> str:
    """The i18n key of a rejected field."""
    return _FIELD_KEYS.get(field_name, INVALID_SETTINGS_KEY)


# --- contract ----------------------------------------------------------------------------------


class SendOutcome(StrEnum):
    OK = "ok"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"


@dataclass(frozen=True, slots=True)
class SendResult:
    outcome: SendOutcome
    code: str = "ok"

    @classmethod
    def ok(cls) -> SendResult:
        return cls(SendOutcome.OK)

    @classmethod
    def retryable(cls, code: str) -> SendResult:
        return cls(SendOutcome.RETRYABLE, error_code(code))

    @classmethod
    def permanent(cls, code: str) -> SendResult:
        return cls(SendOutcome.PERMANENT, error_code(code))


@dataclass(frozen=True, slots=True)
class FieldError:
    """A rejected setting: the field name and a stable reason, never the value."""

    field: str
    reason: str


@dataclass(frozen=True, slots=True)
class RenderedAlert:
    """The alert text in the tenant language. Plain text, NOT escaped: values come from domain
    names and params (untrusted), so every channel escapes for its own format."""

    language: str
    title: str
    detail: str
    domain: str


@dataclass(frozen=True, slots=True)
class ResolvedChannel:
    """A channel with its decrypted secrets, built only at send time. repr hides settings."""

    id: int
    tenant_id: int
    kind: str
    name: str
    config: Mapping[str, Any] = field(repr=False)
    secrets: Mapping[str, str] = field(repr=False)


@runtime_checkable
class Channel(Protocol):
    kind: str

    def validate_config(self, config: Mapping[str, Any]) -> list[FieldError]: ...

    def validate_secrets(self, secrets: Mapping[str, str]) -> list[FieldError]: ...

    async def send(
        self, alert: AlertMessage, rendered: RenderedAlert, channel: ResolvedChannel
    ) -> SendResult: ...


class ChannelRegistry:
    """Channel implementations by kind (only kinds of `CHANNEL_KINDS`)."""

    __slots__ = ("_channels",)

    def __init__(self, channels: Mapping[str, Channel] | None = None) -> None:
        checked: dict[str, Channel] = {}
        for kind, channel in (channels or {}).items():
            if kind not in CHANNEL_KINDS or getattr(channel, "kind", None) != kind:
                raise ValueError("channel registered under a wrong or unknown kind")
            if not isinstance(channel, Channel):
                raise TypeError("registered object does not implement the Channel protocol")
            checked[kind] = channel
        self._channels = checked

    def get(self, kind: str) -> Channel | None:
        return self._channels.get(kind)

    @property
    def kinds(self) -> frozenset[str]:
        return frozenset(self._channels)


def default_registry() -> ChannelRegistry:
    """The channels of `app.services.alert_channels.CHANNELS`; empty without that package."""
    if importlib.util.find_spec(CHANNELS_PACKAGE) is None:
        return ChannelRegistry()
    module = importlib.import_module(CHANNELS_PACKAGE)
    return ChannelRegistry(getattr(module, "CHANNELS", {}))


# --- settings validation and sealing -----------------------------------------------------------

# kind -> (config fields: required?), (secret fields: required?)
_CONFIG_FIELDS: Final[Mapping[str, Mapping[str, bool]]] = {
    "email": {"recipients": True},
    "webhook": {},
    "slack": {},
    "teams": {},
}
_SECRET_FIELDS: Final[Mapping[str, Mapping[str, bool]]] = {
    "email": {},
    "webhook": {"url": True, "signing_secret": False},
    "slack": {"url": True},
    "teams": {"url": True},
}


def _fields(
    value: object, allowed: Mapping[str, bool], scope: str
) -> tuple[dict[str, Any], list[FieldError]]:
    if not isinstance(value, Mapping) or not all(isinstance(k, str) for k in value):
        return {}, [FieldError(scope, "malformed")]
    errors = [FieldError(scope, "unknown_field") for k in value if k not in allowed][:1]
    errors += [FieldError(k, "required") for k, req in allowed.items() if req and k not in value]
    return dict(value), errors


def _recipients(value: object) -> list[FieldError]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_RECIPIENTS:
        return [FieldError("recipients", "count")]
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            return [FieldError("recipients", "malformed")]
        try:
            address = normalize_email(item)
        except ValueError:
            return [FieldError("recipients", "malformed")]
        if address != item or address in seen or any(c in item for c in "\r\n,;<>\"'"):
            return [FieldError("recipients", "malformed")]
        seen.add(address)
    return []


def check_url(value: object, allowed_ports: tuple[int, ...]) -> FieldError | None:
    """Write-time URL check (convenience; the guarded client is the control at send time)."""
    if not isinstance(value, str) or not value or len(value) > MAX_URL:
        return FieldError("url", "malformed")
    target = parse_url(value, allowed_ports)
    if isinstance(target, FetchError):
        return FieldError("url", str(target.kind))
    if target.scheme != "https":
        return FieldError("url", "scheme_not_allowed")
    return None


def _signing_secret(value: object) -> list[FieldError]:
    if (
        not isinstance(value, str)
        or not MIN_SIGNING_SECRET <= len(value) <= MAX_SIGNING_SECRET
        or not all(0x21 <= ord(c) <= 0x7E for c in value)
    ):
        return [FieldError("signing_secret", "malformed")]
    return []


def validate_config(
    kind: str, config: object, registry: ChannelRegistry
) -> tuple[dict[str, Any], list[FieldError]]:
    """Base checks of the non-secret settings of `kind`, then the channel's own (if any)."""
    values, errors = _fields(config, _CONFIG_FIELDS[kind], "config")
    if not errors and "recipients" in values:
        errors = _recipients(values["recipients"])
    channel = registry.get(kind)
    if not errors and channel is not None:
        errors = list(channel.validate_config(values))
    return values, errors


def validate_secrets(
    kind: str, secrets: object, registry: ChannelRegistry, allowed_ports: tuple[int, ...]
) -> tuple[dict[str, str], list[FieldError]]:
    """Base checks of the secret settings of `kind`, then the channel's own (if any)."""
    values, errors = _fields(secrets, _SECRET_FIELDS[kind], "secrets")
    if not errors and "url" in values:
        bad = check_url(values["url"], allowed_ports)
        errors = [] if bad is None else [bad]
    if not errors and "signing_secret" in values:
        errors = _signing_secret(values["signing_secret"])
    channel = registry.get(kind)
    if not errors and channel is not None:
        errors = list(channel.validate_secrets(values))
    return values, errors


def seal_secrets(cipher: SecretCipher, secrets: Mapping[str, str]) -> tuple[str | None, list[str]]:
    """(token, field names) to store; (None, []) when there is no secret setting."""
    if not secrets:
        return None, []
    return cipher.encrypt(json.dumps(dict(secrets), sort_keys=True)), sorted(secrets)


def open_secrets(cipher: SecretCipher, token: str | None) -> dict[str, str]:
    """The secret settings of a stored token. Raises SecretsError (fixed text) when unreadable."""
    if token is None:
        return {}
    text = cipher.decrypt(token)
    data: object = None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise SecretsError("stored channel secret is malformed")
    return data


# --- rendering ---------------------------------------------------------------------------------


def render(message: AlertMessage, language: str, domain: str) -> RenderedAlert:
    """Title and detail of `message.code` in `language` (English fallback)."""
    params = {"subject": "", "before": "", "after": "", **message.params, "domain": domain}
    prefix = f"{I18N_PREFIX}.{message.code}"
    return RenderedAlert(
        language=language,
        title=t(f"{prefix}.title", language, **params),
        detail=t(f"{prefix}.detail", language, **params),
        domain=domain,
    )


# --- test send rate limit ----------------------------------------------------------------------


class TestSendLimiter:
    """At most `capacity` test sends per (tenant, channel) per `window`, in memory, per process
    (a restart starts with a full allowance). Thread-safe."""

    __test__ = False  # not a pytest class

    def __init__(
        self,
        clock: Clock,
        *,
        capacity: int = DEFAULT_TEST_CAPACITY,
        window: timedelta = DEFAULT_TEST_WINDOW,
    ) -> None:
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive int")
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")
        self._clock = clock
        self._capacity = capacity
        self._window = window
        self._grants: dict[tuple[int, int], deque[datetime]] = {}
        self._lock = threading.Lock()

    def try_acquire(self, tenant_id: int, channel_id: int) -> timedelta | None:
        """None when granted, else how long until a slot frees up."""
        now = self._clock.now()
        with self._lock:
            grants = self._grants.setdefault((tenant_id, channel_id), deque())
            while grants and grants[0] <= now - self._window:
                grants.popleft()
            if len(grants) >= self._capacity:
                return max(grants[0] + self._window - now, timedelta(seconds=1))
            grants.append(now)
            return None


# --- dispatcher --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Loaded:
    record: AlertChannelRecord
    token: str | None = field(repr=False)
    language: str
    domain: str


class AlertDispatcher:
    """The delivery loop and the test send. Dependencies are injected (see module docstring)."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        alerts: AlertService,
        registry: ChannelRegistry,
        cipher: SecretCipher,
        clock: Clock,
        *,
        poll_interval: timedelta = DEFAULT_POLL_INTERVAL,
        tenant_batch: int = DEFAULT_TENANT_BATCH,
        delivery_batch: int = DEFAULT_DELIVERY_BATCH,
        test_timeout: timedelta = DEFAULT_SEND_TIMEOUT,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        for name, value in (("poll_interval", poll_interval), ("test_timeout", test_timeout)):
            if not isinstance(value, timedelta) or value <= timedelta(0):
                raise ValueError(f"{name} must be a positive timedelta")
        for name, number in (("tenant_batch", tenant_batch), ("delivery_batch", delivery_batch)):
            if type(number) is not int or not 1 <= number <= 1000:
                raise ValueError(f"{name} must be an int between 1 and 1000")
        self._factory = factory
        self._alerts = alerts
        self._registry = registry
        self._cipher = cipher
        self._clock = clock
        self._poll = poll_interval
        self._tenant_batch = tenant_batch
        self._delivery_batch = delivery_batch
        self._test_timeout = test_timeout
        self._sleep = sleep

    # --- loading -------------------------------------------------------------------------------

    def _load(self, ctx: TenantContext, channel_id: int, domain_id: int) -> _Loaded | None:
        with self._factory.begin() as db:
            repos = repo_for(ctx, db)
            record = repos.alert_channels.get(channel_id)
            if record is None:
                return None
            tenant = repos.tenant.get()
            domain = repos.domains.get(domain_id) if domain_id > 0 else None
            return _Loaded(
                record=record,
                token=repos.alert_channels.secret_token(channel_id),
                language=tenant.language if tenant is not None else "en",
                domain=domain.name if domain is not None else "",
            )

    def _resolve(self, ctx: TenantContext, loaded: _Loaded) -> tuple[Channel, ResolvedChannel]:
        """The channel implementation and decrypted settings; DeliveryError if unusable."""
        record = loaded.record
        channel = self._registry.get(record.kind)
        if channel is None:
            raise DeliveryError(CHANNEL_UNAVAILABLE)
        try:
            secrets = open_secrets(self._cipher, loaded.token)
        except SecretsError:
            raise DeliveryError(SECRET_UNREADABLE) from None
        if channel.validate_config(record.config) or channel.validate_secrets(secrets):
            raise DeliveryError(CONFIG_INVALID)
        resolved = ResolvedChannel(
            record.id, ctx.tenant_id, record.kind, record.name, record.config, secrets
        )
        return channel, resolved

    # --- delivery ------------------------------------------------------------------------------

    async def sender(self, ctx: TenantContext, channel_id: int, message: AlertMessage) -> None:
        """The M7-14 `Sender`: returns when the channel accepted, else raises DeliveryError."""
        loaded = await asyncio.to_thread(self._load, ctx, channel_id, message.domain_id)
        if loaded is None:
            raise DeliveryError(CHANNEL_MISSING)
        if not loaded.record.enabled:
            raise DeliveryError(CHANNEL_DISABLED)
        channel, resolved = self._resolve(ctx, loaded)
        rendered = render(message, loaded.language, loaded.domain)
        result = await channel.send(message, rendered, resolved)
        if not isinstance(result, SendResult):
            raise DeliveryError(INVALID_RESULT)
        if result.outcome is not SendOutcome.OK:
            raise DeliveryError(error_code(result.code))

    def _due_tenants(self, now: datetime) -> list[int]:
        with self._factory.begin() as db:
            return AlertDispatchRepository(db).tenants_with_due(now, self._tenant_batch)

    async def run_once(self) -> DeliveryReport:
        """One pass over the tenants with due deliveries; returns the summed report."""
        tenants = await asyncio.to_thread(self._due_tenants, self._clock.now())
        totals = {"sent": 0, "failed": 0, "abandoned": 0, "skipped": 0}
        for tenant_id in tenants:
            try:
                report = await self._alerts.deliver_due(
                    TenantContext(tenant_id, None), self.sender, limit=self._delivery_batch
                )
            except Exception as exc:  # noqa: BLE001 - one tenant never stops the loop
                logger.error(
                    "alert delivery pass failed: %s",
                    type(exc).__name__,
                    extra={"event": "alert_dispatch.tenant_failed", "tenant_id": tenant_id},
                )
                continue
            for key in totals:
                totals[key] += getattr(report, key)
        return DeliveryReport(**totals)

    async def run(self, stop: asyncio.Event | None = None) -> None:
        """Loop `run_once` every `poll_interval` until cancelled or `stop` is set."""
        while stop is None or not stop.is_set():
            try:
                await self.run_once()
            except Exception as exc:  # noqa: BLE001 - the loop survives a failed pass
                logger.error(
                    "alert dispatch pass failed: %s",
                    type(exc).__name__,
                    extra={"event": "alert_dispatch.pass_failed"},
                )
            seconds = self._poll.total_seconds()
            if stop is None:
                await self._sleep(seconds)
            else:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), seconds)

    # --- test send -----------------------------------------------------------------------------

    async def send_test(self, ctx: TenantContext, channel_id: int) -> SendResult | None:
        """Send a test alert to one channel (enabled or not); None for no such channel."""
        if not isinstance(ctx, TenantContext):
            raise TypeError("send_test requires a TenantContext")
        loaded = await asyncio.to_thread(self._load, ctx, channel_id, 0)
        if loaded is None:
            return None
        message = AlertMessage(0, 0, TEST_KIND, TEST_CODE, {}, self._clock.now())
        try:
            channel, resolved = self._resolve(ctx, loaded)
            rendered = render(message, loaded.language, "")
            result = await asyncio.wait_for(
                channel.send(message, rendered, resolved), self._test_timeout.total_seconds()
            )
        except DeliveryError as exc:
            return SendResult.permanent(exc.code)
        except TimeoutError:
            return SendResult.retryable(SEND_TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - a channel bug is a failed test, not a 500
            logger.error(
                "alert channel raised %s on a test send",
                type(exc).__name__,
                extra={"event": "alert_dispatch.test_crashed", "tenant_id": ctx.tenant_id},
            )
            return SendResult.retryable(INTERNAL_ERROR)
        if not isinstance(result, SendResult):
            return SendResult.permanent(INVALID_RESULT)
        return SendResult(result.outcome, error_code(result.code))


__all__ = [
    "Channel",
    "ChannelRegistry",
    "AlertDispatcher",
    "FieldError",
    "RenderedAlert",
    "ResolvedChannel",
    "SendOutcome",
    "SendResult",
    "TestSendLimiter",
    "check_url",
    "default_registry",
    "field_key",
    "open_secrets",
    "render",
    "seal_secrets",
    "validate_config",
    "validate_secrets",
]
