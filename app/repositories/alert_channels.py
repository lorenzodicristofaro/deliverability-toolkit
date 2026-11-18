"""Alert channel repositories (M7-15). The only access path to `alert_channels`.

`AlertChannelRepository` is tenant-scoped (reached through `repo_for`): built only with a
`TenantContext`, every query filtered on `tenant_id = ctx.tenant_id`, every row written with the
context tenant. A channel of another tenant behaves exactly like a missing or malformed id (None /
False). Records never carry the secret token: `secret_token(id)` is a separate read, used only by
the dispatcher at send time (and the test send), so no list or API path can serialize it.

Deleting a channel also deletes, in the same transaction and tenant, the alert rules that route
to it and its deliveries (what a CASCADE FK would do; `alert_deliveries.channel_id` and
`alert_rules.channel_id` have no FK yet, see `app.models.alert`).

`AlertDispatchRepository` is the system entry point of the delivery loop (M7-15, like
`MonitorSchedulerRepository`): `tenants_with_due(now, limit)` is its only cross-tenant read and
returns tenant ids only; the loop then works through `repo_for(TenantContext(tenant_id))`.
`AlertChannelSecretRotation.rotate_all(rotate)` is the only cross-tenant write: it re-encrypts
every stored token with the caller's `rotate` (key rotation, `app.core.secrets_crypto.rotate`).

Values are validated before the database (same outcome on SQLite and PostgreSQL) and rejected with
`AlertChannelInvalid(field, reason)`, never echoing the value. The semantic validation of a
kind's settings is the dispatcher's (`app.services.alert_dispatch`). Writes are flushed, not
committed: the caller owns the transaction. A concurrent create with the same name surfaces as
an IntegrityError from the flush.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import ColumnElement, Select, delete, func, select
from sqlalchemy.orm import Session

from app.core.tenancy import TenantContext
from app.models import AlertChannel, AlertDelivery, AlertRule
from app.models.alert_channel import CHANNEL_KINDS, MAX_CHANNEL_NAME_LENGTH
from app.repositories.base import MAX_LIMIT, _install_tenant_guard, coerce_id

_install_tenant_guard(AlertChannel.tenant_id)

DUE_STATUSES: Final = ("pending", "failed")
MAX_SECRET_FIELDS: Final = 8
MAX_FIELD_NAME: Final = 32


class AlertChannelInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"alert channel {field} rejected: {reason}")
        self.field = field
        self.reason = reason


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _aware(value: object, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AlertChannelInvalid(name, "not_aware")
    return value.astimezone(UTC)


def _kind(value: object) -> str:
    if not isinstance(value, str) or value not in CHANNEL_KINDS:
        raise AlertChannelInvalid("kind", "unknown_kind")
    return value


def _name(value: object) -> str:
    if not isinstance(value, str):
        raise AlertChannelInvalid("name", "malformed")
    name = value.strip()
    if not name or len(name) > MAX_CHANNEL_NAME_LENGTH:
        raise AlertChannelInvalid("name", "length")
    if any(not c.isprintable() for c in name):
        raise AlertChannelInvalid("name", "control_character")
    return name


def _enabled(value: object) -> bool:
    if type(value) is not bool:
        raise AlertChannelInvalid("enabled", "malformed")
    return value


def _config(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(k, str) for k in value):
        raise AlertChannelInvalid("config", "malformed")
    return dict(value)


def _secret(token: object, fields: object) -> tuple[str | None, list[str]]:
    if not isinstance(fields, Sequence) or isinstance(fields, str):
        raise AlertChannelInvalid("secret_fields", "malformed")
    names = sorted(set(fields))
    if len(names) != len(fields) or len(names) > MAX_SECRET_FIELDS:
        raise AlertChannelInvalid("secret_fields", "malformed")
    if any(not isinstance(n, str) or not n or len(n) > MAX_FIELD_NAME for n in names):
        raise AlertChannelInvalid("secret_fields", "malformed")
    if token is None:
        if names:
            raise AlertChannelInvalid("secret", "missing")
        return None, []
    if not isinstance(token, str) or not token or not names:
        raise AlertChannelInvalid("secret", "malformed")
    return token, names


@dataclass(frozen=True, slots=True)
class AlertChannelRecord:
    """A channel without its secret token. `secret_fields` are names only."""

    id: int
    kind: str
    name: str
    enabled: bool
    config: Mapping[str, Any] = field(repr=False)
    secret_fields: tuple[str, ...]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, row: AlertChannel) -> AlertChannelRecord:
        return cls(
            id=row.id,
            kind=row.kind,
            name=row.name,
            enabled=row.enabled,
            config=dict(row.config),
            secret_fields=tuple(row.secret_fields),
            created_at=_utc(row.created_at),
            updated_at=_utc(row.updated_at),
        )


class AlertChannelRepository:
    """The context tenant's alert channels."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _select(self, *criteria: ColumnElement[bool]) -> Select[AlertChannel]:
        return select(AlertChannel).where(AlertChannel.tenant_id == self._ctx.tenant_id, *criteria)

    def _row(self, channel_id: object) -> AlertChannel | None:
        cid = coerce_id(channel_id)
        if cid is None:
            return None
        return self._session.scalars(self._select(AlertChannel.id == cid)).one_or_none()

    def list_all(self, *, limit: int = MAX_LIMIT) -> list[AlertChannelRecord]:
        if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
            raise AlertChannelInvalid("limit", "out_of_range")
        stmt = self._select().order_by(AlertChannel.id).limit(limit)
        return [AlertChannelRecord.from_model(r) for r in self._session.scalars(stmt)]

    def get(self, channel_id: object) -> AlertChannelRecord | None:
        row = self._row(channel_id)
        return None if row is None else AlertChannelRecord.from_model(row)

    def count(self) -> int:
        stmt = select(func.count()).where(AlertChannel.tenant_id == self._ctx.tenant_id)
        return int(self._session.scalar(stmt) or 0)

    def name_taken(self, name: object, *, exclude_id: int | None = None) -> bool:
        criteria = [AlertChannel.name == _name(name)]
        if exclude_id is not None:
            criteria.append(AlertChannel.id != exclude_id)
        return self._session.scalars(self._select(*criteria)).first() is not None

    def secret_token(self, channel_id: object) -> str | None:
        """The stored Fernet token (never plaintext); None for no secret or no such channel."""
        row = self._row(channel_id)
        return None if row is None else row.secret

    def create(
        self,
        *,
        kind: object,
        name: object,
        enabled: object,
        config: object,
        secret_token: object,
        secret_fields: object,
        now: object,
    ) -> AlertChannelRecord:
        token, names = _secret(secret_token, secret_fields)
        at = _aware(now, "now")
        row = AlertChannel(
            tenant_id=self._ctx.tenant_id,
            kind=_kind(kind),
            name=_name(name),
            enabled=_enabled(enabled),
            config=_config(config),
            secret=token,
            secret_fields=names,
            created_at=at,
            updated_at=at,
        )
        self._session.add(row)
        self._session.flush()
        return AlertChannelRecord.from_model(row)

    def update(
        self,
        channel_id: object,
        *,
        now: object,
        name: object = None,
        enabled: object = None,
        config: object = None,
        secret: tuple[object, object] | None = None,
    ) -> AlertChannelRecord | None:
        """Change the given fields (None: unchanged); `secret` is (token, field names) and
        replaces the whole stored secret. None for a missing or foreign channel."""
        at = _aware(now, "now")
        row = self._row(channel_id)
        if row is None:
            return None
        if name is not None:
            row.name = _name(name)
        if enabled is not None:
            row.enabled = _enabled(enabled)
        if config is not None:
            row.config = _config(config)
        if secret is not None:
            row.secret, row.secret_fields = _secret(*secret)
        row.updated_at = at
        self._session.flush()
        return AlertChannelRecord.from_model(row)

    def delete(self, channel_id: object) -> bool:
        """Delete the channel with its rules and deliveries (same tenant, same transaction)."""
        row = self._row(channel_id)
        if row is None:
            return False
        tenant = self._ctx.tenant_id
        self._session.execute(
            delete(AlertRule)
            .where(AlertRule.tenant_id == tenant, AlertRule.channel_id == row.id)
            .execution_options(synchronize_session=False)
        )
        self._session.execute(
            delete(AlertDelivery)
            .where(AlertDelivery.tenant_id == tenant, AlertDelivery.channel_id == row.id)
            .execution_options(synchronize_session=False)
        )
        self._session.delete(row)
        self._session.flush()
        return True


class AlertDispatchRepository:
    """System entry point of the delivery loop. Not part of `repo_for`."""

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    def tenants_with_due(self, now: object, limit: object) -> list[int]:
        """Ids of the tenants that have a due (`pending`/`failed`, `next_attempt_at <= now`)
        delivery, ascending, at most `limit` (1..MAX_LIMIT). Read-only; ids only."""
        at = _aware(now, "now")
        if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
            raise AlertChannelInvalid("limit", "out_of_range")
        stmt = (
            select(AlertDelivery.tenant_id)
            .distinct()
            .where(
                AlertDelivery.status.in_(DUE_STATUSES),
                AlertDelivery.next_attempt_at <= at,
            )
            .order_by(AlertDelivery.tenant_id)
            .limit(limit)
        )
        return list(self._session.scalars(stmt))


class AlertChannelSecretRotation:
    """Key rotation entry point (operator command). Not part of `repo_for`."""

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    def rotate_all(self, rotate: Callable[[str], str]) -> int:
        """Replace every stored token with `rotate(token)` (re-encryption under the primary
        key); returns the number of rows changed. A token `rotate` cannot read raises its error
        and the caller's transaction is rolled back, so nothing is half-rotated."""
        changed = 0
        stmt = select(AlertChannel).where(AlertChannel.secret.is_not(None))
        for row in self._session.scalars(stmt):
            assert row.secret is not None
            row.secret = rotate(row.secret)
            changed += 1
        self._session.flush()
        return changed


__all__ = [
    "AlertChannelInvalid",
    "AlertChannelRecord",
    "AlertChannelRepository",
    "AlertChannelSecretRotation",
    "AlertDispatchRepository",
]
