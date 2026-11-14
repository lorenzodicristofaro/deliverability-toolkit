"""DNSBL list enablement repository (M7-05c). The only access path to `dnsbl_list_enablements`.

Instance-level data (no tenant): like `GlobalDkimSelectorRepository`, it is NOT part of
`repo_for`. Writes are reached only through `app.services.dnsbl_admin` after the instance admin
check (`instance.manage`); reads of the enabled ids (`enabled_ids`) serve every check run, which
needs no permission beyond the one to run the check.

A row means "enabled"; `disable` deletes it. `enable` is an upsert: re-enabling a list records the
new acknowledgement, actor and time. Callers get immutable `DnsblEnablementRecord`s, never ORM
objects.

Validation before the database (identical outcome on SQLite and PostgreSQL): the list id is a
slug `[a-z0-9][a-z0-9-]{0,39}` (the rule of `app.checks.dnsbl_schema`), the flags are real bools,
`policy_acknowledged` must be True, times are timezone-aware. `DnsblEnablementInvalid` names the
field and a stable reason, never the value. Whether the id names a shipped list is the service's
check (the repository does not read YAML).

A concurrent first enable of the same list surfaces as `EnablementConflict` from the flush; the
session must then be rolled back by the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dnsbl_enablement import DnsblListEnablement

_LIST_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
# More rows than any seed can hold (dnsbl_schema.MAX_LISTS is 100): reads never page.
MAX_ROWS: Final = 1000


class DnsblEnablementInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"dnsbl enablement {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class EnablementConflict(Exception):
    """A concurrent enable inserted the same list first; roll the session back."""


@dataclass(frozen=True, slots=True)
class DnsblEnablementRecord:
    list_id: str
    enabled_by: int | None
    enabled_at: datetime
    policy_acknowledged: bool
    policy_acknowledged_at: datetime
    unverified_confirmed: bool

    @classmethod
    def from_model(cls, row: DnsblListEnablement) -> DnsblEnablementRecord:
        return cls(
            list_id=row.list_id,
            enabled_by=row.enabled_by,
            enabled_at=row.enabled_at,
            policy_acknowledged=row.policy_acknowledged,
            policy_acknowledged_at=row.policy_acknowledged_at,
            unverified_confirmed=row.unverified_confirmed,
        )


def valid_list_id(value: object) -> bool:
    return isinstance(value, str) and _LIST_ID.fullmatch(value) is not None


def _list_id(value: object) -> str:
    if not valid_list_id(value):
        raise DnsblEnablementInvalid("list_id", "invalid")
    assert isinstance(value, str)
    return value


def _flag(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise DnsblEnablementInvalid(field, "not_a_bool")
    return value


def _aware(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DnsblEnablementInvalid(field, "not_aware")
    return value


def _actor(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise DnsblEnablementInvalid("enabled_by", "invalid")
    return value


class DnsblEnablementRepository:
    """Instance-level enablement rows (admin service and check runs only)."""

    def __init__(self, session: Session) -> None:
        self._db = session

    def _row(self, list_id: str) -> DnsblListEnablement | None:
        return self._db.scalars(
            select(DnsblListEnablement).where(DnsblListEnablement.list_id == list_id)
        ).one_or_none()

    # --- reads ------------------------------------------------------------------------------------

    def enabled_ids(self) -> frozenset[str]:
        """The ids of every enabled list (malformed ids cannot be stored, see the CHECKs)."""
        stmt = select(DnsblListEnablement.list_id).limit(MAX_ROWS)
        return frozenset(self._db.scalars(stmt).all())

    def records(self) -> list[DnsblEnablementRecord]:
        stmt = select(DnsblListEnablement).order_by(DnsblListEnablement.list_id).limit(MAX_ROWS)
        return [DnsblEnablementRecord.from_model(r) for r in self._db.scalars(stmt).all()]

    def get(self, list_id: object) -> DnsblEnablementRecord | None:
        """The row of `list_id`; None if absent or malformed."""
        if not valid_list_id(list_id):
            return None
        assert isinstance(list_id, str)
        row = self._row(list_id)
        return None if row is None else DnsblEnablementRecord.from_model(row)

    # --- writes -----------------------------------------------------------------------------------

    def enable(
        self,
        list_id: object,
        *,
        actor: object,
        policy_acknowledged: object,
        unverified_confirmed: object,
        now: object,
    ) -> DnsblEnablementRecord:
        """Insert or refresh the row of `list_id` (flushed, not committed)."""
        lid = _list_id(list_id)
        if not _flag(policy_acknowledged, "policy_acknowledged"):
            raise DnsblEnablementInvalid("policy_acknowledged", "required")
        confirmed = _flag(unverified_confirmed, "unverified_confirmed")
        when = _aware(now, "now")
        by = _actor(actor)
        row = self._row(lid)
        if row is None:
            row = DnsblListEnablement(list_id=lid)
            self._db.add(row)
        row.enabled_by = by
        row.enabled_at = when
        row.policy_acknowledged = True
        row.policy_acknowledged_at = when
        row.unverified_confirmed = confirmed
        try:
            self._db.flush()
        except IntegrityError:
            raise EnablementConflict from None
        return DnsblEnablementRecord.from_model(row)

    def disable(self, list_id: object) -> bool:
        """Delete the row of `list_id` (flushed, not committed); False if there was none."""
        if not valid_list_id(list_id):
            return False
        result = self._db.execute(
            delete(DnsblListEnablement).where(DnsblListEnablement.list_id == list_id)
        )
        return bool(getattr(result, "rowcount", 0))
