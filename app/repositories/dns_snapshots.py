"""DNS snapshot repositories (M7-08). The only access path to `dns_snapshots`.

Two classes, deliberately separate:

`DnsSnapshotRepository` is tenant-scoped (reached through `repo_for`). Built only with a
`TenantContext`; every query is filtered on `tenant_id = ctx.tenant_id` and every row is written
with the context tenant; a domain or snapshot of another tenant behaves exactly like a missing or
malformed one (None / empty); the composite FK (domain_id, tenant_id) -> domains(id, tenant_id)
makes a cross-tenant row impossible in the database too. Not built on `TenantScopedRepository`
because its generic `add(obj)` would bypass the validation below. Snapshots are immutable: there
is no update; deletion happens only by retention (`DnsSnapshotRetentionRepository`) or cascade.

`DnsSnapshotRetentionRepository.prune_all_tenants(cutoff)` is the ONLY cross-tenant method in this
module: the system entry point of retention (`app.services.retention`), like
`CheckRunRetentionRepository`. Not part of `repo_for`, takes no tenant from its caller, deletes by
age only in bounded batches, and never deletes the newest snapshot of a domain (the baseline the
next diff needs, even when snapshotting paused for longer than the window).

The repository validates what it stores: a 64-hex content hash, a bounded list of mappings whose
JSON text, measured as the column stores it (`json.dumps`, default separators), stays within
`MAX_ENTRIES_BYTES`, and no NUL. The content itself is built and checked by
`app.services.dns_diff`. Validation raises `DnsSnapshotInvalid` with the field and a stable
reason, never the value.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import ColumnElement, Select, and_, delete, exists, or_, select
from sqlalchemy.orm import Session, aliased

from app.core.tenancy import TenantContext
from app.models import Domain
from app.models.dns_snapshot import MAX_ENTRIES, MAX_ENTRIES_BYTES, DnsSnapshot
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, _install_tenant_guard, coerce_id

_install_tenant_guard(DnsSnapshot.tenant_id)

HASH_RE: Final = re.compile(r"[0-9a-f]{64}")
PRUNE_BATCH: Final = 1000


class DnsSnapshotInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"dns snapshot {field} rejected: {reason}")
        self.field = field
        self.reason = reason


def _utc(value: datetime) -> datetime:
    # SQLite returns naive datetimes: values are always written as UTC, so tag them back.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _aware(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DnsSnapshotInvalid(field, "not_aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class DnsSnapshotRecord:
    id: int
    domain_id: int
    taken_at: datetime
    content_hash: str
    entries: tuple[Mapping[str, Any], ...]
    truncated: bool

    @classmethod
    def from_model(cls, row: DnsSnapshot) -> DnsSnapshotRecord:
        return cls(
            id=row.id,
            domain_id=row.domain_id,
            taken_at=_utc(row.taken_at),
            content_hash=row.content_hash,
            entries=tuple(row.entries),
            truncated=row.truncated,
        )


def _content_hash(value: object) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise DnsSnapshotInvalid("content_hash", "malformed")
    return value


def _entries(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise DnsSnapshotInvalid("entries", "not_a_list")
    if len(value) > MAX_ENTRIES:
        raise DnsSnapshotInvalid("entries", "too_many")
    if not all(isinstance(item, dict) for item in value):
        raise DnsSnapshotInvalid("entries", "bad_item")
    try:
        text = json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        raise DnsSnapshotInvalid("entries", "not_json") from None
    # The size as stored (ASCII-escaped JSON text), not the size of the Python objects.
    if len(text) > MAX_ENTRIES_BYTES:
        raise DnsSnapshotInvalid("entries", "too_large")
    if _has_nul(value):
        raise DnsSnapshotInvalid("entries", "nul")
    return value


def _has_nul(value: object) -> bool:
    """A real NUL character in any string (key or value) of the JSON-serialisable `value`.

    Checked on the Python values, not on the JSON text: the six characters `\\u0000` in a TXT
    record are ordinary content (stored as `\\\\u0000`) and must be accepted. Iterative, so deep
    nesting cannot exhaust the stack (json.dumps already accepted the structure)."""
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if "\x00" in item:
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list | tuple):
            stack.extend(item)
    return False


def _limit(limit: object) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an int between 1 and {MAX_LIMIT}")
    return limit


class DnsSnapshotRepository:
    """DNS snapshots of the context tenant's domains."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _select(self, *criteria: ColumnElement[bool]) -> Select[DnsSnapshot]:
        return select(DnsSnapshot).where(DnsSnapshot.tenant_id == self._ctx.tenant_id, *criteria)

    # --- reads ------------------------------------------------------------------------------

    def get(self, snapshot_id: object) -> DnsSnapshotRecord | None:
        """The snapshot; None if missing, foreign or malformed."""
        sid = coerce_id(snapshot_id)
        if sid is None:
            return None
        row = self._session.scalars(self._select(DnsSnapshot.id == sid)).one_or_none()
        return None if row is None else DnsSnapshotRecord.from_model(row)

    def latest(self, domain_id: object) -> DnsSnapshotRecord | None:
        """The newest snapshot of the domain; None if there is none or the domain is missing,
        foreign or malformed."""
        did = coerce_id(domain_id)
        if did is None:
            return None
        stmt = (
            self._select(DnsSnapshot.domain_id == did)
            .order_by(DnsSnapshot.taken_at.desc(), DnsSnapshot.id.desc())
            .limit(1)
        )
        row = self._session.scalars(stmt).first()
        return None if row is None else DnsSnapshotRecord.from_model(row)

    def list_for_domain(
        self, domain_id: object, *, limit: int = DEFAULT_LIMIT
    ) -> list[DnsSnapshotRecord]:
        """Newest-first snapshots of the domain, at most `limit`; empty for a missing, foreign or
        malformed domain."""
        size = _limit(limit)
        did = coerce_id(domain_id)
        if did is None:
            return []
        stmt = (
            self._select(DnsSnapshot.domain_id == did)
            .order_by(DnsSnapshot.taken_at.desc(), DnsSnapshot.id.desc())
            .limit(size)
        )
        return [DnsSnapshotRecord.from_model(r) for r in self._session.scalars(stmt)]

    # --- writes (flushed, not committed) ------------------------------------------------------

    def record(
        self,
        domain_id: object,
        *,
        taken_at: object,
        content_hash: object,
        entries: object,
        truncated: object = False,
    ) -> DnsSnapshotRecord | None:
        """Store one snapshot. None (nothing written) if the domain is missing, foreign or
        malformed; DnsSnapshotInvalid for a bad value."""
        moment = _aware(taken_at, "taken_at")
        digest = _content_hash(content_hash)
        stored = _entries(entries)
        if type(truncated) is not bool:
            raise DnsSnapshotInvalid("truncated", "not_a_bool")
        did = coerce_id(domain_id)
        if did is None:
            return None
        owned = select(Domain.id).where(Domain.id == did, Domain.tenant_id == self._ctx.tenant_id)
        if self._session.scalar(owned) is None:
            return None
        row = DnsSnapshot(
            tenant_id=self._ctx.tenant_id,
            domain_id=did,
            taken_at=moment,
            content_hash=digest,
            entries=stored,
            truncated=truncated,
        )
        self._session.add(row)
        self._session.flush()
        self._session.refresh(row)
        return DnsSnapshotRecord.from_model(row)


class DnsSnapshotRetentionRepository:
    """System entry point of retention. Not part of `repo_for`.

    `prune_all_tenants` is the only cross-tenant method for snapshots (see the module docstring).
    """

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    def prune_all_tenants(self, cutoff: object) -> int:
        """Delete the snapshots of ANY tenant with `taken_at < cutoff`, except the newest one of
        each domain, in batches of `PRUNE_BATCH`. Returns how many were deleted. Flushed, not
        committed."""
        moment = _aware(cutoff, "cutoff")
        newer = aliased(DnsSnapshot)
        has_newer = exists().where(
            newer.domain_id == DnsSnapshot.domain_id,
            newer.tenant_id == DnsSnapshot.tenant_id,
            or_(
                newer.taken_at > DnsSnapshot.taken_at,
                and_(newer.taken_at == DnsSnapshot.taken_at, newer.id > DnsSnapshot.id),
            ),
        )
        total = 0
        while True:
            ids = list(
                self._session.scalars(
                    select(DnsSnapshot.id)
                    .where(DnsSnapshot.taken_at < moment, has_newer)
                    .order_by(DnsSnapshot.id)
                    .limit(PRUNE_BATCH)
                )
            )
            if not ids:
                return total
            result = self._session.execute(delete(DnsSnapshot).where(DnsSnapshot.id.in_(ids)))
            total += int(result.rowcount)  # type: ignore[attr-defined]
            self._session.flush()
