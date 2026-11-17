"""Check run history repositories (M7-07). The only access path to `check_runs`.

Two classes, deliberately separate:

`CheckRunRepository` is tenant-scoped (reached through `repo_for`). Built only with a
`TenantContext`; every query is filtered on `tenant_id = ctx.tenant_id` and every row is written
with the context tenant; a domain or run of another tenant behaves exactly like a missing or
malformed one (None / empty); the composite FK (domain_id, tenant_id) -> domains(id, tenant_id)
makes a cross-tenant row impossible in the database too. Not built on `TenantScopedRepository`
because its generic `add(obj)` would bypass the validation below. Runs are immutable: there is no
update, and deletion happens only by retention (`CheckRunRetentionRepository`) or by cascade.

`CheckRunRetentionRepository` holds `prune_all_tenants(cutoff)`, the ONLY cross-tenant method in
this module. It is the system entry point of retention (`app.services.retention`), like
`MonitorSchedulerRepository`: not part of `repo_for`, takes no tenant from its caller, deletes
rows by age only, in bounded batches.

Findings are stored as stable codes and params only (see `app.models.check_run`). Input is a
sequence of `app.checks.models.Finding` or mappings with `code` and `params`; titles, details and
evidence are never stored. Findings are sorted by (code, params) so storage, truncation and
`findings_hash` are deterministic; the hash covers the full list, the stored list is capped at
`MAX_FINDINGS` / `MAX_FINDINGS_BYTES` (a prefix, with `findings_truncated` set). The byte cap is
measured on the JSON text as stored (SQLAlchemy's default `json.dumps` serialization).

Validation raises `CheckRunInvalid` with the field and a stable reason, never the value.
Keyset pagination orders by (started_at DESC, id DESC); the cursor is the last item's pair.

`trend` (M7-12b) aggregates a window into fixed-size UTC buckets for the history trend. It reads
only (started_at, status, check_id) in the list order (started_at DESC, id DESC), never the
findings JSON, and buckets in Python: `floor` is epoch arithmetic on aware UTC datetimes (exact
for any moment, before 1970 too), so it does not depend on the dialect, on how SQLite stores the
timestamp text or on the PostgreSQL session time zone. The read is bounded by `max_runs` (the
newest runs win); see `RunTrend`.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import ColumnElement, Select, and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.checks.models import Finding
from app.core.tenancy import TenantContext
from app.models import CheckRun, Domain
from app.models.check_run import (
    MAX_CHECK_ID_LENGTH,
    MAX_DURATION_MS,
    MAX_FINDINGS,
    MAX_FINDINGS_BYTES,
    SOURCES,
    STATUSES,
)
from app.repositories.base import DEFAULT_LIMIT, MAX_LIMIT, _install_tenant_guard, coerce_id

_install_tenant_guard(CheckRun.tenant_id)

CHECK_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9_.:-]*")
CODE_RE: Final = re.compile(r"[A-Z][A-Z0-9_]*")
MAX_PARAMS_DEPTH: Final = 4
PRUNE_BATCH: Final = 1000
MAX_TREND_SCAN: Final = 100_000
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_MICROSECOND: Final = timedelta(microseconds=1)


class CheckRunInvalid(ValueError):
    """A value was rejected before the database. Never contains the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"check run {field} rejected: {reason}")
        self.field = field
        self.reason = reason


def _utc(value: datetime) -> datetime:
    # SQLite returns naive datetimes: values are always written as UTC, so tag them back.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _aware(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CheckRunInvalid(field, "not_aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class StoredFinding:
    code: str
    params: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class CheckRunRecord:
    id: int
    domain_id: int
    check_id: str
    status: str
    started_at: datetime
    duration_ms: int
    source: str
    findings: tuple[StoredFinding, ...]
    findings_truncated: bool
    findings_hash: str

    @classmethod
    def from_model(cls, row: CheckRun) -> CheckRunRecord:
        return cls(
            id=row.id,
            domain_id=row.domain_id,
            check_id=row.check_id,
            status=row.status,
            started_at=_utc(row.started_at),
            duration_ms=row.duration_ms,
            source=row.source,
            findings=tuple(StoredFinding(str(f["code"]), f["params"]) for f in row.findings),  # type: ignore[arg-type]
            findings_truncated=row.findings_truncated,
            findings_hash=row.findings_hash,
        )


@dataclass(frozen=True, slots=True)
class RunCursor:
    """Position after a listed run: pass `RunPage.next_cursor` back to get the following page."""

    started_at: datetime
    id: int


@dataclass(frozen=True, slots=True)
class RunPage:
    items: tuple[CheckRunRecord, ...]
    next_cursor: RunCursor | None


@dataclass(frozen=True, slots=True)
class CheckBucket:
    """One check in one bucket: the status of its LATEST run there (started_at, then id) and
    how many runs it had."""

    status: str
    runs: int


@dataclass(frozen=True, slots=True)
class TrendBucket:
    start: datetime
    counts: Mapping[str, int]  # every status of STATUSES, zeros included
    checks: Mapping[str, CheckBucket]  # insertion order: latest run first

    @property
    def runs(self) -> int:
        return sum(self.counts.values())


@dataclass(frozen=True, slots=True)
class RunTrend:
    """The non-empty buckets of a window, newest first.

    `truncated` is True when the window held more than `max_runs` runs: only the newest
    `max_runs` were read, the oldest bucket read is incomplete and is left out, and `complete_from`
    is the start of the bucket after it (no bucket before it is reported). Otherwise
    `complete_from` is the floor of `since`."""

    buckets: tuple[TrendBucket, ...]
    truncated: bool
    complete_from: datetime


def bucket_floor(value: datetime, size: timedelta) -> datetime:
    """Start of the UTC bucket of `size` (aligned on the Unix epoch) holding `value` (aware)."""
    step = size // _MICROSECOND
    return _EPOCH + (value - _EPOCH) // _MICROSECOND // step * step * _MICROSECOND


# --- validation / normalisation ---------------------------------------------------------------


def _json_value(value: object, depth: int) -> Any:
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CheckRunInvalid("findings", "bad_params")
        return value
    if depth >= MAX_PARAMS_DEPTH:
        raise CheckRunInvalid("findings", "bad_params")
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise CheckRunInvalid("findings", "bad_params")
        return {k: _json_value(value[k], depth + 1) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_json_value(v, depth + 1) for v in value]
    raise CheckRunInvalid("findings", "bad_params")


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _stored_size(item: object) -> int:
    # Length of the item as the JSON column stores it: SQLAlchemy's default serializer is
    # `json.dumps` with its default separators and ensure_ascii (ASCII: characters are bytes);
    # keys are already sorted by `_json_value`.
    return len(json.dumps(item))


def _one_finding(item: object) -> dict[str, Any]:
    if isinstance(item, Finding):
        code: object = item.code
        params: object = dict(item.params)
    elif isinstance(item, Mapping):
        code, params = item.get("code"), item.get("params", {})
    else:
        raise CheckRunInvalid("findings", "bad_item")
    if not isinstance(code, str) or not CODE_RE.fullmatch(code):
        raise CheckRunInvalid("findings", "bad_code")
    if not isinstance(params, Mapping):
        raise CheckRunInvalid("findings", "bad_params")
    return {"code": code, "params": _json_value(params, 0)}


def normalize_findings(findings: object) -> tuple[list[dict[str, Any]], bool, str]:
    """(stored list, truncated flag, hash of the full sorted list)."""
    if not isinstance(findings, (list, tuple)):
        raise CheckRunInvalid("findings", "not_a_list")
    full = sorted((_one_finding(f) for f in findings), key=_dump)
    digest = hashlib.sha256(_dump(full).encode("ascii")).hexdigest()
    kept: list[dict[str, Any]] = []
    size = 2  # "[]"; the cap is on the stored text, so items are joined by ", "
    for item in full:
        if len(kept) >= MAX_FINDINGS:
            break
        size += _stored_size(item) + (2 if kept else 0)
        if size > MAX_FINDINGS_BYTES:
            break
        kept.append(item)
    return kept, len(kept) < len(full), digest


def _check_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_CHECK_ID_LENGTH
        or not CHECK_ID_RE.fullmatch(value)
    ):
        raise CheckRunInvalid("check_id", "malformed")
    return value


def _choice(value: object, field: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CheckRunInvalid(field, "unknown")
    return value


def _duration(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_DURATION_MS:
        raise CheckRunInvalid("duration_ms", "out_of_range")
    return value


def _limit(limit: object) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an int between 1 and {MAX_LIMIT}")
    return limit


class CheckRunRepository:
    """Check runs of the context tenant's domains."""

    __slots__ = ("_ctx", "_session")

    def __init__(self, ctx: TenantContext, session: Session) -> None:
        if not isinstance(ctx, TenantContext):
            raise TypeError("a TenantContext is required to build a tenant repository")
        self._ctx = ctx
        self._session = session

    @property
    def ctx(self) -> TenantContext:
        return self._ctx

    def _select(self, *criteria: ColumnElement[bool]) -> Select[CheckRun]:
        return select(CheckRun).where(CheckRun.tenant_id == self._ctx.tenant_id, *criteria)

    # --- reads ------------------------------------------------------------------------------

    def get(self, run_id: object) -> CheckRunRecord | None:
        """The run; None if missing, foreign or malformed."""
        rid = coerce_id(run_id)
        if rid is None:
            return None
        row = self._session.scalars(self._select(CheckRun.id == rid)).one_or_none()
        return None if row is None else CheckRunRecord.from_model(row)

    def list_for_domain(
        self,
        domain_id: object,
        *,
        check_id: object = None,
        since: object = None,
        until: object = None,
        limit: int = DEFAULT_LIMIT,
        cursor: RunCursor | None = None,
    ) -> RunPage:
        """Newest-first page of the domain's runs, optionally of one check and within
        `since <= started_at < until`. An empty page for a missing, foreign or malformed domain.
        Keyset pagination: pass the previous `next_cursor` (None on the last page)."""
        size = _limit(limit)
        criteria: list[ColumnElement[bool]] = []
        if check_id is not None:
            criteria.append(CheckRun.check_id == _check_id(check_id))
        if since is not None:
            criteria.append(CheckRun.started_at >= _aware(since, "since"))
        if until is not None:
            criteria.append(CheckRun.started_at < _aware(until, "until"))
        if cursor is not None:
            if not isinstance(cursor, RunCursor) or type(cursor.id) is not int:
                raise CheckRunInvalid("cursor", "malformed")
            at = _aware(cursor.started_at, "cursor")
            criteria.append(
                or_(
                    CheckRun.started_at < at,
                    and_(CheckRun.started_at == at, CheckRun.id < cursor.id),
                )
            )
        did = coerce_id(domain_id)
        if did is None:
            return RunPage((), None)
        stmt = (
            self._select(CheckRun.domain_id == did, *criteria)
            .order_by(CheckRun.started_at.desc(), CheckRun.id.desc())
            .limit(size + 1)
        )
        rows = list(self._session.scalars(stmt))
        page = tuple(CheckRunRecord.from_model(r) for r in rows[:size])
        more = len(rows) > size
        nxt = RunCursor(page[-1].started_at, page[-1].id) if more else None
        return RunPage(page, nxt)

    def trend(
        self,
        domain_id: object,
        *,
        since: object,
        until: object,
        size: object,
        max_runs: object,
        check_id: object = None,
    ) -> RunTrend:
        """The domain's runs with `since <= started_at < until` (optionally of one check),
        aggregated per bucket of `size` (see `RunTrend`). Empty for a missing, foreign or
        malformed domain; CheckRunInvalid for a bad value."""
        start = _aware(since, "since")
        end = _aware(until, "until")
        if not isinstance(size, timedelta) or size < _MICROSECOND or size % _MICROSECOND:
            raise CheckRunInvalid("size", "out_of_range")
        if type(max_runs) is not int or not 1 <= max_runs <= MAX_TREND_SCAN:
            raise CheckRunInvalid("max_runs", "out_of_range")
        criteria = [CheckRun.started_at >= start, CheckRun.started_at < end]
        if check_id is not None:
            criteria.append(CheckRun.check_id == _check_id(check_id))
        complete_from = bucket_floor(start, size)
        did = coerce_id(domain_id)
        if did is None:
            return RunTrend((), False, complete_from)
        stmt = (
            select(CheckRun.started_at, CheckRun.status, CheckRun.check_id)
            .where(CheckRun.tenant_id == self._ctx.tenant_id, CheckRun.domain_id == did, *criteria)
            .order_by(CheckRun.started_at.desc(), CheckRun.id.desc())
            .limit(max_runs + 1)
        )
        rows = self._session.execute(stmt).all()
        truncated = len(rows) > max_runs
        if truncated:
            rows = rows[:max_runs]
            complete_from = bucket_floor(_utc(rows[-1][0]), size) + size
        counts: dict[datetime, dict[str, int]] = {}
        checks: dict[datetime, dict[str, list[Any]]] = {}
        for at, status, cid in rows:  # newest first: a check's first row in a bucket is its latest
            key = bucket_floor(_utc(at), size)
            if key < complete_from:
                break
            if key not in counts:
                counts[key] = dict.fromkeys(STATUSES, 0)
                checks[key] = {}
            counts[key][status] += 1
            checks[key].setdefault(cid, [status, 0])[1] += 1
        buckets = tuple(
            TrendBucket(
                key,
                counts[key],
                {cid: CheckBucket(state, n) for cid, (state, n) in checks[key].items()},
            )
            for key in counts
        )
        return RunTrend(buckets, truncated, complete_from)

    def latest_non_error(self, domain_id: object, check_id: object) -> CheckRunRecord | None:
        """The newest run of one check of the domain whose status is not `error` (the baseline
        of change detection, M7-10b), however many `error` runs came after it. None if there is
        none or the domain is missing, foreign or malformed; CheckRunInvalid for a malformed
        check id. Served by the (tenant, domain, check, started_at) index, newest first."""
        cid = _check_id(check_id)
        did = coerce_id(domain_id)
        if did is None:
            return None
        stmt = (
            self._select(
                CheckRun.domain_id == did, CheckRun.check_id == cid, CheckRun.status != "error"
            )
            .order_by(CheckRun.started_at.desc(), CheckRun.id.desc())
            .limit(1)
        )
        row = self._session.scalars(stmt).first()
        return None if row is None else CheckRunRecord.from_model(row)

    def latest_per_check(self, domain_id: object) -> list[CheckRunRecord]:
        """The most recent run of each check of the domain, ordered by check id."""
        did = coerce_id(domain_id)
        if did is None:
            return []
        ranked = (
            select(
                CheckRun.id.label("rid"),
                func.row_number()
                .over(
                    partition_by=CheckRun.check_id,
                    order_by=(CheckRun.started_at.desc(), CheckRun.id.desc()),
                )
                .label("rn"),
            )
            .where(CheckRun.tenant_id == self._ctx.tenant_id, CheckRun.domain_id == did)
            .subquery()
        )
        stmt = self._select(CheckRun.id.in_(select(ranked.c.rid).where(ranked.c.rn == 1))).order_by(
            CheckRun.check_id
        )
        return [CheckRunRecord.from_model(r) for r in self._session.scalars(stmt)]

    # --- writes (flushed, not committed) ------------------------------------------------------

    def record(
        self,
        domain_id: object,
        *,
        check_id: object,
        status: object,
        started_at: object,
        duration_ms: object,
        source: object,
        findings: object,
    ) -> CheckRunRecord | None:
        """Store one run. None (nothing written) if the domain is missing, foreign or malformed;
        CheckRunInvalid for a bad value."""
        cid = _check_id(check_id)
        state = _choice(status, "status", STATUSES)
        origin = _choice(source, "source", SOURCES)
        start = _aware(started_at, "started_at")
        took = _duration(duration_ms)
        stored, truncated, digest = normalize_findings(findings)
        did = coerce_id(domain_id)
        if did is None:
            return None
        owned = select(Domain.id).where(Domain.id == did, Domain.tenant_id == self._ctx.tenant_id)
        if self._session.scalar(owned) is None:
            return None
        row = CheckRun(
            tenant_id=self._ctx.tenant_id,
            domain_id=did,
            check_id=cid,
            status=state,
            started_at=start,
            duration_ms=took,
            source=origin,
            findings=stored,
            findings_truncated=truncated,
            findings_hash=digest,
        )
        self._session.add(row)
        self._session.flush()
        self._session.refresh(row)
        return CheckRunRecord.from_model(row)


class CheckRunRetentionRepository:
    """System entry point of retention. Not part of `repo_for`.

    `prune_all_tenants` is the only cross-tenant method for check runs (see the module docstring).
    """

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    def prune_all_tenants(self, cutoff: object) -> int:
        """Delete the runs of ANY tenant with `started_at < cutoff`, in batches of
        `PRUNE_BATCH`. Returns how many were deleted. Flushed, not committed."""
        moment = _aware(cutoff, "cutoff")
        total = 0
        while True:
            ids = list(
                self._session.scalars(
                    select(CheckRun.id)
                    .where(CheckRun.started_at < moment)
                    .order_by(CheckRun.id)
                    .limit(PRUNE_BATCH)
                )
            )
            if not ids:
                return total
            result = self._session.execute(delete(CheckRun).where(CheckRun.id.in_(ids)))
            total += int(result.rowcount)  # type: ignore[attr-defined]
            self._session.flush()
