"""History read model of a monitored domain (M7-12): check runs, trend series, DNS snapshots and
the diff of two snapshots. Read-only; every answer is a JSON-ready dict.

Authorization is the same as the monitor routes (`app.services.monitors`), decided before any
repository call and before any query parameter is looked at:
- `domain.read` on the domain (a client viewer only on assigned domains; toggles can switch it
  off), else 404, exactly like a missing, malformed or foreign domain;
- the domain must exist in the context tenant, else 404;
- then `monitor.read`, else 403. No active tenant: 404.
The errors are the monitor ones (`MonitorNotFound`, `MonitorForbidden`, i18n keys
`monitor.error.not_found` / `api.error.forbidden`); a bad query parameter is `HistoryInvalid`
(422, `api.error.invalid_request`, never echoing the value).

Query parameters are parsed here from the raw `Mapping[str, str]` (the router rejects repeated
names): unknown names, malformed values and out-of-range values are `HistoryInvalid`.

Bounds (module constants, not settings):
- `MAX_PAGE_SIZE` (200) rows per page, `DEFAULT_PAGE_SIZE` (50); more is a 422.
- `MAX_WINDOW` (366 days): a runs window wider than this keeps its `until` and moves `since`
  forward; the answer says `window.capped: true`. A trend window is also limited by the bucket
  cap below, whichever is smaller.
- `MIN_MOMENT` (1970-01-01 UTC) .. `MAX_MOMENT` (9000-01-01 UTC), inclusive: the accepted
  `since`/`until`, so window arithmetic (default window, bucket alignment, caps) stays far from
  the `datetime` limits; any arithmetic overflow left is still a 422, never a 500.
- `MAX_BUCKETS` (500) buckets per trend; `MAX_TREND_RUNS` (20000) runs read per trend. When a cap
  bites, the OLDEST part of the window is dropped (`window.capped` / `window.truncated`). The
  trend is aggregated by `CheckRunRepository.trend` (M7-12b), which reads only the started_at,
  status and check_id columns (never findings) and buckets in Python, identically on SQLite and
  PostgreSQL; the run cap is kept so the read stays bounded whatever the run density.

Cursors (runs and snapshots): `base64url(json)` of `["r"|"s", domain_id, epoch_microseconds, id]`,
at most `MAX_CURSOR_LENGTH` characters. The domain id is checked against the request's domain and
the kind against the route, so a cursor cannot be replayed on another domain or list. A cursor
carries no tenant and no authority: the repository filters on tenant and domain, so a forged
position can only move inside rows the caller may already read. Anything else (bad base64, JSON,
shape, types, range, other domain) is `HistoryInvalid`.

Trend buckets are UTC and aligned to the unit (`hour`: minute 0; `day`: 00:00 UTC): a run belongs
to the bucket `floor(started_at)`. `since`/`until` (ISO 8601 with a UTC offset or `Z`; naive is
rejected; outside `MIN_MOMENT`..`MAX_MOMENT` is a 422) are half-open
(`since <= started_at < until`) and are widened to bucket boundaries.
Per bucket: `counts` (runs per status, all statuses present), `runs`, and `checks`:
check_id -> {`status` of the check's LATEST run in the bucket, `runs`}. Every bucket of the window
is listed, empty ones included.

Findings are stored as code + params only. Each is returned as `{code, params, title, detail,
remediation}`; the three texts are rendered for `lang` with the finding key convention
(`finding.<CODE>.title|detail|remediation`) and `app.checks.finding_text.display_params`; a code
without catalogue keys, or a template the params cannot fill, gives null texts (never an error,
never the raw params in text).

Diff: `from` is the "before", `to` the "after" snapshot, both ids of the domain; either one
missing, foreign or of another domain is a 404. The change list is `diff_snapshots`'s (an entry in
state `error` on either side is `inconclusive`, never added or removed). A stored snapshot that
cannot be read is a 409 (`api.error.conflict`).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy.orm import Session

from app.checks.finding_text import display_params
from app.core.i18n import DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES, load_catalogue, placeholders
from app.core.permissions import Action, DomainResource, Principal, can
from app.core.tenancy import TenantContext
from app.core.text import visible
from app.models.check_run import STATUSES
from app.repositories import TenantRepositories, repo_for
from app.repositories.base import coerce_id, parse_id
from app.repositories.check_runs import (
    CHECK_ID_RE,
    CheckRunInvalid,
    CheckRunRecord,
    RunCursor,
    StoredFinding,
)
from app.repositories.dns_snapshots import DnsSnapshotRecord, SnapshotCursor
from app.services.clock import Clock, SystemClock
from app.services.dns_diff import SnapshotFormatError, diff_snapshots, from_stored
from app.services.monitors import MonitorError, MonitorForbidden, MonitorNotFound

DEFAULT_PAGE_SIZE: Final = 50
MAX_PAGE_SIZE: Final = 200
MAX_WINDOW: Final = timedelta(days=366)
DEFAULT_TREND_WINDOW: Final = timedelta(days=7)
MAX_BUCKETS: Final = 500
MAX_TREND_RUNS: Final = 20000
MAX_CURSOR_LENGTH: Final = 200
MAX_CHECK_ID_LENGTH: Final = 96
BUCKETS: Final[Mapping[str, timedelta]] = {"hour": timedelta(hours=1), "day": timedelta(days=1)}
DEFAULT_BUCKET: Final = "day"
INVALID_KEY: Final = "api.error.invalid_request"
CONFLICT_KEY: Final = "api.error.conflict"

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
MIN_MOMENT: Final = _EPOCH
MAX_MOMENT: Final = datetime(9000, 1, 1, tzinfo=UTC)
_ISO_RE: Final = re.compile(r"[0-9T:.+\-Z ]{10,40}")
_FORBIDDEN_PARAM_NAMES: Final = frozenset({"key", "lang"})  # arguments of `t()`


class HistoryInvalid(MonitorError):
    """A malformed or out-of-range query parameter. Never carries the value."""

    status = 422
    key = INVALID_KEY


class HistoryUnreadable(MonitorError):
    """A stored snapshot that cannot be read back."""

    status = 409
    key = CONFLICT_KEY


# --- query parameters ---------------------------------------------------------------------------


def _only(params: Mapping[str, str], allowed: frozenset[str]) -> None:
    if set(params) - allowed:
        raise HistoryInvalid


def _limit(raw: str | None) -> int:
    if raw is None:
        return DEFAULT_PAGE_SIZE
    if not raw.isascii() or not raw.isdigit() or len(raw) > 4:
        raise HistoryInvalid
    value = int(raw)
    if not 1 <= value <= MAX_PAGE_SIZE:
        raise HistoryInvalid
    return value


def _moment(raw: str | None) -> datetime | None:
    if raw is None:
        return None
    if _ISO_RE.fullmatch(raw) is None:
        raise HistoryInvalid
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        raise HistoryInvalid from None
    if value.tzinfo is None:
        raise HistoryInvalid
    try:
        value = value.astimezone(UTC)
    except (OverflowError, ValueError):
        raise HistoryInvalid from None
    if not MIN_MOMENT <= value <= MAX_MOMENT:
        raise HistoryInvalid
    return value


def _check_id(raw: str | None) -> str | None:
    if raw is None:
        return None
    if len(raw) > MAX_CHECK_ID_LENGTH or CHECK_ID_RE.fullmatch(raw) is None:
        raise HistoryInvalid
    return raw


def _micros(value: datetime) -> int:
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def encode_cursor(kind: str, domain_id: int, at: datetime, row_id: int) -> str:
    raw = json.dumps([kind, domain_id, _micros(at), row_id], separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("ascii")).decode("ascii").rstrip("=")


def decode_cursor(raw: str, kind: str, domain_id: int) -> tuple[datetime, int]:
    """(timestamp, id) of a cursor made by `encode_cursor` for this kind and domain."""
    if not raw or len(raw) > MAX_CURSOR_LENGTH or not raw.isascii():
        raise HistoryInvalid
    try:
        data = json.loads(
            base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
        )
    except (binascii.Error, ValueError, RecursionError):
        raise HistoryInvalid from None
    if not (isinstance(data, list) and len(data) == 4):
        raise HistoryInvalid
    k, did, micros, row_id = data
    if k != kind or any(type(v) is not int for v in (did, micros, row_id)):
        raise HistoryInvalid
    if did != domain_id or coerce_id(row_id) is None:
        raise HistoryInvalid
    try:
        at = _EPOCH + timedelta(microseconds=micros)
    except OverflowError:
        raise HistoryInvalid from None
    if not _EPOCH <= at < datetime(9999, 1, 1, tzinfo=UTC):
        raise HistoryInvalid
    return at, row_id


# --- findings -----------------------------------------------------------------------------------


def _template(key: str, lang: str) -> str | None:
    """The template `t(key, lang)` would use (`lang`, else English), None when there is none."""
    template = load_catalogue(lang).get(key) if lang in SUPPORTED_LANGUAGES else None
    return template if template is not None else load_catalogue(DEFAULT_LANGUAGE).get(key)


def _text(key: str, lang: str, params: Mapping[str, Any]) -> str | None:
    """`key` rendered with `params`; None when it has no template or the params cannot fill it.

    Formatted here rather than through `t()`: with strict mode off `t()` returns the raw template
    (`{count}` shown to the user) when a param is missing or does not fit its format."""
    template = _template(key, lang)
    if template is None:
        return None
    try:
        names = placeholders(template)
    except ValueError:
        return None
    if any(re.split(r"[.\[]", name, maxsplit=1)[0] not in params for name in names):
        return None
    try:
        return template.format_map(params)
    except (KeyError, IndexError, ValueError, TypeError, AttributeError):
        return None


def render_finding(finding: StoredFinding, lang: str) -> dict[str, Any]:
    """Code, params as stored, and the texts in `lang` (null when not renderable)."""
    base = f"finding.{finding.code}"
    texts: dict[str, str | None] = {"title": None, "detail": None, "remediation": None}
    if isinstance(finding.params, Mapping):
        try:
            shown = display_params(finding.code, finding.params, lang)
        except Exception:  # noqa: BLE001 - display is best effort, never a 500
            shown = dict(finding.params)
        safe = {
            k: visible(v) if isinstance(v, str) else v
            for k, v in shown.items()
            if isinstance(k, str) and k not in _FORBIDDEN_PARAM_NAMES
        }
        for name in texts:
            texts[name] = _text(f"{base}.{name}", lang, safe)
    return {
        "code": finding.code,
        "params": dict(finding.params) if isinstance(finding.params, Mapping) else {},
        **texts,
    }


def _run_json(run: CheckRunRecord, lang: str) -> dict[str, Any]:
    return {
        "id": run.id,
        "domain_id": run.domain_id,
        "check_id": run.check_id,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "duration_ms": run.duration_ms,
        "source": run.source,
        "findings": [render_finding(f, lang) for f in run.findings],
        "findings_truncated": run.findings_truncated,
    }


# --- trend --------------------------------------------------------------------------------------


def _floor(value: datetime, size: timedelta) -> datetime:
    step = int(size.total_seconds()) * 1_000_000
    return _EPOCH + timedelta(microseconds=_micros(value) // step * step)


def _ceil(value: datetime, size: timedelta) -> datetime:
    floor = _floor(value, size)
    return floor if floor == value else floor + size


class HistoryService:
    """One request's history reads. `ctx` is None when the session has no active tenant."""

    def __init__(
        self,
        db: Session,
        ctx: TenantContext | None,
        principal: Principal,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal
        self._clock: Clock = clock if clock is not None else SystemClock()

    # --- authorization ------------------------------------------------------------------------

    def check_read(self, domain_id: object) -> int:
        """The id of an existing domain of the context tenant the caller may read the history of."""
        if self._ctx is None:
            raise MonitorNotFound
        did = coerce_id(domain_id)
        if did is None:
            raise MonitorNotFound
        resource = DomainResource(self._ctx.tenant_id, did)
        if not can(self._principal, Action.DOMAIN_READ, resource):
            raise MonitorNotFound
        if repo_for(self._ctx, self._db).domains.get(did) is None:
            raise MonitorNotFound
        if not can(self._principal, Action.MONITOR_READ, resource):
            raise MonitorForbidden
        return did

    def _repos(self) -> TenantRepositories:
        assert self._ctx is not None  # check_read ran
        return repo_for(self._ctx, self._db)

    # --- runs ---------------------------------------------------------------------------------

    def runs(self, domain_id: int, params: Mapping[str, str], lang: str) -> dict[str, Any]:
        _only(params, frozenset({"check_id", "since", "until", "limit", "cursor"}))
        check_id = _check_id(params.get("check_id"))
        since, until = _moment(params.get("since")), _moment(params.get("until"))
        limit = _limit(params.get("limit"))
        cursor = None
        if "cursor" in params:
            at, row_id = decode_cursor(params["cursor"], "r", domain_id)
            cursor = RunCursor(at, row_id)
        if since is not None and until is not None and since >= until:
            raise HistoryInvalid
        capped = False
        try:
            if since is not None and until is not None and until - since > MAX_WINDOW:
                since, capped = until - MAX_WINDOW, True
        except OverflowError:
            raise HistoryInvalid from None
        try:
            page = self._repos().check_runs.list_for_domain(
                domain_id,
                check_id=check_id,
                since=since,
                until=until,
                limit=limit,
                cursor=cursor,
            )
        except CheckRunInvalid:
            raise HistoryInvalid from None
        nxt = page.next_cursor
        return {
            "items": [_run_json(r, lang) for r in page.items],
            "next_cursor": None
            if nxt is None
            else encode_cursor("r", domain_id, nxt.started_at, nxt.id),
            "window": {
                "since": None if since is None else since.isoformat(),
                "until": None if until is None else until.isoformat(),
                "capped": capped,
                "max_days": MAX_WINDOW.days,
            },
            "page_size_max": MAX_PAGE_SIZE,
        }

    # --- trend --------------------------------------------------------------------------------

    def trend(self, domain_id: int, params: Mapping[str, str]) -> dict[str, Any]:
        _only(params, frozenset({"check_id", "since", "until", "bucket"}))
        check_id = _check_id(params.get("check_id"))
        unit = params.get("bucket", DEFAULT_BUCKET)
        if unit not in BUCKETS:
            raise HistoryInvalid
        size = BUCKETS[unit]
        until = _moment(params.get("until")) or self._clock.now().astimezone(UTC)
        try:
            since = _moment(params.get("since")) or until - DEFAULT_TREND_WINDOW
            if since >= until:
                raise HistoryInvalid
            first, end = _floor(since, size), _ceil(until, size)
            capped = False
            limit_buckets = min(MAX_BUCKETS, MAX_WINDOW // size)
            if (end - first) // size > limit_buckets:
                first, capped = end - limit_buckets * size, True
            total = (end - first) // size
            starts = [first + i * size for i in range(total)]
        except OverflowError:
            raise HistoryInvalid from None
        try:
            trend = self._repos().check_runs.trend(
                domain_id,
                since=first,
                until=end,
                size=size,
                max_runs=MAX_TREND_RUNS,
                check_id=check_id,
            )
        except CheckRunInvalid:
            raise HistoryInvalid from None
        truncated = trend.truncated
        if truncated:
            # Newest runs were read first: the oldest bucket read was incomplete and is left out.
            first = trend.complete_from
            starts = [s for s in starts if s >= first]
        found = {b.start: b for b in trend.buckets}
        buckets: list[dict[str, Any]] = []
        for s in starts:
            b = found.get(s)
            buckets.append(
                {
                    "start": s.isoformat(),
                    "runs": 0 if b is None else b.runs,
                    "counts": dict.fromkeys(STATUSES, 0) if b is None else dict(b.counts),
                    "checks": {}
                    if b is None
                    else {c: {"status": v.status, "runs": v.runs} for c, v in b.checks.items()},
                }
            )
        return {
            "bucket": unit,
            "buckets": buckets,
            "window": {
                "since": starts[0].isoformat() if starts else first.isoformat(),
                "until": end.isoformat(),
                "capped": capped,
                "truncated": truncated,
                "max_buckets": MAX_BUCKETS,
                "max_days": MAX_WINDOW.days,
            },
        }

    # --- snapshots ----------------------------------------------------------------------------

    def snapshots(self, domain_id: int, params: Mapping[str, str]) -> dict[str, Any]:
        _only(params, frozenset({"limit", "cursor"}))
        limit = _limit(params.get("limit"))
        before = None
        if "cursor" in params:
            at, row_id = decode_cursor(params["cursor"], "s", domain_id)
            before = SnapshotCursor(at, row_id)
        rows = self._repos().dns_snapshots.list_for_domain(
            domain_id, limit=limit + 1, before=before
        )
        page = rows[:limit]
        nxt = None
        if len(rows) > limit:
            nxt = encode_cursor("s", domain_id, page[-1].taken_at, page[-1].id)
        return {
            "items": [
                {
                    "id": s.id,
                    "domain_id": s.domain_id,
                    "taken_at": s.taken_at.isoformat(),
                    "content_hash": s.content_hash,
                    "truncated": s.truncated,
                    "entry_count": len(s.entries),
                }
                for s in page
            ],
            "next_cursor": nxt,
            "page_size_max": MAX_PAGE_SIZE,
        }

    def _snapshot(self, domain_id: int, raw: str | None) -> DnsSnapshotRecord:
        if raw is None:
            raise HistoryInvalid
        sid = parse_id(raw)
        record = None if sid is None else self._repos().dns_snapshots.get(sid)
        if record is None or record.domain_id != domain_id:
            raise MonitorNotFound
        return record

    def diff(self, domain_id: int, params: Mapping[str, str]) -> dict[str, Any]:
        _only(params, frozenset({"from", "to"}))
        # Both ids are required; a missing one is a malformed request, an unknown one a 404.
        if "from" not in params or "to" not in params:
            raise HistoryInvalid
        before = self._snapshot(domain_id, params["from"])
        after = self._snapshot(domain_id, params["to"])
        try:
            changes = diff_snapshots(
                from_stored(list(before.entries), before.content_hash, before.truncated),
                from_stored(list(after.entries), after.content_hash, after.truncated),
            )
        except SnapshotFormatError:
            raise HistoryUnreadable from None
        return {
            "from": _snapshot_ref(before),
            "to": _snapshot_ref(after),
            "changes": [
                {
                    "name": c.name,
                    "type": c.rdtype,
                    "kind": c.kind,
                    "before_hash": c.before_hash,
                    "after_hash": c.after_hash,
                    "before_values": list(c.before_values),
                    "after_values": list(c.after_values),
                }
                for c in changes
            ],
        }


def _snapshot_ref(s: DnsSnapshotRecord) -> dict[str, Any]:
    return {
        "id": s.id,
        "taken_at": s.taken_at.isoformat(),
        "content_hash": s.content_hash,
        "truncated": s.truncated,
    }
