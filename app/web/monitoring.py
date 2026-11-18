"""Domain page "Monitoring" tab (M7-13): `/domains/{domain_id}/monitoring`.

Everything goes through the M7-11 `MonitorService` and the M7-12 `HistoryService` (tenant
repositories + `can()`): this module holds no repository and repeats no authorization except the
display decision (`monitor.manage` shows the controls).

Routes (anonymous GET -> 303 /login, anonymous POST -> 401 after the CSRF middleware):
- GET  /domains/{domain_id}/monitoring          the tab: the target (interval, checks, enabled),
                                                the last status per check, the run history (newest
                                                first, `cursor` pages to older runs), the trend
                                                chart (`bucket` = `day`|`hour`, the service's
                                                default window), the snapshot list and the diff of
                                                two snapshots (`from`, `to`; default: the two
                                                newest);
- POST /domains/{domain_id}/monitoring          create the target, or change it when it exists
                                                (`interval_seconds`, `check_ids` repeated,
                                                `enabled` checkbox);
- POST /domains/{domain_id}/monitoring/delete   remove the target (history is kept).

Order of the answers, as the API: no active tenant, a missing, foreign, malformed or (client
viewer) unassigned domain -> 404 page; a readable domain without `monitor.read` (toggle off) ->
403 page; a write without `monitor.manage` (analysts keep it, client viewers never) -> 403 page.
Permission and domain are decided before the form body is read. A malformed `cursor`/`bucket`
query is the 422 page; an unknown or unreadable diff snapshot is a note in the diff section.

Untrusted text: diff `before_values`/`after_values` (raw DNS text) and finding texts are rendered
autoescaped and through `visible` (no `|safe`, no JavaScript, no innerHTML). The charts are inline
SVG built here from numbers and catalogue labels only; buckets are labelled by their UTC start.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from app.api.v1.history import history_clock
from app.api.v1.monitors import monitor_clock
from app.core.permissions import Action, DomainResource, can
from app.models.check_run import STATUSES
from app.models.monitor_target import ALLOWED_INTERVALS_SECONDS
from app.repositories.monitor_targets import MonitorTargetRecord, known_check_ids
from app.services.clock import Clock
from app.services.domains import DomainServiceError
from app.services.history import BUCKETS, DEFAULT_BUCKET, HistoryService
from app.services.monitors import (
    INVALID_CHECKS_KEY,
    INVALID_INTERVAL_KEY,
    INVALID_REQUEST_KEY,
    MonitorError,
    MonitorExists,
    MonitorNotFound,
    MonitorService,
)
from app.web.deps import DbDep, SettingsDep
from app.web.dns_tools import visible
from app.web.domains import Web, WebDep, _domain_id
from app.web.templating import error_page, payload_too_large, read_form, render, request_language

router = APIRouter()

__all__ = ["router", "visible"]

_NO_STORE: Final = {"Cache-Control": "no-store"}
HISTORY_PAGE: Final = 25
SNAPSHOT_PAGE: Final = 20
MAX_FORM_CHECKS: Final = 64  # as the API's MAX_CHECK_IDS
MAX_FIELD_LENGTH: Final = 96
INTERVAL_KEYS: Final[Mapping[int, str]] = {
    3600: "monitor.tab.interval.hour",
    21600: "monitor.tab.interval.six_hours",
    43200: "monitor.tab.interval.twelve_hours",
    86400: "monitor.tab.interval.day",
}
DIFF_NOT_FOUND: Final = "monitor.diff.not_found"
DIFF_UNREADABLE: Final = "monitor.diff.unreadable"
BUCKET_KEYS: Final[Mapping[str, str]] = {
    "day": "monitor.chart.bucket.day",
    "hour": "monitor.chart.bucket.hour",
}
_NOTICES: Final = {"saved": "monitor.tab.flash.saved", "deleted": "monitor.tab.flash.deleted"}
_CONTROL_CATEGORIES: Final = frozenset({"Cc", "Cs"})
_INTERVALS_BY_TEXT: Final[Mapping[str, int]] = {str(s): s for s in ALLOWED_INTERVALS_SECONDS}

# Chart geometry (SVG user units; the SVG scales to the container width).
CHART_W: Final = 720
CHART_H: Final = 220
PAD_L: Final = 36
PAD_R: Final = 8
PAD_T: Final = 10
PAD_B: Final = 28
BAR_GAP: Final = 2
MAX_X_LABELS: Final = 6
STRIP_ROW: Final = 18
STRIP_LABEL_W: Final = 150

Clocks = tuple[Clock, Clock]


def _clocks(
    history: Annotated[Clock, Depends(history_clock)],
    monitor: Annotated[Clock, Depends(monitor_clock)],
) -> Clocks:
    return history, monitor


ClocksDep = Annotated[Clocks, Depends(_clocks)]


# --- chart model --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Segment:
    status: str
    count: int
    x: float
    y: float
    width: float
    height: float


@dataclass(frozen=True, slots=True)
class Bar:
    label: str  # bucket start, UTC
    runs: int
    segments: tuple[Segment, ...]


@dataclass(frozen=True, slots=True)
class Tick:
    value: int
    y: float


@dataclass(frozen=True, slots=True)
class XLabel:
    text: str
    x: float


@dataclass(frozen=True, slots=True)
class Cell:
    label: str
    status: str | None  # None: no run of the check in the bucket
    runs: int
    x: float
    width: float


@dataclass(frozen=True, slots=True)
class StripRow:
    check_id: str
    y: float
    cells: tuple[Cell, ...]


@dataclass(slots=True)
class Chart:
    width: int = CHART_W
    height: int = CHART_H
    plot_left: int = PAD_L
    plot_right: int = CHART_W - PAD_R
    baseline: float = CHART_H - PAD_B
    bars: list[Bar] = field(default_factory=list)
    ticks: list[Tick] = field(default_factory=list)
    x_labels: list[XLabel] = field(default_factory=list)
    strip: list[StripRow] = field(default_factory=list)
    strip_height: int = 0
    total_runs: int = 0
    capped: bool = False
    truncated: bool = False


def bucket_label(start: str, unit: str) -> str:
    """A bucket's UTC start as shown: `YYYY-MM-DD` (day) or `YYYY-MM-DD HH:00` (hour)."""
    try:
        moment = datetime.fromisoformat(start)
    except ValueError:
        return ""
    return moment.strftime("%Y-%m-%d") if unit == "day" else moment.strftime("%Y-%m-%d %H:00")


def _count(value: object) -> int:
    return value if type(value) is int and value > 0 else 0


def _map(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def build_chart(trend: Mapping[str, Any], checks: Sequence[str]) -> Chart:
    """The stacked status bars (runs per status per bucket) and the per-check status strip of a
    trend answer, as SVG coordinates. Only numbers, statuses from `STATUSES`, check ids from
    `checks` and bucket starts go in; malformed entries count as zero."""
    unit = trend.get("bucket", DEFAULT_BUCKET)
    raw = trend.get("buckets")
    buckets: list[Mapping[str, Any]] = (
        [b for b in raw if isinstance(b, Mapping)] if isinstance(raw, list) else []
    )
    window = _map(trend.get("window"))
    chart = Chart(capped=bool(window.get("capped")), truncated=bool(window.get("truncated")))
    n = len(buckets)
    if n == 0:
        return chart
    plot_w = chart.plot_right - chart.plot_left
    plot_h = chart.baseline - PAD_T
    slot = plot_w / n
    bar_w = max(slot - BAR_GAP, 1.0)
    counts_per_bucket: list[dict[str, int]] = []
    for b in buckets:
        counts = _map(b.get("counts"))
        counts_per_bucket.append({s: _count(counts.get(s)) for s in STATUSES})
    top = max((sum(c.values()) for c in counts_per_bucket), default=0)
    scale_max = max(top, 1)
    chart.total_runs = sum(sum(c.values()) for c in counts_per_bucket)
    chart.ticks = [
        Tick(v, chart.baseline - plot_h * v / scale_max)
        for v in sorted({0, (scale_max + 1) // 2, scale_max})
    ]
    labels = [bucket_label(str(b.get("start", "")), str(unit)) for b in buckets]
    for i, counts in enumerate(counts_per_bucket):
        x = chart.plot_left + i * slot + BAR_GAP / 2
        y = chart.baseline
        segments: list[Segment] = []
        for status in STATUSES:
            count = counts[status]
            if count == 0:
                continue
            h = plot_h * count / scale_max
            y -= h
            segments.append(Segment(status, count, round(x, 2), round(y, 2), round(bar_w, 2),
                                    round(h, 2)))  # fmt: skip
        chart.bars.append(Bar(labels[i], sum(counts.values()), tuple(segments)))
    step = max(1, -(-n // MAX_X_LABELS))
    chart.x_labels = [
        XLabel(labels[i], round(chart.plot_left + i * slot + slot / 2, 2))
        for i in range(0, n, step)
    ]
    cell_slot = (chart.plot_right - STRIP_LABEL_W) / n
    for row, check_id in enumerate(checks):
        cells: list[Cell] = []
        for i, b in enumerate(buckets):
            entry = _map(_map(b.get("checks")).get(check_id))
            found = entry.get("status")
            cells.append(
                Cell(
                    labels[i],
                    found if found in STATUSES else None,
                    _count(entry.get("runs")),
                    round(STRIP_LABEL_W + i * cell_slot + BAR_GAP / 2, 2),
                    round(max(cell_slot - BAR_GAP, 1.0), 2),
                )
            )
        chart.strip.append(StripRow(check_id, row * STRIP_ROW, tuple(cells)))
    chart.strip_height = len(checks) * STRIP_ROW
    return chart


# --- view model ---------------------------------------------------------------------------------


@dataclass(slots=True)
class Tab:
    target: MonitorTargetRecord | None
    checks: list[str]  # the check ids shown (the target's, else every schedulable one)
    last: dict[str, dict[str, Any] | None]  # check id -> newest run (API shape) or None
    runs: dict[str, Any]
    trend: dict[str, Any]
    chart: Chart
    snapshots: dict[str, Any]
    diff: dict[str, Any] | None
    diff_note: str | None  # i18n key when the requested diff cannot be shown
    bucket: str
    diff_from: str
    diff_to: str


def _clean(value: str) -> str | None:
    if len(value) > MAX_FIELD_LENGTH:
        return None
    if any(unicodedata.category(c) in _CONTROL_CATEGORIES for c in value):
        return None
    return value


def _query(request: Request) -> dict[str, str] | None:
    """The tab's own query parameters (others ignored); None when one is repeated or malformed."""
    pairs = [
        (k, v)
        for k, v in request.query_params.multi_items()
        if k in ("bucket", "cursor", "from", "to")
    ]
    found = dict(pairs)
    if len(found) != len(pairs):
        return None
    if any(_clean(v) is None for v in found.values()):
        return None
    if found.get("bucket", DEFAULT_BUCKET) not in BUCKETS:
        return None
    return found


def _load(
    history: HistoryService, monitors: MonitorService, did: int, query: Mapping[str, str], lang: str
) -> Tab:
    """Every DB read of the tab (sync: run in a worker thread). `did` passed `check_read`."""
    try:
        target: MonitorTargetRecord | None = monitors.get(did)
    except MonitorNotFound:
        target = None
    checks = list(target.check_ids) if target is not None else sorted(known_check_ids())
    last: dict[str, dict[str, Any] | None] = {}
    for check_id in checks:
        items = history.runs(did, {"check_id": check_id, "limit": "1"}, lang)["items"]
        last[check_id] = items[0] if items else None
    run_params = {"limit": str(HISTORY_PAGE)}
    if "cursor" in query:
        run_params["cursor"] = query["cursor"]
    runs = history.runs(did, run_params, lang)
    bucket = query.get("bucket", DEFAULT_BUCKET)
    trend = history.trend(did, {"bucket": bucket})
    snapshots = history.snapshots(did, {"limit": str(SNAPSHOT_PAGE)})
    diff_from, diff_to = query.get("from", ""), query.get("to", "")
    if not diff_from and not diff_to and len(snapshots["items"]) >= 2:
        diff_from = str(snapshots["items"][1]["id"])
        diff_to = str(snapshots["items"][0]["id"])
    diff: dict[str, Any] | None = None
    note: str | None = None
    if diff_from or diff_to:
        try:
            diff = history.diff(did, {"from": diff_from, "to": diff_to})
        except MonitorError as exc:
            note = DIFF_NOT_FOUND if exc.status in (404, 422) else DIFF_UNREADABLE
    shown = sorted(
        set(checks) | {c for b in trend["buckets"] for c in b["checks"] if c in known_check_ids()}
    )
    return Tab(
        target=target,
        checks=checks,
        last=last,
        runs=runs,
        trend=trend,
        chart=build_chart(trend, shown),
        snapshots=snapshots,
        diff=diff,
        diff_note=note,
        bucket=bucket,
        diff_from=diff_from,
        diff_to=diff_to,
    )


def _services(web: Web, db: DbDep, settings: SettingsDep, clocks: Clocks) -> tuple[
    HistoryService, MonitorService
]:  # fmt: skip
    principal = web.service.principal
    return (
        HistoryService(db, web.ctx, principal, clock=clocks[0]),
        MonitorService(
            db,
            web.ctx,
            principal,
            max_targets=settings.monitor_max_targets_per_tenant,
            clock=clocks[1],
        ),
    )


def _respond(request: Request, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    response = render(request, "monitoring/tab.html", status_code=status_code, logged_in=True,
                      **ctx)  # fmt: skip
    response.headers.update(_NO_STORE)
    return response


def _failure(request: Request, exc: MonitorError | DomainServiceError) -> HTMLResponse:
    """404 -> the translated 404 page (exception handler); 403 -> the denied page."""
    if exc.status == 404:
        raise HTTPException(status_code=404)
    if exc.status == 403:
        response = render(request, "domains/denied.html", status_code=403, logged_in=True)
        response.headers.update(_NO_STORE)
        return response
    raise exc


def _prepare(
    web: Web,
    history: HistoryService,
    monitors: MonitorService,
    domain_id: int | None,
    query: Mapping[str, str],
    lang: str,
) -> tuple[Any, Tab, bool]:
    """Sync part of the page: authorization, the domain view, the tab data, the controls flag."""
    did = history.check_read(domain_id)
    view = web.service.get(did)
    tab = _load(history, monitors, did, query, lang)
    can_manage = can(
        web.service.principal, Action.MONITOR_MANAGE, DomainResource(web.ctx.tenant_id, did)
    )
    return view, tab, can_manage


async def _page(
    request: Request,
    web: Web,
    db: DbDep,
    settings: SettingsDep,
    clocks: Clocks,
    domain_id: int | None,
    query: Mapping[str, str],
    *,
    status_code: int = 200,
    error: str | None = None,
    notice: str | None = None,
    form: Mapping[str, Any] | None = None,
) -> Response:
    history, monitors = _services(web, db, settings, clocks)
    try:
        view, tab, can_manage = await run_in_threadpool(
            _prepare, web, history, monitors, domain_id, query, request_language(request.scope)
        )
    except (MonitorError, DomainServiceError) as exc:
        if exc.status == 422:
            return error_page(request, 422, "invalid_request")
        return _failure(request, exc)
    if form is None:
        target = tab.target
        form = {
            "interval_seconds": target.interval_seconds if target else 86400,
            "check_ids": list(target.check_ids) if target else sorted(known_check_ids()),
            "enabled": target.enabled if target else True,
        }
    return _respond(
        request,
        status_code,
        domain_id=view.id,
        display_name=view.display_name,
        tab=tab,
        can_manage=can_manage,
        can_check=can(
            web.service.principal, Action.CHECK_RUN, DomainResource(web.ctx.tenant_id, view.id)
        ),
        error=error,
        flash=_NOTICES.get(notice or ""),
        form=form,
        statuses=STATUSES,
        intervals=[(s, INTERVAL_KEYS[s]) for s in ALLOWED_INTERVALS_SECONDS],
        all_checks=sorted(known_check_ids()),
        buckets=list(BUCKET_KEYS.items()),
        check_keys={c: f"checks.{c}.title" for c in known_check_ids()},
    )


# --- routes -------------------------------------------------------------------------------------


@router.get("/domains/{domain_id}/monitoring", include_in_schema=False)
async def monitoring_tab(
    request: Request,
    web: WebDep,
    db: DbDep,
    settings: SettingsDep,
    clocks: ClocksDep,
    domain_id: str,
) -> Response:
    query = _query(request)
    notice = request.query_params.get("notice")
    if query is None:
        # The domain and permission first, so a denied caller gets 403/404 whatever it sent.
        history, _ = _services(web, db, settings, clocks)
        try:
            await run_in_threadpool(history.check_read, _domain_id(domain_id))
        except MonitorError as exc:
            return _failure(request, exc)
        return error_page(request, 422, "invalid_request")
    return await _page(
        request, web, db, settings, clocks, _domain_id(domain_id), query, notice=notice
    )


def _parse_form(raw: Mapping[str, list[str]]) -> tuple[dict[str, Any], str | None]:
    """(fields for the service, error key). Values that are repeated, over-long or carry control
    characters never reach the service; the echo keeps only clean values."""
    intervals = raw.get("interval_seconds", [])
    checks = raw.get("check_ids", [])
    enabled = raw.get("enabled", [])
    # Only the offered values are accepted (no number parsing of user input).
    interval = _INTERVALS_BY_TEXT.get(intervals[0]) if len(intervals) == 1 else None
    too_many = len(checks) > MAX_FORM_CHECKS
    clean_checks = [] if too_many else [c for c in checks if _clean(c) is not None]
    fields: dict[str, Any] = {
        "interval_seconds": interval if interval is not None else 0,
        "check_ids": clean_checks,
        "enabled": enabled == ["1"],
    }
    if too_many or len(clean_checks) != len(checks) or not clean_checks:
        return fields, INVALID_CHECKS_KEY
    if interval is None or len(enabled) > 1:
        return fields, INVALID_INTERVAL_KEY if interval is None else INVALID_REQUEST_KEY
    return fields, None


def _save(monitors: MonitorService, did: int, fields: Mapping[str, Any]) -> None:
    """Create the target, or change it when the domain already has one."""
    try:
        monitors.get(did)
    except MonitorNotFound:
        try:
            monitors.create(did, **fields)
            return
        except MonitorExists:
            pass  # created concurrently: change it instead
    monitors.update(did, **fields)


@router.post("/domains/{domain_id}/monitoring", include_in_schema=False)
async def monitoring_save(
    request: Request,
    web: WebDep,
    db: DbDep,
    settings: SettingsDep,
    clocks: ClocksDep,
    domain_id: str,
) -> Response:
    _, monitors = _services(web, db, settings, clocks)
    try:  # permission and domain first: a denied caller never has its body read
        did = await run_in_threadpool(monitors.check_manage, _domain_id(domain_id))
    except MonitorError as exc:
        return _failure(request, exc)
    await run_in_threadpool(db.rollback)
    raw = await read_form(request)
    if raw is None:
        return payload_too_large(request)
    fields, error = _parse_form(raw)
    status = 422
    if error is None:
        try:
            await run_in_threadpool(_save, monitors, did, fields)
        except MonitorError as exc:
            if exc.status in (403, 404):
                return _failure(request, exc)
            status, error = exc.status, exc.key
        else:
            return RedirectResponse(f"/domains/{did}/monitoring?notice=saved", status_code=303)
    return await _page(
        request, web, db, settings, clocks, did, {}, status_code=status, error=error, form=fields
    )


@router.post("/domains/{domain_id}/monitoring/delete", include_in_schema=False)
async def monitoring_delete(
    request: Request,
    web: WebDep,
    db: DbDep,
    settings: SettingsDep,
    clocks: ClocksDep,
    domain_id: str,
) -> Response:
    _, monitors = _services(web, db, settings, clocks)
    try:
        await run_in_threadpool(monitors.delete, _domain_id(domain_id))
    except MonitorNotFound:
        # A readable domain without a target (or a missing one): the service says 404 for both,
        # and `check_manage` already ran inside `delete`, so nothing is disclosed.
        raise HTTPException(status_code=404) from None
    except MonitorError as exc:
        return _failure(request, exc)
    did = _domain_id(domain_id)
    return RedirectResponse(f"/domains/{did}/monitoring?notice=deleted", status_code=303)
