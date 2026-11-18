# M7-13 Monitoring page and trend charts
Milestone: M7
Branch: feature/m7-13-monitoring-ui
Files in scope: app/web/monitoring.py, app/web/templates/monitoring/ (new), app/web/static/ (chart asset only), app/main.py (router registration only), tests/web/test_monitoring_ui.py, locales/en.json, locales/it.json
Out of scope: alert channel UI (M7-15 provides API only; a UI for channels is deferred unless the GM adds a ticket), API changes
Depends on: M7-11, M7-12, M7-12b
Parallel-safe: no (router registry, locales)
Model: sonnet
Acceptance criteria:
- Per-domain monitoring tab: configure target (interval, checks, enable) via the M7-11 API/service, last status per check, history table, trend chart, snapshot diff view.
- Charts rendered server-side as inline SVG (no new JS dependency and no CDN; if the existing UI already ships a chart library, reuse it and say so); all values escaped; works without JS.
- Permission-aware: read-only for viewers, controls hidden and server-enforced; CSRF on forms.
- Tests: permission and tenancy per role on every route, escaping of hostile record values in the diff view (a `"><script>` TXT value rendered escaped), empty states, en and it render with no missing keys.
New i18n keys: monitor.tab.*, monitor.chart.*, monitor.diff.* (en + it, listed by the coder in the PR)
Status: done (merged 8cb7933, QA APPROVE round 1)
Notes (coder):
- Routes: GET /domains/{id}/monitoring (query `bucket`, `cursor`, `from`, `to`), POST /domains/{id}/monitoring (create, or change the existing target), POST /domains/{id}/monitoring/delete. Everything goes through MonitorService / HistoryService; no repository in app/web/monitoring.py.
- Charts: server-side inline SVG (stacked runs per status per bucket + per-check status strip), CSS classes only (the CSP allows no inline styles), native SVG `<title>` tooltips, a table view in `<details>`; no JS and no chart library (none shipped before). Chart CSS appended to app/web/static/app.css.
- Accepted deviation (GM): no JS polling of the trend endpoint; the page works without JS and has a Refresh link.
- Extra files touched (required by the suite, outside "Files in scope"): tests/tenancy/test_matrix.py and tests/tenancy/test_id_range.py (new routes must be listed), tests/web/test_async_handlers_guard.py (module added to the AST guard).
- Scope extension (GM decision): app/web/templates/domains/** and the tests that pin the domain tab bar. The domain page, ESPs and Authentication tabs link to Monitoring when the caller has `monitor.read` on the domain (client viewers on assigned domains included), hidden otherwise; the Monitoring tab links to Authentication with `check.run`. The templates have no principal, so the display flag is computed in Python: `DomainRow.can_monitor` (app/web/domains.py) and a `can_monitor` context value in app/web/domain_esps.py and app/web/authentication.py (one `can()` each, no other change). Tests: tests/web/test_monitoring_ui.py (`test_tab_bar_*`).
- New i18n keys (en + it): monitor.tab.{title, heading, refresh, target, target_none, state, enabled, disabled, interval_label, interval.hour, interval.six_hours, interval.twelve_hours, interval.day, next_run, last_run, never, checks, create, save, delete, delete_hint, last_status, history, history_empty, history_older, findings_truncated, utc, flash.saved, flash.deleted, col.check, col.status, col.started, col.findings}; monitor.chart.{title, bucket_label, bucket.day, bucket.hour, bucket_start, capped, caption, empty, no_runs, per_check, runs, strip_caption, table}; monitor.diff.{title, from, to, compare, none, not_enough, not_found, unreadable, kind.added, kind.removed, kind.changed, kind.inconclusive, col.name, col.type, col.kind, col.before, col.after}.
Note (from M7-12): the history API returns raw untrusted DNS-derived text in diff `before_values`/`after_values` and in finding `params`. M7-13 must render them autoescaped, pass them through `app.core.text.visible()`, and never use innerHTML. Label trend buckets by their start (windows are widened to whole buckets). M7-13 polls the trend endpoint, hence the dependency on M7-12b.
Note (from M7-11): monitor API routes: GET /api/v1/monitors and GET/POST/PATCH/DELETE /api/v1/domains/{id}/monitor (router in app/api/__init__.py). Permission actions `monitor.read` / `monitor.manage` are domain-level; client viewer has read on assigned domains only, never manage. The `permission.monitor.*` labels exist in locales but are unused until a toggle UI exists: if M7-13 adds permission toggles it must render them.
