# M7-13 Monitoring page and trend charts
Milestone: M7
Branch: feature/m7-13-monitoring-ui
Files in scope: app/web/monitoring.py, app/web/templates/monitoring/ (new), app/web/static/ (chart asset only), app/main.py (router registration only), tests/web/test_monitoring_ui.py, locales/en.json, locales/it.json
Out of scope: alert channel UI (M7-15 provides API only; a UI for channels is deferred unless the GM adds a ticket), API changes
Depends on: M7-11, M7-12
Parallel-safe: no (router registry, locales)
Model: sonnet
Acceptance criteria:
- Per-domain monitoring tab: configure target (interval, checks, enable) via the M7-11 API/service, last status per check, history table, trend chart, snapshot diff view.
- Charts rendered server-side as inline SVG (no new JS dependency and no CDN; if the existing UI already ships a chart library, reuse it and say so); all values escaped; works without JS.
- Permission-aware: read-only for viewers, controls hidden and server-enforced; CSRF on forms.
- Tests: permission and tenancy per role on every route, escaping of hostile record values in the diff view (a `"><script>` TXT value rendered escaped), empty states, en and it render with no missing keys.
New i18n keys: monitor.tab.*, monitor.chart.*, monitor.diff.* (en + it, listed by the coder in the PR)
Status: todo
