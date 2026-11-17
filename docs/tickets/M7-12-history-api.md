# M7-12 History and snapshot read API
Milestone: M7
Branch: feature/m7-12-history-api
Files in scope: app/api/v1/history.py, app/services/history.py, app/main.py (router registration only), tests/api/test_history.py, tests/services/test_history.py
Out of scope: charts and pages (M7-13), writing history
Depends on: M7-07, M7-08, M7-11
Parallel-safe: no (router registry; follows M7-11 for permissions)
Model: sonnet (QA on opus: tenancy)
Acceptance criteria:
- `GET` run history per domain/check with window and keyset pagination (page size cap), trend series (status counts and per-check status over time, bucketed server-side with a bucket cap), snapshot list and diff between two snapshot ids of the same domain.
- Uses `monitor.read`; ids from another tenant or domain give 404; a client viewer sees only assigned domains.
- Findings returned as codes + params plus rendered text for the request language (en/it) using the existing finding text helper; unknown codes degrade safely.
- Tests: permission matrix per role, cross-tenant ids on every endpoint, pagination bounds, malformed query params, large windows capped.
New i18n keys: none beyond existing finding keys
Status: done (0a7c87b, QA APPROVE round 2)
Result: routes GET /api/v1/domains/{id}/history/{runs,trend,snapshots,snapshots/diff?from=&to=}; router in app/api/__init__.py; tests in tests/api/test_history_api.py. GM-approved extras: app/core/text.py (visible()), app/web/dns_tools.py (re-export), tests/tenancy/test_matrix.py, tests/tenancy/test_id_range.py.
Caps: page 50 default / 200 max; runs window <=366 days (`capped` flag); trend hour/day UTC, <=500 buckets, <=20000 runs scanned (`truncated` flag); since/until bounded 1970..9000 UTC (422 outside).
QA round 1 (Sonnet code) found: OverflowError -> 500 on extreme dates (now bounded, 422); finding texts showed raw placeholders with strict mode off (now null); vacuous cursor test fixed; visible() moved to app/core/text.py. Fixed by an Opus coder; round 2 APPROVE.
Follow-up: M7-12b replaces the 20000-row Python scan with a repository aggregation.
Note (from M7-11): monitor routes exist: GET /api/v1/monitors and GET/POST/PATCH/DELETE /api/v1/domains/{id}/monitor (router in app/api/__init__.py, register history there too). Permission actions `monitor.read` / `monitor.manage` are domain-level; a client viewer has read on assigned domains only. Ordering convention: 404 before 403.
