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
Status: todo
