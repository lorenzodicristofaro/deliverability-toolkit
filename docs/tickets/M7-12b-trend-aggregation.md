# M7-12b Trend aggregation in the repository
Milestone: M7
Branch: feature/m7-12b-trend-aggregation
Files in scope: app/repositories/check_runs.py, app/services/history.py, tests/repositories/ (check_runs aggregation tests), tests/services/ (history trend tests), tests/api/test_history_api.py (only if output assertions need adjusting)
Out of scope: API routes and response shape (must stay identical), UI (M7-13), schema/migrations unless an index is strictly needed (then say so and ask the GM first)
Depends on: M7-12
Parallel-safe: no (check_runs repository, history service)
Model: sonnet
Acceptance criteria:
- Replace the Python scan in `app/services/history.py` `_scan` (up to 20000 full CheckRun rows including findings JSON) with a tenant-scoped repository aggregation in `app/repositories/check_runs.py` (GROUP BY bucket, status, check_id, or a column-only select that never loads findings JSON). Access only through the repository with a `TenantContext`.
- Identical API output for `GET /api/v1/domains/{id}/history/trend` (hour/day UTC buckets, bucket starts, counts, per-check status).
- Same caps and flags semantics (<=500 buckets, window widening to whole buckets, `truncated`), or, if aggregation makes the 20000-run scan cap unnecessary, lift it and document the decision in the ticket and in the service docstring; keep the 500-bucket cap.
- Works on SQLite and PostgreSQL (bucketing expression per dialect, or bucket in Python over column-only rows); document the choice.
- Tests on SQLite and PG: bucket boundaries (exactly on the hour/day edge, UTC), empty window, cap/flag behaviour, cross-tenant and cross-domain isolation (other tenant's runs never counted), existing M7-12 trend tests still pass unchanged.
New i18n keys: none
Status: todo
