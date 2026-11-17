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
Status: done (191d875, QA APPROVE round 1; Opus coder chosen up front by the GM, Opus QA)

Decision record:
- Column-only select of (started_at, status, check_id) through the tenant-scoped `CheckRunRepository.trend(domain_id, since, until, size, max_runs, check_id=None)`; the findings JSON is no longer loaded.
- Bucketing is done in Python with `bucket_floor` (UTC epoch arithmetic, correct before 1970, independent of the SQLite text format and the PG session timezone).
- SQL GROUP BY rejected: backend-specific epoch expressions, floor division of negative epochs, and a window function would be needed.
- The 20000-run cap is kept with unchanged `truncated` semantics; the 500-bucket cap and API output are unchanged.
- The equivalence test keeps the old scan as the reference implementation.
