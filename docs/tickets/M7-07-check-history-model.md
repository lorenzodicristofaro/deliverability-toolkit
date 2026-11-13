# M7-07 Check run history: model, migration, repository, retention
Milestone: M7
Branch: feature/m7-07-check-history
Files in scope: app/models/check_run.py, app/models/__init__.py, migrations/versions/<next revision>_check_runs.py, app/repositories/check_runs.py, app/repositories/__init__.py, app/services/retention.py, tests/repositories/test_check_runs.py, tests/services/test_retention.py, docs/CHECKS.md (history paragraph only)
Out of scope: scheduler, API/UI, DNS snapshots (M7-08), alerts
Depends on: M7-06
Parallel-safe: no (models registry, migration chain)
Model: sonnet
Acceptance criteria:
- Tables `check_runs` (id, tenant_id, domain_id, check_id, status ok/info/warn/fail/error exactly as the Check contract, started_at, duration_ms, source scheduled|manual, findings JSON bounded in size, findings_hash) per ARCHITECTURE section 5 (`check_results` naming: follow the architecture if it names it differently and say so). Index (tenant_id, domain_id, check_id, started_at).
- Findings stored as stable codes + params only (no rendered text, so i18n applies at display); size cap per run, over-cap truncated with a flag.
- Repository via TenantContext only; list by domain/check with time window and keyset pagination; latest-per-check query.
- Retention per ARCHITECTURE section 5: configurable setting for raw run retention (days, bounded), `prune_check_runs(now, policy)` deletes by tenant-agnostic system method that is explicitly named; aggregates are not part of this ticket. Tested with a fake clock.
- Cross-tenant isolation tests; migration up/down on SQLite and PostgreSQL.
New i18n keys: none
Status: todo
