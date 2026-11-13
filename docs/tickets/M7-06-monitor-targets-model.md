# M7-06 Monitor targets: model, migration, repository
Milestone: M7
Branch: feature/m7-06-monitor-targets-model
Files in scope: app/models/monitor_target.py, app/models/__init__.py, migrations/versions/<next revision after 0009>_monitor_targets.py, app/repositories/monitor_targets.py, app/repositories/__init__.py, tests/repositories/test_monitor_targets.py, tests/test_migrations (existing migration tests, extend)
Out of scope: API/UI (M7-11), scheduler (M7-09), history tables
Depends on: none
Parallel-safe: no (models registry and migration chain; serialize with M7-07, M7-08, M7-14, M7-15)
Model: sonnet (tenant isolation is exercised through the existing repository base; QA on opus because of tenancy)
Acceptance criteria:
- Table `monitor_targets`: id, tenant_id (NOT NULL, FK), domain_id (FK, tenant-consistent), check ids set (JSON list from the registry allowlist), interval_seconds (enum of allowed values, min bound a constant), enabled, next_run_at, last_run_at, last_status, created_at/updated_at. Unique (tenant_id, domain_id).
- Repository only through `TenantContext` (CLAUDE.md non-negotiable); one scheduler-only method `due_targets(now, limit)` that is explicitly named as cross-tenant, takes no tenant data from callers, and is documented as the only such method (see how app/repositories/base.py handles system access; follow that, do not bypass).
- Cross-tenant tests: tenant A cannot read, update or delete tenant B targets; a domain from another tenant is rejected at insert; `due_targets` returns only enabled rows with next_run_at <= now, ordered, limited, and carries tenant_id so execution rebuilds a TenantContext.
- Migration upgrades from head on SQLite and PostgreSQL, downgrade works, FK cascade on domain/tenant delete tested.
New i18n keys: none
Status: todo
