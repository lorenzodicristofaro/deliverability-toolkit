# M5-05b content_rules index rework (SQLite planner error)
Milestone: M5
Branch: feature/m5-05b-content-rules-index-fix
Files in scope: migrations/versions/<new 0007>_content_rules_indexes.py, app/models/content_rule.py, tests/repositories/test_content_rules.py
Out of scope: repository logic, other tables
Depends on: M5-06
Parallel-safe: no (migration)
Model: opus (tenant isolation)
Context: M5-06 QA reproduced "internal query planner error" on SQLite 3.46.1 and 3.53.1 for `(scope='global' OR scope='tenant' AND tenant_id=?) AND seed_key=?` with content_rules' plain `ix_content_rules_tenant_id` plus partial `uq_content_rules_tenant_seed_key ... WHERE scope='tenant'` (migration 0005:134,144). Current code never runs that query; M5-12/M5-18 would. Repro: /tmp/claude-1000/-home-lorenzo-projects-deliverability-toolkit/4a5a5d18-83e3-43a7-bbfa-0ad272870188/scratchpad/repro.py
Acceptance criteria:
- New migration 0007 (do not edit 0005, it is on dev) reworks indexes the way 0006 did for dkim_selectors: non-partial unique (tenant_id, seed_key) (NULLs distinct on SQLite and PG), the global partial unique seed_key index kept, no partial tenant index; model matches (`alembic check` clean); downgrade restores 0005's indexes.
- Uniqueness unchanged: same seed_key twice in one tenant rejected; same key in two tenants allowed; global uniqueness unchanged.
- Regression test: tenant OR-filter + seed_key lookup with bound parameters runs on SQLite (and PG on CI), plus the same with `kind`/`enabled` filters.
- Single Alembic head; upgrade/downgrade -1/upgrade clean.
New i18n keys: none
Status: todo
