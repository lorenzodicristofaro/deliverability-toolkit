# M5-06 dkim_selectors model, migration, repository and seed sync
Milestone: M5
Branch: feature/m5-06-dkim-selectors-model
Files in scope: app/models/dkim_selector.py, app/models/__init__.py, migrations/versions/<date>_0006_dkim_selectors.py, app/repositories/dkim_selectors.py, app/repositories/__init__.py, app/services/seed_sync.py (generic sync helper, created here, reused by M5-12), tests/repositories/test_dkim_selectors.py, tests/services/test_seed_sync.py
Out of scope: API, UI, changing app/checks/dkim_selectors.py (M5-20), editing seeds/dkim_selectors.yaml content.
Depends on: M5-05
Parallel-safe: no (models/migrations/repositories registry; serialize after M5-05)
Model: opus (tenant-scoped data)
Acceptance criteria:
- Columns: id, scope (global|tenant, CHECK), tenant_id (NULL iff global), selector, provider, notes, enabled, seed_key, verified_on/status inherited from the seed row, timestamps; unique (scope, tenant_id, selector).
- Same repository isolation rules as M5-05 (TenantContext reads = global + own tenant; writes force tenant_id).
- Selector name validated as a DNS label (reuse the M3 selector validation); invalid or NUL rejected before DB.
- `seed_sync`: idempotent upsert of global rows from the YAML seed keyed by seed_key; rows edited by an admin (enabled flag, notes) are NOT overwritten on re-sync (store `locally_modified`); a seed row removed from the file is disabled, not deleted. Runs at app start and via CLI hook later; never touches tenant rows. Offline, no network.
- Tests: first sync, re-sync no-op, seed change, admin-modified row kept, removed seed row disabled, tenant isolation, malformed YAML -> error (not partial sync).
New i18n keys: none
Status: done
