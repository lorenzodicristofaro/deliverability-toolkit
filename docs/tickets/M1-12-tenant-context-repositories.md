# M1-12 TenantContext and tenant-scoped repository base
Milestone: M1
Branch: feature/m1-12-tenant-context-repos
Files in scope: app/core/tenancy.py, app/repositories/__init__.py, app/repositories/base.py, app/repositories/tenant.py, app/repositories/membership.py, tests/repositories/test_base_repository.py
Out of scope: domain repository (M1-18), endpoints, permission checks (M1-11), PostgreSQL RLS (optional later)
Depends on: M1-10
Parallel-safe: yes with M1-11 (disjoint files)
Model: opus
Acceptance criteria:
- `TenantContext(tenant_id, principal)` is immutable; repositories are only constructible with one. `/repositories` is the only place with queries on tenant-owned tables (CLAUDE.md rule); a test greps `app/` outside `app/repositories` and `migrations/` for `select(`/`session.query` on tenant models and fails on matches.
- Base repository injects `tenant_id` into every select/update/delete and on insert (caller cannot pass another tenant_id; passing one raises). `get` of another tenant's id returns None (maps to 404 upstream), never raises a distinguishable error.
- Routers/services never receive a raw session for tenant data: factory `repo_for(ctx, session)` is the sole entry (documented).
- Tests on SQLite (and PostgreSQL when configured): two tenants with rows; every base method (get, list, add, update, delete, count) is proven not to cross tenants; attempt to update tenant_id is rejected.
- Memberships repository for the user's own tenants lives in a clearly named non-tenant-scoped module with a docstring explaining why (listing a user's tenants is a user-scoped query).
New i18n keys: none
Status: done (merged into dev, QA APPROVE after fix round 1; SQLite 484, PG 602 passed)
