# M1-10 Core tenancy models and migration
Milestone: M1
Branch: feature/m1-10-core-models
Files in scope: app/models/user.py, app/models/tenant.py, app/models/membership.py, app/models/domain.py, app/models/__init__.py, migrations/versions/<new revision>, tests/models/test_models.py
Out of scope: repositories, permission logic, sessions table (M1-13), audit_log, check_* tables, API keys
Depends on: M1-06
Parallel-safe: no (models and migrations are shared hotspots)
Model: opus
Acceptance criteria:
- Tables per ARCHITECTURE sections 4-5: `users` (email unique case-insensitive, password_hash nullable until set, language, is_instance_admin, is_active), `tenants` (name, slug unique, language), `memberships` (user, tenant, role enum owner/admin/analyst/client_viewer, feature_toggles JSON), `domain_access` (membership, domain), `domains` (tenant_id NOT NULL, name normalised/IDNA-lowercase, unique per tenant).
- Every tenant-owned table has non-null `tenant_id` and an FK; `domain_access` is constrained so membership.tenant_id equals domain.tenant_id (composite FK or check, strategy stated in summary; must work on SQLite and PostgreSQL).
- Unique (user, tenant) on memberships; deleting a tenant cascades or is restricted (decision stated); no orphan rows (tests).
- One Alembic revision; upgrade/downgrade tested on SQLite and PostgreSQL (when TEST_DATABASE_URL set).
- Tests: constraint violations (duplicate domain per tenant allowed across tenants, cross-tenant domain_access rejected, null tenant_id rejected).
- Instance admin = `users.is_instance_admin` (GM decision Q4a in M1-01).
New i18n keys: none
Status: done (merged into dev, QA APPROVE incl. should-fix delta; SQLite 318 passed, PG models+db 150 passed)
