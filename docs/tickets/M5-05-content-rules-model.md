# M5-05 content_rules model, migration and repository
Milestone: M5
Branch: feature/m5-05-content-rules-model
Files in scope: app/models/content_rule.py, app/models/__init__.py, migrations/versions/<date>_0005_content_rules.py, app/repositories/content_rules.py, app/repositories/__init__.py, tests/repositories/test_content_rules.py, tests/test_migrations (existing migration test, if any)
Out of scope: seed (M5-12), engine (M5-13), API, UI.
Depends on: M5-04
Parallel-safe: no (models, migrations and repositories registry; serialize M5-05 -> M5-06 -> M5-07 so Alembic keeps a single head)
Model: opus (tenant isolation)
Acceptance criteria:
- Columns: id, scope (`global`|`tenant`, DB CHECK), tenant_id (NULL iff global, DB CHECK + FK), name, kind (`regex`|`keyword`), pattern, flags, weight (bounded int), category, language (nullable, BCP47-ish short code), enabled, severity, source_ref/verified_on/status (`verified`|`unverified`, for seed rows), seed_key (nullable, unique per scope, for seed sync), created_at/updated_at, created_by.
- Repository is the only access path. Reads take a `TenantContext` and return global rows + that tenant's rows only; writes of tenant rows force tenant_id from the context; global writes need an explicit instance-admin entry point (not reachable from tenant API without the M5-04 check at the service layer).
- Pattern validated before insert via the M5-03 compile check is NOT done here (service layer, M5-18); repository only enforces length and NUL rejection (NUL before DB, PG rejects it).
- Tenancy tests: tenant A cannot read/update/delete tenant B rows (id guessing returns None/not found); global rows readable by all, writable by none via the tenant path.
- Migration upgrade/downgrade tested; PG-specific constraints verified (PG params skip locally, will run on dev CI: coder notes this).
New i18n keys: none
Status: done
