# M6-02 domain_esps model, migration and repository
Milestone: M6
Branch: feature/m6-02-domain-esps-model-repository
Files in scope: app/models/domain_esp.py, app/models/__init__.py, migrations/versions/<date>_0009_domain_esps.py, app/repositories/domain_esps.py, app/repositories/__init__.py, tests/repositories/test_domain_esps.py
Out of scope: service, API, UI, the profile loader (M6-01), `esp_profiles` table and tenant profile overrides (not in M6, see open questions in the PM report)
Depends on: none (pattern: M5-06; read app/repositories/base.py and app/repositories/domain.py first)
Parallel-safe: yes with M6-01 (disjoint directories); NOT with any other ticket touching models, migrations or the repositories registry
Model: opus (tenant-scoped data)
Acceptance criteria:
- Table `domain_esps`: id, tenant_id, domain_id, esp_id (profile slug, plain string, no FK because profiles live in YAML; same slug regex as M6-01), optional `return_path_host` and `tracking_host` (hostnames, normalised like domain names, must equal or end with `.<domain name>`, enforced in the repository), created_at. Unique (domain_id, esp_id). Composite FK (domain_id, tenant_id) -> domains(id, tenant_id) so a cross-tenant row is impossible (same technique as `domain_access`, M1-10); ON DELETE CASCADE from domain and tenant.
- Repository built with a `TenantContext`: every read and write is scoped by tenant_id from the context, never from arguments; `list_for_domain`, `list_for_domains`, `add` (idempotent per (domain, esp)), `update_hosts`, `remove`. A domain id from another tenant behaves as not found (no row, no exception that leaks existence).
- Cap: at most 10 ESPs per domain (repository error beyond it).
- Migration works on SQLite and PostgreSQL, upgrade and downgrade; model and migration agree (existing drift test stays green).
- Tests (both backends where the suite supports it): tenancy isolation (tenant A cannot read, add to, update or remove tenant B rows), duplicate add, cascade on domain delete and tenant delete, host validation table (valid, foreign suffix, NUL, too long, uppercase, trailing dot, IDN not accepted), cap.
- The tenancy test matrix/guards that scan repositories (tests/tenancy) stay green; add the new repository where they enumerate repositories.
New i18n keys: none
Status: done
Merge note: merged into local dev at f46a41e after QA APPROVE; the GM gate on 0f7803c passed the full PostgreSQL suite (28712 passed), with lint clean.
