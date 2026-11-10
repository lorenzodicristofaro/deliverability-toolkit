# M5-23 Custom checks admin: service, REST and run wiring
Milestone: M5
Branch: feature/m5-23-custom-checks-api
Files in scope: app/services/custom_checks_admin.py, app/api/v1/custom_checks.py, app/api/__init__.py (one include_router line), app/checks/registry.py + app/services/checks.py (only to run enabled custom checks for a domain; coder inspects the seams first), tests/services/test_custom_checks_admin.py, tests/api/test_custom_checks_api.py, tests/tenancy/test_matrix.py, locales/en.json, locales/it.json
Out of scope: UI (M5-24), http_fetch, changing built-in check results.
Depends on: M5-04, M5-07, M5-22
Parallel-safe: no (router registry, registry module, locale files)
Model: opus (scope authorization, user-supplied regex executed against DNS data)
Acceptance criteria:
- CRUD with the same scope and authorization rules as M5-18; definitions validated with the M5-22 schema; `http_fetch` kind -> 422 "not available yet". tenant_id only from TenantContext; foreign ids 404; authorization before repository (spy).
- `POST /api/v1/custom-checks/test`: dry run a definition against a domain the caller may `check.run` (existing permission and DomainResource) with the real service path but stored nowhere; DNS failure surfaces as `error`.
- Custom checks execute in the normal domain run for the tenant that owns them (plus enabled global ones), never for another tenant's domains; a built-in-only domain run is byte-equal to pre-M5 (regression against M3 acceptance fixtures).
- Tenancy/permission tests per role and verb, plus: analyst cannot create, client viewer cannot read or run; routes in the coverage matrix; denial never invokes the evaluator or DNS (spies).
New i18n keys: api.custom_checks.error.invalid_definition, .kind_unavailable, .scope_forbidden, .not_found, .name_too_long (en + it)
Status: in-review
