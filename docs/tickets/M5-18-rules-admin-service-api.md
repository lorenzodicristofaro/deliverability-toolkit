# M5-18 Content rules admin: service and REST (global vs tenant, test on sample)
Milestone: M5
Branch: feature/m5-18-rules-admin-api
Files in scope: app/services/content_rules_admin.py, app/api/v1/rules.py, app/api/__init__.py (one include_router line), tests/services/test_content_rules_admin.py, tests/api/test_rules_api.py, tests/tenancy/test_matrix.py, locales/en.json, locales/it.json
Out of scope: UI (M5-19), DKIM selectors, custom checks.
Depends on: M5-03, M5-04, M5-05, M5-12, M5-13
Parallel-safe: no (router registry, locale files)
Model: opus (global vs tenant authorization on writes)
Endpoints: GET/POST /api/v1/rules, GET/PATCH/DELETE /api/v1/rules/{id}, POST /api/v1/rules/test (test a rule on a sample before saving).
Acceptance criteria:
- Scope rules from M5-04: scope `global` writes only for an instance admin; scope `tenant` writes only for OWNER/ADMIN of the active tenant; reads for OWNER/ADMIN/ANALYST (global + own tenant). The service authorizes with `can(...)` BEFORE touching the repository; denial never reaches the repository (spy).
- Request scope is never trusted for tenant_id: tenant rows take the id from the TenantContext. Attempt to create a tenant rule for another tenant, to PATCH/DELETE another tenant's or a global row from the tenant path -> 404/403 per existing convention (tested for each verb).
- Validation on create/update: pattern through `compile_checked` (M5-03), pattern length, weight bounds, category/language values, name length; failures 422 `{key, message, field, reason}`, no echo of the pattern content beyond a safe error code.
- `POST /rules/test`: body {kind, pattern, flags, sample text}; runs through safe_regex with the enforced timeout and match cap; returns matches (bounded snippets) or `timed_out: true` / `invalid`; stores nothing; requires `rules.manage` on the scope being edited; sample size capped. A catastrophic pattern returns `timed_out` quickly (test).
- Editing a seed-derived global row sets `locally_modified` (M5-06/M5-12 semantics); changes take effect on the next analysis without restart or deploy (test: change rule via API, next `analyze_content` call reflects it).
- Tenancy/permission test per role and per verb (owner, admin, analyst, client viewer, foreign tenant, instance admin, anonymous); routes in the route-coverage matrix.
- Audit: write operations log the actor, rule id and scope, never the pattern body in logs.
New i18n keys: api.rules.error.invalid_pattern, .pattern_too_long, .invalid_weight, .invalid_language, .scope_forbidden, .not_found, .sample_too_large, .timed_out (en + it)
Status: todo
