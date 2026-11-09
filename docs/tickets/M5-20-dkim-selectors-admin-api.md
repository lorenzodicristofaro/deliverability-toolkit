# M5-20 DKIM selectors admin: service, REST and check wiring
Milestone: M5
Branch: feature/m5-20-dkim-selectors-api
Files in scope: app/services/dkim_selectors_admin.py, app/api/v1/dkim_selectors.py, app/api/__init__.py (one include_router line), app/checks/dkim_selectors.py (only the data-source seam; coder inspects first), tests/services/test_dkim_selectors_admin.py, tests/api/test_dkim_selectors_api.py, tests/checks (existing DKIM tests must stay green and byte-equal), tests/tenancy/test_matrix.py, locales/en.json, locales/it.json
Out of scope: UI (M5-21), changing check logic or results for the default seed, DNS behaviour.
Depends on: M5-04, M5-06
Parallel-safe: no (router registry, locale files)
Model: opus (scope authorization)
Acceptance criteria:
- CRUD with the same scope and authorization rules as M5-18 (global: instance admin; tenant: OWNER/ADMIN; read: OWNER/ADMIN/ANALYST); tenant_id from TenantContext only; foreign tenant ids give 404; authorization before repository (spy).
- Validation: selector is a valid DNS label (reuse M3 validation), provider/notes length, NUL; 422 shape as other APIs.
- The DKIM selector discovery uses global enabled rows + the tenant's rows from the DB; with only the synced seed, results are byte-equal to the pre-M5 results (regression test against the existing M3 acceptance fixtures). If the check cannot be wired without changing its results or its pure/offline unit tests, the coder stops and reports to the GM instead of forcing it.
- A tenant's selectors never leak into another tenant's check results (two-tenant test).
- Tenancy/permission tests per role and verb; routes in the coverage matrix.
New i18n keys: api.dkim_selectors.error.invalid_selector, .too_long, .duplicate, .scope_forbidden, .not_found (en + it)
GM notes (from M5-06 QA): `GlobalDkimSelectorRepository.update` does not set `locally_modified`; the admin service MUST pass `locally_modified=True` on every admin edit of a global row, or the next seed sync reverts it. Test this.
Status: done
