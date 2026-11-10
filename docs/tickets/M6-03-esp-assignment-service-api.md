# M6-03 ESP assignment service and REST (+ profile catalogue)
Milestone: M6
Branch: feature/m6-03-esp-assignment-service-api
Files in scope: app/services/domain_esps.py, app/api/v1/domain_esps.py, app/api/__init__.py (one include_router line), tests/services/test_domain_esps.py, tests/api/test_domain_esps_api.py, tests/tenancy/test_matrix.py, locales/en.json, locales/it.json
Out of scope: UI (M6-07), running the profile check (M6-06), changing permissions.py unless the coder proves the reused actions cannot express the rules below (then stop and report to the GM)
Depends on: M6-01, M6-02
Parallel-safe: no (router registry, locale files, tenancy matrix)
Model: opus (permissions, tenant data)
Acceptance criteria:
- Routes (names indicative, follow app/api/v1/domains.py): `GET /api/v1/esp-profiles` (catalogue: id, name, homepage, status, verified_on, sources; read-only, from the M6-01 loader), `GET /api/v1/domains/{id}/esps`, `PUT /api/v1/domains/{id}/esps/{esp_id}` (assign, optional `return_path_host`, `tracking_host`), `DELETE /api/v1/domains/{id}/esps/{esp_id}`.
- Authorization via `can()` before any repository call (spy test), reusing existing actions: read = `domain.read` for OWNER/ADMIN/ANALYST; write = `domain.update` for OWNER/ADMIN. Client viewers get 403 on every ESP route (SPEC section 3: no ESP data for them; GM to confirm, see open questions), including the catalogue. Anonymous 401. Per-user feature toggles honoured as elsewhere.
- tenant_id only from TenantContext; a domain of another tenant or an invisible domain gives 404; an unknown `esp_id` gives 404 on the catalogue and 422 on PUT; hosts validated by the M6-02 rules, error shape as other APIs; duplicate PUT is idempotent (200, no second row).
- Tenancy/permission tests per role and verb; all four routes appear in the coverage matrix (tests/tenancy/test_matrix.py); two-tenant test shows no leak through list or catalogue.
- Instance admin without a membership gets no access (ARCHITECTURE section 4.6).
- QA (M6-02): `DomainEspRepository.add` is idempotent and never changes stored hosts. Re-adding an assignment with different hosts must not be treated as an upsert: use `update_hosts`, or reject.
- QA (M6-02): a concurrent duplicate add raises IntegrityError at flush. Map it to the idempotent result, or roll back, and never return a 500.
- QA (M6-02): the service validates that `esp_id` names a loaded profile (app/esp/profile.py).
- QA (M6-02): renaming a domain does not re-check stored hosts. Note this for whichever ticket adds renaming (not in this ticket).
New i18n keys: api.domain_esps.error.unknown_esp, .invalid_host, .host_outside_domain, .too_many, .not_found (en + it)
Status: done (merged into local dev at fff0823 after QA APPROVE; GM gate full PostgreSQL suite 29343 passed, lint clean. QA should-fix on a broken profiles directory moved to M6-06)
