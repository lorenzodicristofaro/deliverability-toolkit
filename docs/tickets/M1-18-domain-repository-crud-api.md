# M1-18 Domain repository and CRUD endpoints
Milestone: M1
Branch: feature/m1-18-domain-crud
Files in scope: app/repositories/domain.py, app/services/domains.py, app/api/__init__.py, app/api/v1/domains.py, app/main.py (router registration), locales/en.json, locales/it.json, app/core/domain_names.py, tests/repositories/test_domain_repository.py, tests/api/test_domains.py, tests/core/test_domain_names.py, pyproject.toml, uv.lock (IDNA 2008 dependency only)
Out of scope: DNS checks on domains, ESP assignment, UI pages (M1-19), API keys, bulk import
Depends on: M1-11, M1-12, M1-15
Parallel-safe: no (router registry app/main.py)
Model: opus
Acceptance criteria:
- Domain name validation at the edge (IDNA to ASCII, lowercase, length 253/label 63, label rules, rejects IPs, whitespace, trailing dot normalised); table-driven tests incl. malformed input. No DNS lookup.
- IDNA conversion uses IDNA 2008 (UTS #46), not the stdlib idna codec (IDNA 2003); pick a maintained library, record its name/version in the summary. The model validator from M1-10 currently rejects non-ASCII names; after this ticket the edge converts U-labels to A-labels before they reach the model (GM, from M1-10 review).
- Endpoints (GM decision Q7): routes use the session's active tenant, `/api/v1/domains`, not `/tenants/{id}/...`. GET list, GET one, POST, PATCH, DELETE, all through `DomainRepository(ctx)` and `can()`.
- Client viewer: list and get return only assigned domains; unassigned domain id returns 404 (not 403). Assign/unassign domain access: PUT /api/v1/domains/{id}/access (admin/owner only).
- Tenancy/permission tests (generated matrix) for EVERY endpoint: anonymous 401; user of tenant A gets 404 on tenant B domain (get, patch, delete, access); client viewer 404 on unassigned and 403 on write; analyst cannot create/delete; duplicate name in same tenant 409, same name in another tenant allowed.
- Mutations require CSRF when cookie-authenticated; responses carry no other-tenant data in errors.
- Audit log is not in M1; leave a TODO comment referencing M10 only.
New i18n keys: api.error.not_found, api.error.forbidden, api.error.conflict, domain.error.invalid_name (en + it)
Status: todo
