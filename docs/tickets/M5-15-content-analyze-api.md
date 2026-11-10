# M5-15 REST endpoint POST /api/v1/content/analyze
Milestone: M5
Branch: feature/m5-15-content-api
Files in scope: app/api/v1/content.py, app/api/__init__.py (one include_router line), tests/api/test_content_analyze.py, tests/tenancy/test_matrix.py (and route-coverage matrix file), locales/en.json, locales/it.json
Out of scope: UI, CLI, multipart dependency, storage.
Depends on: M5-04, M5-14
Parallel-safe: no (router registry and locale files)
Model: sonnet
Acceptance criteria:
- Body: JSON `{html?, text?, subject?, language?}` (application/json) OR raw `message/rfc822` (.eml); other types 415. Response is the `ContentAnalysis` JSON from M5-14, byte-equal to the service output.
- Size cap enforced WHILE reading (counter, same style as M4-11), Content-Length checked first: over cap -> 413 without buffering the rest. NUL -> 422 `{key, message, field, reason}` without echoing input. Empty input (no html, no text, no eml) -> 422. Invalid language value -> 422.
- Auth: 401 anonymous (CSRF rules as other mutating routes), 404 no/stale active tenant, 403 when `can(principal, Action.CONTENT_ANALYZE, TenantResource(tenant_id))` is false. On any denial the analyzer is NOT invoked (monkeypatch spy).
- Tenancy/permission test per role (owner, admin, analyst allowed; client viewer, foreign tenant, anonymous denied); route added to the route-coverage matrix. Tenant rules of another tenant never applied (two-tenant test with a distinguishing rule).
- Offline (sockets blocked, DNS fake asserts zero queries); nothing stored (row counts unchanged); no content in logs.
New i18n keys: api.content.error.unsupported_media_type, api.content.error.too_large, api.content.error.nul_byte, api.content.error.empty, api.content.error.invalid_language, api.content.error.invalid_body (en + it)
GM note (constraints from M5-14): `analyze_content(ctx, session, content)` is synchronous and blocks up to about 15 s, so the route must call it with `run_in_threadpool`; the JSON shape of ContentAnalysis gets frozen by this ticket.
Status: done
