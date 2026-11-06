# M3-15 Checks REST endpoints
Milestone: M3
Branch: feature/m3-15-checks-api
Files in scope: app/api/v1/checks.py, app/main.py (router registration only), app/web/deps.py (resolver/ctx dependency only, keep tiny), tests/api/test_checks_api.py, tests/tenancy/ (route classification for the new routes, required by the route-coverage guard)
Note: Router registered in app/api/__init__.py (the /api/v1 registry), not app/main.py; accepted by GM.
Out of scope: SSE (M3-16), UI, persistence of results (decision below)
Depends on: M3-08, M3-10, M3-13, M3-14 (M3-11 may land after; the endpoint returns whatever the DMARC check returns)
Parallel-safe: no (app/main.py router registry)
Model: sonnet
Persistence decision: none in M3. The Authentication tab runs checks live; the History tab, trends and scheduled runs (check_runs/check_results tables with migrations on SQLite+PG) belong to a later milestone, so no migration or model work here. Retention is therefore not an M3 concern.
Acceptance criteria:
- `POST /api/v1/domains/{domain_id}/checks/{check_id}` (check_id in `spf|dkim|dmarc|all`) and `POST /api/v1/domains/{domain_id}/checks` (body: ids list) return the `CheckResult` JSON from the M3-02 service, loaded via `app/repositories` with a TenantContext (never raw queries), gated by `Action.CHECK_RUN` on `DomainResource`. Follow app/api/v1/domains.py conventions for method, CSRF and error shape.
- Free: `POST /api/v1/checks/free` (name, ids) gated by `Action.DNS_TOOLS`, no tenant data, same service and result schema.
- Status codes: anonymous 401 (or existing convention); no permission 403; domain of another tenant or unknown id 404 (no existence leak, same as domains API); unknown check id / invalid name 422; DNS failures are 200 with status `error` in the body.
- Tenancy/permission tests for EVERY route: owner/admin/analyst 200; client viewer 200 only for an assigned domain, 403/404 for an unassigned domain; tenant A user cannot run on tenant B's domain; client viewer on the free route 403; toggle `check.run: false` denies.
- Resolver comes from the overridable dependency (M2-04 fake in tests); no network. Per-request caps (ids list size) enforced. OpenAPI schemas present; route-coverage guard passes.
- Risk noted: no per-user rate limiting yet (already in TODO follow-ups); checks fan out many DNS queries (DKIM probe), so the concurrency bound is per request only.
New i18n keys: none (API returns codes)
Status: done
