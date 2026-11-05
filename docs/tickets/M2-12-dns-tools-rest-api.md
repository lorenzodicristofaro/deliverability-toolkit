# M2-12 DNS tools REST endpoints
Milestone: M2
Branch: feature/m2-12-dns-tools-api
Files in scope: app/api/v1/dns_tools.py, app/main.py (router registration only), app/web/deps.py (only if a DNS resolver dependency provider is needed; keep tiny), tests/api/test_dns_tools_api.py, tests/tenancy/ (matrix classification for the new routes, as required by the route-coverage guard)
Out of scope: web UI (M2-13/14), rate limiting infrastructure (see risk), storing results
Depends on: M2-05, M2-06, M2-08, M2-09, M2-10, M2-11
Parallel-safe: no (app/main.py router registry)
Model: sonnet
Acceptance criteria:
- Endpoints under `/api/v1/dns/`: `POST /lookup` (name, type or `all`, resolver selector, no_cache), `POST /reverse` (ip), `POST /trace` (name, type), `POST /propagation` (name, type, resolver ids). POST with JSON body so the existing CSRF/session rules apply the same way as app/api/v1/domains.py (coder follows that file's conventions; if it uses another method convention, follow it and say so).
- Each handler requires an authenticated session with an active membership and `can(Action.DNS_TOOLS)`; anonymous -> 401 (or the API's existing convention), client viewer -> 403, analyst/admin/owner -> 200. Tenancy/permission tests for EVERY route (non-negotiable), incl. a user from tenant A with no memberships and a client viewer with a `dns.tools: true` toggle (still 403).
- Responses are stable JSON with `state` codes from M2-02, plus `evaluated` flags from M2-08/M2-10; failures return 200 with the failure state in the body (the query ran; the DNS condition is data), while input validation errors return 422 with the validator reason code (no echo of raw input in logs). Unknown resolver id -> 422.
- The resolver in use comes from a dependency (overridable in tests with the M2-04 fake; no network in tests). Request-size and concurrency caps enforced; an overall per-request deadline.
- OpenAPI shows schemas; route-coverage guard in tests/tenancy passes.
- Risk noted for GM: no per-user rate limiting exists yet (only login throttle); caps are per request. Follow-up candidate in TODO.md.
New i18n keys: none (API returns codes; UI translates)
Status: todo
