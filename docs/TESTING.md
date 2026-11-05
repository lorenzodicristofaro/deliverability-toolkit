# Testing

Commands are in `CLAUDE.md`. DB tests run on SQLite and, when `TEST_DATABASE_URL` is set, on
PostgreSQL (shared `db_url` fixture in `tests/conftest.py`; the tenancy suite has its own
module-scoped `world` fixture in `tests/tenancy/conftest.py` with the same two parameters).

## Tenancy matrix (M1-20)

`tests/tenancy/test_matrix.py` is generated from the FastAPI route table: every leaf route
(method x path) of `app.main.create_app()` must be a `MATRIX` entry or an `EXEMPT` path, or
`test_every_route_is_in_the_matrix_or_exempt` fails. Routes are enumerated with
`fastapi.routing.iter_route_contexts` (FastAPI 0.162 wraps included routers, so `app.routes`
does not list leaf routes); the enumeration is self-tested against a nested synthetic app and
against every `APIRouter` declared in `app.web` / `app.api`.

### Adding an endpoint

1. Add `(METHOD, "/full/path/{param}"): Entry(Kind.<KIND>, ...)` to `MATRIX`.
   - `DOMAIN`: addresses one domain by `{domain_id}`; every role gets 404 for a tenant B domain,
     for a session whose active tenant is B, and (client viewer) for an unassigned domain.
   - `COLLECTION`: list/create in the active tenant; give the expected status per role for the
     own-tenant request (`own=` for GET, `smuggle=` for writes that also try to pass a tenant B id).
   - `LANDING`, `SESSION`, `SWITCH`: see the module docstring.
   - Pass `body=` for writes. A new resource type (not a domain) needs a new `Kind` with its
     cross-tenant target and an explicit expectation in `_expected`.
2. Every matrix route must depend on `app.web.deps.current_session`
   (`test_matrix_routes_require_a_session_and_exempt_ones_no_tenant`).
3. Every case also checks that responses and captured logs never contain tenant B strings
   (tenant name, slug, domain names in A-label and U-label form, user emails), and that neither
   tenant's data changed.

Never "fix" a failing case by changing the expectation to what the code does. If the matrix finds
an isolation bug, mark the case `xfail(strict=True)` with the reason and open a ticket.

### Exemptions

Exemptions are by path (all methods) and must stay minimal. Each needs a reason here and in
`EXEMPT`; exempt routes may not depend on `current_session` or `tenant_ctx`.

| Path | Reason |
|------|--------|
| `/healthz` | Liveness probe for orchestrators; no session, no tenant data. |
| `/login` | Pre-session login form; resolves no tenant context (covered by `tests/web/test_auth_endpoints.py`). |
| `/setup` | First-run wizard, 404 once any user exists (covered by `tests/web/test_setup.py`). |
| `/static` | Packaged CSS/JS (`StaticFiles` mount); no session, no data. |
| `/language` | Sets the language cookie only; no session or tenant data. |

`test_exempt_routes_leak_nothing` still requests them as every role and checks for leaks.

## M1 acceptance

`tests/tenancy/test_acceptance_m1.py` holds the named M1 acceptance tests
(`test_user_from_tenant_a_cannot_read_tenant_b_data`,
`test_client_viewer_limited_to_assigned_domains`) and the session/switch checks.
