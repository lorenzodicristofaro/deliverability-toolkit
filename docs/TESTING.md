# Testing

Commands are in `CLAUDE.md`. DB tests run on SQLite and, when `TEST_DATABASE_URL` is set, on
PostgreSQL. In `tests/conftest.py`, `migrated_db_url` gives each test an empty migrated schema
(SQLite copies a migrated session template; PostgreSQL TRUNCATEs the project tables per test).
`db_url` stays truly empty and is for tests that run real migrations through
`real_migrations_engine`. The tenancy suite keeps its own module-scoped `world` fixture in
`tests/tenancy/conftest.py` with the same two parameters.

## CI jobs and PostgreSQL

Workflow `.github/workflows/ci.yml` runs lint and type checks in `lint` and splits the tests into
two jobs on separate runners, selected by the `--db-backend` option (`tests/conftest.py`):

| Job | Command | Runs | Database |
|-----|---------|------|----------|
| `test-sqlite` | `uv run pytest --db-backend=sqlite` | every test except the PostgreSQL params: non-DB tests and the SQLite params | none |
| `test-postgres` | `uv run pytest --db-backend=postgresql` | only the PostgreSQL params | `postgres:17` service |

A test is a PostgreSQL param if it carries the skip marker with `PG_SKIP_REASON`, that is, exactly
the tests that would be skipped without PostgreSQL. The two sides are disjoint and together are the
whole collection. `--db-backend=postgresql` without `TEST_DATABASE_URL` is a usage error, so the job
cannot skip every test and pass. Without the option, pytest runs both sides as before.

Run the PostgreSQL params locally against a throwaway database:

```
TEST_DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/ci_test uv run pytest -q --tb=short
```

Add `--db-backend=postgresql` for that side only. `TEST_DATABASE_URL` must point to a database
with "test" in its name and different from `DATABASE_URL`: the suite drops its tables, and pytest
refuses to start otherwise. Only one suite may use that database at a time, so do not run two
PostgreSQL runs in parallel against it.

Changes that touch only root `*.md` files or the docs listed under `paths-ignore` in `ci.yml` skip
that workflow entirely. A skipped workflow reports no result: a required check on it stays Pending
and blocks the pull request. `docs/TESTING.md` is not ignored because
`test_exemptions_are_documented` reads it. Secret scanning is in `secret-scan.yml`, which has no path
filter and runs on docs-only changes too.

## Seed sync at app startup

`app.main` runs the real seed sync at every app start. The modules in `SEEDLESS_MODULES`
(`tests/conftest.py`) start the app very often and never use the global knowledge tables, so their
startup skips it. The `seed_table_access` fixture fails any test in those modules that reads or
writes `content_rules` or `dkim_selectors`; such a module must be removed from the set. Everything
else, including seed sync, content rule, DKIM, check and acceptance tests, keeps the real sync.

## Tenancy matrix (M1-20)

`tests/tenancy/test_matrix.py` is generated from the FastAPI route table: every leaf route
(method x path) of `app.main.create_app()` must be a `MATRIX` entry or an `EXEMPT` path, or
`test_every_route_is_in_the_matrix_or_exempt` fails. Routes are enumerated with
`fastapi.routing.iter_route_contexts` (FastAPI 0.162 wraps included routers, so `app.routes`
does not list leaf routes); the enumeration is self-tested against a nested synthetic app and
against every `APIRouter` declared in `app.web` / `app.api`.

`iter_route_contexts` is an undocumented FastAPI internal. `pyproject.toml` therefore pins
`fastapi>=0.162.0,<0.163`. When FastAPI is bumped, re-verify the enumeration (read
`fastapi/routing.py` of the new version and run `uv run pytest tests/tenancy -k enumeration`)
before widening the pin.

The world is module scoped. Before every test the `world` fixture compares both tenants with
the seeded baseline and fails loudly (`WorldMutated`) when they differ, so a case that changed
the data cannot make later cases pass vacuously; the earlier test is then the suspect. Tests that
create data on purpose (the successful UI "smuggle" create) delete it before they end.
`test_mutated_world_is_detected` self-tests the guard.

### Adding an endpoint

1. Add `(METHOD, "/full/path/{param}"): Entry(Kind.<KIND>, ...)` to `MATRIX`.
   - `DOMAIN`: addresses one domain by `{domain_id}`; every role gets 404 for a tenant B domain,
     for a session whose active tenant is B, and (client viewer) for an unassigned domain.
   - `COLLECTION`: list/create in the active tenant; give the expected status per role for the
     own-tenant request (`own=` for GET, `smuggle=` for writes that also try to pass a tenant B id).
   - `LANDING`, `SESSION`, `SWITCH`: see the module docstring.
   - `DNS`: tenant-level `dns.tools` routes (M2-12); anonymous 401, a session whose active tenant
     is B 404, and per-role `own=` statuses (client viewer 403). The tenancy world overrides the
     `dns_backend` dependency with fixtures, so no request touches the network.
   - Pass `body=` for writes. A new resource type (not a domain) needs a new `Kind` with its
     cross-tenant target and an explicit expectation in `_expected`.
2. Every matrix route must depend on `app.web.deps.current_session`
   (`test_matrix_routes_require_a_session_and_exempt_ones_no_tenant`).
3. Every case also checks that responses and captured logs never contain tenant B strings
   (tenant name, slug, domain names in A-label and U-label form, user emails), and that neither
   tenant's data changed.

Never "fix" a failing case by changing the expectation to what the code does. If the matrix finds
an isolation bug, add the case to the entry's `xfail` mapping, keyed by `(role, target)` with the
reason and the ticket id, e.g.
`Entry(Kind.DOMAIN, xfail={("viewer", "unassigned"): "M2-xx: viewer reads unassigned domain"})`.
The generated case is then marked `xfail(strict=True)`: it fails again (XPASS) once the bug is
fixed, and the mapping entry must be removed in the fixing ticket.

### Exemptions

Exemptions are by (method, path): a new verb on an exempt path (e.g. `DELETE /login`) is not
exempt and fails the guard (`test_exemption_is_per_method`). They must stay minimal. Each needs a
reason here and in `EXEMPT`; exempt routes may not depend on `current_session` or `tenant_ctx`.
`*` is the method of a mount.

| Route | Reason | Requested by `test_exempt_routes_leak_nothing` |
|-------|--------|-----------------------------------------------|
| `GET /healthz` | Liveness probe for orchestrators; no session, no tenant data. | yes (200) |
| `HEAD /healthz` | Same. | yes (200) |
| `GET /login` | Pre-session login form; resolves no tenant context. | yes (200) |
| `POST /login` | Login; covered by `tests/web/test_auth_endpoints.py`. | no |
| `GET /setup` | First-run wizard, 404 once any user exists. | yes (404) |
| `POST /setup` | Setup submit; covered by `tests/web/test_setup.py`. | no |
| `* /static` | Packaged CSS/JS (`StaticFiles` mount); no session, no data. | yes (`GET /static/app.css`, 200) |
| `POST /language` | Sets the language cookie only; no session or tenant data. | yes (303) |

The requested routes are sent as anonymous and as every role, and the responses and logs are
checked for tenant B strings.

## M1 acceptance

`tests/tenancy/test_acceptance_m1.py` holds the named M1 acceptance tests
(`test_user_from_tenant_a_cannot_read_tenant_b_data`,
`test_client_viewer_limited_to_assigned_domains`) and the session/switch checks.
