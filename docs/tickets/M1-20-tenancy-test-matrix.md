# M1-20 Tenancy test matrix and M1 acceptance tests
Milestone: M1
Branch: feature/m1-20-tenancy-matrix
Files in scope: tests/tenancy/conftest.py, tests/tenancy/test_matrix.py, tests/tenancy/test_acceptance_m1.py, docs/TESTING.md (short section on how new endpoints join the matrix)
Out of scope: production code changes (findings are reported to GM as new tickets, not fixed here), PostgreSQL RLS, Playwright
Depends on: M1-17, M1-18, M1-19
Parallel-safe: no (runs against all of the above; conftest shared)
Model: opus
Acceptance criteria:
- Fixtures: two tenants, users per role (owner, admin, analyst, client viewer with assigned and unassigned domains), instance admin, anonymous; seeded through repositories/services, not raw SQL.
- Matrix is generated from the FastAPI route table: a test fails if a non-public route (everything except /healthz, /login, /setup, static) is not covered by a matrix entry or an explicit documented exemption. This is the guard that makes "every endpoint needs a tenancy test" automatic for later milestones.
- Matrix asserts: cross-tenant resource returns 404 for every role and every verb (UI and API); anonymous gets 401/redirect; client viewer never receives unassigned domains in list responses, HTML or JSON; session of user A never resolves tenant B context; switching to a non-member tenant fails.
- M1 acceptance (TODO): "user from tenant A cannot read tenant B data" and "client viewer limited to assigned domains" each have a named test.
- Leak checks: error bodies and logs for a cross-tenant request do not contain tenant B names.
- Runs on SQLite and, when TEST_DATABASE_URL is set, PostgreSQL (CI from M1-07).
New i18n keys: none
Status: todo
