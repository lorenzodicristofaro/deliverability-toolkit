# M1-07 CI: run pytest on PostgreSQL as well as SQLite
Milestone: M1
Branch: feature/m1-07-ci-pytest-postgres
Files in scope: .github/workflows/ci.yml, tests/conftest.py (DB fixture parametrization only), docs/CONTRIBUTING-tests note if one exists (else none)
Out of scope: unbound jobs (M1-08), release workflows, secrets
Depends on: M1-06
Parallel-safe: no (ci.yml, tests/conftest.py shared with M1-06)
Model: sonnet
Acceptance criteria:
- M0-05 follow-up: lint-test job (or a new `test-postgres` job) runs `uv run pytest -q --tb=short` against a `postgres:17` service container (same tag as compose.yaml) with `TEST_DATABASE_URL` set; the SQLite run stays. Credentials are throwaway literals for the ephemeral service, no `secrets.*`.
- Remove the `TODO(M1)` comment in ci.yml.
- DB tests use one fixture that yields a clean schema (migrated via Alembic) per backend; no test depends on backend-specific behaviour unless marked.
- Locally: `docker compose --profile postgres` or a throwaway container runs the suite green on PostgreSQL; coder reports it. The GitHub run itself is unverified until the GM pushes `dev`.
- Third-party actions stay SHA-pinned; none added unless required (service containers need no action).
New i18n keys: none
Status: todo
