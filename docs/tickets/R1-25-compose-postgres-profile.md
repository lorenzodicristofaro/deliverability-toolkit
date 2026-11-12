# R1-25 The postgres compose profile: document the DATABASE_URL, startup retry, CI smoke
Milestone: R1
Branch: feature/r1-25-compose-postgres-profile
Findings: INFRA-03 (low)
Files in scope: compose.yaml, .env.example, .github/workflows/ci-infra.yml, tests/test_compose_config.py, install docs (docs/SETUP.md; coder states which), optionally an entrypoint wait loop (Dockerfile CMD or a small script)
Out of scope: forwarding of other settings (R1-04), container hardening (R1-29), image pinning (R1-26), migration lock (R1-28), changing the default database
Depends on: R1-04 (same `environment:` block and parity test)
Parallel-safe: no with R1-04, R1-26, R1-27, R1-29 (compose.yaml, Dockerfile, ci-infra.yml shared): serialize
Model: sonnet (configuration, docs and a CI step)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected: a static test in tests/test_compose_config.py that the documented example URL exists in `.env.example`/compose header and uses service name `postgres` and the compose default user and database.)
- `.env.example` and the compose header document the PostgreSQL URL form (`postgresql://deliverability:<password>@postgres:5432/deliverability`, matching the compose defaults actually in the file; verify, do not invent), including that special characters in the password must be percent-encoded.
- Startup ordering: compose cannot make `depends_on` conditional on a profile, so either document the retry behaviour (`restart: unless-stopped`) or add a short wait loop when `DATABASE_URL` is PostgreSQL; the coder picks one and states it.
- `docker-build` in `.github/workflows/ci-infra.yml` gets a second smoke step: `--profile postgres` with throwaway credentials, `--wait`, then `/healthz`; action pins and permissions unchanged (`contents: read`). The Docker jobs cannot be run locally: state that the first real proof is the dev CI run.
- Static test passes; existing compose tests green. ruff, mypy, relevant tests green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `compose.yaml:10-37` (app: no `depends_on`), `compose.yaml:39-58` (postgres), `.env.example:7-8,35-36`, `.github/workflows/ci-infra.yml:105-124` (smoke: default profile only), `.github/workflows/ci.yml:82-109` (PostgreSQL tests use a service container, not the image).
- Problem: `docker compose --profile postgres up` starts PostgreSQL, but the app keeps `sqlite:////data/app.db` unless the operator writes a `DATABASE_URL` by hand; no file shows the URL to use. The app does not wait for the database: the container CMD runs `alembic upgrade head` at once, fails while PostgreSQL initialises, and relies on `restart: unless-stopped`. No CI job starts the image against PostgreSQL, so this path is unverified end to end. An operator can believe the data is in PostgreSQL while it is in the SQLite volume.
- Evidence: `grep -n depends_on compose.yaml` returns nothing. `.env.example:7-8` documents only the SQLite URL. Scenario: `.env` has `POSTGRES_PASSWORD=x`, operator runs `docker compose --profile postgres up -d` -> both containers healthy, the app writes to `/data/app.db`, the `postgres-data` volume stays empty.
- Suggested fix: as in the criteria.
- Tests to add: the CI smoke step; a static test in `tests/test_compose_config.py` that the documented example URL uses the service name `postgres` and the default user and database of the compose file.
- Confidence: high for the missing wiring; medium for the first-start failure loop (read from the CMD, not run).
