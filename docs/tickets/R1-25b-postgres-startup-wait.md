# R1-25b Postgres profile: bounded database wait before migrations (CI infra red on 278bd34)
Milestone: R1 (follow-up of R1-25)
Branch: feature/r1-25b-postgres-startup-wait
Findings: dev CI infra run 43429085815 (278bd34): step "Compose up with postgres profile and wait for healthy" failed
after 1 s, `app-1 is unhealthy`; app log shows alembic's connection to postgres refused while postgres was still
starting, so the container exited. `docker compose up --wait` fails as soon as the app exits and does not wait for
`restart: unless-stopped`. 8ee174b passed by timing.
Files in scope: migrations/env.py (engine path, PostgreSQL only), tests/migrations/ (new or extended test),
docs/SETUP.md (section 8: replace "relies on restart" with the wait), .env.example / compose.yaml header only if they
describe the retry, ARCHITECTURE.md is edited by the GM (coder proposes wording)
Out of scope: .github/** (no workflow change), Dockerfile, the advisory lock semantics from R1-28, SQLite behaviour
Depends on: R1-25, R1-28 (done)
Parallel-safe: yes (nothing else in flight)
Model: opus (fix after a CI failure)
Acceptance criteria:
- Reproduce first: a unit test (no network, no real database) showing that today a first connection error on the
  PostgreSQL engine path aborts the migration at once; it fails on dev 4c2b68a.
- On PostgreSQL only, the engine path retries the first connection (before taking the R1-28 advisory lock) on
  connection-refused / server-starting errors (state exactly which exception classes and why), with bounded total
  time (named constant, about 60 s, backoff capped at a few seconds) and a clear operator log line per attempt
  (no secrets: never log the URL or password). After the bound, the original error propagates (non-zero exit).
- Authentication errors, unknown database and other non-transient errors are NOT retried (test rows).
- SQLite path and the injected-connection path (used by tests and the app) are unchanged.
- Tests are table-driven with a fake connect function; no wall clock (inject sleep/clock).
- docs/SETUP.md section 8 states the wait and its bound instead of relying on the restart loop.
- ruff, mypy, relevant tests green, including the R1-28 concurrency test on local PostgreSQL.
- Proof: the next dev CI infra run (postgres-profile smoke) is green; the GM checks it.
New i18n keys: none (operator log only)
Status: done (QA APPROVE, branch cc94255; 7/17 tests fail on base; Docker smoke 3/3 coder + 1/1 QA)
