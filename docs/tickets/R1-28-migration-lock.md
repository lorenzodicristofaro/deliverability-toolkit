# R1-28 Migrations: no race between replicas that start together
Milestone: R1
Branch: feature/r1-28-migration-lock
Findings: INFRA-06 (low; confidence medium, not reproduced by the reviewer)
Files in scope: migrations/env.py (PostgreSQL advisory lock around the migration) OR Dockerfile CMD (migrate only for `ROLE` web/all) (coder picks and states), ARCHITECTURE.md:154-155 (a note: the GM edits ARCHITECTURE.md, so the coder proposes the wording in the summary instead of editing it), a PostgreSQL test (tests/migrations/ or tests/test_migrations_concurrency.py)
Out of scope: worker mode design (`ROLE` is not used by any code yet), SQLite behaviour, new migrations
Depends on: none
Parallel-safe: no with R1-25/R1-26/R1-29 if the Dockerfile route is chosen; yes with migrations/env.py only
Model: sonnet (small, local change; raise to opus if combined with the worker-mode design)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fail-safe change and report "not reproduced" with what was tried (the reviewer did not reproduce it). Test: on PostgreSQL, two `alembic upgrade head` runs from an empty database in two threads/processes both end at head without error. It needs local PostgreSQL (`dt-test-pg`, TEST_DATABASE_URL passed per command); if unavailable, say so and leave the test for CI.
- Fix: either take a PostgreSQL advisory lock around the migration in `migrations/env.py` (SQLite path unchanged), or migrate only when `ROLE` is `web`/`all` and document that one web container starts first.
- The test asserts both runs end at head and `alembic_version` has one row. No wall clock (use barriers/events).
- Proposed ARCHITECTURE.md wording given in the summary; do not edit ARCHITECTURE.md.
- ruff, mypy, relevant tests green (PostgreSQL params if local PG is up).
New i18n keys: none
Status: done (QA APPROVE round 2, merged 1ecb89c; branch cc04ea9; round 1 CHANGES REQUESTED: PG test not parametrised. Reproduced on local PG: base env.py fails 3/3 with UniqueViolation, fix passes 3/3)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `Dockerfile:50` (CMD), `migrations/env.py:19-29`, `ARCHITECTURE.md:154-155` (`ROLE=web|worker|all`, several workers on PostgreSQL).
- Problem: the image CMD always migrates before it starts uvicorn. ARCHITECTURE plans several containers on one PostgreSQL database. Two containers that start together both run the same DDL; `migrations/env.py` takes no lock, so one can fail on "relation already exists" or on the `alembic_version` update and then restart. No harm today, because `ROLE` is not used by any code yet and SQLite deployments have one container.
- Evidence: `migrations/env.py` opens a connection and calls `context.run_migrations()` directly. `grep -n -i "advisory\|lock" migrations/env.py app/core/db.py` returns nothing.
- Suggested fix: when worker mode is implemented, either take a PostgreSQL advisory lock around the migration in `migrations/env.py`, or migrate only when `ROLE` is `web`/`all`.
- Tests to add: a PostgreSQL test that runs two upgrades from an empty database in two threads and expects both to end at head.
- Confidence: medium (standard Alembic behaviour; not reproduced).
