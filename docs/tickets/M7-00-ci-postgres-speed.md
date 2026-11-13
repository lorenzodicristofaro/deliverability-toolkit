# M7-00 CI test speed 3: pytest-xdist for the PostgreSQL and SQLite test jobs
Milestone: M7
Branch: feature/m7-00-ci-test-speed-3
Files in scope: tests/conftest.py, tests/support/** (if needed), pyproject.toml, uv.lock, docs/TESTING.md, .github/workflows/ci.yml
Out of scope: anything under app/, removing, skipping, de-parametrising or marking flaky any test, changing what a test asserts.
Depends on: none (GM serializes it after M7-01)
Parallel-safe: no (shared fixtures, CI workflow)
Model: opus
Approval: maintainer, 2026-11-13, on condition that test quality does not decrease.
Context: test-postgres grew from 5.1 min (run 42600956376, 592cd46, after M5-15c) to about 13 min (run 43486040307, dcca37e); test-sqlite from 2.4 to 11.4 min. The split by `--db-backend` (tests/conftest.py, ci.yml) is intact; the growth comes from more tests (PostgreSQL params about 2791 -> about 5900). The job already prints `nproc` and `--durations=25`. M5-15d (tmpfs) gave no gain. Measurement method: see docs/tickets/M5-15c-test-suite-speed-2.md.
Steps:
1. Measure locally on PostgreSQL (container dt-test-pg, TEST_DATABASE_URL passed per command, one suite at a time) and on SQLite: top durations and setup vs call split (`--durations`, `--setup-show` or `-rA` timing as needed). Write the numbers in the "Measured" section below.
2. Apply pytest-xdist to both test jobs: one database per worker (per-worker PostgreSQL database or schema, per-worker SQLite paths), migrate once per worker. If xdist is not viable, shard the PostgreSQL job with a CI matrix instead. Write decision and reason here and in docs/TESTING.md.
Acceptance criteria:
- The set of test ids executed in CI is identical before and after, per job: the coder proves it by comparing `--collect-only -q` outputs (sorted) for the SQLite job and the PostgreSQL job before and after (for a matrix, the union of shards equals the before set, no overlap). Proof recorded in the ticket.
- No test removed, skipped, de-parametrised or marked flaky.
- Tests stay isolated: no shared mutable DB state between workers. All green with `-p no:randomly`, and with random order if a random-order plugin exists; otherwise two full runs with different worker counts, all green. Results recorded.
- Local runs work without xdist options too (single process still supported); docs/TESTING.md describes worker count, per-worker databases, and how to run PostgreSQL params locally.
- Lint and type checks unchanged; each test job keeps `timeout-minutes`; existing `needs:` still hold; secret scanning and docs-only skip rules from M5-15c unchanged.
- Target: each test job at most 50% of its current duration (PostgreSQL about 13 min -> at most about 6.5 min; SQLite about 11.4 min -> at most about 5.7 min), measured on dev CI after merge. Numbers (run ids, durations, nproc) written in the ticket. If the target is missed, report to the GM with the measured split rather than weakening any test.
New i18n keys: none
Notes: changes under .github/workflows/ are pushed by the maintainer (the GM token has no Workflows permission); the GM flags this merge for the maintainer. The runner CPU count is read from the job's `nproc` output; do not assume more than the measured value.
Measured: (to be filled by the coder)
Status: todo
