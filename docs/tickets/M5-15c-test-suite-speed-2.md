# M5-15c Test suite speed: seed sync cost, parallel CI jobs, no full CI for docs-only pushes
Milestone: M5
Branch: feature/m5-15c-test-speed-2
Files in scope: tests/conftest.py and test fixtures that build the app, .github/workflows/ (ci.yml and one new workflow if needed), docs/TESTING.md
Out of scope: anything under app/, removing or skipping tests, changing what a test asserts.
Depends on: M5-15b
Parallel-safe: no
Model: opus
Context: QA measured on tests/api/test_domains.py that seed sync at every app lifespan (YAML parse plus about 24 DKIM inserts per test) is about 66% of the remaining setup time. Baseline after M5-15b: pytest 622 s (CI run 42590173500, 2 CPU runner); original baseline 948 s.
Acceptance criteria:
- Seed sync cost per test is removed or cut for tests that do not need it, by a test-side mechanism such as caching parsed seeds for the session or stubbing the sync in fixtures that need no global rows; the coder picks it. Tests that verify seed sync or depend on seeded global rows still exercise the real thing, and startup seed behaviour stays covered.
- CI runs the tests in parallel jobs: one on SQLite and non-DB tests without a PostgreSQL service, one with only the PostgreSQL params and the PostgreSQL service. Lint and type checks keep running and fail the workflow. The union of tests executed equals today's (the coder proves it by comparing test ids from `--collect-only` with the selection of each job, and accounts for any test that runs only when TEST_DATABASE_URL is set but has no postgresql param). Any `needs:` between jobs still holds. Each test job has a `timeout-minutes`.
- Docs-only pushes skip the test, build and integration jobs (ignore `docs/**` and root `*.md`), but secret scanning still runs on every push, because docs/WORKFLOW.md promises scanning on every commit and docs can contain secrets. Coder confirms no test reads a file under the ignored paths in a way that makes a docs-only change able to break the suite, or narrows the ignore list.
- docs/TESTING.md describes the CI job split and how to run the PostgreSQL params locally.
- Measured on dev CI after merge: duration of each test job, against the 622 s baseline; the longest test job should be at most 50% of the 948 s original baseline (474 s).
New i18n keys: none
Measured (run 42600956376 on 592cd46, all jobs green): test-sqlite pytest 128 s (20162 passed), test-postgres pytest 270 s (2791 passed), whole CI workflow 5 min 11 s; original baseline 948 s; the 474 s target is met.
Status: done
