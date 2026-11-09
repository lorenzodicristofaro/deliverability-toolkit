# M5-15b Test DB fixtures: migrate once per session, restore per test
Milestone: M5
Branch: feature/m5-15b-test-db-speed
Files in scope: tests/conftest.py, test fixtures that call Alembic upgrade or create_all in tests/ (36 call sites in 26 files; the coder lists the ones changed), pyproject.toml and uv.lock only if a test-only dependency is justified, .github/workflows/ci.yml (only to print durations or enable parallelism)
Out of scope: anything under app/, any change to what a test asserts, removing or skipping tests, running a test on only one database when it runs on both today, docs/WORKFLOW.md.
Depends on: M5-15
Parallel-safe: no (touches shared fixtures across tests/)
Model: opus
Context (measured 2026-11-09, CI run 42537182500): pytest took 948 s for 22650 tests. Fitting the log timestamps gives about 0.18 s per PostgreSQL test (494 s for 2688), 0.15 s per SQLite test (401 s for 2675), 0.002 s per non-DB test (39 s for 17289). Most DB time is in tests/api (297 s), tests/web (276 s), tests/repositories (153 s). Locally, in tests/api/test_domains.py, setup is about 70% of per-test time. `db_url` in tests/conftest.py runs `drop_all` before and after every PostgreSQL test and fixtures run `alembic upgrade head` per test.
Acceptance criteria:
- Alembic migrations run once per test session per database backend for tests that need only a migrated, empty schema. Each test still starts from an empty migrated schema on both SQLite and PostgreSQL: SQLite by copying a migrated template file, PostgreSQL by a per-test data reset (for example TRUNCATE of all project tables with sequences restarted) or an equally isolated mechanism; the coder picks and justifies it.
- Tests that exercise migrations themselves (tests/test_db.py, tests/models/test_models.py and any like them) still run real upgrade/downgrade from a truly empty database, and cannot leave the shared schema altered for later tests.
- Test isolation is proven by a test: a row, or a sequence value, written by one test is not visible to the next on each backend.
- Any seed data or state created by migrations is restored per test, or the coder shows there is none.
- The TEST_DATABASE_URL refusal safety check in pytest_sessionstart still guards every destructive reset, including any new one.
- Collected test count does not decrease (compare `pytest --collect-only -q` with dev), and every test parametrized on sqlite and postgresql today still is. SPEC section 7 (both databases tested in CI) stays satisfied.
- The local suite is measured before and after, with times reported in the coder's summary. The PostgreSQL path cannot run locally (no server), so the code must be reviewed for it and CI on dev is its first real run.
- Target: the CI pytest step at least 50% faster than the 948 s baseline, measured on the dev CI run after merge. pytest-xdist is optional and only if it is safe with the chosen isolation and worth it on the CI runner's actual CPU count.
New i18n keys: none
Status: todo
