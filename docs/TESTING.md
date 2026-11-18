# Testing

Commands are in `CLAUDE.md`. DB tests run on SQLite and, when `TEST_DATABASE_URL` is set, on
PostgreSQL. In `tests/conftest.py`, `migrated_db_url` gives each test an empty migrated schema
(SQLite copies a migrated session template; PostgreSQL TRUNCATEs the project tables per test).
`db_url` stays truly empty and is for tests that run real migrations through
`real_migrations_engine`. The tenancy suite keeps its own module-scoped `world` fixture in
`tests/tenancy/conftest.py` with the same two parameters.

## CI jobs and PostgreSQL

Workflow `.github/workflows/ci.yml` runs lint and type checks in `lint` and splits the tests into
two checks, selected by the `--db-backend` option (`tests/conftest.py`). Each check runs as a
matrix of shards on separate runners (see "Shards" below):

| Check | Shard command | Runs | Database |
|-------|---------------|------|----------|
| `test-sqlite` | `uv run pytest -n auto --db-backend=sqlite --shard=K/4 -m "$PYTEST_MARKERS"` | every test except the PostgreSQL params: non-DB tests and the SQLite params | none |
| `test-postgres` | `uv run pytest -n auto --db-backend=postgresql --shard=K/6 -m "$PYTEST_MARKERS"` | only the PostgreSQL params | `postgres:17` service per shard |

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
PostgreSQL runs in parallel against it (an xdist run counts as one suite: its workers use separate
databases).

Changes that touch only root `*.md` files or the docs listed under `paths-ignore` in `ci.yml` skip
that workflow entirely. A skipped workflow reports no result: a required check on it stays Pending
and blocks the pull request. `docs/TESTING.md` is not ignored because
`test_exemptions_are_documented` reads it. Secret scanning is in `secret-scan.yml`, which has no path
filter and runs on docs-only changes too.

`.github/workflows/codeql.yml` runs CodeQL (advanced setup) for `python`, `javascript-typescript` and
`actions` on pushes to `main`, pull requests to `main` and weekly (Mondays 04:23 UTC). It is not a
required check. `.github/codeql/codeql-config.yml` sets `paths-ignore: tests` because `tests/` holds
intentional ReDoS fixtures and HTML/URL assertions that CodeQL reports as high alerts, and the default
setup cannot exclude paths. The maintainer must switch CodeQL from Default to Advanced setup in the
repository settings, otherwise the upload is rejected.

## Parallel runs (pytest-xdist, M7-00)

Every test shard runs with `-n auto`: pytest-xdist starts one worker process per CPU available to the
job (without psutil, `auto` is the CPU count the process may use, the same number `nproc` prints in
the job log). Plain `uv run pytest` without `-n` still runs in a single process, unchanged.

- SQLite: every worker has its own `tmp_path` base directory, so the migrated template and the
  per-test database copies are per worker; migrations run once per worker.
- PostgreSQL: `pytest_sessionstart` in `tests/conftest.py` gives each worker its own database on
  the same server, `<name>_gwN` (for example `ci_test_gw0`), created on first use and left empty
  at the end. It vets `TEST_DATABASE_URL` first (`refusal_reason`), derives the worker name from
  `PYTEST_XDIST_WORKER` (only `gw` plus digits is accepted), and rewrites `TEST_DATABASE_URL` for
  that worker process only, so every fixture, the tenancy world and spawned migration processes
  use the worker database. Without xdist the database named in `TEST_DATABASE_URL` is used. The
  role in `TEST_DATABASE_URL` needs the CREATEDB privilege (the CI service user and the
  `postgres` image's default user have it).
- Workers share no database, file or schema; the per-test isolation inside a worker is the same as
  in a single-process run.

pytest-xdist requires every worker to collect the same test ids, so parameter ids must not depend
on the process (no tokens or object addresses in ids; give such parameters `ids=`). A test with
process-dependent ids makes the run fail with "Different tests were collected", never skip
silently. Since M7-00b the whole tree runs under xdist, `tests/core/test_csrf.py` and
`tests/core/test_security.py` included.

Use `-n 4` (or any number) to pick the worker count; `-n 0` disables xdist.

## Shards (M7-00b)

`--shard=K/N` (`tests/conftest.py`, `tests/support/sharding.py`) collects only the test files of
shard K of N; the other files are not even imported. Whole files are assigned, so module-scoped
fixtures (the tenancy `world`) are never duplicated across shards. The split is deterministic: the
files are dealt out heaviest first to the least loaded shard, by the measured seconds per file in
`tests/support/shard_weights.json` for the selected `--db-backend` (a file never measured counts
as 1 s, a file measured only on the other backend as 0). The shards of one N are disjoint and
together are exactly the unsharded selection; `tests/support/test_sharding.py` checks this for
the real tree and that the `ci.yml` matrices list every shard 1..N with the same N.

In CI, `test-sqlite` runs 4 shards and `test-postgres` 6 (jobs `test-sqlite-shard` and
`test-postgres-shard`, each shard `-n auto` on its own runner, the PostgreSQL ones with their own
service). The jobs named `test-sqlite` and `test-postgres` keep the required check names: they
need all their shards, run even when a shard failed (`if: always()`), and fail unless every shard
succeeded. Shards run with `fail-fast: false`, so every failing shard reports.

The weights only affect balance, never which tests run. Refresh them after large test changes:
run each side unsharded with `--durations=0 --durations-min=0` (or every shard and concatenate the
outputs) and pass the two outputs to `uv run python -m tests.support.sharding SQLITE_LOG PG_LOG`.

## The `slow` marker (M7-00b)

`slow` marks the redundant rows of the regex timing (ReDoS) tests: per guarded entry point one
timing test keeps running everywhere, the other rows of the same test carry
`pytest.mark.slow`. CI deselects them on `dev` pushes and pull requests
(`PYTEST_MARKERS=not integration and not slow` in `ci.yml`) and runs them on `main` pushes and in
the weekly scheduled run (Tuesdays 03:41 UTC, `not integration`). A plain local `uv run pytest`
runs them (the default `addopts` excludes only `integration`).

Timing tests that stay on every run (they keep "regex timeout enforced by test" true on dev):
`tests/core/test_safe_regex.py::test_catastrophic_pattern_is_cut_off[(a+)+$-...]`,
`test_process_stays_responsive_after_timeout`, `test_batch_with_catastrophic_rule_in_the_middle`
and the other cut-off tests there; `tests/services/test_content_rules_engine.py`
(`..._real_worker`); `tests/parsers/test_content_html.py` (`space_run_both_sides` rows of both
linearity tests, `test_charset_search_linear_on_whitespace_runs`);
`tests/parsers/test_content_subject.py` (`space_run_around_counter`); `tests/parsers/test_spf.py`
(`test_adversarial_inputs_are_fast`); `tests/parsers/test_received.py` (`test_scanners_linear`,
`test_public_api_bounded_time`); `tests/parsers/test_authres.py`
(`test_10k_resinfo_is_linear`). List the slow rows with `uv run pytest --collect-only -q -m slow`.

## Running everything locally

The CI-equivalent run of one side, unsharded (shards only split the same selection):

```
uv run pytest -q --tb=short -n auto --db-backend=sqlite -m "not integration and not slow"
TEST_DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/ci_test uv run pytest -q --tb=short -n auto --db-backend=postgresql -m "not integration and not slow"
```

One CI shard: add `--shard=2/4` (SQLite) or `--shard=5/6` (PostgreSQL). Everything, as on `main`:
`uv run pytest -q --tb=short -n auto` (with `TEST_DATABASE_URL` set for the PostgreSQL params);
only the slow rows: `uv run pytest -q -m slow`. One PostgreSQL run at a time against the same
server (the worker databases are `ci_test_gw0`, `ci_test_gw1`, ...).

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
