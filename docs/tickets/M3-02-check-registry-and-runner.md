# M3-02 Check registry and runner service
Milestone: M3
Branch: feature/m3-02-check-registry-runner
Files in scope: app/checks/registry.py, app/services/checks.py, tests/checks/test_registry.py, tests/services/test_checks_service.py
Out of scope: concrete checks, routes, CLI, persistence
Depends on: M3-01
Parallel-safe: yes (new files only)
Model: sonnet
Acceptance criteria:
- `register(check)` / `get(check_id)` / `all_ids()`; duplicate ids raise; registration happens by explicit import list in `app/checks/registry.py` (`load_builtin_checks()`), not import side effects, so tests can use an empty registry.
- `app/services/checks.py` is THE entry point for UI, API and CLI: `run_check(check_id, name, ctx) -> CheckResult` and `run_checks(ids, name, ctx) -> list[CheckResult]` (concurrent, bounded, per-check deadline).
- A check that raises, or exceeds its deadline, yields `CheckResult(status="error")` with a generic `CHECK_INTERNAL_ERROR` / `CHECK_TIMEOUT` finding; exceptions never escape and are logged without echoing raw input.
- Unknown check id -> typed error (mapped to 404/422 by callers); invalid domain name -> `InvalidTarget` using `app/core/domain_names` / the M2-01 record-name validator (underscore-safe).
- Duration and started_at filled by the runner from the context clock; tests use a fake clock and the M2-04 fake resolver; no network.
- CheckResult.build() is the documented sole factory; the runner wraps any check exception or timeout into status `error` (never `ok`). The runner does NOT wrap the resolver (GM decision 2026-11-06): each check converts DNS failures to `error` itself via CheckResult.build(evaluated=False). Tests here: a check that raises, and one that exceeds its deadline, yield `error`. (From M3-01 QA: CheckResult has no `evaluated` field, so a direct constructor can produce `ok`.)
- SATISFIED BY DELEGATION (GM decision 2026-11-06): "a check whose DNS lookup returns SERVFAIL/timeout yields error" is covered by the per-check tickets (M3-08, M3-10, M3-11, M3-13) and M3-19; QA must not fail M3-02 on it.
- Tests: ordering of results is by requested ids, timeout, exception, unknown id, bad name table.
New i18n keys: finding.CHECK_INTERNAL_ERROR.*, finding.CHECK_TIMEOUT.* (en + it; locale files are touched here, so merge before other locale-touching M3 tickets)
Status: done
