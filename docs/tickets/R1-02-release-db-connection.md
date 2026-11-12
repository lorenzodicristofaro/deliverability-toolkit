# R1-02 Release the DB connection after authentication, before DNS work and body reads
Milestone: R1
Branch: feature/r1-02-release-db-connection
Findings: AUTH-01 (medium)
Files in scope: app/web/deps.py, app/core/db.py (only for explicit pool settings, optional), new tests/web/test_connection_release.py; the routes below ONLY if the central fix leaves a route holding a connection (see criteria): app/web/authentication.py, app/web/dns_tools.py, app/api/v1/dns_tools.py, app/web/message.py, app/api/v1/message.py
Out of scope: permission order, tenancy checks, `analyze_content` rule-loading transaction (TODO M5-15 QA, line 290: a different concern, the transaction is opened inside the service after the dependency), the sync-on-event-loop `db.rollback()` at app/api/v1/content.py:170 (TODO line 289, same concern as R1-13), moving DB calls to the threadpool (R1-13)
Depends on: none
Parallel-safe: no with R1-13 (depends on this) and with any ticket touching app/web/deps.py; yes with the others
Model: opus (authentication dependency)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- After `_build` has produced the `AuthSession` (plain values plus a detached `User`; `expire_on_commit=False` is already set), the dependency ends the transaction (`db.rollback()` or `db.close()`) before returning, so a route holds a connection only while it queries. Verify no caller relies on a lazy load of `auth.user` or of attributes of loaded objects after the release.
- Parametrized test over every route that awaits DNS or reads a large body (web Authentication tab `run_checks`; the eight DNS tool routes web + the four API DNS tool routes; web and API message analyzer): assert `engine.pool.checkedout() == 0` inside the awaited call (spy inside the awaited function, same method as the review's scratch test). Pool class is QueuePool (5 + 10 overflow, 30 s checkout timeout).
- If, after the central fix, a route still shows `checkedout() == 1` because the route itself queries before its await (domain lookup, repository read), add an explicit `db.rollback()` in that route only (as the checks API does) and keep the test green. No other change to those routes.
- Test that 20 concurrent slow DNS tool requests do not delay `/healthz` and a login (use a fake slow resolver and event/barrier counters, no wall-clock assertion).
- Existing 401/403/404 order and tenancy tests unchanged and green (tests/tenancy/test_matrix.py).
- Per-route `db.rollback()` calls that become redundant: keep as documentation or remove, state which in the summary.
- Tests table-driven, no network, no wall-clock assertions. ruff, mypy, relevant tests and the tenancy matrix green. Full suite only if deps.py changes behaviour for all routes (it does: run it).
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location:
  - cause: `app/web/deps.py:145-156` (`_resolve` commits, then `select(User)` and the membership queries begin a new transaction that nothing ends), `app/web/deps.py:82-88` (`get_db` closes only after the response), `app/core/db.py:34` (default QueuePool: 5 + 10 overflow, 30 s checkout timeout)
  - routes that then await slow work without releasing: `app/web/authentication.py:57-64` (`run_checks`), `app/web/dns_tools.py:151-178`, `:182-212`, `:274-316`, `:351-380` (`read_form`, then `lookup`/`reverse`/`trace`/`check_propagation` under a 20 s deadline), `app/api/v1/dns_tools.py:558-651` (four routes, same deadline), `app/web/message.py:131-150` and `app/api/v1/message.py:87-103` (body read up to several MiB, then analysis in a worker thread)
- Problem: after authentication the request's `Session` holds an open transaction, so a pooled connection, until the response is finished. The checks API, the ESP tab, the content analyzer and the rules test route end it explicitly ("no pooled connection is held during DNS") but the Authentication tab, all eight DNS tool routes and both message analyzer routes do not. Fifteen concurrent slow requests (slow DNS, or an authenticated client sending its body slowly) use every connection; every other request then blocks in a worker thread for 30 s in `_resolve` and fails with a 500. Blocked threads also fill the shared threadpool, which `/healthz` uses too.
- Evidence (scratch test, SQLite, project fixtures, spy inside the awaited call): `GET /domains/{id}/authentication` -> `engine.pool.checkedout() == 1` while `run_checks` runs; `POST /tools/dns/lookup` -> `checkedout() == 1` while `lookup` runs; pool class QueuePool. Scenario: an analyst opens 15 traces against a name whose servers do not answer (20 s each) -> login and every page of every tenant hang, then 500.
- Suggested fix: fix it once in the dependency layer: after `_build` has produced the `AuthSession`, end the transaction before the dependency returns. Check no caller relies on lazy load of `auth.user`. Then drop the per-route `db.rollback()` calls that become redundant, or keep them as documentation. Files: `app/web/deps.py`, possibly `app/core/db.py` (explicit pool settings), the routes only if the central fix is rejected.
- Tests to add: the parametrized `checkedout() == 0` test above; the concurrency test above.
- Confidence: high (held connection confirmed by execution; exhaustion scenario by reasoning from pool defaults, not load-tested).
- Already tracked: partly. TODO has the narrow item on `db.rollback()` at app/api/v1/content.py:170 (line 289) and the `analyze_content` connection item (line 290); both left to their own tickets. The missing release on the routes above is not tracked.
