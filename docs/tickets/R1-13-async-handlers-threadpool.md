# R1-13 Synchronous DB calls on the event loop in async web handlers
Milestone: R1
Branch: feature/r1-13-async-handlers-threadpool
Findings: AUTH-08 (low)
Files in scope: app/web/domain_esps.py, app/web/custom_checks.py, app/web/rules.py, app/web/dkim_selectors.py, app/web/authentication.py, a new AST guard test (tests/web/test_async_handlers_guard.py or under tests/core; coder states which), per-route tests only as needed
Out of scope: changing permission order (401/403/404), service/repository logic, the central connection release (R1-02), `db.rollback()` at app/api/v1/content.py:170 (TODO.md:289, same concern: may be folded here ONLY if the coder confirms it is the same one-line change; otherwise leave)
Depends on: R1-02 (central connection release first, to avoid touching the same routes twice)
Parallel-safe: no with R1-02 and R1-12 (shared route files); serialize after R1-02
Model: sonnet (mechanical restructuring; permission order must not change; QA compares the 401/403/404 order before and after)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected: the AST guard or a session whose `execute`/`commit` asserts it is not on the event-loop thread.)
- Handlers split as the checks API does (`app/api/v1/checks.py:252-254`, `app/web/auth.py:164`): async part for the body read and DNS, sync helper for the DB work through `run_in_threadpool`; or make the handler sync when it awaits nothing but the body and read the body in a dependency.
- Listed call sites covered: `app/web/domain_esps.py:149-211` (`_page`: `service.list_for_domain`, `web.service.get`, `service.catalogue`, `resolve_esp_run`), `:227-274` (`service.check_write`, `service.assign` with commit), `:277-299` (`service.remove`); `app/web/authentication.py:57`; `app/web/custom_checks.py:585,588,742,766` and the `_form_page`/`_list_page` reads; `app/web/rules.py:554,556,633,653`; `app/web/dkim_selectors.py:434,436,513,535`.
- Guard test: fails when an `async def` route calls a known service or repository method outside `run_in_threadpool` (an AST check is enough); allow-list explicit and commented.
- 401/403/404 order unchanged: existing tenancy matrix and route tests green; add no behaviour change.
- No network, no wall clock. ruff, mypy, relevant tests and tests/tenancy/test_matrix.py green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: as listed in the criteria.
- Problem: these handlers are `async def` (they await a body read or a DNS call) and call the synchronous SQLAlchemy session directly, so queries and commits run on the event loop. On SQLite the calls are short; on PostgreSQL, or SQLite waiting for a write lock (up to the 5 s driver timeout), one stalled statement freezes every request and every SSE stream of the process. Other async routes already use `run_in_threadpool` for the same work.
- Evidence: `esps_attach` is `async def` and calls `service.assign(...)` (insert, flush, commit) at `app/web/domain_esps.py:265` with no thread hop; `checks_delete` calls `service.delete` at `app/web/custom_checks.py:766` the same way.
- Suggested fix: as in the criteria.
- Tests to add: guard test (AST) or per-route tests with a session whose `execute` asserts it is not on the loop thread.
- Confidence: high for the pattern; low for real-world impact on the default SQLite deployment.
- Related TODO: line 289 (content API rollback on the loop).
