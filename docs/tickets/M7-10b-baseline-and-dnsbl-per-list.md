# M7-10b Baseline lookup beyond 50 runs, DNSBL judged per list
Milestone: M7
Branch: feature/m7-10b-baseline-dnsbl
Files in scope: app/services/monitor_run.py, app/services/change_detect.py, app/repositories/check_runs.py, app/api/v1/checks.py (helper extraction only), a shared registry-preparation helper module under app/services/, tests/services/test_monitor_run.py, tests/services/test_change_detect.py, tests/repositories/test_check_runs.py, relevant API check tests
Out of scope: alert delivery and dedup (M7-14), UI, new checks, new i18n keys
Depends on: M7-10
Parallel-safe: no (monitor_run / change_detect, shared with M7-14 consumers)
Model: opus
Acceptance criteria:
- (a, should-fix) monitor_run.py ~363-372 looks for the last non-error run only within the newest 50 runs per check (HISTORY_LIMIT). After >=50 consecutive error runs the baseline is None, recovery emits only check_error_cleared and that run becomes the baseline, so a listing that appeared during a long outage never yields new_listing. Add a tenant-scoped repository query for the latest non-error run per check in app/repositories/check_runs.py (with tests, including tenant isolation) and use it in the executor. Check whether the DNS snapshot baseline has the same 50-limit issue and fix it the same way if so. Test: >=50 error runs between the baseline and the new run still yields new_listing.
- (b, GM decision) Judge DNSBL listings per list. Today one erroring list makes the whole dnsbl run `error`, so a permanently failing list blocks listing alerts for all lists. Use the per-list evaluated data: emit new_listing / listing_cleared for lists evaluated in both the new run and the per-list baseline (last run where that list was evaluated). A list in error yields only error events for that list, never a false cleared. The check's overall status stays as it is (error remains error). Table-driven tests: one list errors while another changes; list errors then recovers; list never evaluated in baseline; all lists evaluated.
- (c, nit) new_listing is currently suppressed when baseline findings were truncated. Emit it instead and rely on M7-14 dedup (the fingerprint is stable). Test updated.
- (d, nit) Extract one shared helper for preparing the domain registry, used by both app/api/v1/checks.py `_prepare` and monitor_run.prepare_registry. Align failure behaviour and document the decision in the helper docstring: the API keeps returning a typed error, the executor records `error`. API behaviour unchanged (existing API tests stay green). In checks.py only the helper extraction is touched.
- (e, nit) Add a test for the RUNNER_FAILED path in monitor_run.py ~255-259.
- No network in tests; ruff, mypy and relevant tests green (including PostgreSQL params if local PG is up); full suite not required unless shared fixtures change.
New i18n keys: none
Status: done (ead5671, QA APPROVE round 1)
Record:
- GM-approved extra files: app/repositories/dns_snapshots.py + tests (snapshot baseline keyset paging, same 50-limit issue fixed).
- New CheckRunRepository.latest_non_error (tenant-scoped).
- New app/services/domain_registry.prepare_domain_registry(strict), shared by API and executor.
- change_detect API is now CheckState(check_id, status, lists) + CheckInput.
- Follow-ups recorded in TODO.md under M7-10b (per-list evaluated storage, snapshot truncated equivalence, checks.py _prepare_all/_prepare_free).
