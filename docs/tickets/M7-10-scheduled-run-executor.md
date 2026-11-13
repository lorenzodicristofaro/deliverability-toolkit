# M7-10 Scheduled run executor: run checks, store history, snapshot, emit change events
Milestone: M7
Branch: feature/m7-10-run-executor
Files in scope: app/services/monitor_run.py, app/services/change_detect.py, app/services/scheduler.py (call site only), tests/services/test_monitor_run.py, tests/services/test_change_detect.py
Out of scope: alert delivery and dedup state (M7-14), API/UI, new checks
Depends on: M7-05, M7-07, M7-08, M7-09
Parallel-safe: no (touches scheduler.py)
Model: sonnet
Acceptance criteria:
- Executor rebuilds a TenantContext from the target's tenant_id, runs the configured check ids through the existing orchestration (app/services/checks.py), writes a `check_runs` row per check and a DNS snapshot, updates target last_run_at/last_status/next_run_at. Check `error` is stored as `error` and never converted to ok.
- `change_detect` is pure: takes (previous run/snapshot, new run/snapshot) and returns typed events: record_changed (from the diff), new_listing and listing_cleared (DNSBL, by list id), policy_regression (status worsened, e.g. ok -> fail, defined by severity ordering), check_error_started/cleared. An `error` result produces no record/listing/regression event, only the error events (no false "cleared").
- Events carry a stable fingerprint (kind, domain_id, subject, new-state hash) used by M7-14 for dedup; fingerprint is deterministic and tested.
- Expiring certificates/keys (SPEC 4.3) are NOT produced here: no certificate check exists before M9; documented in docs/MONITORING.md by M7-20.
- Tests with fake checks and fake DNS (no network): first run has no events (baseline), unchanged run none, change, revert, listing appears/disappears, error in the middle, exception in a check isolated, tenant context correctness.
New i18n keys: none
Status: todo
