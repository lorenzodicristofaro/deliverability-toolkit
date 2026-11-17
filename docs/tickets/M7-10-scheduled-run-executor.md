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
Status: done (fff4656, QA APPROVE round 1; coder Opus, QA Opus)
Extra files approved by GM: app/services/scheduler.py (shutdown restore of claims, _tick_lock), tests/services/test_scheduler.py, app/main.py (executor wiring, log_only_run removed), ARCHITECTURE §6.
Decisions: EventSink(ctx, events) is injectable, default log_events (M7-14 replaces it); STATUS_RANK ok=info < warn < fail, error is outside the ranking; dnsbl is excluded from policy_regression; fingerprint = sha256 of [kind, domain_id, subject, sha256(after)].
Follow-ups from QA: see M7-10b.
Note (from M7-08, merged 05cd067): take snapshots via app/services/dns_snapshot (repo_for(ctx).dns_snapshots); the heartbeat (store in full only on change or after DNS_SNAPSHOT_HEARTBEAT_HOURS) is handled there. For record_changed, compare each entry against its last non-error state: use app/services/dns_diff.carry_forward(baseline, current) before diff_snapshots, otherwise changes across a transient error are reported only as inconclusive. Valid SPF -> quoted/broken SPF shows as `removed`.
Note (from M7-09 QA): unknown check ids arrive in ScheduledRun.unknown_check_ids; M7-10 must record them as `error`. app/main.py currently wires `log_only_run`; M7-10 replaces it. Build the TenantContext from DueTarget.tenant_id for each run.
Note (should-fix carried from M7-09 QA): on shutdown, claimed-but-cancelled or not-started runs lose a whole interval (next_run_at already advanced). Fix: carry new_next_run_at in ScheduledRun; on cancel/not-started do a conditional claim(id, new_next, claimed_at) to restore the previous time. Also make shutdown take _tick_lock / await the in-progress tick (app/services/scheduler.py ~352, ~409-419) so no planning thread commits claims after lifespan exit.
Note (from M7-07, merged 4628d94): write runs through repo_for(ctx).check_runs; findings stored as {code, params} only (no rendered text); check_id column width is 96.
