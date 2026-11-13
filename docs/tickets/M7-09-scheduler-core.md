# M7-09 Scheduler core: rate limits, jitter, concurrency, maintenance jobs
Milestone: M7
Branch: feature/m7-09-scheduler-core
Files in scope: app/services/scheduler.py, app/services/rate_limit.py, app/services/clock.py (small Clock protocol if none exists), app/core/config.py (settings below), app/main.py (lifespan wiring only), .env.example, docs/SETUP.md (settings rows), tests/services/test_scheduler.py, tests/services/test_rate_limit.py
Out of scope: what a run does (M7-10), UI/API, alerts, models
Depends on: M7-06, M7-07
Parallel-safe: no (app/main.py, config)
Model: sonnet (escalate per rules; QA on opus: concurrency and tenancy boundary)
Acceptance criteria:
- APScheduler in-process per ARCHITECTURE section 6 (verify the current APScheduler version API from its docs; add the dependency with a pinned bound and say so); the policy logic is plain functions so tests need neither APScheduler nor real time.
- `ROLE=web|worker|all` honoured: the scheduler starts only for `worker`/`all` (ROLE as in ARCHITECTURE; if the setting does not exist yet, add it with the three values and validation).
- Selection: each tick reads `due_targets(now)`, applies jitter (deterministic from an injected random source), a global concurrency semaphore (setting, bounded), and per-target-key rate limiting. Rate-limit keys: per DNSBL list id, per remote host for http_fetch, per tenant. Token-bucket or minimum-interval limiter with an injected Clock; limiter state is in memory and a restart cannot cause a burst larger than the bucket (tests: restart resets to a full bucket but never exceeds capacity per window).
- A target skipped for rate limit is rescheduled (not dropped, not counted as a failed run); one slow or failing target never blocks others; overlapping runs of the same target are impossible (claim by updating next_run_at transactionally; concurrent claim test with two scheduler instances over the same DB gives exactly one winner).
- Maintenance jobs: the session purge (R1-14 follow-up: call `purge_sessions` with a policy on a timer, not only at startup) and `prune_check_runs`/snapshot prune from M7-07/08.
- Tests with fake clock, fake resolver and fake run function (no network, no sleeping): jitter bounds, semaphore cap, per-list rate limit across many targets, reschedule after skip, claim race, shutdown cancels in-flight work, exception in one job is logged and does not stop the loop.
New i18n keys: none
Status: todo
