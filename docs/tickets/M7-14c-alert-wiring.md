# M7-14c Wire alert emission into monitoring runs and start the delivery worker
Milestone: M7
Branch: feature/m7-14c-alert-wiring
Files in scope: app/services/monitor_run.py (or the actual M7-10 run executor module that holds the event sink; the coder confirms), app/main.py (lifespan/scheduler start only), app/core/config.py, app/services/alerts.py (constructor wiring only), .env.example, compose.yaml, docs/SETUP.md (section 11 rows), locales/en.json, locales/it.json (config error keys only), tests/services/test_monitor_run.py (or the matching existing test module), tests/services/test_alert_wiring.py, tests/test_main_lifespan.py (or matching), tests/core/test_config.py, tests/test_compose_config.py (only if its expectations need the new variables)
Out of scope: concrete channels, rendering, UI, changes to alert state/dedup semantics (M7-14), dispatcher internals (M7-15)
Depends on: M7-14, M7-15 (dispatcher loop)
Parallel-safe: no (config, compose, locales, app.main shared files)
Model: opus
Why: M7-14 (branch feature/m7-14-alert-state-dedup, in review) built alert state/dedup with an `emit` API in app/services/alerts.py, but monitor runs still call `log_events` (the M7-10 run executor sink) and nothing starts the M7-15 dispatcher loop. Without this the M7 acceptance "changes produce alerts exactly once" is not reachable end-to-end. (GM decision 2026-11-18.)
Scope:
- Replace the log-only event sink with a call to the alerts service `emit`. Sync DB work runs via asyncio.to_thread / run_in_threadpool, never on the event loop.
- Start the M7-15 dispatcher loop in the scheduler process only (ROLE worker or all, never ROLE=web), with clean shutdown (cancel and await on lifespan exit).
- Call the M7-14 round-2 `release_suppressed` function periodically from the scheduler process (e.g. each dispatcher tick or maintenance run), so a stream whose last state was suppressed during `min_realert` is delivered once the window ends (GM decision 2026-11-18, M7-14 QA finding 1).
- On the exception `__call__` raises when emit had failures (M7-14 QA finding 3), retry the same (latest) run's events with bounded attempts and backoff; never replay an older run after a newer one for the same target.
- Move M7-14's constructor settings (min_realert default 1 h, max attempts, backoff, lease, send timeout < lease) to settings in app/core/config.py with validated ranges; add to .env.example, forward in compose.yaml (tests/test_compose_config.py enforces it) and add rows to docs/SETUP.md section 11.
Acceptance criteria:
- A run whose result changes emits exactly one alert row (fake resolver, fake clock); a repeated identical run emits none; an error run never emits a removed/cleared alert.
- Emit failures are logged (no secrets, no bodies), retried for the latest run only, and never fail the run nor stop the scheduler; a transient DB error on emit does not lose the alert (test with a failing-then-succeeding repository).
- listed -> cleared -> listed inside `min_realert`: after the window the scheduler delivers "listed" exactly once (fake clock).
- With ROLE=web no dispatcher task starts; with worker or all exactly one starts; it is cancelled cleanly on shutdown.
- Invalid setting values stop the app at startup with an i18n error.
- No network in unit tests; no blocking DB call on the event loop.
New i18n keys: config errors for the new settings (en + it); exact names follow the existing config error key pattern; locale files touched, so serialize
Status: todo
Note: `log_events` is in app/services/monitor_run.py (checked by the GM 2026-11-18). `release_suppressed` and the emit-failure exception come from M7-14 round 2: use their final names from the merged code.
