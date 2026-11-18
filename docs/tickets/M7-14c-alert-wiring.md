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
- Move M7-14's constructor settings (min_realert default 1 h, max attempts, backoff, lease) to settings in app/core/config.py with validated ranges; add to .env.example, forward in compose.yaml (tests/test_compose_config.py enforces it) and add rows to docs/SETUP.md section 11.
Acceptance criteria:
- A run whose result changes emits exactly one alert row (fake resolver, fake clock); a repeated identical run emits none; an error run never emits a removed/cleared alert.
- Emit failures are logged (no secrets, no bodies) and never fail the run nor stop the scheduler.
- With ROLE=web no dispatcher task starts; with worker or all exactly one starts; it is cancelled cleanly on shutdown.
- Invalid setting values stop the app at startup with an i18n error.
- No network in unit tests; no blocking DB call on the event loop.
New i18n keys: config errors for the new settings (en + it); exact names follow the existing config error key pattern; locale files touched, so serialize
Status: todo
Note: the executor module path and `log_events` location are unverified assumptions from the GM; confirm in code before starting.
