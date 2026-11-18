# M7-14d Close the stale-replay window between the latest-run check and the alert insert
Milestone: M7
Branch: feature/m7-14d-alert-replica-window
Files in scope: app/services/alerts.py (emit path, `_emit_one`), app/services/monitor_run.py (`_emit`, `_still_latest`, docstring), app/repositories/ (only the alert/monitor-run repository methods needed for the in-transaction check; the coder confirms), ARCHITECTURE.md section 6 (remove the caveat only; the GM or maintainer applies it if the PM may not edit it), tests/services/test_alerts.py, tests/services/test_monitor_run.py, tests/services/test_alert_wiring.py (or the matching existing modules)
Out of scope: alert state/dedup semantics (M7-14), dispatcher internals (M7-15), retry/backoff settings (M7-14c), UI, channels
Depends on: M7-14c
Parallel-safe: no (alerts service and monitor_run.py are shared with M7-14c)
Model: opus (concurrency)
Why: in M7-14c the `_still_latest` replica guard in app/services/monitor_run.py `_emit` runs in a separate step from the alert insert. A rare window remains: a transient emit error, plus a newer run on the same target that completes on another worker within the retry window (about 6 s). The retry can then replay an older state out of order and insert a wrong head change (for example "listed" after "cleared").
Scope:
- Move the "this is still the latest run for the target" check into the alerts service and execute it in the same transaction as the alert insert.
- The check runs under the head-row lock (`SELECT .. FOR UPDATE` in `_emit_one`), so a newer run's emit cannot interleave between check and insert. On SQLite (no row locks) use an equivalent guard (for example a single-writer transaction such as BEGIN IMMEDIATE, or a conditional insert); the coder states which in the PR.
- If the run is no longer the latest, emit nothing for it and return a non-failure result (the retry must not loop on it).
- Keep the existing public emit API and EmitIncomplete behaviour; tenant data only through /repositories with a TenantContext.
- Remove the separate `_still_latest` step from `_emit` once the service performs the check, or reduce it to a cheap pre-filter that is not relied on for correctness.
- Remove the documented caveat about this window from ARCHITECTURE.md section 6 and from the monitor_run.py docstring (if the caveat text is not present in the merged code, say so in the PR; do not invent it).
Acceptance criteria:
- A deterministic test reproduces the interleaving (older run's emit fails transiently, newer run completes and emits, older run's retry fires) and produces no stale head change: the head stays at the newer state and no "listed after cleared" alert row exists.
- The test passes on SQLite and on PostgreSQL (PostgreSQL via TEST_DATABASE_URL, per the local PG test procedure; CI is the gate).
- The in-order case still emits exactly once; a repeated identical run still emits none.
- The check and the insert are provably in one transaction (test with a failing insert: no partial state).
- No blocking DB call on the event loop; no network in unit tests.
- The ARCHITECTURE.md section 6 and monitor_run.py docstring caveats are gone.
New i18n keys: none
Status: done
Note: the interleaving test needs a controllable barrier/fake clock, not sleeps. If the PostgreSQL test needs two connections, follow the existing emit-vs-release race test pattern from M7-14.
