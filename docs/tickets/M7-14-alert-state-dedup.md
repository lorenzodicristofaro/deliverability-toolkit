# M7-14 Alert state, dedup and exactly-once delivery design
Milestone: M7
Branch: feature/m7-14-alert-dedup
Files in scope: app/models/alert.py, app/models/__init__.py, migrations/versions/<next revision>_alerts.py, app/repositories/alerts.py, app/repositories/__init__.py, app/services/alerts.py, ARCHITECTURE.md (alerts paragraph in section 6), tests/services/test_alerts.py, tests/repositories/test_alerts.py
Out of scope: channel config and secrets (M7-15), concrete channels (M7-16..19), API/UI, alert rule UI
Depends on: M7-10
Parallel-safe: no (models registry, migration chain)
Model: opus (concurrency/state design; GM may downgrade after review of the design note)
Design to implement and record in ARCHITECTURE.md:
- Delivery semantics: "exactly once per change" means exactly one alert row per (tenant, fingerprint, state transition), and at-least-once delivery attempts per channel with an idempotent per-channel delivery record, so a restart or retry never creates a second alert nor re-sends one already marked delivered. State plainly in the doc that exactly-once at the remote endpoint cannot be guaranteed after a crash between send and commit; the guarantee is on alert creation, and delivery is marked before any retry decision.
- Tables: `alerts` (id, tenant_id, domain_id, kind, fingerprint, state_hash, created_at, payload codes+params bounded) with UNIQUE (tenant_id, fingerprint, state_hash); `alert_deliveries` (alert_id, channel_id, status pending|sent|failed|abandoned, attempts, next_attempt_at, last_error code only). Creation uses INSERT with unique-conflict as the dedup point (works on SQLite and PostgreSQL; no check-then-insert).
- Flapping control: an event is re-alerted only after the state truly changed; A -> B -> A produces alerts for each distinct transition (documented) but a minimum re-alert interval per fingerprint is a setting; suppressed events are counted, not lost silently (kept as suppressed row or counter, decide and document).
- Retry: bounded attempts with backoff from an injected clock; `abandoned` after the cap; failures logged without secrets or bodies.
Acceptance criteria:
- `emit(events)` from M7-10 creates alerts idempotently: same events twice -> one alert; two concurrent emitters -> one alert (test with two sessions); process restart simulated by rebuilding the service and replaying the same events and the same run -> no new alert, no new delivery rows, a `pending` delivery resumes, a `sent` one is not re-sent.
- Alert rules: minimal model deciding which event kinds go to which channels per tenant (kinds from M7-10); default if none configured: no delivery (alerts still recorded for the UI).
- Tenant isolation tests on repository; migration up/down SQLite and PostgreSQL; fake clock, no network.
New i18n keys: ALERT_RECORD_CHANGED, ALERT_NEW_LISTING, ALERT_LISTING_CLEARED, ALERT_POLICY_REGRESSION, ALERT_CHECK_ERROR (.title/.detail) (en + it); locale files touched, so serialize
Status: todo
