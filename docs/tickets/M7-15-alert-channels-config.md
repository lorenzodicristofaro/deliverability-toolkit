# M7-15 Alert channel configuration, encrypted secrets, dispatcher interface
Milestone: M7
Branch: feature/m7-15-alert-channels
Files in scope: app/models/alert_channel.py, app/models/__init__.py, migrations/versions/<next revision>_alert_channels.py, app/repositories/alert_channels.py, app/repositories/__init__.py, app/services/alert_dispatch.py (Channel protocol, registry, worker loop), app/api/v1/alert_channels.py, app/core/permissions.py, app/main.py (router registration only), tests/api/test_alert_channels.py, tests/services/test_alert_dispatch.py, tests/repositories/test_alert_channels_repository.py (renamed: basename clash with tests/api), locales/en.json, locales/it.json
Out of scope: concrete channels, alert creation (M7-14), UI
Depends on: M7-14, M7-14b, M7-11
Parallel-safe: no (models, migrations, permissions, router registry, locales)
Model: opus (secret encryption, permissions, tenancy)
Acceptance criteria:
- `alert_channels` (id, tenant_id, kind email|webhook|slack|teams, name, enabled, config JSON non-secret, secret ciphertext). Webhook URLs and signing secrets are secrets: stored encrypted with `app/core/secrets_crypto.py` (M7-14b); decrypt only at send time. Secrets never returned by the API after creation (masked), never logged.
- Channel protocol: `validate_config(config) -> errors`, `async send(alert, rendered, channel) -> SendResult(ok|retryable|permanent, code)`; registry by kind; dispatcher loop reads `alert_deliveries`, renders for the tenant language, calls the channel, updates the delivery row, honours attempts/backoff from M7-14. A channel exception becomes a failed attempt, never crashes the loop.
- A test channel action ("send test alert") endpoint, rate limited per channel.
- Channel URLs are validated at write time (scheme, host syntax) and again at send time by the guarded client (M7-01); validation at write is a convenience, not the control.
- API: CRUD under a new permission `alert.manage` held by owner and admin only. Reason: SPEC section 3 gives analyst "no user/integration management" and a channel stores a credential/webhook URL (integration-like); client viewers get no access to channels at all (not grantable). Add the action to ROLE_ACTIONS in app/core/permissions.py and the module docstring; every endpoint has tenancy and permission tests, cross-tenant 404, secret never in responses or logs (test greps the response and captured log output).
- Tests: no network, fake channel.
Guarded client rules apply unchanged to webhook targets (GM decision: no private-target allowlist in M7).
New i18n keys: alert.channel.* validation errors, permission label for `alert.manage` (en + it)
Notes from M7-14b follow-ups (low priority, may be split out):
- `get_cipher()` is cached with functools.cache; with new callers here, add a shared conftest fixture that clears the cache (today only tests/core/test_secrets_crypto.py does).
- No command exists yet to re-encrypt stored secrets after key rotation; docs/SETUP.md section 10 says it comes with this ticket.
Status: done (merged dacd1bb, QA APPROVE round 1 + should-fix verified)
Implementation notes (coder, 2026-11-18):
- Migration 0017 follows 0016 (M7-14). No FK from `alert_deliveries.channel_id` / `alert_rules.channel_id` to `alert_channels`: adding it needs edits to app/models/alert.py and to M7-14 tests that use free channel ids (tests/migrations/test_0016_alerts.py, tests/repositories/test_alerts_repository.py, tests/services/test_alerts.py), all outside this ticket. `alert_channels` has UNIQUE (id, tenant_id) ready for a composite FK; until then deleting a channel deletes its rules and deliveries in the same transaction (what CASCADE would do). GM 2026-11-18: FK is a follow-up (GM adds it to TODO).
- Router registered in app/api/__init__.py (where `api_router` includes every v1 router), not app/main.py. GM 2026-11-18: accepted.
- Defaults (project choices, not vendor facts; GM 2026-11-18: accepted as defaults):
  - URLs (webhook/slack/teams) must be https: `check_url` in app/services/alert_dispatch.py
  - signing secret 16..256 printable ASCII: `MIN_SIGNING_SECRET` / `MAX_SIGNING_SECRET`, app/services/alert_dispatch.py
  - email recipients 1..10: `MAX_RECIPIENTS`, app/services/alert_dispatch.py
  - 50 channels per tenant: `MAX_CHANNELS`, app/api/v1/alert_channels.py
  - 3 test sends per channel per 10 minutes, in memory per process: `DEFAULT_TEST_CAPACITY` / `DEFAULT_TEST_WINDOW`, app/services/alert_dispatch.py
  - poll interval 30 s: `DEFAULT_POLL_INTERVAL`, app/services/alert_dispatch.py (tenant batch `DEFAULT_TENANT_BATCH` 100, delivery batch `DEFAULT_DELIVERY_BATCH` 50)
  M7-14c may move them to settings.
- Abandon now (GM 2026-11-18, scope extended to app/services/alerts.py, app/repositories/alerts.py and their tests, plus the ARCHITECTURE section 6 abandonment sentence): `DeliveryError(code, permanent=True)` makes `deliver_due` mark the delivery `abandoned` at once via `AlertDeliveryRepository.mark_abandoned` (same attempt guard as `mark_sent`, a stale worker cannot abandon; a lost mark counts as skipped). The dispatcher raises it for a `permanent` SendResult and a deleted channel; `retryable`, timeouts, channel exceptions and disabled/unregistered/unreadable/misconfigured channels keep backoff.
- Suite-wide test files changed: tests/core/test_permissions.py (alert.manage row, action list, matrix size, toggle block), tests/tenancy/test_matrix.py (6 entries, `b_alert_channel`), tests/tenancy/test_id_range.py (`CHANNEL_ID_ROUTES`), tests/conftest.py (autouse fixture clearing `get_cipher` cache, M7-14b follow-up). GM 2026-11-18: accepted.
- Not done: the operator command to re-encrypt secrets after key rotation and its docs/SETUP.md section 10 text (CLI and SETUP.md are outside the files in scope; GM 2026-11-18: follow-up added to TODO by the GM); the repository entry point `AlertChannelSecretRotation.rotate_all` exists and is tested. ARCHITECTURE section 6 has no "Alert channels" paragraph yet (file not in scope).
- For M7-14c (QA 2026-11-18): the test-send limit is keyed per (tenant, channel id), so deleting and recreating a channel resets it; `tenants_with_due` takes the lowest 100 tenant ids per pass (`DEFAULT_TENANT_BATCH`), so with more tenants due the higher ids can starve: add fairness (e.g. rotate or order by oldest due) when wiring the loop.
- QA should-fix (2026-11-18): a concurrent duplicate name raising IntegrityError at the repository flush is now rolled back and answered 409 (`ChannelsApi._write`), with the error dropped so no SQL parameters (token ciphertext) reach the logs.
Note: the migration chain head is now 0013 (dns_snapshots, M7-08, merged 05cd067); the new revision follows it (or a later head if M7-14 merges first).
