# M7-15 Alert channel configuration, encrypted secrets, dispatcher interface
Milestone: M7
Branch: feature/m7-15-alert-channels
Files in scope: app/models/alert_channel.py, app/models/__init__.py, migrations/versions/<next revision>_alert_channels.py, app/repositories/alert_channels.py, app/repositories/__init__.py, app/services/alert_dispatch.py (Channel protocol, registry, worker loop), app/api/v1/alert_channels.py, app/core/permissions.py, app/main.py (router registration only), tests/api/test_alert_channels.py, tests/services/test_alert_dispatch.py, tests/repositories/test_alert_channels.py, locales/en.json, locales/it.json
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
Status: todo
