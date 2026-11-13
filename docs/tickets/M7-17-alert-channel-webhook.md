# M7-17 Alert channel: generic webhook
Milestone: M7
Branch: feature/m7-17-alert-webhook
Files in scope: app/services/alert_channels/webhook.py, app/services/alert_channels/__init__.py (registry line), docs/MONITORING.md (payload section stub, completed by M7-20), tests/services/test_alert_webhook.py
Out of scope: Slack/Teams formats, UI, locale files (payload is machine-readable JSON, no user-facing strings)
Depends on: M7-15, M7-01
Parallel-safe: no (shared registry file with the other channels); disjoint otherwise
Model: sonnet (QA opus: outbound request to a user-supplied URL)
Acceptance criteria:
- POST JSON with a versioned payload (`schema_version`, alert id, kind, domain, tenant-safe fields, codes + params, timestamps, link) documented in docs/MONITORING.md; stable and covered by a snapshot test.
- All I/O through `app/net/guarded_http` (POST allowed there by this ticket only if M7-01 supports it; if M7-01 offers GET/HEAD only, extend the client in a separate step flagged to the GM, not inside this ticket). Redirects not followed for POST by default.
- Optional HMAC signature header using the channel secret; the algorithm, header name and timestamp rule are PROJECT choices, documented as such (not a vendor standard). Constant-time comparison is for receivers; documented sample verifier in the docs.
- Result mapping: 2xx ok, 408/429/5xx/timeouts/dns errors retryable (honour Retry-After within a cap), other 4xx permanent, blocked address permanent with code `blocked`. Response body never stored or logged beyond a bounded status code.
- Tests (fake guarded client): each mapping, blocked URL, payload snapshot, signature test vector, hostile domain names in the payload (valid JSON, no injection), size cap.
New i18n keys: none
Status: todo
