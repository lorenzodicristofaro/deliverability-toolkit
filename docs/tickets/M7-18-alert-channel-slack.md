# M7-18 Alert channel: Slack incoming webhook
Milestone: M7
Branch: feature/m7-18-alert-slack
Files in scope: app/services/alert_channels/slack.py, app/services/alert_channels/__init__.py (registry line), docs/MONITORING.md (Slack section), tests/services/test_alert_slack.py
Out of scope: Slack apps/OAuth, interactive components, other channels
Depends on: M7-17
Parallel-safe: no (shared registry file, builds on the webhook sender)
Model: sonnet
UNVERIFIED external facts (CLAUDE.md non-negotiable): the Slack incoming-webhook payload format (text field, Block Kit shape, mrkdwn escaping rules, size limits), the webhook URL host/shape, and HTTP response codes/retry behaviour. The coder MUST read Slack's current official documentation, record URLs and the retrieval date in code comments and docs/MONITORING.md, and mark any point it cannot confirm as `unverified` in the docs and in the PR. Do not copy payload shapes from memory.
Acceptance criteria:
- Payload built only from the documented fields; text escaped per the documented control characters (values from domain names/params are untrusted); length truncated to the documented limits (cite them; if not documented, use a conservative project cap and say so).
- Channel config validates the URL scheme/host against what the docs state; the host check is a convenience, the guarded client is the control. Reuses the M7-17 sender (no second HTTP path).
- Response mapping per the documented codes, otherwise as M7-17; Slack's response body never stored.
- Tests (fake guarded client): payload golden file, escaping of `<`, `>`, `&`, mentions (`<!channel>`-like and `@` injection attempts) in domain/params, truncation, each response mapping.
New i18n keys: ALERT_SLACK_* message labels if any are not reused from alert keys (en + it); prefer reuse, none expected
Status: todo
