# M7-16 Alert channel: email
Milestone: M7
Branch: feature/m7-16-alert-email
Files in scope: app/services/alert_channels/email.py, app/services/alert_channels/__init__.py, app/core/config.py (SMTP settings), .env.example, docs/SETUP.md (settings rows), ARCHITECTURE.md (section 9 note), tests/services/test_alert_email.py, locales/en.json, locales/it.json
Out of scope: inbound mail, a general SMTP module (M9 optional), other channels
Depends on: M7-15
Parallel-safe: no (config, locales; shares alert_channels/__init__ registry with M7-17..19)
Model: sonnet (QA opus if it adds an SMTP client: ARCHITECTURE section 9 lists SMTP as guarded)
Acceptance criteria:
- Operator-level SMTP relay settings (host, port, STARTTLS/TLS mode, username, password via env, From address); channel config holds only recipient addresses (validated, count cap). Strict header-injection safety: no CR/LF in any header value, subject length cap.
- GM decision: the notification SMTP relay (SMTP_* env, instance admin setting, SPEC section 3) is operator-configured trusted infrastructure like RESOLVER_ADDRS, may be private, and does not go through the guarded client. Record this in ARCHITECTURE section 9 (the guarded SMTP client remains for SMTP checks, M9). Recipient addresses never become connection targets.
- Message: plain text + simple HTML, content rendered from alert codes+params in the tenant language (en/it), all values escaped; links use BASE_URL.
- Send via a thread/async-safe SMTP library call with timeout; result mapping: connection/4xx -> retryable, 5xx -> permanent, TLS failure -> retryable with code.
- Tests with a fake SMTP transport (no network): success, 4xx, 5xx, timeout, injection attempts in domain names and params, missing settings -> channel reports `permanent` with code `not_configured`.
New i18n keys: ALERT_EMAIL_SUBJECT, ALERT_EMAIL_BODY intro/footer keys (en + it)
Status: todo
