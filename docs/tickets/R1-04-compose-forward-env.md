# R1-04 compose.yaml forwards every documented setting (BASE_URL, session timeouts, ...)
Milestone: R1
Branch: feature/r1-04-compose-forward-env
Findings: AUTH-03 (medium; cross-confirmed by the infra review)
Files in scope: compose.yaml, .env.example, tests/test_compose_config.py, app/core/config.py (read only, unless the optional startup warning is done: then app/main.py or app/core/config.py plus locale-free log text), docs/SETUP.md (only if it lists the variables)
Out of scope: trusted-proxy setting (TODO.md:318), `__Host-` cookies (R1-15), the postgres profile wiring (R1-25), container hardening (R1-29), changing defaults of any setting
Depends on: none
Parallel-safe: no with R1-25 and R1-29 (same compose.yaml and tests/test_compose_config.py; serialize R1-04 first)
Model: sonnet (configuration plumbing and a parity test; no auth logic changes; QA may use Opus because it concerns cookie/HSTS plumbing)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected reproduction: a parity test in tests/test_compose_config.py comparing the `Settings` fields documented in `.env.example` with the `environment:` block of the app service of compose.yaml.)
- Every `Settings` field documented in `.env.example` that is meant for the container (BASE_URL, LOG_LEVEL, ROLE, ALLOW_*, SESSION_IDLE_TIMEOUT_MINUTES, SESSION_ABSOLUTE_TIMEOUT_MINUTES, and the rest the parity test finds) is forwarded, e.g. `BASE_URL: ${BASE_URL:-http://localhost:8000}`, with the SAME default as `Settings`; or `env_file` with `required: false`. Do not change any default value.
- Parity test: fails when a documented setting is not forwarded; the allow-list of intentionally unforwarded names (if any) is explicit and commented.
- Test that `BASE_URL=https://...` yields `Secure` on all three cookies (session, `dt_csrf`, language) and the HSTS header (extend the existing unit-level test only if the gap is the plumbing; do not duplicate).
- Optional: startup warning when `BASE_URL` is `http://` and the host is not localhost (log only, no user-facing string).
- Tests table-driven, no network, no wall clock. ruff, mypy, tests/test_compose_config.py green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `compose.yaml:14-21` (the `environment:` block lists only `DATABASE_URL`, `SECRET_KEY`, `ENCRYPTION_KEY`, `RESOLVER_MODE`, `RESOLVER_ADDRS`; no `env_file`), `.env.example:25-26`, `app/core/security.py:170` (`secure=` from `BASE_URL`), `app/core/csrf.py:137-145` (same for `dt_csrf`), `app/core/security_headers.py:48-51` (HSTS from `BASE_URL`).
- Problem: `.env.example` tells the operator to set `BASE_URL`, `LOG_LEVEL`, `ROLE`, `ALLOW_*` and the session timeouts in `.env`. Docker Compose uses `.env` only to interpolate `compose.yaml`; a variable reaches the container only if `environment:` or `env_file:` names it. With the shipped file `BASE_URL=https://...` is silently ignored, the app keeps the default `http://localhost:8000`, and the session, CSRF and language cookies are issued without `Secure` and no `Strict-Transport-Security` header is sent, even on an HTTPS deployment. Same for `SESSION_IDLE_TIMEOUT_MINUTES` and `SESSION_ABSOLUTE_TIMEOUT_MINUTES`: shortened values are ignored.
- Evidence: `grep -n 'BASE_URL\|env_file\|SESSION_\|LOG_LEVEL' compose.yaml` returns nothing. `session_cookie_settings` computes `secure=settings.base_url.lower().startswith("https://")`. Scenario: `.env` has `BASE_URL=https://dt.example.org`, stack behind a TLS proxy -> `Set-Cookie: dt_session=...; HttpOnly; Path=/; SameSite=lax` with no `Secure`.
- Suggested fix: forward every documented setting in `compose.yaml`, or add `env_file` with `required: false`. Extend `tests/test_compose_config.py` so that every `Settings` field documented in `.env.example` is forwarded. Consider a startup warning when `BASE_URL` is `http://` and the host is not localhost.
- Tests to add: the parity test above; a test that `BASE_URL=https://...` yields `Secure` on all three cookies and the HSTS header.
- Confidence: high for the missing forwarding; medium for impact (an operator may pass the variable another way).
- Already tracked: no. Related: AUTH-10 (R1-15) needs this first; R1-25 and R1-29 edit the same file.
