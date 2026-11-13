# R1-15 __Host- cookie prefix on https and an expiry on the pre-session CSRF token
Milestone: R1
Branch: feature/r1-15-host-cookies-csrf-expiry
Findings: AUTH-10 (low)
Files in scope: app/core/security.py, app/core/csrf.py, app/web/auth.py, tests that name the cookies (tests/core/test_csrf.py, tests/web/test_auth_endpoints.py, tests/web/test_setup.py and others found by grep; the coder lists them)
Out of scope: compose plumbing (R1-04), SameSite policy, session lifetime, API-key/bearer CSRF exemption (TODO)
Depends on: R1-04 (`__Host-` needs `Secure`, which needs `BASE_URL` to reach the app)
Parallel-safe: no with R1-03 and R1-12 (app/web/auth.py); serialize after them
Model: opus (CSRF and session cookie handling)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- When `BASE_URL` is https, the cookies are named `__Host-dt_session` and `__Host-dt_csrf` (`Path=/`, no `Domain`, `Secure`); when http they keep the current names and keep working. The language cookie is not part of this unless the coder shows it is needed (state it).
- Reading both old and new names for one release so nobody is logged out on upgrade; document the migration in a code comment and docs/HANDOFF-style note in the summary (not a doc edit unless a user doc names the cookies).
- The double-submit token carries an issue time and is refused when older than a named limit; time injected in tests (no sleeping). Existing valid-token tests stay green; the limit is longer than any normal form-open time and its value is justified in a comment.
- Tests: https config issues `__Host-` cookies for session and csrf; a token older than the limit is refused (403 as today); http config unchanged; old-name cookie accepted on https during the transition; token with a tampered timestamp refused (MAC covers it).
- No input echoed in failures. No network. ruff, mypy, relevant tests and the CSRF/auth suites green.
New i18n keys: none
Status: done (QA APPROVE, merged 37368b3)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/core/security.py:36,163-173` (`dt_session`), `app/core/csrf.py:65` (`dt_csrf`), `:91-104` (token = nonce + MAC, no timestamp, no binding), `:112-121` (`check_token` accepts any validly signed pair), `:124-146` (`csrf_token_for`).
- Problem: the double-submit pair for login, setup and the language switch is valid for any browser forever: the server signs a random nonce and checks only the signature and cookie/field equality. An attacker who controls a sibling subdomain (or plain-HTTP traffic for the host while cookies lack `Secure`, see AUTH-03) can plant their own valid `dt_csrf`, or their own `dt_session`, in the victim's browser and then submit the login form cross-site: the victim ends up in the attacker's account (login CSRF / session fixation by cookie tossing). Host-only cookies with the `__Host-` prefix cannot be set from a sibling domain.
- Evidence: `valid_double_submit_cookie` checks length, alphabet and `HMAC(K_double, nonce)` only; `new_double_submit_token` embeds no time or client value. Cookie names `dt_session` and `dt_csrf` are set without a prefix in the `set_cookie` calls at `app/web/auth.py:84-92` and `app/core/csrf.py:138-145`.
- Suggested fix: when `BASE_URL` is https, name the cookies `__Host-dt_session` and `__Host-dt_csrf` (already `Path=/`, no `Domain`, would have `Secure`); add an issue time to the double-submit token and refuse old ones. Reading both old and new names for one release avoids logging everyone out.
- Tests to add: as in the criteria.
- Confidence: medium (the attack needs a cookie-setting position; impact limited to pre-session forms).
