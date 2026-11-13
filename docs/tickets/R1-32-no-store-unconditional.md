# R1-32 Cache-Control: no-store on every response except /static/ and exactly /healthz
Milestone: R1
Branch: feature/r1-32-no-store-unconditional
Findings: AUTH-11 follow-up (R1-16 QA open question: the cookie-keyed rule misses surfaces without a session cookie)
Files in scope: app/core/security_headers.py, tests/core/test_security_headers.py; afterwards remove the per-module `_NO_STORE` constants in app/web/rules.py, message.py, content.py, custom_checks.py, dkim_selectors.py, domain_esps.py ONLY if trivially safe (central header makes them redundant and their tests still pass; otherwise leave them and state why)
Out of scope: SSE headers, static asset caching policy, any route logic
Depends on: R1-16 (done)
Parallel-safe: no with tickets editing the six web modules if constants are removed; otherwise yes (disjoint from R1-15 and R1-30 except nothing shared)
Model: sonnet (one response header); QA on Opus (security middleware)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the gap and fails on dev bcc231b (for example a response to a request WITHOUT a session cookie, such as the login page, the setup wizard page or an API error body, has no `Cache-Control: no-store`). If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- Maintainer decision 2026-11-13: `Cache-Control: no-store` on every response, regardless of the session cookie, except paths under `/static/` and exactly `/healthz` (exact path match, NOT `startswith`: `/healthzfoo` and `/healthz/x` get no-store). State how a route-set `Cache-Control` is treated (keep the R1-16 rule if one exists: a stricter value set by a route is not overwritten).
- Tests (table-driven): authenticated and unauthenticated HTML and JSON responses, 401/403/404/422 error responses, redirects, login and setup pages carry `no-store`; `/static/...` and `/healthz` do not; `/healthzfoo`, `/healthz/` and `/static` (no trailing slash, state the chosen rule) behave as specified. Existing no-store tests stay green.
- ruff, mypy, relevant tests green.
New i18n keys: none
Status: done (merge ebdede2)

## Review details (copied from R1-16 / code review of 2026-11-12, dev 06869fb)
- Source: AUTH-11 (low), `app/web/landing.py:45-53`, `app/web/domains.py:184,247,307`, `app/web/authentication.py:65-72`, `app/web/dns_tools.py:94-108,226`, JSON API responses; per-module `_NO_STORE` in `app/web/rules.py:65`, `message.py:50`, `content.py:48`, `custom_checks.py:71`, `dkim_selectors.py:58`, `domain_esps.py:59`.
- Problem (original): authenticated pages and the JSON API set no cache directive and can stay in the browser cache or an intermediary.
- R1-16 delivered the cookie-keyed rule (merge ee71e69). Follow-up from QA/GM: surfaces not carrying the session cookie (setup wizard token page, login, non-cookie API auth, error bodies) are not covered; an unconditional rule is simpler and safer.
- Confidence: medium (header absence is certain; exposure depends on browser/proxy behaviour).
