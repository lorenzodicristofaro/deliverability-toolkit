# R1-16 Cache-Control: no-store on every response to a request that carried a session cookie
Milestone: R1
Branch: feature/r1-16-cache-control-no-store
Findings: AUTH-11 (low)
Files in scope: app/core/security_headers.py, tests/core/test_security_headers.py; afterwards remove the per-module `_NO_STORE` constants in app/web/rules.py:65, message.py:50, content.py:48, custom_checks.py:71, dkim_selectors.py:58, domain_esps.py:59 ONLY if the central header makes them redundant and their tests still pass (otherwise leave them, state why)
Out of scope: SSE headers, static asset caching policy, any route logic
Depends on: none
Parallel-safe: no with other tickets editing those six web modules (R1-13): serialize after R1-13 if constants are removed
Model: sonnet (one response header); the middleware is security code, so QA on Opus
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- `SecurityHeadersMiddleware` sets `Cache-Control: no-store` on every response to a request that carried a session cookie (and on login/setup pages if the coder shows they carry tenant or token data), excluding `/static/*` and `/healthz`. An existing stricter `Cache-Control` set by a route is not overwritten (state the rule).
- Tests: authenticated HTML pages (landing, a domain page, the Authentication tab, DNS tool results) and authenticated JSON API responses carry `no-store`; `/static/*` and `/healthz` do not; an unauthenticated request without cookie is unchanged.
- Existing no-store tests stay green. ruff, mypy, relevant tests green.
New i18n keys: none
Status: done
Outcome: QA APPROVE; merged into dev (merge ee71e69). Follow-up: R1-32 (unconditional no-store).

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/web/landing.py:45-53`, `app/web/domains.py:184,247,307`, `app/web/authentication.py:65-72`, `app/web/dns_tools.py:94-108,226`, every JSON response of `app/api/v1/domains.py`, `checks.py`, `dns_tools.py`, `domain_esps.py`, `rules.py`, `dkim_selectors.py`, `custom_checks.py`; compare `_NO_STORE` in `app/web/rules.py:65`, `message.py:50`, `content.py:48`, `custom_checks.py:71`, `dkim_selectors.py:58`, `domain_esps.py:59`.
- Problem: newer pages set `Cache-Control: no-store` on every response, older ones and the whole JSON API do not. The landing page (tenant name, domain list), domain pages, the Authentication tab and DNS tool results can stay in the browser cache and be shown from history after logout on a shared machine, and an intermediary may cache authenticated GET responses that carry no cache directive.
- Evidence: `grep -rn 'Cache-Control' app` lists only the six modules above plus the SSE headers; `SecurityHeadersMiddleware` sets no cache header.
- Suggested fix: set `Cache-Control: no-store` in one place for every response to a request that carried a session cookie (for example in `SecurityHeadersMiddleware`, excluding `/static`), then remove the per-module constants.
- Tests to add: authenticated HTML and JSON responses carry `no-store`; `/static/*` and `/healthz` do not.
- Confidence: medium (header absence is certain; exposure depends on browser/proxy behaviour, not tested).
