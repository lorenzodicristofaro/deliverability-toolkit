# M1-14 CSRF protection and security headers
Milestone: M1
Branch: feature/m1-14-csrf-headers
Files in scope: app/core/csrf.py, app/core/security_headers.py, app/main.py (middleware registration), locales/en.json, locales/it.json, tests/core/test_csrf.py, tests/core/test_security_headers.py
Out of scope: login/setup endpoints (M1-15, M1-17), rate limiting, templates (token is exposed via a helper only)
Depends on: M1-13
Parallel-safe: no (app/main.py)
Model: opus
Acceptance criteria:
- State-changing methods (POST, PUT, PATCH, DELETE) on cookie-authenticated UI routes require a valid CSRF token bound to the session (token derived from the session id with SECRET_KEY, or per-session stored value; approach stated). Missing/invalid token returns 403.
- Pre-session forms (login, setup) use a signed double-submit cookie token.
- Token comparison is constant-time; token accepted from form field or `X-CSRF-Token` header (HTMX).
- Headers on all responses: CSP without inline scripts (`default-src 'self'`, no `unsafe-inline` for script), X-Content-Type-Options, Referrer-Policy, frame-ancestors/X-Frame-Options, Permissions-Policy minimal. HSTS only when BASE_URL is https. Exact values documented in code comments; no claim about browser behaviour beyond what is tested.
- Table-driven tests: each method x token state x authenticated/anonymous; /healthz stays unaffected.
New i18n keys: csrf.invalid (en + it)
Status: done
Outcome: merged into dev (QA APPROVE after round 1).
- Session-bound token is an HMAC of the session token; pre-session forms use a signed double-submit cookie `dt_csrf`.
- The check denies by default for every method except GET/HEAD/OPTIONS/TRACE.
- 500 responses carry the security headers.
- Multipart forms need the `X-CSRF-Token` header (python-multipart is not a dependency).
