# M1-15 Login, logout, throttling, auth dependencies, active-tenant switch
Milestone: M1
Branch: feature/m1-15-login-logout
Files in scope: app/web/auth.py, app/web/deps.py, app/web/templates/login.html, app/services/login_throttle.py, app/main.py (router registration), locales/en.json, locales/it.json, tests/web/test_auth_endpoints.py, tests/web/test_login_throttle.py
Out of scope: setup wizard (M1-17), TOTP/API keys/share links (M10), OIDC, password reset by email (not in M1 TODO)
Depends on: M1-11, M1-12, M1-13, M1-14, M1-16
Parallel-safe: no (router registry app/main.py, locales)
Model: opus
Acceptance criteria:
- POST /login (email, password) creates a session; generic failure message that does not reveal whether the user exists; POST /logout revokes the session. All forms use CSRF from M1-14.
- Login throttling per (IP, account) with backoff and a lockout window; storage in DB or in-process (state decision stated; must work with ROLE=all single process); tests with injectable clock.
- Dependencies: `current_principal` (401/redirect when anonymous), `tenant_ctx` (builds TenantContext from the session's active tenant; 404 when the user has no membership in it), `require(action, resource)` using `can()`.
- POST /tenants/switch (GM decision Q4a: active tenant is stored in the session) sets active tenant only if the user has a membership; otherwise 404 (tenancy test).
- Every new endpoint has a tenancy/permission test: anonymous denied, user of tenant A cannot switch to tenant B, inactive user cannot log in.
- Redirect targets after login are validated as local paths (open-redirect test).
- Log lines contain no credentials.
- Validate session active_tenant_id against the user's active membership when building TenantContext, failing closed.
- Callers pass SessionPolicy.from_settings(settings).
New i18n keys: auth.login.title, auth.login.email, auth.login.password, auth.login.submit, auth.login.failed, auth.login.throttled, auth.logout, auth.tenant_switch.denied (en + it)
Status: todo
