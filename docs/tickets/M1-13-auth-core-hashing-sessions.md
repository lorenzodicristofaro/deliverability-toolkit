# M1-13 Auth core: argon2 hashing and sessions
Milestone: M1
Branch: feature/m1-13-auth-core
Files in scope: app/core/security.py, app/services/auth.py, app/models/session.py, app/models/__init__.py, migrations/versions/<new revision>, pyproject.toml, uv.lock, tests/core/test_security.py, tests/services/test_auth.py
Out of scope: HTTP endpoints (M1-15), CSRF (M1-14), TOTP (M10), login throttling (M1-15), API keys
Depends on: M1-10, M1-12
Parallel-safe: no (models, migrations, pyproject)
Model: opus
Acceptance criteria:
- `argon2-cffi` hashing with library defaults (parameters recorded), `verify` with rehash-on-login when parameters change; timing-safe handling of unknown users (dummy verify) in the service.
- Session design per GM decision Q3: server-side `sessions` rows keyed by a hashed random token, user_id, created/expires/last_seen, revoked_at, active_tenant_id; cookie holds the opaque token signed with SECRET_KEY). Only the hash of the token is stored.
- Functions: create, resolve (rejects expired, revoked, inactive user), revoke one, revoke all for user; idle and absolute expiry from Settings with safe defaults stated.
- Cookie settings helper: HttpOnly, SameSite=Lax, Secure derived from BASE_URL scheme.
- Tests: wrong password, unknown user, tampered cookie, expired, revoked, inactive user, password change revokes other sessions. No secrets in logs.
- Passwords are never logged or placed in exceptions.
New i18n keys: none
Status: todo
