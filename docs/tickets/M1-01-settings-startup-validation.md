# M1-01 Settings object and startup validation
Milestone: M1
Branch: feature/m1-01-settings-startup-validation
Files in scope: app/core/config.py, app/main.py, tests/test_settings.py, tests/test_config.py (extend only), pyproject.toml, uv.lock, .env.example
Out of scope: logging (M1-03), DB engine (M1-06), compose changes (M1-04), docs/openapi exposure (M1-02), any DNS query code
Depends on: M0-03
Parallel-safe: no (pyproject/uv.lock, app/main.py)
Model: sonnet
Acceptance criteria:
- A `Settings` object loads the ARCHITECTURE section 11 variables: DATABASE_URL (default `sqlite:////data/app.db`), SECRET_KEY, ENCRYPTION_KEY, RESOLVER_MODE (`system|custom|unbound`, default `system`), RESOLVER_ADDRS (parsed with the existing `parse_resolver_addrs`), ROLE (`web|worker|all`, default `all`), ALLOW_SMTP_CHECKS and ALLOW_REGISTRATION (default false), BASE_URL, LOG_LEVEL. SMTP_* is out of scope until M7 alerts.
- M0-03 follow-up: an empty or whitespace-only SECRET_KEY or ENCRYPTION_KEY counts as missing; startup raises `ConfigError` and the process does not serve. Table-driven tests: unset, empty, spaces, valid.
- Invalid RESOLVER_MODE/ROLE/bool values raise `ConfigError` with an i18n key; RESOLVER_MODE=custom or unbound with empty RESOLVER_ADDRS is an error.
- Settings are validated at app creation (factory or lifespan), not at import time of unrelated modules, so unit tests can build apps with explicit settings.
- Secret values never appear in `repr`/str of Settings nor in ConfigError messages (test).
- `.env.example` documents each variable; no real secrets.
- Existing tests, ruff, mypy green; no network in tests.
New i18n keys (en + it, files created by M1-09; until then keys are constants only): config.missing, config.invalid_value, config.resolver_addrs_required
Status: todo

## GM decisions (2026-11-04)
- Q1: use pydantic-settings (new dependency).
- Q2: disable /docs, /redoc, /openapi.json (M1-02 as proposed); revisit with auth/API keys in M10.
- Q3: server-side session rows + signed opaque cookie (revocable), consistent with ARCHITECTURE "signed session cookies" + "session revocation".
- Q4a: active tenant stored in the session; instance admin = `users.is_instance_admin`.
- Q4b: instance-admin access to tenant data: ESCALATED to the maintainer. Until answered, implement deny (M1-11 as written).
- Q5: `app` always joins `dns`.
- Q6: yes, a one-time setup token is logged at first start and invalidated after setup.
- Q7: active-tenant based `/api/v1/domains`.
- Role enum (owner, admin, analyst, client_viewer) plus JSON `feature_toggles` enforced only through `can()`: confirmed by GM (SPEC §3, ARCHITECTURE §4).
