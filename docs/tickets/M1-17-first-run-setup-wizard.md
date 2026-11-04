# M1-17 First-run setup wizard (creates instance admin)
Milestone: M1
Branch: feature/m1-17-setup-wizard
Files in scope: app/web/setup.py, app/services/setup.py, app/web/templates/setup.html, app/main.py (router registration), locales/en.json, locales/it.json, tests/web/test_setup.py
Out of scope: tenant creation UI beyond the first tenant, email verification, ALLOW_REGISTRATION flow (not in M1 TODO)
Depends on: M1-15
Parallel-safe: no (app/main.py, locales)
Model: opus
Acceptance criteria:
- While no user exists, GET /setup shows the form and every other UI route redirects to it; /healthz is unaffected. Once any user exists, /setup returns 404 permanently (test, including a race: two concurrent submissions create exactly one admin, enforced by a DB constraint or transaction, not only app logic).
- Form: email, password (minimum length and a documented policy; no composition rules theatre), confirm, optional first tenant name. Creates the instance admin (`users.is_instance_admin`, GM decision Q4a) and the first tenant with an owner membership if a tenant name is given; stores the argon2 hash; logs the user in.
- Setup does not require login but requires CSRF (M1-14). GM decision Q6: a one-time setup token is logged at first start (only the token hash is stored) and required by the form, so an exposed fresh instance cannot be claimed by a stranger; it is invalidated after setup (test).
- Tests: validation errors, already-initialised 404, concurrent setup, redirect-to-setup behaviour, no password in logs.
New i18n keys: setup.title, setup.email, setup.password, setup.password_confirm, setup.tenant_name, setup.submit, setup.error.password_short, setup.error.password_mismatch, setup.error.email_invalid, setup.token_required (en + it)
Status: todo
