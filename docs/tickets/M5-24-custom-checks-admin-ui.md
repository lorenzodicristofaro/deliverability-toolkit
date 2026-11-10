# M5-24 Admin UI: custom checks
Milestone: M5
Branch: feature/m5-24-custom-checks-ui
Files in scope: app/web/custom_checks.py, app/web/__init__.py (router include), templates (coder names), tests/web/test_custom_checks_ui.py, locales/en.json, locales/it.json
Out of scope: API changes; http_fetch (shown as disabled/"coming in a later release" only, not selectable).
Depends on: M5-23
Parallel-safe: no (router registry and locale files)
Model: sonnet
Acceptance criteria:
- Form builds a definition for the three DNS kinds (kind, record type, name template, regex or range, severity, en + it remediation); global vs tenant sections as in M5-19; "Test on domain" uses the M5-23 dry-run.
- `http_fetch` option is disabled in the UI and rejected server-side if posted directly (test).
- Server-side permission tests (analyst, client viewer, other-tenant admin direct posts denied; service not invoked); CSRF; XSS test on name, regex, remediation text and evidence.
- Both locales; i18n scan passes.
New i18n keys: web.custom_checks.title, .tab.global, .tab.tenant, .field.*, .kind.*, .kind.http_fetch_unavailable, .test.*, .flash.* (coder lists final set) (en + it)
Status: in-review
