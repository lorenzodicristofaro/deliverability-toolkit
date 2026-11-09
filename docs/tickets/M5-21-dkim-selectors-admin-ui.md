# M5-21 Admin UI: DKIM selectors
Milestone: M5
Branch: feature/m5-21-dkim-selectors-ui
Files in scope: app/web/dkim_selectors.py, app/web/__init__.py (router include), templates (coder names), tests/web/test_dkim_selectors_ui.py, locales/en.json, locales/it.json
Out of scope: API changes, rules and custom-check UIs.
Depends on: M5-20
Parallel-safe: no (router registry and locale files)
Model: sonnet
Acceptance criteria:
- Global and tenant sections, add/edit/enable-disable/delete with name, provider, notes; global editing shown only to instance admin.
- Server-side permission tests posting directly as analyst, client viewer and another tenant's admin (denied; service not invoked); CSRF on all forms; XSS test on provider and notes.
- Both locales; i18n scan passes.
New i18n keys: web.dkim_selectors.title, .tab.global, .tab.tenant, .col.*, .action.*, .flash.* (coder lists final set) (en + it)
Status: done
