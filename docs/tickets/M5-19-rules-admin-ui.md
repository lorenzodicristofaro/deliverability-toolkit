# M5-19 Admin UI: content rules (global/tenant tabs, test on sample)
Milestone: M5
Branch: feature/m5-19-rules-ui
Files in scope: app/web/rules.py, app/web/__init__.py (router include), templates for list/edit/test partial (coder names), tests/web/test_rules_ui.py, locales/en.json, locales/it.json
Out of scope: API changes, DKIM selectors/custom checks UIs.
Depends on: M5-18
Parallel-safe: no (router registry and locale files)
Model: sonnet
Acceptance criteria:
- List with global (read-only unless instance admin) and tenant sections; create/edit/enable-disable/delete; "Test on sample" panel posting to the same service as the API; shows matches or "timed out" / "invalid pattern" messages localized.
- Buttons shown only when permitted, but permission is enforced server-side regardless (tests post directly as analyst / client viewer / other-tenant admin -> denied, service not invoked).
- CSRF on every mutating form; XSS test with `<script>` in pattern, name, category and sample (escaped everywhere, including the match snippets).
- Unverified seed rows display an "unverified" badge; verified rows show `verified_on` and sources.
- Both locales; i18n scan passes.
New i18n keys: web.rules.title, .tab.global, .tab.tenant, .col.*, .action.*, .test.title, .test.run, .test.timed_out, .test.invalid, .badge.unverified, .flash.* (coder lists final set) (en + it)
Status: todo
