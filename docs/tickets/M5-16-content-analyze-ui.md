# M5-16 Web UI: content analyzer page (paste / .eml upload)
Milestone: M5
Branch: feature/m5-16-content-ui
Files in scope: app/web/content.py, app/web/__init__.py (router include), templates for the page and result partial (coder names), static JS only if M4-12 pattern needs it (no inline scripts, CSP), tests/web/test_content_ui.py, locales/en.json, locales/it.json
Out of scope: API, CLI, rules admin.
Depends on: M5-01, M5-14, M5-15
Parallel-safe: no (router registry and locale files)
Model: sonnet
Acceptance criteria:
- Page with HTML textarea, text textarea, subject, optional .eml upload (same flow as the M4-12 message UI); results show status, rule results grouped by category, findings flat by severity, per-section status table, evidence escaped. Pasted HTML is NEVER rendered as HTML (escaped only; an optional preview, if any, uses a sandboxed iframe with no scripts; default: no preview).
- Uses the M5-01 localized-413 mechanism: no-JS post over the decoded cap `MAX_RAW_BYTES` (2 MiB) gives the localized 413, not a CSRF 403; `data-max-bytes` equals the server constant (test).
- Permissions: anonymous -> redirect/401 as other pages, client viewer 403, foreign/stale tenant 404; nav entry hidden when not permitted; denial does not invoke the analyzer (spy).
- Result equals the API result for the same input (UI status/codes compare).
- XSS test: `<script>`, `"><img onerror=...>` in html, subject, evidence snippets and rule names are escaped in the response.
- Both locales render; i18n scan test passes.
New i18n keys: web.content.title, .intro, .field.html, .field.text, .field.subject, .field.eml, .submit, .error.too_large, .error.empty, .error.nul_byte, .section.* , .col.* (coder lists final set) (en + it)
GM note (constraints from M5-14): the UI must display `complete`, because overall can be `ok` with complete=False; `rules.facts.complete` is the engine's own value and can differ from the overall one, so show the overall one as the result's completeness.
Status: done
