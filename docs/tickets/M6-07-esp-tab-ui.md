# M6-07 Domain page ESPs tab
Milestone: M6
Branch: feature/m6-07-esp-tab-ui
Files in scope: app/web/domain_esps.py, app/web/__init__.py (router registration only), app/web/templates/domains/ (new ESPs tab and fragment templates; coder checks the existing tab layout from M3-17), tests/web/test_domain_esps_ui.py, locales/en.json, locales/it.json
Out of scope: REST changes, check logic, profile content, new permissions
Depends on: M6-03, M6-06
Parallel-safe: no (web router registry, locale files)
Model: sonnet (UI over an existing service; QA on Opus because it renders tenant data and untrusted DNS text)
Acceptance criteria:
- Domain page tab "ESPs" (SPEC section 6): lists assigned ESPs with name, profile status and `verified_on`, a form to attach an ESP from the catalogue (with optional return-path and tracking hostnames) and a remove control; a button runs the `esp` check and shows its findings through the existing findings renderer, grouped per ESP.
- Uses the M6-03 service, never a repository or session directly; CSRF on every mutating form as other pages; viewers and users without `domain.update` see no mutating controls and get 403 on direct POSTs; client viewers do not get the tab (403 on the URL).
- Profile and DNS-derived text is autoescaped; no raw HTML; all labels through i18n; the unverified badge and sources links (https only) are shown for unverified profiles.
- Tests: render per role, tenant isolation (tenant B domain id gives 404), CSRF missing gives the standard error, XSS payload in a hostname or DNS evidence is escaped.
New i18n keys: web.domain.esps.title, .empty, .attach, .remove, .run, .host_return_path, .host_tracking, .unverified, .sources, .error (en + it)
Status: todo
