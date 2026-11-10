# M6-07 Domain page ESPs tab
Milestone: M6
Branch: feature/m6-07-esp-tab-ui
Files in scope: app/web/domain_esps.py, app/web/__init__.py (router registration only), app/web/templates/domains/ (new ESPs tab and fragment templates; coder checks the existing tab layout from M3-17), tests/web/test_domain_esps_ui.py, locales/en.json, locales/it.json
Out of scope: REST changes, check logic, profile content, new permissions
Depends on: M6-03, M6-06, M6-06b, M6-06c, M6-13
Parallel-safe: no (web router registry, locale files)
Model: sonnet (UI over an existing service; QA on Opus because it renders tenant data and untrusted DNS text)
Acceptance criteria:
- Domain page tab "ESPs" (SPEC section 6): lists assigned ESPs with name, profile status and `verified_on`, a form to attach an ESP from the catalogue (with optional return-path and tracking hostnames) and a remove control; a button runs the `esp` check and shows its findings through the existing findings renderer, grouped per ESP.
- Uses the M6-03 service, never a repository or session directly; CSRF on every mutating form as other pages; viewers and users without `domain.update` see no mutating controls and get 403 on direct POSTs. Client viewers (maintainer decision 2026-11-10, M6-06c) see the tab read-only on domains assigned to them: assigned ESPs, the `esp` check result, and the ESPs detected in DNS but not assigned (M6-13), flagged as possible stale configuration; no attach, edit or remove controls and no run-write actions; unassigned or foreign domains give 404.
- Profile and DNS-derived text is autoescaped; no raw HTML; all labels through i18n; the unverified badge and sources links (https only) are shown for unverified profiles.
- Detected-not-assigned ESPs (ESP_DETECTED_NOT_ASSIGNED findings) are listed in their own section of the tab with the evidence and the hint, for every role that can read the tab.
- Tests: render per role (including client viewer read-only: no forms or buttons that mutate, detected ESPs shown), tenant isolation (tenant B domain id gives 404), CSRF missing gives the standard error, XSS payload in a hostname or DNS evidence is escaped.
New i18n keys: web.domain.esps.title, .empty, .attach, .remove, .run, .host_return_path, .host_tracking, .unverified, .sources, .error (en + it)
Status: done (merged into local dev after QA APPROVE; DNS-evidence XSS regression test moved to TODO follow-ups; GM gate full PostgreSQL suite on the combined merge)
