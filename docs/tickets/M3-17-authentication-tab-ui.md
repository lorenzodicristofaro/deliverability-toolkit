# M3-17 Domain page "Authentication" tab
Milestone: M3
Branch: feature/m3-17-authentication-tab
Files in scope: app/web/authentication.py, app/main.py (router registration only), app/web/templates/domains/detail.html (tab bar link only), app/web/templates/domains/authentication.html, app/web/templates/checks/_result.html, app/web/static/js/dkim_stream.js (tiny EventSource client, if static JS is needed), locales/en.json, locales/it.json (checks.* keys), tests/web/test_authentication_tab.py, tests/tenancy/ (route classification)
Out of scope: ESP/Reputation/History tabs, persistence, DKIM stream route itself (M3-16)
Depends on: M3-15, M3-16
Parallel-safe: no (main.py, locale files, detail.html)
Model: sonnet
Acceptance criteria:
- `GET /domains/{domain_id}/authentication` renders SPF and DMARC results server-side (via the M3-02 service, same objects as the API) and mounts the DKIM stream from M3-16; gated by `Action.CHECK_RUN`; tab bar added to the domain detail page (only the Authentication link now; other tabs come later).
- Each finding shows severity, translated title/detail/remediation via `t(finding.title_key, **params)`; evidence escaped; docs link only if https; status badge for `ok|warn|fail|info|error`, with `error` clearly distinct ("could not evaluate", not "missing").
- Language en and it both render without missing-key fallbacks (test with both).
- Works without JS for SPF/DMARC; DKIM streaming uses native `EventSource` from a same-origin static file (HTMX under CSP `script-src 'self'` is UNVERIFIED, M1-16, so do not depend on it); non-JS fallback shows a link to the REST result or a noscript note.
- Client viewer: sees the tab for assigned domains, 403/404 page for others; analyst/admin/owner all domains; tenancy/permission tests for the route.
New i18n keys: checks.tab.authentication, checks.status.{ok,warn,fail,info,error}, checks.severity.*, checks.spf.title, checks.dmarc.title, checks.dkim.title, checks.run_again (en + it)
Status: done
