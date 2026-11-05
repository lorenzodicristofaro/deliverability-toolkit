# M2-13 DNS tools web UI: shell, lookup and reverse
Milestone: M2
Branch: feature/m2-13-dns-tools-ui
Files in scope: app/web/dns_tools.py, app/web/templates/dns/ (index.html, lookup_result.html, reverse_result.html), app/web/templates/base.html (nav link only, shown only with the permission), app/main.py (router registration), app/web/landing.py, app/web/static/app.css, app/web/templating.py, app/web/deps.py (nav flag), locales/en.json, locales/it.json, tests/web/test_dns_tools_ui.py, tests/tenancy/ (route classification)
Out of scope: trace and propagation views (M2-14), new JS (CSP is `script-src 'self'`, HTMX status is unverified: plain form POST plus server-rendered result, no inline scripts)
Depends on: M2-11, M2-12
Parallel-safe: no (app/main.py, base.html, locales)
Model: sonnet
Acceptance criteria:
- Page `/tools/dns` (free tools menu): form with name/IP, record type select (incl. "all"), resolver select (default + public list from M2-07, unverified entries labelled), no-cache checkbox; result tables per record type; reverse form. Server-rendered with CSRF token and the same error/denied templates as M1-19.
- Menu entry and page visible only if `can(DNS_TOOLS)`; client viewer gets 403 on the routes and no menu entry; anonymous redirects to login. Tenancy/permission test for every route (non-negotiable).
- Every state has its own message and visual treatment: nxdomain "name does not exist", nodata "name exists but has no record of this type", and servfail/timeout/refused/blocked/malformed/network_error/truncated rendered as "could not be evaluated" with the reason, never as "no record found" (test asserts the strings differ and that servfail never renders the nxdomain/nodata text).
- All text via i18n keys, en + it, both rendered in a test; all record data (TXT contents, names) HTML-escaped (test with `<script>` in a TXT record from the fake). Long TXT values wrapped, not truncated silently.
- Underscore names and IDN input accepted; validation error displayed with a key (not the raw validator text).
New i18n keys (en + it): tools.dns.title, tools.dns.name, tools.dns.type, tools.dns.type.all, tools.dns.resolver, tools.dns.resolver.default, tools.dns.resolver.unverified, tools.dns.no_cache, tools.dns.submit, tools.dns.reverse.title, tools.dns.reverse.ip, tools.dns.reverse.fcrdns.match, tools.dns.reverse.fcrdns.mismatch, tools.dns.reverse.fcrdns.not_evaluated, tools.dns.state.ok, tools.dns.state.nxdomain, tools.dns.state.nodata, tools.dns.state.servfail, tools.dns.state.refused, tools.dns.state.timeout, tools.dns.state.truncated, tools.dns.state.malformed, tools.dns.state.network_error, tools.dns.state.blocked, tools.dns.state.error, tools.dns.invalid_name, tools.dns.invalid_ip, tools.dns.denied, nav.tools.dns
Status: done

GM note 2026-11-06: QA r2 failed (session fallback wrote last_seen_at); maintainer approved a 3rd round; fallback removed. DNS tools nav link shows only on pages that resolve the session (not on /login, 404, setup).
