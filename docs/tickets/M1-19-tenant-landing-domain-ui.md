# M1-19 Tenant landing page and domain management UI
Milestone: M1
Branch: feature/m1-19-landing-domain-ui
Files in scope: app/web/deps.py, app/repositories/__init__.py, app/web/landing.py, app/web/domains.py, app/web/templates/landing.html, app/web/templates/domains/ (list, form, detail stub), app/main.py (router registration), locales/en.json, locales/it.json, tests/web/test_landing.py, tests/web/test_domains_ui.py
Out of scope: traffic-light status, SPF/DKIM/DMARC summaries and trends (M3+; placeholders say "not checked yet" via i18n), domain page tabs beyond a stub, free tools menu
Depends on: M1-16, M1-18
Parallel-safe: no (app/main.py, locales)
Model: sonnet
Acceptance criteria:
- `/` (authenticated) renders the tenant landing: one row per domain visible to the user, with last-check column as an empty-state; empty-state when no domains; tenant name and switcher shown when the user has several memberships.
- Add, rename and delete domain forms use the M1-18 service and `can()`; buttons for actions the role lacks are not rendered (and the endpoints still enforce, tested).
- Client viewer sees only assigned domains on the landing and cannot open an unassigned domain URL (404) nor the add/delete forms (403/absent).
- Tenancy/permission tests for every route: anonymous redirects to login, tenant A user gets 404 for tenant B domain pages, viewer limits.
- All text via keys, both languages rendered in a test; markup escaped (domain name with HTML chars test).
- `/` is a real route (setup redirects to it after creating the admin): an authenticated GET returns 200, anonymous redirects to login or setup; test that the post-setup redirect lands on a 200 page.
- Move client-viewer assigned-domain loading into app/web/deps.py (the M1-18 service does it inline now).
- Register the domain repositories in `repo_for` (app/repositories/__init__.py).
- Show the A-label (xn--) next to the Unicode display name, and flag mixed-script names (UTS #39 lookalikes). Record any library choice with name, version and licence, or mark it unverified.
- Verify "/" is registered as a real route (check it is there).
New i18n keys: landing.title, landing.empty, landing.domain.name, landing.domain.last_check, landing.domain.never_checked, domain.add, domain.add.submit, domain.delete, domain.delete.confirm, domain.rename, domain.detail.title, domain.access.title (en + it)
Status: todo
