# M1-16 Base templates, static assets, dark mode, language switch
Milestone: M1
Branch: feature/m1-16-base-templates-dark-mode
Files in scope: app/web/templating.py, app/web/templates/base.html, app/web/static/app.css, app/web/static/theme.js, app/main.py (static mount, template setup, catalogue validation in lifespan), app/core/i18n.py (validate_catalogues + Accept-Language length cap only), tests/test_i18n.py (extend), locales/en.json, locales/it.json, pyproject.toml, uv.lock, tests/web/test_templating.py
Out of scope: login/landing/domain pages, HTMX/Alpine vendoring beyond what the base needs, SSE, branding (M10)
Depends on: M1-09
Parallel-safe: no (app/main.py, pyproject)
Model: sonnet
Acceptance criteria:
- QA follow-up from M1-09: `validate_catalogues()` in app/core/i18n.py eager-loads every SUPPORTED_LANGUAGES locale file and is called from the app lifespan, so a missing or invalid locale file aborts startup; test with LOCALES_DIR pointed at an empty dir. `parse_accept_language` truncates the header to 4 KB before parsing; test it.
- Jinja2 environment with autoescape on, a `t()` global bound to the request language (M1-09), `csrf_token()` helper (stubbed until M1-14 merges; wire when available).
- `base.html`: lang attribute, nav slots, theme toggle. CSS with variables, light/dark via `prefers-color-scheme` plus a persisted user override; contrast target WCAG AA for the default palette (state how checked; do not claim an automated audit that was not run).
- No inline scripts or inline styles (CSP from M1-14): `theme.js` is a static file. No CDN, no Node toolchain; any vendored lib is listed with version and licence (AGPL-compatible) or omitted.
- Language switch via query/POST sets a cookie; resolution order from M1-09.
- Tests: template renders in en and it, escapes injected markup, no `<script>` without `src`, static files served, missing translation key fails the test.
- Keyboard focus styles visible; skip-link present.
- Confirm HTMX works under the CSP `script-src 'self'` with no unsafe-inline, against the official HTMX docs (e.g. its indicator-style config). If it cannot be confirmed, record it as unverified in the ticket outcome.
- Error pages (404/500) are translated via i18n keys.
- Templates get the token through `csrf_token_for()` (M1-14).
New i18n keys: ui.nav.home, ui.nav.logout, ui.theme.toggle, ui.theme.light, ui.theme.dark, ui.language.label, ui.skip_to_content (en + it)
Status: todo
