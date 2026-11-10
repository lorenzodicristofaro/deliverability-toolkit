# M5-23b DKIM provider visible to client viewers
Milestone: M5
Branch: feature/m5-23b-dkim-provider-for-viewers
Files in scope:
- app/services/dkim_probe_selectors.py (resolve name -> provider map from the tenant repository; ProbeSelectors gains it)
- app/checks/dkim.py (SelectorResult / `_selector_data` carry an optional provider, never notes)
- app/api/v1/checks.py (domain DKIM result for the caller, tenant-scoped)
- app/web/checks_stream.py (SSE `_row`, `dkim_events` accept the map)
- app/web/templates/checks/_dkim_row.html (render provider when present)
- locales/en.json, locales/it.json (only the keys below; shared files, serialize)
- tests/services/test_dkim_probe_selectors.py, tests/checks/test_dkim_check.py, tests/api/test_checks_api.py, tests/api/test_dkim_selector_wiring.py, tests/web/test_checks_stream.py, tests/tenancy/ (matrix entry only if a route changes)
Out of scope: admin pages and REST of `/dkim-selectors` (admin only, unchanged), the free route and CLI `check` (tenant-less, seed only), seed sync, models, migrations, notes in any viewer-reachable surface.
Depends on: M5-23
Parallel-safe: no (locale files, shared check and stream code)
Model: opus
Context:
- Maintainer decision 2026-11-10, overrules the earlier GM decision: in DKIM results for an assigned domain a client viewer sees the selector name AND the provider; `notes` stays admin-only.
- Finding: no redaction code exists today. DKIM results (`app/checks/dkim.py` `_selector_data`, `app/web/checks_stream.py` `_row`) carry selector names only; provider and notes are exposed only by the admin surfaces (`app/api/v1/dkim_selectors.py:131-133`, `app/web/dkim_selectors.py`). So the work is to ADD provider to results for every caller that may see the domain, not to remove a filter. The coder must confirm this by grep before starting and report if a redaction exists elsewhere.
- Provider comes from the tenant repository rows (`all_visible` in `dkim_probe_selectors.py`); a seed-file fallback (no global rows) may use the seed `provider` field (None for unverified entries). Provider value comes from stored data, so escape it on render like selector names (see `test_hostile_selector_name_is_escaped`).
Acceptance criteria:
- A client viewer on its assigned domain sees the provider next to the selector name for global selectors, in the API result and in the SSE stream.
- Same for a selector owned by the viewer's own tenant.
- A selector with no provider (null) renders without one, no placeholder text invented.
- `notes` never appears in any API body, SSE event or HTML fragment reachable by a viewer (assert on the raw response text).
- Admin and tenant admin results are unchanged except that provider is present like for viewers (no admin-only field added or removed).
- No cross-tenant leak: a tenant row of tenant A (name and provider) never appears for tenant B, on API or SSE; test with the same selector name under two tenants with different providers.
- A disabled row contributes no provider and no probe; when an enabled tenant row and an enabled global row share a name, the tenant row's non-empty provider wins (GM decision 2026-11-10: more specific, shown only inside that tenant); an empty tenant provider falls back to the global one. State the rule in the module docstring and test both cases.
- Tenancy/permission tests on every affected surface: API domain check (viewer assigned 200, viewer unassigned 404, foreign tenant 404, no active tenant 404), web SSE stream (same matrix), plus the new content assertions above.
- Free route and CLI `check` output unchanged.
- Unit tests stay offline; ruff, mypy and the relevant tests green, including the PostgreSQL params if local PG is up.
New i18n keys: only if the row template needs a visible provider label, e.g. web.checks.dkim.provider (en + it); no hardcoded text. The coder lists the final keys in the PR.
Status: in-review
