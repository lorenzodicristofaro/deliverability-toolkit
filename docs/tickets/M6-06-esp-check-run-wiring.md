# M6-06 Wire the ESP check into domain runs + broken-profiles handling
Milestone: M6
Branch: feature/m6-06-esp-check-run-wiring
Files in scope: app/services/checks.py and/or app/api/v1/checks.py (only the seam where custom checks are added via `CheckRegistry.with_checks`; coder inspects first), app/web/checks_stream.py only if the SSE stream builds its own registry, app/services/domain_esps.py, app/api/v1/domain_esps.py, locales/en.json, locales/it.json, tests/api/test_checks_api.py (or the existing domain-run test files, extended), tests for domain_esps (service and API: catalogue, GET list, PUT), tests/tenancy/test_matrix.py (only if routes change)
Out of scope: UI tab (M6-07), check logic (M6-04/05), localized rendering of finding params (M6-06b), free (tenant-less) checks and the CLI `check`, which stay without ESP data
Depends on: M6-03, M6-04
Parallel-safe: no (shared services/api checks seam and locale files, also touched by M5-23 code)
Model: opus (tenant data reaches a check)
Acceptance criteria:
- A run on a tenant domain loads that domain's assignments through the M6-02 repository with the caller's `TenantContext`, builds `EspProfileCheck` from the M6-01 profiles, and adds it with `with_checks`; the `esp` check is included in `all` only when at least one ESP is assigned, and can be requested by id (`esp`) like any check; with no assignment it returns the M6-04 "info, nothing assigned" result.
- Authorization is the existing `check.run` rule; no new route. A tenant's assignments never appear in another tenant's run (two-tenant test).
- Client viewers: on an assigned domain they get the full `esp` result, in `all` and by id, like any role that may run checks there (maintainer decision 2026-11-10, implemented in M6-06c; M6-06 originally shipped it withheld with 403). M6-13 later makes `esp` run in `all` even with no assignment. Their run otherwise follows the existing rules.
- A profile id stored in the DB but missing from the loaded profiles (profile removed or renamed) gives status `error` for that ESP, not a crash and not `ok`.
- A repository or profile-load failure gives `error` for the `esp` check only; other checks in `all` still run. The existing `all` run results for domains without ESPs are byte-equal to before (regression test).
- `esp` is a reserved check id: a custom check named `esp` is rejected (or documented, whichever the code already does); add a test. `DuplicateCheckError` for `esp` cannot happen.
- QA (M6-03): a broken profiles directory must never give a bare 500. Today it does at app/services/domain_esps.py:387, :407 and :411 and app/api/v1/domain_esps.py:76, because `load_esp_profiles` caches only successful loads.
- QA (M6-03): follow the existing pattern: app/services/dkim_probe_selectors.py:93 and app/web/checks_stream.py:204 catch `KnowledgeError` (`EspProfileError` is a subclass) and log a warning.
- QA (M6-03): the ESP routes return a handled, localized 503 with a new key such as `api.domain_esps.error.profiles_unavailable` (en + it).
- QA (M6-03): the ESP check in domain runs returns `error` (not evaluated) in the same case.
- QA (M6-03): tests cover the catalogue, the GET list and PUT.
New i18n keys: `api.domain_esps.error.profiles_unavailable` (en + it; name may vary); reuse M6-04 keys; add `api.checks.error.esp_unavailable` en + it only if the coder needs it
Status: done (merged into local dev at 7c31bc2 after QA APPROVE; GM gate full PostgreSQL suite green, lint clean)
