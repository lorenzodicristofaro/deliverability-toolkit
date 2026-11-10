# M6-05 Combined ESP SPF lookup budget finding
Milestone: M6
Branch: feature/m6-05-esp-combined-spf-lookups
Files in scope: app/checks/esp_profile.py (add one finding), tests/checks/test_esp_profile_spf_budget.py, locales/en.json, locales/it.json
Out of scope: changing `app/checks/spf.py` / `spf_tree.py` behaviour or its results, flattening or generating SPF records (hints only)
Depends on: M6-04
Parallel-safe: no (same module as M6-04, locale files)
Model: opus (SPF logic)
Acceptance criteria:
- Covers SPEC 4.2 "SPF combines three ESPs and exceeds 10 lookups": when two or more ESPs are assigned and the domain's resolved SPF tree exceeds the lookup limit (use the existing counter in the SPF tree, do not recount), emit `ESP_SPF_COMBINED_OVER_LIMIT` with the list of assigned ESPs whose includes are in the tree and the total; at the near-limit threshold used by `SPF_NEAR_LOOKUP_LIMIT` emit a low-severity variant only if that threshold is reusable without duplicating the constant (otherwise skip it and say so).
- Does not fire for a single ESP (the plain SPF check already reports it) and does not duplicate `SPF_TOO_MANY_LOOKUPS` text; it only adds the ESP attribution.
- SPF resolution failure gives `error` (same rule as M6-04), never a clean pass. Truncated tree gives `error` with `SPF_RESOLUTION_TRUNCATED` semantics preserved.
- Table-driven tests with fake DNS: one, two and three ESPs, under and over the limit, nested includes, include loop, DNS error.
New i18n keys: finding.ESP_SPF_COMBINED_OVER_LIMIT.title/detail/remediation (en + it)
Status: done (merged into local dev at b36c9f8 after QA APPROVE; permerror test rows added at ac97c33; GM gate full PostgreSQL suite green, lint clean)
