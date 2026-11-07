# M5-13 Content rules engine (regex/keyword, weights, categories, language)
Milestone: M5
Branch: feature/m5-13-rules-engine
Files in scope: app/services/content_rules_engine.py, tests/services/test_content_rules_engine.py
Out of scope: persistence (uses repositories from M5-05), admin API/UI, findings text (M5-14).
Depends on: M5-03, M5-05
Parallel-safe: yes (new service file; disjoint from other M5 tickets of this wave)
Model: opus (executes admin-supplied regexes on user content)
Acceptance criteria:
- `evaluate_rules(rules, *, subject, text, html_visible_text, language_hint, limits) -> RuleResults`: only enabled rules whose `language` is NULL or equals the hint; keyword rules (case-folded, word-boundary option) and regex rules; every regex goes through `app.core.safe_regex` (M5-03) with the enforced timeout; no direct `re` use on rule patterns (test greps the module).
- A timed-out or invalid rule yields a per-rule result `error` (never `ok`, never silently skipped) and does not stop the others; total time budget across all rules enforced; over budget -> remaining rules `error`/`not_evaluated`.
- Score: sum of weights of matched rules, capped, grouped by category; deterministic ordering of results (by weight, then rule id).
- Evidence is a bounded snippet (length-capped, control chars stripped), never the full body.
- Tenant merge: global rules + tenant rules; a tenant rule with the same `seed_key`/name may disable a global one for that tenant only (coder states the rule; tenant rules cannot affect other tenants). Tested with two tenants.
- Table-driven tests: catastrophic pattern rule -> that rule `error`, others fine, wall time bounded; language filter; disabled rules; unicode folding; empty input; 1 MB input (capped).
New i18n keys: none
Status: todo
