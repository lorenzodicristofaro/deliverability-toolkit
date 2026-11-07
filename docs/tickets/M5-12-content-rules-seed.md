# M5-12 content_rules seed and sync
Milestone: M5
Branch: feature/m5-12-content-rules-seed
Files in scope: seeds/content_rules.yaml, the knowledge loader/schema entry for it (follow the dkim_selectors pattern; coder names files), app/services/seed_sync.py (extend, from M5-06), app startup hook already used for dkim seed sync, tests/knowledge/test_content_rules_seed.py, tests/services/test_seed_sync.py
Out of scope: engine (M5-13), admin UI, any vendor spam-word list.
Depends on: M5-05, M5-06
Parallel-safe: no (touches seed_sync shared with M5-06 and the startup hook)
Model: sonnet
Acceptance criteria:
- Seed is SMALL. Only rules that are structural or have an official source (e.g. URL in visible text that differs from href is handled by M5-09, not here). Each rule has: key, kind, pattern, weight, category, language, enabled, `verified_on`, `sources` (URL list), `status: verified|unverified`. Anything the coder cannot source is `unverified` and `enabled: false`; the PR summary lists them for the maintainer to confirm. NO invented vendor/ISP spam-word lists; generic examples (e.g. shouting punctuation patterns) are marked `unverified` heuristics.
- CI schema validation: unknown keys rejected, `verified_on` not in the future (host-clock tolerance noted in Follow-ups), sources required for `verified`, every regex compiles via `compile_checked` (M5-03 must be merged first; if not, coder adds only a TODO test and says so), language codes valid.
- Sync into `content_rules` global rows is idempotent, keeps admin edits (same `locally_modified` rule as M5-06), disables rows removed from the seed, never touches tenant rows.
- Tests: schema negative cases, sync idempotency, admin edit preserved, removed row disabled.
New i18n keys: none (rule names/explanations live in the seed; en + it text fields `title`/`advice` required per rule so the UI needs no key)
Status: todo
