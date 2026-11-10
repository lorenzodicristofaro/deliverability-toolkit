# HANDOFF — 2026-11-10 (M6 in progress)

Resume with `/gm`. Written after the 5-hour usage limit hit two coders mid-start (M6-07, M6-13b); nothing of theirs was committed.

## State
- M1–M5 accepted; `qa` → `main` pending the maintainer for M1–M5.
- Local-only until 2026-12-21 (no pushes). Local `dev` is the gate with the full PostgreSQL suite.
- M6 done on local dev (d0c38e6, last gate 29779 passed): M6-00, 01, 02, 03, 04, 05, 06, 06b, 06c, 12, 13.
- M6 open: M6-13b (DKIM detection probes bounded + fail-fast; must merge before M6-08..10), M6-07 (ESPs tab UI, Sonnet coder, Opus QA), M6-08/09/10 (real vendor profiles, serialize: locales), M6-11 (acceptance tests).
- Maintainer decision 2026-11-10: client viewers read ESP data on assigned domains (assigned + detected ESPs + full `esp` result), no writes; SPEC §3 updated.

## How the work runs now (maintainer decisions 2026-11-09)
- Sonnet → Opus: once Sonnet code fails (QA, tests or CI), all further coder work on that ticket goes to a NEW coder on Opus (docs/WORKFLOW.md section 3).
- QA on Sonnet only for low-risk Sonnet tickets; Opus for auth, permissions, tenancy, parsers, untrusted input.
- Coder runs relevant tests only (full suite if shared fixtures or app-wide code change); QA runs the full suite once, on the final round; GM runs it on the merge result.
- Local PostgreSQL: container `dt-test-pg` (Docker Desktop must be running). Prefix each pytest with `TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test`. One suite at a time. The full suite takes about 10 minutes, so run the merge gate in the background.
- CI runs `lint`, `test-sqlite`, `test-postgres` in parallel. Docs-only pushes skip the tests; `secret-scan` still runs.
- Agent worktrees start stale: give each coder the exact `dev` hash.
- After a merge, check CI, then close the ticket and tick TODO.md.

## GM decisions this session
- CLI: `--tenant-id`/`--user-id` through `app/cli/tenant_scope.py` (maintainer choice); they are not authentication.
- `dtk content`: `ok` with `complete` false exits 1, so a run without `--eml` never exits 0.
- Seeded global rule: DELETE is 409 (disable it instead); any accepted PATCH pins it against seed updates.
- M5-16 criteria reworded: rule results grouped by category, findings flat by severity.
- DKIM selectors: tenant-scoped surfaces probe enabled global plus tenant rows; free checks and CLI `check` stay on the seed. Caps: 50 per tenant, 200 global, 250 merged at probe time. Seed sync adopts an unseeded global row by name.
- DKIM results show selector name and provider to every role, notes never (maintainer decision 2026-11-10, M5-23b).

## Open maintainer decisions
- SPEC §5 still lists HTTP custom checks; `http_fetch` is deferred to M7 (M5-22). The wording needs the maintainer.
- Check GitHub branch protection: if `lint-test` is required, replace it with `lint`, `test-sqlite`, `test-postgres`.
- Gmail clipping and URL shorteners unverified (t.co, tinyurl.com, ow.ly, buff.ly, lnkd.in, is.gd, j.mp).
- Carried over: M4 provider samples; `qa` → `main` for M1–M4; Mailchimp/Postmark/HubSpot DKIM sources; the PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. Run M6-13b (opus) and M6-07 (sonnet, QA opus) in parallel from dev d0c38e6; merge each with a full PostgreSQL gate.
2. Then M6-08, 09, 10 one at a time (official sources only; unverified → ask the maintainer), then M6-11.
3. Milestone end: full suite on dev, report docs/reports/M6.md; maintainer items in TODO.md (ESP overrides deferred, Italian profile notes review, flaky timing tests).
