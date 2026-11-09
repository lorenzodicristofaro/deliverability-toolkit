# HANDOFF — 2026-11-10 (M5 in progress)

Resume with `/gm`. Written as a safeguard: the 5-hour usage limit has been hit three times on this milestone.

## State
- M1–M4 are accepted; `qa` → `main` is still pending the maintainer.
- M5 done with green CI: M5-01..M5-21, plus M5-05b, M5-15b, M5-15c, M5-15d (tried, no gain, reverted), M5-17a, M5-17b.
- M5-22 (custom checks schema and DNS evaluator): branch `feature/m5-22-custom-checks-eval`, commit d941950, base 6e322eb, worktree `.claude/worktrees/agent-aead13de42f239dfb`. Written by Opus (GM choice). QA round 1 was cut off by the usage limit before any verdict; merge only on APPROVE.
- `dev` local may be ahead of `origin/dev` by bookkeeping commits, which go out with the next push.

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
- A client viewer sees selector names (not provider or notes) in DKIM results for an assigned domain. The maintainer may overrule this.

## Open maintainer decisions
- SPEC §5 still lists HTTP custom checks; `http_fetch` is deferred to M7 (M5-22). The wording needs the maintainer.
- Check GitHub branch protection: if `lint-test` is required, replace it with `lint`, `test-sqlite`, `test-postgres`.
- Gmail clipping and URL shorteners unverified (t.co, tinyurl.com, ow.ly, buff.ly, lnkd.in, is.gd, j.mp).
- Carried over: M4 provider samples; `qa` → `main` for M1–M4; Mailchimp/Postmark/HubSpot DKIM sources; the PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. M5-22: finish QA round 1 (Opus), merge on APPROVE, run the gate with PostgreSQL, push, check CI, close it.
2. M5-23 (opus) and M5-24 in order (TODO.md). From M5-22 for M5-23: a global row with only `remediation_key` yields a finding with no remediation text; `app/models/custom_check.py` docstring still says the service layer validates.
3. M5-25 acceptance tests and docs/CONTENT.md (must state the `--lang`/`--output-lang` difference and that a run without `--eml` exits 1), then the M5 report and `dev` → `qa`.
