# HANDOFF — 2026-11-10 (M5 accepted)

Resume with `/gm`. Written as a safeguard: the 5-hour usage limit has been hit three times on this milestone.

## State
- M1–M5 are accepted (M5 on 2026-11-10, report docs/reports/M5.md); `qa` → `main` is pending the maintainer for M1–M5.
- `dev` promoted to `qa` at 101d43b (tree identical to dev 3bb1eb8, dev CI 42846313400 green). qa CI run 42848145136 was left running (token cannot cancel).
- Local-only until the Actions minutes renew on 2026-12-21 (maintainer decision 2026-11-10): no pushes; commit locally; the local PostgreSQL suite is the gate. Then batched pushes (docs/WORKFLOW.md push policy). M6-00 (CI minutes) must be verified by the first push after 2026-12-21.
- M6-00 (CI minutes) merged locally (b94793e). Local `dev` is ahead of origin by several commits; they go out with the first push after 2026-12-21. The rest of M6 (ESP profiles) is not split yet.

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
1. `pm` splits M6 (ESP profiles) into tickets after M6-00; GM reviews them. ESP facts need official sources, otherwise `unverified` and ask the maintainer.
2. Work locally only: merge each ticket into local `dev` with the full PostgreSQL suite as the gate; no pushes before 2026-12-21.
3. Maintainer items: SPEC §5 wording (http_fetch moved to M7), the branch protection check, unverified seeds and shorteners, `qa` → `main` for M1–M5.
