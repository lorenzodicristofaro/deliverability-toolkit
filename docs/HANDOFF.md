# HANDOFF — 2026-11-07 (M5 in progress, paused for usage limits)

Resume with `/gm`. The session was paused at the maintainer's request because weekly usage reached 94%.

## State
- `dev` is at 6c067f0. CI is green there, including PostgreSQL. M1–M4 are accepted; `qa` → `main` is still pending the maintainer.
- M5 is 12 of 26 tickets done, all merged into `dev` with QA APPROVE and green CI: M5-01..M5-11 and M5-05b.
- **M5-12 is parked.** It is on branch `feature/m5-12-content-rules-seed` in worktree `.claude/worktrees/agent-a9f625099ac8e60f3`, at WIP commit 6f25ef4. That commit holds a partial `seeds/content_rules.yaml` and `app/checks/content_rules_seed.py`. It was committed with `--no-verify` and has not been reviewed or tested. The coder stopped on the 5-hour limit before the i18n keys, the sync, the startup wiring and the tests.
  - To resume, start a coder (Opus) on that worktree: tell it to review the WIP, run the pre-commit hooks, and finish the ticket including its GM notes.
- Next tickets after M5-12: M5-13 rules engine (Opus), then M5-14 analysis service, then M5-15..M5-25 in order (see TODO.md).

## GM decisions this session (2026-11-07)
- HTTP-fetch custom checks move to M7, because they need the guarded client; the M5-22 coder updates ARCHITECTURE/TODO. M5 ships the DNS kinds only.
- ReDoS guard: stdlib `re` runs in a killable subprocess. `search_many` uses one worker per text, live workers are capped at 4 per OS process, and a busy pool returns BUSY with complete=False. All rules must be built with `compile_checked`.
- Permissions: `rules.read` is tenant-scoped; global rules are managed with `rules.manage(GLOBAL)` by instance admins only. Tenant toggles never restrict the global scope.
- `content_rules`:
  - Seeded rules take their text from i18n keys `CONTENT_RULE.<seed_key>.title/.advice`. Admin-written rules store title and advice in DB columns.
  - `sources` is a JSON list.
  - A tenant override must reference an existing global seed_key. Seed entries removed from the YAML are disabled, never deleted.
- Index pattern for every scoped table: a non-partial unique `(tenant_id, key)` plus a partial global unique index. Never a partial tenant index, because it triggers a SQLite planner bug (fixed in M5-05b).
- `custom_checks`: `remediation_key` is global-only, and every check needs exactly one remediation source.
- Seed sync failures at startup are logged and must not block startup (M5-12 wires this).
- The maintainer allowed the GM to use Opus over a ticket's Sonnet when needed. Applied to M5-09, M5-10, M5-12, and M5-11's second round.
- The maintainer approved a third QA round for M5-08; the round-2 regression came from a GM request.

## Open maintainer decisions
- URL shorteners still unverified (seeds/url_shorteners.yaml): t.co (help.x.com returned 403), tinyurl.com, ow.ly, buff.ly, lnkd.in, is.gd, j.mp.
- The M5-12 seed: when it is finished, its unverified/disabled rules need your confirmation.
- Carried over from earlier: M4 provider samples; `qa` → `main` for M1–M4; Mailchimp/Postmark/HubSpot DKIM sources; the PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. Finish M5-12 from the parked worktree (Opus coder, then QA). Merge, push `dev`, and wait for CI.
2. M5-13, the rules engine (Opus). It uses `safe_regex.search_many` and must run it in a thread pool from async code.
3. M5-14, the content analysis service. It must use `unaligned_count`/`unevaluated_count` from M5-09, and the One-Click facts from M5-10 (`post_value_exact`, `nonstandard_authority`).
