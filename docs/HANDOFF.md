# HANDOFF — 2026-11-14 (M7 in progress, paused on maintainer request)

Resume with `/gm`. Milestone **M7 — Monitoring**, 22 tickets in docs/tickets/M7-*.md, list in TODO.md (dependency order).

## Done this session (all QA APPROVE, merged into dev)
- M7-00 CI speed: pytest-xdist, one DB per worker. Dev CI test jobs 12.9 -> 6.1 min (PG), 11.4 -> 5.5 min (SQLite).
  test_csrf.py / test_security.py run in a separate single-process step (random param ids).
- M7-01 guarded outbound HTTP client `app/net/` (anti-SSRF, httpx2, IP pinning via `sni_hostname`); ARCHITECTURE §9.
- M7-03 DNSBL engine, M7-03b bitmask codes + `default_enabled`, M7-04 `seeds/dnsbl.yaml` (spamcop, surbl, uribl;
  all `unverified`, all disabled by default), M7-05 `dnsbl` check in API/CLI/web, M7-05c instance-admin enablement
  (`/dnsbl-lists`, migration 0010; CLI with unreadable enablement -> error, exit 2).

## State
- `dev` at the commit carrying this file (merge bbdb6a5 + docs). `qa` at 55bc152, not promoted (milestone open). `main` unchanged.
- Local test PostgreSQL `dt-test-pg` was running this session.

## Maintainer decisions (2026-11-14)
- Lists with restrictive usage policies are disabled by default; the admin enables them after acknowledging the policy.
- Spamhaus only via the operator's own DQS key (M7-05b, after M7-14b).
- SpamCop and Barracuda: keep disabled / out of the seed, investigate later (TODO.md follow-up has what was found).
- Earlier GM decisions: notification SMTP relay is trusted operator infra (M7-16); no private webhook targets in M7.

## Open maintainer actions
- None blocking. Later: official Barracuda BRBL page text; SpamCop IPv6/usage terms.

## Next 3 steps
1. M7-14b secret encryption service (opus, no deps): unblocks M7-15 and M7-05b.
2. M7-06 monitor_targets model (sonnet), then M7-07 / M7-08 / M7-09 in order (migrations: serialize).
3. M7-02 http_fetch custom check (opus; depends only on M7-01) whenever a slot is free.

## Notes
- Agent worktrees: tell coders the dev hash and to `git checkout -B <branch> <hash>` (worktrees start at origin/main).
- Push alone, never in a compound command. Commits touching `.github/workflows/` are pushed by the maintainer.
- Low follow-ups added to TODO.md: flaky-candidate test_fold_bomb_is_bounded_and_fast; stable ids for csrf/security
  tests; worker DB name length; wall-clock tests under xdist; shared loader helpers for dnsbl_schema; nav link to
  /dnsbl-lists; private webhook allowlist (possible).
