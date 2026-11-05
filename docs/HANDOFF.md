# HANDOFF — 2026-11-06 (end of M2)

Resume with `/gm`.

## State
- M2 accepted 2026-11-06: M2-01..M2-15 done, CI green on PG at 8083cc5, `dev` merged into `qa`. Report: docs/reports/M2.md.
- Next milestone: M3 — SPF, DKIM, DMARC (not yet split into tickets).

## Open maintainer decisions
- `qa` → `main` promotion of M1 and M2: maintainer only.
- SecLists password list: xato.net dataset terms unverified (before public release).
- HTMX under CSP `script-src 'self'`: unverified (M1-16); M2 UI uses no JS.
- Cleanup: stale worktrees in .claude/worktrees/ and old local branches (agent worktrees start at origin/main, see memory worktree-base-stale).

## Next 3 steps
1. `/gm` → have pm split M3 into tickets (SPF/DKIM/DMARC parsers build on app/dns lookup service; TXT via join_txt_strings, latin-1 lossless).
2. Schedule the DNS-tools follow-ups before any shared deployment: per-user rate limit + global concurrency cap.
3. Ask the maintainer to start Docker locally, so PG tests run before merge (memory pg-tests-ci-only).
