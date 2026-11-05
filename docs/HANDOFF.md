# HANDOFF — 2026-11-05 (end of M1)

Resume with `/gm`.

## State
- M1 accepted 2026-11-05: all of M1-01..M1-20 done, CI green on PG at d2e5e4a, `dev` merged into `qa`. Report: docs/reports/M1.md.
- Next milestone: M2 — DNS engine (not yet split into tickets).

## Open maintainer decisions
- Domain name rules: DECIDED 2026-11-05 (single-label, numeric TLD, underscore rejected for tenant domains; underscores allowed in DNS-tool record names; trim surrounding whitespace). Implement the trim as the first M2 ticket or a small fix.
- SecLists password list: the xato.net dataset terms are unverified (before public release).
- HTMX under CSP `script-src 'self'`: unverified (M1-16).
- `qa` → `main` promotion of M1: maintainer only.
- Cleanup: stale worktrees in .claude/worktrees/ and local branch feature/m1-13-auth-core (the auto-mode classifier denied removal).

## Next 3 steps
1. `/gm` → have pm split M2 into tickets; review them.
2. Prioritise the post-M1 follow-ups before any reverse-proxy or multi-process deployment (trusted proxy, DB throttle).
3. Ask the maintainer to start Docker locally, so PG tests run before merge (memory pg-tests-ci-only).
