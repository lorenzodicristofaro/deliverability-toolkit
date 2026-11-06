# HANDOFF — 2026-11-06 (end of M3)

Resume with `/gm`.

## State
- M3 accepted 2026-11-06: M3-01..M3-19 done, CI green on PG at 0e3511a, `dev` merged into `qa`. Report: docs/reports/M3.md.
- Next milestone: M4 — Original (headers) analyzer (not yet split into tickets).

## Open maintainer decisions
- `qa` → `main` promotion of M1, M2 and M3: maintainer only.
- Confirm the 9 DKIM seed selectors in seeds/dkim_selectors.yaml (all `unverified`, no provider) against official vendor docs.
- Confirm the Public Suffix List data licence (MPL-2.0 per PyPI only; seeds/public_suffix_source.yaml).
- SecLists password list terms and HTMX under CSP: still unverified (from M1).
- Cleanup: stale worktrees in .claude/worktrees/ and old local branches (agent worktrees start at origin/main).

## Next 3 steps
1. `/gm` → have pm split M4 into tickets (raw message and header parsing is opus-tier per WORKFLOW; reuse M3 SPF/DKIM/DMARC parsers for Authentication-Results alignment).
2. Before any shared deployment: per-user rate limit + global concurrency cap for DNS tools and checks (the Authentication tab runs live DNS on GET).
3. Small cleanup ticket for the M3 follow-ups (shared result serializer, typer private import pin, socket guard to tests/conftest.py).
