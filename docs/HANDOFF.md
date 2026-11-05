# HANDOFF — 2026-11-05 (session 2)

Resume with `/gm`.

## Current milestone: M1 — Core platform
| Ticket | Status |
|---|---|
| M1-01..M1-19 | done (merged into dev, QA APPROVE, CI green on PG at f9b0e4b) |
| M1-15 hotfix (NUL bytes in login email, PG-only) | done (73f62f1) |
| M1-20 tenancy matrix + M1 acceptance | in-progress: coder (opus) stopped by the usage limit while writing tests/tenancy/conftest.py; worktree .claude/worktrees/agent-af4ff2fdb27996f4d (uncommitted WIP). Resume that coder, or restart M1-20 from dev f9b0e4b. |

## Open maintainer decisions (unverified / to confirm)
- Domain name rules: single-label, all-numeric TLD, underscore and surrounding whitespace are rejected (M1-18).
- SecLists common-password list: the xato.net source dataset terms are unverified (before public release).
- HTMX under CSP `script-src 'self'`: unverified (M1-16).
- Cleanup: stale worktrees in .claude/worktrees/ and local branch feature/m1-13-auth-core (the auto-mode classifier denied removal).

## Process notes
- PG tests only run in CI (see memory pg-tests-ci-only): watch dev CI after every merge.

## Next 3 steps
1. Finish M1-20, then QA, merge and dev CI.
2. Full suite on dev; if green, merge dev → qa, push qa and watch CI.
3. Write docs/reports/M1.md (max 30 lines); ask the maintainer about the decisions above.
