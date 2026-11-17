# HANDOFF — 2026-11-17 evening (M7 in progress, paused on maintainer request)

Resume with `/gm`. Milestone **M7 — Monitoring**, tickets in docs/tickets/M7-*.md, list in TODO.md.

## Done (all QA APPROVE, merged into dev, pushed)
- Earlier today: M7-14b, M7-06, M7-07, M7-08, M7-09, M7-10, M7-10b.
- This session part: M7-02 http_fetch kind (7e449c1), M7-11 monitor target API + permissions (83f4919),
  M7-12 history read API (0a7c87b), M7-12b trend aggregation (191d875), M7-21a domain verification via DNS TXT (ea6d500).
- Migration head on dev: 0015. Dev CI green up to 83f4919/0a7c87b checks seen; CI for ea6d500 was still running at pause:
  check it first.

## Maintainer decisions (2026-11-17)
- Domain ownership verification required (SPEC §3): DNS TXT primary (M7-21a, done), email to a role address at the
  domain as alternative (M7-21b, after M7-16). http_fetch and its scheduling need a verified domain.
- Notify the maintainer explicitly whenever a push must be done by them.

## Open maintainer actions
- None blocking. Pending from earlier: Barracuda BRBL text; SpamCop IPv6/usage terms; DMARC tag case-sensitivity.
- Info: http_fetch scope is narrower than SPEC "HTTP fetch matches" (own domain/subdomain, default ports, GET, one
  header check, API-only in UI). Maintainer may update SPEC wording or ask to widen.

## Next 3 steps
1. Check CI on ea6d500.
2. M7-13 monitoring page + SVG trend charts (ticket says sonnet; GM has been choosing opus up front since Sonnet code
   needed rework on M7-07, M7-08, M7-12). Must escape untrusted DNS text (notes in ticket).
3. M7-14 alert state/dedup (opus), then M7-15 (opus), M7-16, M7-21b, M7-17..19, M7-05b, M7-20.

## Notes
- Agent worktrees: give coders the dev hash, `git checkout -B <branch> <hash>`; if a branch is held by another
  worktree, use a new local branch name and merge the commit directly.
- Local full suite the CI way: `-n auto --ignore=tests/core/test_security.py --ignore=tests/core/test_csrf.py`, then
  those two single-process. PG: prefix TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test,
  one run at a time.
- Routers live in app/api/__init__.py (not app/main.py). Test files in tests/api and tests/services must not share a
  basename (no __init__.py): API tests use the `_api` suffix.
- Old agent worktrees under .claude/worktrees/ can be cleaned up (all their commits are merged).
