# HANDOFF — 2026-11-17 (M7 in progress, paused: usage limit reached)

Resume with `/gm`. Milestone **M7 — Monitoring**, tickets in docs/tickets/M7-*.md, list in TODO.md.

## Done this session (all QA APPROVE, merged into dev, pushed)
- M7-14b secret encryption (383dfd1), M7-06 monitor targets (b492b9e), M7-07 check runs + retention (4628d94),
  M7-08 DNS snapshots + diff (05cd067), M7-09 scheduler core (5f2442c), M7-10 run executor (fff4656),
  M7-10b baseline past history limit + DNSBL per list (ead5671). Bookkeeping up to 517c498.
- Migration head on dev: 0013. Dev CI green up to fff4656; later merges not yet checked (check before next merge).

## Parked
- **M7-02 http_fetch kind** (opus), branch `feature/m7-02-http-fetch-kind` in worktree
  `.claude/worktrees/agent-adabea543d0921130`, WIP commit affc928 (model KINDS + migration 0014 + its test, unfinished,
  untested). GM decisions given to the coder (re-give to a new Opus coder with this file):
  - Scope widened (option a): app/models/custom_check.py, migration 0014 (rewrite kind_valid CHECK) + test,
    app/repositories/custom_checks.py, app/api/v1/custom_checks.py (docstring), app/services/custom_checks_admin.py,
    app/web/custom_checks.py + templates/custom_checks/form.html, docs/CONTENT.md, and tests:
    tests/content/test_acceptance_m5.py, tests/services/test_custom_checks_admin.py, tests/repositories/test_custom_checks.py,
    tests/web/test_custom_checks_ui.py, tests/api/test_custom_checks_api.py.
  - Host rule: structured scheme (https default) / host template (`{domain}` or ASCII labels + `.{domain}`, no IDN) /
    path (starts `/`, restricted charset, capped) / no port; URL built by construction, host re-checked before fetch.
  - Fetch capped at remaining run budget (12 s vs client 20 s) -> error `run_budget_exceeded`; `fetcher` param on
    CustomDnsCheck for tests; limits via limits_from_settings(get_settings()).
  - Web form: http_fetch stays NOT selectable (API-only in M7), disabled option with i18n hint; editing an existing
    http_fetch definition in the UI must not wipe it. Follow-up: form editor.
  - Remove CUSTOM_KIND_UNAVAILABLE / kind_unavailable keys if unused afterwards. Downgrade of 0014 with existing
    http_fetch rows: coder decides and documents.
  - Ticket file is docs/tickets/M7-02-custom-check-http-fetch.md (add widened scope + decisions to it via pm).

## Open maintainer actions
- None blocking. Later: Barracuda BRBL page text; SpamCop IPv6/usage terms; DMARC tag case-sensitivity (TODO follow-up).

## Next 3 steps
1. Finish M7-02 (new Opus coder from affc928 with decisions above) -> QA opus -> merge.
2. M7-11 monitor target API + permissions (opus; locales, so after M7-02).
3. M7-12 history/snapshot read API, then M7-14 alert state/dedup (opus; depends M7-10b).

## Notes
- Agent worktrees: tell coders the dev hash and to `git checkout -B <branch> <hash>`; if a branch is held by another
  worktree, use a new local branch name and merge the commit directly.
- Local full suite the CI way: `-n auto --ignore=tests/core/test_security.py --ignore=tests/core/test_csrf.py`, then
  those two single-process. PG: prefix TEST_DATABASE_URL=postgresql://ci:ci-throwaway-password@localhost:5432/ci_test.
- Sonnet code needed Opus rework on M7-07 and M7-08; GM picked Opus up front from M7-09 on.
