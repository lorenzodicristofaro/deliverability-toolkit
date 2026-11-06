# HANDOFF — 2026-11-07 (M4 in progress, session paused by maintainer)

Resume with `/gm`.

## State
- dev = origin/dev at 1192a50 (+ this handoff commit); CI green on 1192a50 incl. PostgreSQL.
- Done (merged, QA APPROVE, CI green): M4-01 header parser, M4-06 `message.analyze` permission, M4-07 sample corpus + MANIFEST.
- M4-04 Authentication-Results parser: coder committed 90b078c on branch feature/m4-04-authentication-results
  (worktree .claude/worktrees/agent-ad844f14649b4868c, clean tree). The coder was stopped before its final
  report, so lint/tests are NOT confirmed. Status: in-review (needs a test run, then QA).
- Todo: M4-02, 03, 05, 08–14.

## GM decisions (2026-11-07)
- Caps: 2 MiB raw, 128 KiB headers, 500 headers, 8 KiB per physical line, 64 KiB per unfolded field,
  MIME depth 10, 200 parts.
- M4 stores nothing; the analyzer is offline and does not verify DKIM/ARC signatures.
- `message.analyze`: owner/admin/analyst, never client viewer (ARCHITECTURE updated).
- M4-08 alignment stays on sonnet.

## Open maintainer decisions
- Provider samples (Gmail, Outlook/M365, SES, SendGrid, MailUp): sanitized real .eml plus an official source
  and check date per header shape (checklist in tests/fixtures/messages/README.md). Until then they are
  `unverified` and M4 acceptance = RFC corpus verified, provider samples pending.
- From M3: `qa` → `main` for M1–M3; Mailchimp/Postmark/HubSpot DKIM sources; PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. In the M4-04 worktree run ruff + mypy + the full suite; if green → qa-reviewer → merge (else back to coder).
2. M4-03 Received chain, then M4-02 MIME (opus, one at a time unless quota allows 2).
3. M4-05 ARC and M4-08 alignment; then 09–13 serially; then 14.
