# HANDOFF — 2026-11-07 (M4 accepted, conditionally)

Resume with `/gm`.

## State
- M4 is done: M4-01..M4-14 are merged into `dev` with QA APPROVE. The local full suite is green (8974 passed). Report: docs/reports/M4.md.
- `dev` → `qa` done at c2c2733 (CI 42378609022 green incl. PostgreSQL, after a test socket-guard fix 3e6730e).
- Acceptance condition: the parser is verified against the RFC corpus, and provider samples are still pending (TODO.md M4 block).

## GM decisions (2026-11-07)
- Received redaction masks every `@` token in hop text and drops hop fields that contain `@` or `<`.
- An unusable Reply-To gives an info finding (MSG_REPLY_TO_UNUSABLE) and does not set error status.
- The 1 h hop-delay threshold is a documented heuristic.
- M4-14's third QA round was docs-only, approved by the maintainer.

## Open maintainer decisions
- Provider samples: sanitized real Gmail, Outlook/M365, SES, SendGrid and MailUp .eml files, each with an official source and check date. Checklist: tests/fixtures/messages/README.md.
- `qa` → `main` for M1–M4.
- From M3: Mailchimp/Postmark/HubSpot DKIM sources; PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. Start M5 (content analyzer + admin rules): have `pm` split it into tickets in docs/tickets/.
2. Choose which M4 follow-ups to do before M5. Recommended: MIME cap consistency, and the CSRF 1 MiB vs UI 413 mismatch.
3. When the provider samples arrive, add them to MANIFEST as verified and rerun test_acceptance_m4.py.
