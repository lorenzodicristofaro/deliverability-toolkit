# HANDOFF — 2026-11-07 (M4 in progress)

Resume with `/gm`.

## State
- M4 split into 14 tickets (docs/tickets/M4-*.md, commit 20417ad on dev).
- M4-01 header parser: in-progress (coder, opus, branch feature/m4-01-header-parser).
- All other M4 tickets: todo. Nothing stored in M4; analyzer is offline (no DNS/network).

## GM decisions (2026-11-07)
- Caps accepted: 2 MiB raw, 128 KiB headers, 500 headers, 8 KiB/line, MIME depth 10, 200 parts.
- M4-08 alignment stays on sonnet (pure comparison over the existing org-domain helper; QA reviews).

## Open maintainer decisions
- Provider samples (Gmail, Outlook, SES, SendGrid, MailUp): sanitized real samples needed; until then M4-07 marks them `unverified`
  and M4 acceptance = RFC corpus verified, provider samples pending.
- From M3: `qa` → `main` for M1–M3; Mailchimp/Postmark/HubSpot DKIM sources; PSL licence; SecLists terms; HTMX under CSP.

## Next 3 steps
1. QA M4-01 → merge into dev.
2. M4-06 (permission) and M4-07 (corpus), one at a time.
3. M4-02/03/04 (at most 2 in parallel, disjoint files), then 05, 08, and 09–13 serially, then 14.
