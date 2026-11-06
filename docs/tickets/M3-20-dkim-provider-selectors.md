# M3-20 DKIM seed: provider selectors and selector→provider mapping
Milestone: M3
Branch: feature/m3-20-dkim-provider-selectors
Files in scope: seeds/dkim_selectors.yaml, app/checks/dkim_selectors.py (only if the schema needs a field), tests/checks/test_dkim_selectors.py
Out of scope: the M6 ESP profiles (full SPF/return-path/tracking config), the admin UI, and any per-customer generated selectors that cannot be listed statically.
Depends on: M3-12
Parallel-safe: yes
Model: sonnet
Acceptance criteria:
- For each major ESP, find the DKIM selector names from the vendor's OFFICIAL documentation, read during this ticket: Mailchimp (incl. Mandrill/Mailchimp Transactional), Brevo, ActiveCampaign, MailUp, SendGrid, Mailgun, Amazon SES, Postmark, SparkPost, HubSpot, Klaviyo, Microsoft 365, Google Workspace, Zoho Mail. Record whether the record is TXT or a CNAME delegation, and whether the selector is fixed or per-customer.
- An entry is `verified` only with a https source URL from the vendor's own domain (docs or help center) and verified_on 2026-11-06, and its `provider` set. Each source must say the selector name explicitly; screenshots, blogs, forums and third-party lists do not count.
- Selectors that are per-customer or generated (e.g. a random or customer-specific label) are NOT added as fixed entries. They are listed in the ticket's report section instead, with the vendor's documented pattern.
- When no official page states the selector, the vendor is listed as "not found in official docs", with the URLs checked. Never guess.
- The existing generic entries keep `provider: null` unless an official source maps them. If a generic name such as selector1/selector2 or google is confirmed by an official vendor page, update it to verified with that provider and source.
- Loader invariants still hold: verified requires a source; unverified must not claim a provider; MAX_SELECTORS is respected; names are single labels.
- Tests: a shipped-file test asserts every verified entry has a vendor-domain https source and a provider. Add table rows for any new schema field.
New i18n keys: none
Note: post-acceptance follow-up, requested by maintainer 2026-11-06. Depends on external facts not yet verified; nothing may be filled from memory. Report section (to be completed by the coder) must list per-customer patterns and "not found in official docs" vendors with URLs checked.
Status: todo
