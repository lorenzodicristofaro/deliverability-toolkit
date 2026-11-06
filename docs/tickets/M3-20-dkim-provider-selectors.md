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
Status: done

## Research report
Researched 2026-11-06 with WebFetch on vendor domains only. "Verified" = the fetched official page states the selector name. Note: WebFetch returns a model-summarised view of each page, so the maintainer should spot-check the quoted strings against the URLs.

| Vendor | Selector(s) found | TXT/CNAME | Fixed / per-customer | Official URL(s) checked | Result |
|---|---|---|---|---|---|
| Mailchimp (campaigns) | none; page says CNAME 1/2 Name and Value are shown in the account. `k2._domainkey` appears only as a troubleshooting example | CNAME | per-account display; names not stated as fixed | https://mailchimp.com/help/set-up-email-domain-authentication/ | not found in official docs (k2/k3 not stated) |
| Mandrill / Mailchimp Transactional | `mte1`, `mte2` -> dkim1.mandrillapp.com, dkim2.mandrillapp.com | CNAME | fixed | https://mailchimp.com/developer/transactional/docs/authentication-delivery | verified |
| Brevo | none confirmed. Developer API sample shows TXT host `mail._domainkey.`; help center (brevo1/brevo2 CNAME per search snippet only) returned 403 | TXT (API sample) / CNAME | unclear | https://developers.brevo.com/docs/domain-creation-and-management (fetched); help.brevo.com articles 12163873383186 and 16045394674066 (403) | not found in official docs (sample conflicts with help center; not promoted) |
| ActiveCampaign | none | CNAME (since 2023-02-23, per search snippet) | account-generated CNAMEs | help.activecampaign.com articles 12372243669404, 360015584680, 5955643910300 (403); https://www.activecampaign.com/dkim-spf-check/ (no selector listed) | not found in official docs |
| MailUp | none | CNAME | n/a | https://help.mailup.com/display/MUG/Maximizing+deliverability+for+your+emails and display/mailupQuickStart/... (404) | not found in official docs (ml01/ml02 seen only in a search snippet and third parties; not accepted) |
| SendGrid (Twilio) | `s1`, `s2` (CNAME, automated security on); `m1` (TXT, automated security off) | CNAME / TXT | documented defaults; a custom DKIM selector can be set, targets embed per-account ids | https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication | verified (default names) |
| Mailgun | none; selector is any user-chosen atom (`dkim_selector` API field), key shown in control panel | TXT (CNAME with automatic sender security) | per-customer | https://documentation.mailgun.com/docs/mailgun/user-manual/domains/domains-verify ; https://documentation.mailgun.com/docs/mailgun/api-reference/send/mailgun/domains/post-v4-domains ; .../domain-keys/post-v1-dkim-keys ; help.mailgun.com rotate article (403) | per-customer |
| Amazon SES | per-identity DKIM tokens: 3 CNAMEs `<token>._domainkey` -> `<token>.<SigningHostedZone>`; BYODKIM selector user-chosen | CNAME (Easy DKIM) / TXT (BYODKIM) | per-customer | https://docs.aws.amazon.com/ses/latest/dg/creating-identities.html ; https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim-easy.html | per-customer |
| Postmark | examples `pm._domainkey.example.com` and a date-style `2023060112345pm._domainkey`; page does not say which is fixed; "use the host shown in your DNS Settings" | TXT | unclear / per-customer | https://postmarkapp.com/support/article/setting-up-dkim-for-your-domain ; .../1008-what-are-the-dkim-dns-records (404) | not found in official docs (pm only in examples) |
| SparkPost (Bird) | selector assigned per organization via API/dashboard | TXT | per-customer | https://bird.com/en-us/docs/guides/email/sending-domains (support.sparkpost.com redirects here) | per-customer |
| HubSpot | none; page says two CNAMEs are generated during setup. Only identifier: `smtpapi` as a lookup selector in a troubleshooting step (context unclear, not promoted) | CNAME | generated | https://knowledge.hubspot.com/cos-general/how-to-connect-your-email-sending-domain ; https://knowledge.hubspot.com/domains-and-urls/connect-your-email-sending-domain (same content) | not found in official docs |
| Klaviyo | `km1`/`km2` (marketing), `kt1`/`kt2` (transactional), `ks1`/`ks2` (service), legacy `kl1`/`kl2`; numbering continues (km3/km4) for more domains; dynamic routing uses NS delegation, no selector CNAMEs | CNAME | fixed names for the first domain per send type | https://help.klaviyo.com/hc/en-us/articles/115000357752 | verified (only the listed pairs) |
| Microsoft 365 | `selector1`, `selector2` (hostname identical for all orgs; target is per-tenant) | CNAME | fixed | https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure | verified |
| Google Workspace | `google` (default prefix selector; admin may choose another) | TXT | default fixed, customizable | https://knowledge.workspace.google.com/admin/security/set-up-dkim (support.google.com/a/answer/180504 redirects here) | verified (default) |
| Zoho Mail | none fixed; selector is user-chosen (example `zoho`), TXT host `<selector>._domainkey` | TXT | per-customer | https://www.zoho.com/mail/help/adminconsole/dkim-configuration.html | per-customer |

Generic entries `default`, `dkim`, `mail`, `k1` remain unverified with `provider: null`. `s1`, `s2`, `selector1`, `selector2`, `google` were promoted as above.

Inaccessible: Brevo and ActiveCampaign help centers (403), MailUp help (404), Postmark article 1008 (404), Mailgun help center (403).
