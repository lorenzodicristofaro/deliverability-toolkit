# M6-16 ESP profiles from maintainer-supplied pages: SendGrid link branding, Mailgun, Brevo
Milestone: M6
Branch: feature/m6-16-esp-maintainer-pages
Files in scope: profiles/esp/sendgrid.yaml, profiles/esp/mailgun.yaml, profiles/esp/brevo.yaml (new), locales/en.json, locales/it.json (only `esp.sendgrid.*`, `esp.mailgun.*`, `esp.brevo.*`), seeds/dkim_selectors.yaml only if a selector is confirmed, tests only if the M6-11 acceptance parametrization needs a fixture change (it derives from profiles, so normally none)
Out of scope: engine and schema changes (a gap goes back to the GM as a finding, not a workaround), other ESPs
Depends on: M6-08, M6-10, M6-11
Parallel-safe: no (locale files)
Model: opus (QA model: opus; QA must re-fetch every cited URL)
Acceptance criteria:
- Same verification rules as M6-08: no vendor facts from memory; each supporting sentence quoted word for word in the Note; `verified_on: 2026-11-11` for values actually read; a value the page contradicts is removed; conflicts between pages (or with `seeds/dkim_selectors.yaml`) are reported, not resolved silently.
- Sources supplied by the maintainer (2026-11-11):
  - SendGrid (Twilio): https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-link-branding and https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication (both HTTP 200).
  - Brevo: https://help.brevo.com/hc/it/articles/12163873383186-Autenticazione-del-dominio-con-Brevo-codice-Brevo-DKIM-DMARC (maintainer notes Brevo generates the records inside its platform).
  - Mailgun: https://help.mailgun.com/hc/en-us/articles/15353034939931-GoDaddy-DNS-Setup-Guide (maintainer notes Mailgun generates an ad-hoc key).
- Reading the help-centre pages: help.brevo.com and help.mailgun.com HTML return 403 (Cloudflare). The same articles are reachable through the vendor's own Zendesk Help Center API (HTTP 200, GM checked): https://help.brevo.com/api/v2/help_center/it/articles/12163873383186.json and https://help.mailgun.com/api/v2/help_center/en-us/articles/15353034939931.json. Cite the PUBLIC article URL in `sources` and state in the Note that the text was read via the API JSON `body`. Other articles on these help centres may be read the same way.
- SendGrid: resolve the unverified `tracking_domain` from the link-branding page (host, record type, target, optional). If confirmed, remove it from `unverified_fields` and set `status: verified` if nothing else is unverified. Re-check that the domain-authentication page still supports the current values.
- Mailgun: resolve the DKIM selector name and record type, the tracking host, whether the tracking CNAME is required when tracking is off, and whether key rotation / Automatic Sender Security makes DKIM a CNAME. If selectors are per-account generated, state exactly what the docs say (pitfall) and report the schema gap to the GM; never invent a selector.
- Brevo: create `profiles/esp/brevo.yaml` only with values the page states (SPF include, DKIM selector/type/target). A brevo-code TXT is a verification record, not SPF/DKIM: model it only if the schema has a place for it, otherwise mention it in a note. Values generated per account are not invented: pitfall plus schema-gap report. If nothing is confirmable, no profile is created and the Note says so.
- Each profile loads with the loader and passes `tests/esp/test_shipped_profiles.py` and the M6-11 acceptance tests (`tests/esp/test_acceptance.py`, `tests/api/test_esp_acceptance.py`). The meta test fails if a profile has no applicable mutation; if Brevo or Mailgun hit that, report to the GM rather than weakening the test.
- i18n key rule as M6-08: `notes_key` has no hyphens; Brevo uses `esp.brevo.*`. Italian strings natural, not machine-literal; vendor UI labels per the M6-10 rule (official Italian label if the vendor's Italian page shows it, else English).
- `target_pattern` `*` matches exactly one whole DNS label; no partial-label patterns.
- The coder lists in the Note which MAINTAINER follow-ups in TODO.md (M6-08 / M6-10) are now resolved; the PM updates TODO.md.
New i18n keys: esp.brevo.* and any changed esp.sendgrid.* / esp.mailgun.* keys (en + it)
Status: todo
