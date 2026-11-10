# M6-10 ESP profiles: Google Workspace, Microsoft 365, Brevo
Milestone: M6
Branch: feature/m6-10-esp-profiles-workspace-marketing
Files in scope: profiles/esp/google-workspace.yaml, profiles/esp/microsoft-365.yaml, profiles/esp/brevo.yaml, locales/en.json, locales/it.json (only the `esp.<id>.*` keys these files reference)
Out of scope: engine, schema changes, the rest of SPEC 4.2's list (Postmark, Mailchimp, Mandrill, Klaviyo, HubSpot, ActiveCampaign, Salesforce Marketing Cloud stay for a later batch after the maintainer sees how the first profiles read)
Depends on: M6-01
Parallel-safe: no with other tickets editing locale files; content otherwise disjoint
Model: sonnet (data only; QA on Opus, must re-fetch every cited URL)
Acceptance criteria:
- Same verification rules as M6-08 (no vendor facts from memory, official URLs in `sources`, quoted support in the Note, real `verified_on`, unconfirmed parts under `unverified_fields` and listed for the maintainer). The M3-20 notes say the Brevo help centre returned 403 to the tool; if still unreachable, Brevo is skipped and reported, not filled from memory.
- Mailbox providers (Google Workspace, Microsoft 365) are sender-side configuration for a domain whose mail is sent through them; the profile describes SPF include and DKIM, not return-path or tracking. Fields that do not apply are omitted, not invented. Where DKIM selectors are tenant-specific or key-rotated, the profile says what the docs state and nothing more.
- Each profile loads with the M6-01 loader and passes `tests/esp/test_shipped_profiles.py`; en + it texts for notes and pitfalls.
- Consistency with `seeds/dkim_selectors.yaml` (Microsoft 365 and Google Workspace selectors were verified in M3-20).
New i18n keys: esp.google-workspace.*, esp.microsoft-365.*, esp.brevo.* notes and pitfall keys (en + it)
Status: todo
