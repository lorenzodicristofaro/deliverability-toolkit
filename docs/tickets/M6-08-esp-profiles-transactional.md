# M6-08 ESP profiles: SendGrid, Amazon SES, Mailgun
Milestone: M6
Branch: feature/m6-08-esp-profiles-transactional
Files in scope: profiles/esp/sendgrid.yaml, profiles/esp/amazon-ses.yaml, profiles/esp/mailgun.yaml, locales/en.json, locales/it.json (only the `esp.<id>.*` note and pitfall keys these files reference)
Out of scope: engine, schema changes (a schema gap goes back to the GM as a finding, not a workaround), other ESPs
Depends on: M6-01
Parallel-safe: no with other tickets editing locale files (M6-03/04/05/07/09/10); content is otherwise disjoint (one YAML per profile)
Model: sonnet (data only; QA on Opus, must re-fetch every cited URL)
Acceptance criteria:
- NO VENDOR FACTS FROM MEMORY. Every value (SPF include, DKIM selector names and CNAME/TXT type, `target_pattern`, return-path and tracking-domain type, pitfalls) is read in this ticket from the vendor's OFFICIAL documentation (vendor-owned domain) and the exact page URL is listed in `sources`. Quote the supporting sentence for each value in the ticket's Note section (short, one line each).
- `verified_on` is the date the pages were actually read. A value the official docs do not state, or a page that cannot be fetched (the M3-20 notes say some help centres returned 403/404, including Mailgun), is NOT guessed: set that field aside under `unverified_fields`, set `status: unverified` if any part rests on it, and list it in the Note for the maintainer. A profile with nothing confirmable is not created; say so.
- Per-customer values (a DKIM target containing a customer id, a return-path host the customer chooses) are expressed with `target_pattern` or left to the per-assignment host (M6-02), never with a real customer value.
- Each profile loads with the M6-01 loader and passes `tests/esp/test_shipped_profiles.py`; notes and pitfall texts exist as i18n keys in en and it (Italian must be correct, not machine-literal; flag any doubt).
- Consistency with `seeds/dkim_selectors.yaml` (M3-20): where both name the same selector, they agree or the difference is explained in the Note.
- i18n key rule: `notes_key` values must not contain hyphens (the loader regex `_NOTES_KEY` in app/esp/profile.py rejects them). The key segment is the profile id with `-` replaced by `_` (profile `amazon-ses` uses `esp.amazon_ses.*`). Profile ids and file names may keep hyphens.
- `target_pattern` `*` matches exactly one whole DNS label. A partial-label prefix such as `selector1-<domain>` can only be written as a whole `*`; do not write partial-label patterns.
- Coder note, Amazon SES: Easy DKIM uses per-domain random selector names, so `dkim.selectors` cannot list fixed names. If the official docs confirm this, the SES profile uses an empty `dkim.selectors` plus a pitfall/note, and the coder reports it to the GM for a later schema extension.
New i18n keys: esp.sendgrid.*, esp.amazon_ses.*, esp.mailgun.* notes and pitfall keys as the profiles reference them (en + it)
Status: todo
