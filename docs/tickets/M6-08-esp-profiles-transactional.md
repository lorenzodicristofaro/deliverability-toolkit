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
Status: in-review

## Note (coder, 2026-11-11)
All pages fetched 2026-11-11. Quotes are from the fetch output (summarised by the fetch tool for SendGrid and Mailgun: QA must re-read).

### sendgrid (status: unverified, only `tracking_domain`)
Source: https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication
- DKIM s1/s2 CNAME: `s1._domainkey.example.com` -> `s1.domainkey.[u00000000].[wl000].sendgrid.net` (same for s2); target_pattern `s1.domainkey.*.*.sendgrid.net` assumes both bracketed parts are one label each (taken from the placeholder example).
- Selector m1: "m1._domainkey.example.com -> k=rsa; t=s; p=..." (TXT, automated security off only). Not listed as a selector (alternative mode, would be reported missing by default); covered by pitfall.
- Return path: "One CNAME record that points mail from your branded URL to the Twilio SendGrid email service." (host `em[0000]`, chosen/generated per account; default "four random alphanumeric characters").
- Custom selector: "Type three letters or numbers that create a custom subdomain."
- Automated security default on: "By default, Twilio SendGrid turns on automated security."
- `spf.includes: []` (round 2): with automated security on, SPF goes through the em host CNAME: "One CNAME record that points mail from your branded URL to the Twilio SendGrid email service and supports SPF" (table: `CNAME em[0000].example.com [u00000000].[wl000].sendgrid.net SPF`); `v=spf1 include:sendgrid.net ~all` appears only on `em[0000]` with automated security OFF, never on the sending domain.
- UNVERIFIED `tracking_domain` (cname): "requires this CNAME record" for click/open tracking; host, target and whether optional are not stated.
- seeds/dkim_selectors.yaml: s1, s2 (cname), m1 (txt) agree.

### amazon-ses (status: verified, round 2)
Sources: creating-identities.html, send-email-authentication-dkim-easy.html, mail-from.html (docs.aws.amazon.com/ses/latest/dg/).
- Easy DKIM: "copy the three CNAME records"; "{{token}}.dkim.{{us-west-2}}.amazonses.com"; example "abc123._domainkey.domain.com".
- Return path (custom MAIL FROM, optional): "(Optional) If you want to Use a custom MAIL FROM domain"; MX "10 feedback-smtp.{{region}}.amazonses.com"; TXT "v=spf1 include:amazonses.com ~all" (on the MAIL FROM subdomain). Return path modelled as `mx`, optional.
- `spf.includes` empty: the include appears only on the MAIL FROM subdomain, none documented for the sending domain.
- Region: "The validation records ... are different for each AWS Region."
- Pitfall `ESP_AMAZON_SES_PER_IDENTITY_DKIM_SELECTORS` verified (GM decision, round 2; creating-identities.html re-fetched 2026-11-11 with curl): "Use the exact record names as provided in the SES console"; "Correct: abc123._domainkey.domain.com"; "Each CNAME record's value is composed of the DKIM token"; "The hosted zone portion varies by AWS Region and identity". Pitfall text (en + it) now says only that: names shown in the console for the identity, value = token + Region/identity-dependent host; no claim of "random". `selectors: []` stays (schema gap reported to GM). With no unverified field left, status is `verified` per docs/ESP_PROFILES.md.

### mailgun (status: verified)
Source: https://documentation.mailgun.com/docs/mailgun/user-manual/domains/domains-verify (the URLs documentation.mailgun.com/.../domain-verification and /get-started/verify-domain returned 404; help.mailgun.com articles returned 403).
- SPF: "v=spf1 include:mailgun.org ~all" (TXT, Required).
- Tracking: "Required for Mailgun to track clicks, opens, and unsubscribes." CNAME value `mailgun.org`; host not stated, so no target_pattern. Marked `optional: false` because the page's table says Required.
- DKIM: TXT, "Find this record in the 'Domain Verification & DNS' section of the Mailgun control panel"; selector name and value NOT stated, so `selectors: []` plus pitfall (same schema gap as SES, a TXT selector with unknown name).
- MX (mxa/mxb.mailgun.org, "Required for Mailgun to receive") and return path are not modelled: MX is for inbound, return path not mentioned.

### Unverified, for the maintainer
- SendGrid tracking/link-branding CNAME: host, target and whether optional (needs the link-branding page).
- SES: a future DKIM `target_pattern` must not assume `dkim.<region>.amazonses.com` ("The hosted zone portion varies by AWS Region and identity"; read `SigningHostedZone`).
- Mailgun: DKIM selector name and tracking host; whether Automatic Sender Security / key rotation makes DKIM a CNAME instead of TXT.
- Mailgun: whether the tracking CNAME is required when tracking is off (profile says `optional: false` from the page's "Required").

Round 2 (coder, 2026-11-11): SendGrid `spf.includes` emptied and removed from unverified_fields; SES pitfall verified and text reworded, SES status verified; Mailgun en label "Domain Verification & DNS"; it "la sicurezza automatizzata (Automated Security)".
