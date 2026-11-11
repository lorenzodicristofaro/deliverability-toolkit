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
- i18n key rule: `notes_key` values must not contain hyphens (the loader regex `_NOTES_KEY` in app/esp/profile.py rejects them). The key segment is the profile id with `-` replaced by `_`. Profile ids and file names may keep hyphens.
- `target_pattern` `*` matches exactly one whole DNS label. A partial-label prefix such as `selector1-<domain>` can only be written as a whole `*`; do not write partial-label patterns.
New i18n keys: esp.google_workspace.*, esp.microsoft_365.*, esp.brevo.* notes and pitfall keys (en + it)
Status: done (Brevo skipped: help.brevo.com 403 Cloudflare challenge, developers page lists no DNS records)

## Note (coder, 2026-11-11)
All pages fetched 2026-11-11 with `curl -sL` (HTTP 200 unless stated); quotes copied from the raw page text.

### google-workspace (status: verified)
Sources: knowledge.workspace.google.com/admin/security/set-up-spf (support.google.com/a/answer/33786 redirects here), .../set-up-dkim, .../set-up-dkim?hl=it.
- SPF, on the domain itself (Host "If the host is the same domain (not subdomain) you are adding the TXT record to, enter the @ symbol."): "If you use only Google Workspace to send email, copy this line of text: v=spf1 include:_spf.google.com ~all" -> `spf.includes: [_spf.google.com]`.
- DKIM TXT: "The record type is TXT ." ; "The first part is the DKIM prefix selector, followed by \"._domainkey\". For example: google._domainkey ." ; "The default prefix selector is google ." -> selector `google`, txt. Agrees with `seeds/dkim_selectors.yaml` (`google`, txt, google_workspace).
- Pitfall CUSTOM_DKIM_PREFIX (verified): "If your domain already uses a DKIM key with the prefix google , enter a different prefix in this field."
- Pitfall START_AUTHENTICATION (verified): "Important: Do not click Start Authentication yet. You'll do that later." ; Step 3 "Turn on & verify DKIM": "select the domain where you want to turn on DKIM." ; "Click Start authentication . When DKIM setup is complete and working correctly, the status at the top of the page changes to: Authenticating email with DKIM ." Path: "Menu Apps Google Workspace Gmail" ; "Click Authenticate email ."
- Italian labels from ?hl=it: "Nella Console di amministrazione Google, vai a Menu App Google Workspace Gmail" ; "Fai clic su Autentica email ." ; "Fai clic su Avvia autenticazione . ... Autenticazione email con DKIM ." ; "Il selettore di prefisso predefinito è google ."
- Not modelled: return path, tracking (mailbox provider; nothing documented).

### microsoft-365 (status: verified)
Sources: learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure and .../email-authentication-dkim-configure.
- SPF, on the custom domain: "Most Microsoft 365 organizations require include:spf.protection.outlook.com in the SPF TXT record for the domain." ; "SPF TXT record for contoso.com in Microsoft 365 and Microsoft 365 Government Community Cloud (GCC) : v=spf1 include:spf.protection.outlook.com -all".
- Pitfall SPF_CLOUD_VARIANTS (verified): "GCC High) and Microsoft 365 Department of Defense (DoD) : v=spf1 include:spf.protection.office365.us -all" ; "Microsoft 365 operated by 21Vianet : v=spf1 include:spf.protection.partner.outlook.cn -all".
- DKIM CNAME selector1/selector2: "Hostname : The values are the same for all Microsoft 365 organizations: selector1._domainkey and selector2._domainkey ." Agrees with `seeds/dkim_selectors.yaml`.
- No `target_pattern` (schema gap, below). Targets: new format "selector1-<CustomDomainWithDashes>._domainkey.<InitialDomainPrefix>.<DynamicPartitionCharacter>-v1.dkim.mail.microsoft" ; "This value is part of the updated DKIM record format for new custom domains in Microsoft 365 introduced in May 2025 . Existing custom domains and initial domains continue to use the old DKIM format:" "selector1-contoso-com._domainkey.contoso.onmicrosoft.com" ; "The old and new formats can't coexist for the same selector ." ; "The values presented in this article are for illustration only ."
- Pitfall TENANT_SPECIFIC_DKIM_TARGETS (verified): quotes above plus "Get-DkimSigningConfig -Identity contoso.com | Format-List Name,Enabled,Status,Selector1CNAME,Selector2CNAME".
- Pitfall ENABLE_DKIM_SIGNING (verified): "go to Email & collaboration > Policies & rules > Threat policies > Email authentication settings page" ; "select the DKIM tab" ; "It takes a few minutes (or possibly longer) for Microsoft 365 to detect the new CNAME records you created." ; "After a while, return to the domain details flyout ... and then select the Sign messages for this domain with DKIM signatures toggle."
- Key rotation: "Only one selector is active" ; "The other selector is inactive. It's activated and used only after any future DKIM key rotation" ; "DKIM signing using a custom domain in Microsoft 365 requires two CNAME records in the domain." Both selectors are therefore required; no rotation pitfall added.
- Not modelled: return path, tracking.

### brevo (skipped)
help.brevo.com/hc/en-us/articles/12163873383186 and 16045394674066 returned HTTP 403 on 2026-11-11. developers.brevo.com/docs/domain-creation-and-management (200) only shows an API response example (`"host_name" : "mail._domainkey."`), not the required DNS records. Per ticket, no `brevo.yaml` and no `esp.brevo.*` keys.

### Unverified list for the maintainer
- None marked unverified.

### For the maintainer / GM (schema gaps and conflicts)
- Schema gap, Microsoft 365 DKIM targets: the first label is a partial label (`selector1-<domain-with-dashes>`) and Microsoft documents two formats with different label counts (`*._domainkey.*.*.dkim.mail.microsoft` new, `*._domainkey.*.onmicrosoft.com` old) that both remain valid. One `target_pattern` per selector cannot express both, so none is set: the check verifies only that the CNAMEs exist, and detection (M6-13) never probes these selectors.
- Conflict on Microsoft's it-it DKIM page (https://learn.microsoft.com/it-it/defender-office-365/email-authentication-dkim-configure, not in `sources` because no Italian label is used): the toggle is "Firma i messaggi per questo dominio con firme DKIM" in one step and "Sign messages for this domain with DKIM signatures (Firma messaggi per questo dominio con firme DKIM )" in another; the settings page is "Impostazioni di autenticazione della posta elettronica" and also "Email impostazioni di autenticazione". No single official Italian label, so the it strings keep the English labels.
- Google's set-up-spf page lists "Microsoft Office 365 (only) v=spf1 include:spf.protection.outlook.com ~all" (`~all`) while Microsoft documents `-all`; the profile checks only the include, so no conflict for the check.

### Italian wording to review
All 5 it strings (esp.google_workspace.* x2, esp.microsoft_365.* x3). Google strings use Google's Italian labels (Console di amministrazione Google, App, Autentica email, Avvia autenticazione, selettore di prefisso); Microsoft strings keep English UI labels (see conflict above).
