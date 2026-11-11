# M6-09 ESP profiles: MailUp (TeamSystem) and other Italian ESPs
Milestone: M6
Branch: feature/m6-09-esp-profiles-italian
Files in scope: profiles/esp/mailup.yaml, optionally profiles/esp/emailchef.yaml and one more Italian profile (see below), locales/en.json, locales/it.json (only the `esp.<id>.*` keys these files reference)
Out of scope: engine, schema changes, ESPs outside this list
Depends on: M6-01
Parallel-safe: no with other tickets editing locale files; content otherwise disjoint
Model: sonnet (data only; QA on Opus, must re-fetch every cited URL)
Acceptance criteria:
- Same verification rules as M6-08: NO vendor facts from memory; every value read from the vendor's official documentation in this ticket, URL in `sources`, supporting sentence quoted in the Note, `verified_on` = the real read date, anything unconfirmed under `unverified_fields` and listed for the maintainer.
- MailUp (TeamSystem) is mandatory. Known starting point, already verified in M3-20 and recorded in docs/tickets/M3-20-dkim-provider-selectors.md: the MailUp help-centre page "DKIM non trovato" (https://helpmailup.atlassian.net/wiki/spaces/MM/pages/37519747/DKIM+non+trovato) for the DKIM selectors. The coder re-reads it (do not copy) and looks in the same official help centre for the SPF include, return-path/bounce and tracking-domain setup; anything not found there stays `unverified`. If the help centre is not reachable from the coder environment, stop and report that the maintainer must supply the page text.
- Other Italian candidates named in SPEC 4.2 are Emailchef, Contactlab/Experian, Agile Telecom and Aruba. Pick at most two whose OFFICIAL documentation is reachable and states the setup (SPF/DKIM at least); skip the rest and list each skipped one with the reason (unreachable, no public doc, not an ESP for third-party domains). Fewer verified profiles beat more unverified ones.
- Each profile loads with the M6-01 loader and passes `tests/esp/test_shipped_profiles.py`; notes/pitfall texts as i18n keys in en and it (the Italian wording is reviewed by the maintainer, flag in the Note).
- Consistency with `seeds/dkim_selectors.yaml` where selectors overlap.
- i18n key rule: `notes_key` values must not contain hyphens (the loader regex `_NOTES_KEY` in app/esp/profile.py rejects them). The key segment is the profile id with `-` replaced by `_`. Profile ids and file names may keep hyphens.
- `target_pattern` `*` matches exactly one whole DNS label. A partial-label prefix such as `selector1-<domain>` can only be written as a whole `*`; do not write partial-label patterns.
New i18n keys: esp.mailup.* (and the other chosen ids) notes and pitfall keys (en + it)
Status: in-review

## Note (coder, 2026-11-11)
All pages fetched 2026-11-11 with `curl -sL` (HTTP 200) and quotes copied from the raw page text (Atlassian pages are server-rendered; the text sits in the HTML).

### mailup (status: verified)
Sources (helpmailup.atlassian.net/wiki/spaces/MM/pages/): 37519747 "DKIM non trovato", 37519762 "SPF non trovato", 810156046 "Configurazione Record SPF", 809926670 "Parametri di configurazione SPF, DKIM e DMARC".
- DKIM: "Chiedigli di creare questi due CNAME" ; "ml01._domainkey.mydomain.com ... e fallo puntare a ml01.dkim.musvc.com." (same for ml02). Selectors are fixed; `target_pattern` is the literal target (no wildcard). Agrees with `seeds/dkim_selectors.yaml` (ml01, ml02).
- SPF: "Se è già attivo un record SPF è necessario aggiungere la stringa "include:musvc.com" prima della keyword finale "~all"." Where: the pages refer to the sending domain ("mydomain.com va sostituito con il dominio mittente utilizzato per gli invii"); no subdomain or CNAME host is involved, so `spf.includes: [musvc.com]`. Placement confirmed on 37519762: "il record SPF del dominio associato all'indirizzo email mittente" ; "l'aggiunta del record SPF al tuo dominio mittente è necessaria per l'implementazione del metodo DMARC".
- Pitfall SPF_ONLY_IF_PUBLISHED (round 2 rewritten): the pages conflict. 810156046 and 809926670: "Se non pubblicato, non è necessario creare un record SPF." 37519762: "Se non hai ancora pubblicato un record SPF, digli di aggiungere questo record TXT: v=spf1 include:musvc.com ~all" and the DMARC sentence above. The en/it text now states that the pages differ and cites 37519762; it makes no single "you do not need one" claim.
- Pitfall DKIM_TXT_ALTERNATIVE: "Se non è possible creare un CNAME, puoi anche implementare l'autenticazione DKIM facendo delle modifiche ad alcuni record TXT delle impostazioni DNS. In tal caso, contattaci per maggiori dettagli" (verified; TXT details not published, so not modelled).
- Pitfall UNAUTHENTICATED_VIA: "Se non autentichi le email, lo faremo noi per te." and Outlook/Gmail may show "tramite" / "per conto" (verified).
- Not modelled (no DNS record documented in the help centre pages read): return path/bounce (no page found), tracking domain (page 37328870 "Dominio di tracciamento - personalizzazione base" describes the feature but states no DNS record type, host or target). Both are simply absent, not marked unverified.

### emailchef (status: verified)
Source: https://emailchef.com/knowledge-base/how-to-set-up-the-domain-authentication-mode/
- SPF: "include:spf.emailchef.com after the v=spf1 string"; if absent, "create a TXT record to add to your email address domain (yourdomain.com)": `v=spf1 a mx include:spf.emailchef.com ?all`. Root domain, so the include goes in `spf.includes`.
- DKIM: "The DKIM record must be added to the subdomain 'mailchef._domainkey'. Like the SPF, the DKIM record can also be inserted as a TXT record." -> selector `mailchef`, type txt. The public key on the page is deliberately not copied.
- Pitfall: "the parameters provided may be different to the parameters on your domain" (verified, quoted).
- Italian label (round 2): source https://emailchef.com/it/documentazione/come-autenticare-il-tuo-dominio/ says "verifica nella sezione Impostazioni > Autenticazione dominio che siano corretti"; the it string uses "Impostazioni > Autenticazione dominio" without the English label.
- Not modelled: bounces ("Emailchef handles your bounces", no DNS record) and tracking (not on the page).
- `mailchef` is not in `seeds/dkim_selectors.yaml` (no overlap, no conflict); the maintainer may want to add it there.

### Skipped candidates
- Contactlab/Experian, Agile Telecom, Aruba: homepages reachable (HTTP 200), but I did not search their documentation for a setup page; the ticket allows at most two profiles and two were verified. Not evaluated, not rejected: no claim about whether they have public docs or serve third-party domains.

### Unverified list for the maintainer
- None marked unverified.

### Italian wording to review
All 4 new it strings (esp.mailup.* x3, esp.emailchef.check_parameters_in_account). MailUp it strings use MailUp's own terms "dominio mittente" and "client di posta elettronica".

### For the maintainer
- MailUp SPF conflict: 810156046 and 809926670 say no SPF record is needed if none is published; 37519762 asks for `v=spf1 include:musvc.com ~all` and says the sending-domain SPF record is needed for DMARC. Pitfall text reports both; please confirm which MailUp guidance is current.
- Whether to add `mailchef` (Emailchef DKIM selector) to `seeds/dkim_selectors.yaml` (out of scope here).
- Italian review of the 4 it strings above.
Schema gaps: none found.

## Round 2 (coder, 2026-11-11)
QA findings fixed: added MailUp 37519762 "SPF non trovato" and Emailchef Italian doc to `sources`, quotes re-checked with curl (REST storage view for Confluence, HTTP 200); MailUp SPF pitfall rewritten to report the conflicting pages; Emailchef it label now "Impostazioni > Autenticazione dominio"; MailUp it strings use "dominio mittente" / "client di posta elettronica"; "For the maintainer" section added.
