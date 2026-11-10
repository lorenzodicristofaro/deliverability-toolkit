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
New i18n keys: esp.mailup.* (and the other chosen ids) notes and pitfall keys (en + it)
Status: todo
