# M6-23 MailUp DKIM: ml01+ml02 CNAMEs OR ml00 TXT (alternative selector sets in the ESP profile schema)
Milestone: M6
Branch: feature/m6-23-mailup-dkim-alternatives
Files in scope: app/esp/profile.py, app/checks/esp_profile.py (DKIM part only), app/checks/finding_text.py (only if param rendering needs it), profiles/esp/mailup.yaml, seeds/dkim_selectors.yaml, locales/en.json, locales/it.json, docs/ESP_PROFILES.md, docs/templates/esp-profile.example.yaml, tests/esp/test_profile_loader.py, tests/esp/test_shipped_profiles.py, tests/esp/test_acceptance.py, tests/checks/test_esp_profile.py (and a new tests/esp or tests/checks file if cleaner), tests/checks/test_dkim_selectors.py (only if the seed test needs a vendor-host entry), ARCHITECTURE.md (only if the ESP profile description changes)
Out of scope: other profiles, ESP detection logic (must stay on CNAME targets), per-assignment selector names (SES/Mailgun gap), verification TXT records, SPF changes, web/API changes
Depends on: M6-17, M6-18 (both merged)
Parallel-safe: yes with M6-24 and M6-25 (disjoint files). Shares locales/*.json and seeds/dkim_selectors.yaml with nothing else in this batch; M6-25 must not touch them.
Model: opus. QA model: opus.

Goal: MailUp's DKIM is correct when the two CNAMEs ml01/ml02 are present OR a TXT record at ml00._domainkey holds a valid key. Maintainer decision 2026-11-12, from MailUp platform knowledge: MailUp checks ml01 and ml02 CNAMEs and also a TXT ml00; if the ml00 TXT is present MailUp considers DKIM correct. Source for the ml00 fact is the maintainer, not an official URL (say so; do not invent a URL). Today the profile requires ml01+ml02 only and the pitfall ESP_MAILUP_DKIM_TXT_ALTERNATIVE says a TXT setup is reported as missing.

Change:
- Schema: add an optional, general way to declare alternative DKIM selector sets. The DKIM part passes if the primary `dkim.selectors` set is fully satisfied OR any alternative set is fully satisfied. Suggested shape: `dkim.alternatives: [[{name: ml00, type: txt}]]`; the coder may refine it but it must stay strict, bounded (caps on sets and entries) and validated like the rest of the loader. Unknown keys rejected.
- A `txt` selector is satisfied by a valid DKIM key record (reuse the existing DKIM record parsing). Malformed = not satisfied; DNS failure on the name = `error`, never ok; no record = not satisfied.
- profiles/esp/mailup.yaml: add the ml00 TXT alternative; YAML comment records the source as maintainer decision 2026-11-12 (the `sources` list keeps the official URLs). Bump `verified_on` only if the official pages are re-read.
- Findings: alternative satisfied -> DKIM ok. Neither set satisfied -> the finding states both expected options (ml01+ml02 CNAMEs, or the ml00 TXT). Replace or reword ESP_MAILUP_DKIM_TXT_ALTERNATIVE / `esp.mailup.dkim_txt_alternative` (en + it) so it no longer says a TXT setup is reported as missing.
- Detection: a bare ml00 TXT must NOT count as evidence of MailUp (generic name). Detection stays on the CNAME targets.
- seeds/dkim_selectors.yaml: add ml00 with provider mailup if the seed format allows (source: maintainer 2026-11-12; note the file-level verified_on caveat from the M6-18 follow-up). If the format cannot carry it, say so and skip.
- docs/ESP_PROFILES.md and docs/templates/esp-profile.example.yaml document the new field; ARCHITECTURE.md only if the profile description changes.

Acceptance criteria (table-driven, no network):
- CNAMEs only: ok. ml00 TXT only: ok. Both: ok. Neither: finding lists both options. Malformed ml00 TXT (and no CNAMEs): not satisfied, not ok. DNS failure on ml00: `error`. Partial CNAMEs (ml01 only) plus no TXT: not satisfied.
- Loader rejection cases: alternatives not a list, empty set, unknown key, bad type, oversize, duplicate names, non-DKIM name.
- Detection test: a domain with only a TXT at ml00._domainkey is not detected as MailUp.
- All shipped profiles still load; en/it key parity test passes; finding params placeholders covered.
- Lint clean: `uv run ruff check . && uv run ruff format --check . && uv run mypy app`.
- Coder runs relevant tests (tests/esp, tests/checks, locale tests); full suite on the final QA round.

New i18n keys: reworded `esp.mailup.dkim_txt_alternative` (en + it); possibly one key for the "both options expected" message (coder to name; en + it). Italian wording for new text goes to the maintainer review.
Unverified external fact: the ml00 behaviour rests on the maintainer's statement of 2026-11-12, not on a checked official page.
Status: todo
