# M6-17 MailUp SPF: apply the maintainer decision (include only when an SPF record exists)
Milestone: M6
Branch: feature/m6-17-mailup-spf-decision
Files in scope: profiles/esp/mailup.yaml, app/esp/ (only if needed), app/checks/ esp check (only if needed), locales/en.json and locales/it.json (`esp.mailup.*` and any new key; also `esp.mailgun.tracking` en + it and `esp.sendgrid.tracking` it), tests/esp/, tests/checks/, docs/ESP_PROFILES.md, docs/CHECKS.md, ARCHITECTURE.md only if the engine/schema change affects it (the coder reports it; the PM never edits it)
Out of scope: other profiles' behaviour (unless they opt in), the `mailchef` seed question, Italian wording review of other strings, Contactlab/Agile Telecom/Aruba
Depends on: M6-16
Parallel-safe: no (locale files)
Model: opus (engine logic + DNS failure handling). QA model: opus.

Maintainer decision (2026-11-11, source of truth):
- MailUp's SPF guidance (`include:musvc.com`) applies when the sending domain ALREADY has an SPF record: that record should include musvc.com.
- If the domain has never had an SPF record, do NOT create one containing only MailUp's include.
- DMARC is not a problem in that case, because SPF for DMARC is evaluated on the return-path domain, not on the From domain.

Goal: `profiles/esp/mailup.yaml` and the `esp` check follow this decision.

Acceptance criteria:
- With MailUp assigned/detected: domain with an SPF record lacking musvc.com gives the missing-include finding as today; domain with NO SPF record gives no missing-include finding for MailUp (an info pitfall explaining the decision is fine).
- Rewrite `esp.mailup.spf_only_if_published` (en + it) to state the rule plainly, attributed as the project's guidance; drop the "help pages differ" wording. Keep the cited sources; record the maintainer decision (2026-11-11) in the profile comment/Note.
- First step for the coder: check how the engine treats `spf.includes` when the domain has no SPF record (app/esp/, app/checks/) and report the finding. If supporting the decision needs a schema field (e.g. a per-profile "SPF include only if a record exists" flag), that is an engine/schema change: allowed, minimal, documented in docs/ESP_PROFILES.md and docs/CHECKS.md; update ARCHITECTURE.md if affected (reported to the GM/PM, not edited by the PM).
- Table-driven tests (no network): SPF record present with the include, present without the include, no record, DNS failure on the SPF lookup gives `error`, never `ok` (no swallowed DNS failure).
- Other profiles' behaviour is unchanged unless they opt in; existing M6-11 acceptance tests and `tests/esp/test_shipped_profiles.py` still pass.
- No vendor facts invented: any value not already verified stays as in the current profile; flag anything unverifiable.
- Locale fixes carried from M6-16 QA (same locale files):
  - (a) `esp.mailgun.tracking` en + it: mention that Mailgun's domain verification docs list the tracking CNAME as required for tracking.
  - (b) locales/it.json `esp.sendgrid.tracking` (line ~235): "da cui serve i link" becomes "da cui distribuisce i link".
New i18n keys: rewritten `esp.mailup.spf_only_if_published` (en + it) and any new `esp.mailup.*` key (en + it); changed `esp.mailgun.tracking` (en + it) and `esp.sendgrid.tracking` (it)
Status: todo
