# M6-18 DKIM seed: add mailchef (Emailchef, TXT) and brevo1/brevo2 (Brevo, CNAME)
Milestone: M6
Branch: feature/m6-18-dkim-seed-mailchef-brevo
Files in scope: seeds/dkim_selectors.yaml, tests/checks/test_dkim_selectors.py (add `"help.brevo.com": "brevo"` and the Emailchef host to `_VENDOR_HOSTS` if needed), seed-sync tests only if they enumerate entries
Out of scope: profiles/esp/*.yaml, locales, app/ code, other selectors, Italian wording review
Depends on: M6-17 (to be safe: M6-17 may touch tests/checks/)
Parallel-safe: no
Model: sonnet. QA model: sonnet (low-risk data change); QA re-fetches the sources.

Maintainer decisions (2026-11-11):
- Adding `mailchef` (Emailchef, TXT) is approved (open question from M6-09).
- `brevo1` / `brevo2` (Brevo, CNAME) were confirmed on help.brevo.com in M6-16 (help articles 16045394674066 and 12163873383186; read via the Zendesk API JSON body because the HTML returns 403).

Acceptance criteria:
- `seeds/dkim_selectors.yaml` gains three entries: `mailchef` (vendor Emailchef, TXT), `brevo1` and `brevo2` (vendor Brevo, CNAME), in the same format as the existing entries (sources, `verified_on`, Note).
- The coder re-reads the official source for each entry before writing it. For Emailchef use the sources listed in `profiles/esp/emailchef.yaml` (`sources`, the ones used in M6-09). For Brevo use the two help articles above (Zendesk API JSON body). Each Note quotes the supporting sentence. If a source cannot be re-read or does not support the entry, mark the entry `unverified` and report it; do not invent values.
- `verified_on` is the date the coder actually re-read the source.
- `tests/checks/test_dkim_selectors.py`: `_VENDOR_HOSTS` extended (`"help.brevo.com": "brevo"`, plus the Emailchef host) if the test requires it; existing seed tests (format, vendor/host match, sync) pass with the new entries.
- No network in unit tests; `uv run pytest -q --tb=short` and the lint commands pass.
New i18n keys: none
Status: done (merge e158ab4)
