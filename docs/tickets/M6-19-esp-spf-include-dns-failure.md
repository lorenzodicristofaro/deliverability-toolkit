# M6-19 esp check: report DNS failures on an ESP's SPF include host
Milestone: M6
Branch: feature/m6-19-esp-include-dns-failure
Files in scope: the esp check under app/checks/ (app/checks/esp_profile.py) and app/esp/ as needed, tests/checks/, tests/esp/, docs/CHECKS.md, locales/en.json and locales/it.json only if a new key is needed
Out of scope: profile YAML content, the `spf` check, ESP detection (M6-13), M6-17's MailUp SPF rule (do not change it), schema changes
Depends on: M6-17 (same check code)
Parallel-safe: no
Model: opus. QA model: opus.

Maintainer decision (2026-11-11, GM recommendation accepted): the `esp` check must never swallow a DNS failure on an ESP's SPF include host.

Current behaviour (from M6-11 QA): with one ESP assigned, SERVFAIL/timeout on the ESP's include host (e.g. musvc.com) gives `esp` status `info` with no finding, by design ("the ESP's own record is the SPF check's business", docs/CHECKS.md). With two SPF ESPs it gives ESP_DNS_ERROR part=spf.lookups, but no test covers it.

Acceptance criteria:
- In BOTH the one-ESP and the multi-ESP case, a DNS failure (SERVFAIL, timeout) on an ESP's SPF include host emits ESP_DNS_ERROR with part=spf.lookups, same shape as the existing two-ESP case, and the check status is non-ok (`partial` or `error` per the existing esp status rules; never `ok` or `info`).
- Table-driven tests, no network (fake DNS), covering: one ESP + include-host SERVFAIL; one ESP + include-host timeout; two ESPs + failure on one; include host resolves OK (behaviour unchanged); NXDOMAIN on the include host (decide per existing semantics for NXDOMAIN in the esp/spf code, and document the decision in the test and in docs/CHECKS.md).
- docs/CHECKS.md esp section: remove the "the ESP's own record is the SPF check's business" exception and describe the new behaviour.
- Existing M6-11 acceptance tests and tests/esp/test_shipped_profiles.py still pass; update only the expectations that encoded the old one-ESP `info` behaviour, and list them in the report.
- If ESP_DNS_ERROR needs a new param or text, add i18n keys en + it; otherwise none.
- No ARCHITECTURE.md edit by the PM; the coder reports if the change affects it.
New i18n keys: none expected (only if a new detail text is needed, en + it)
Status: done (merge 00bed63, QA APPROVE round 2; round 1 CHANGES REQUESTED for one-ESP truncation at/below the include host giving ok, fixed in f702381)
