# M6-13 Detect ESPs configured in DNS but not assigned
Milestone: M6
Branch: feature/m6-13-esp-detection-from-dns
Files in scope: app/checks/esp_detection.py (new, or an extension of the M6-04 check module; coder decides, one concern), app/services/ wiring seam from M6-06 (so detection runs with the `esp` check), app/esp/ only for read helpers on loaded profiles, locales/en.json, locales/it.json, tests/checks/test_esp_detection.py (fixture profiles, fake DNS), tests for the run wiring (extend the M6-06 tests)
Out of scope: UI (M6-07), profile content (M6-08..10), network access outside the guarded client, writes or auto-assignment, SPEC.md/ARCHITECTURE.md
Depends on: M6-06, M6-04, M6-05 (also M6-06c for viewer visibility of the result)
Parallel-safe: no (checks seam, locale files)
Model: opus
Acceptance criteria:
- SPF detection: from the domain's resolved SPF tree (reuse the M6-04/05 resolution; no second resolver), collect every include and redirect target and match them against the verified `spf.includes` of every loaded profile.
- DKIM detection: for every loaded profile, probe only its verified selectors; a hit is a CNAME whose target matches the profile's `target_pattern`. Total DNS queries for DKIM probing are bounded by a named constant cap. At the cap the check stops probing and returns a partial result explicitly marked (`data` flag plus an `ESP_DETECTION_TRUNCATED` finding, en + it, which keeps the status from being `ok`); it never returns a silent `ok` (GM decision 2026-11-10). DNS queries go through `ctx.resolver` like the other checks (no new network path).
- Only verified profile fields are used. Fields marked `unverified` are ignored for matching and a test proves an unverified include or selector never produces a detection.
- Profiles already assigned to the domain are excluded from detection (they are covered by M6-04).
- Finding ESP_DETECTED_NOT_ASSIGNED: severity low, params carry the esp id and name, evidence (matched include or selector and target), and the hint "remove the old records or assign the ESP". Remediation and message keys in en + it. Viewer-safe wording: it says possible stale configuration, not "misconfigured".
- A domain with no assignments and no detections returns a single ESP_NONE_ASSIGNED info result (reuse the M6-04 "nothing assigned" result), not an omitted check, so the `esp` check always has a defined state.
- Consequence for M6-06: the `esp` check now runs in `all` even when nothing is assigned (M6-06 ran it only when at least one ESP was assigned). Update that wiring. The M6-06 byte-equal regression test for domains without ESPs is updated on purpose: the `all` result now includes the `esp` entry. State this in the commit message.
- DNS failure (timeout, SERVFAIL, resolver error) gives `error`, never `ok` and never swallowed. NXDOMAIN on a probed selector is a normal miss, not an error.
- Tests are table-driven with a fake DNS and fixture profiles (no real profile files, no network): SPF include match, redirect match, DKIM CNAME match and mismatch, unverified fields ignored, assigned ESP excluded, no assignment and no detection, cap reached, DNS failure, malformed SPF.
- Detection quality grows with profiles M6-08..10; this ticket's tests use fixtures only.
- Two-tenant test: detection results for tenant A's domain never reach tenant B's run.
New i18n keys: ESP_DETECTED_NOT_ASSIGNED message and remediation, a truncation message if the partial option is chosen, evidence labels as needed (names follow existing finding key conventions; en + it)
Status: done (merged into local dev after QA APPROVE; GM gate full PostgreSQL suite green, lint clean; DKIM concurrency should-fix moved to M6-13b)
