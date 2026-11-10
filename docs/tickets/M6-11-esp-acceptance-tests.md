# M6-11 M6 acceptance: sample domains produce the expected findings
Milestone: M6
Branch: feature/m6-11-esp-acceptance-tests
Files in scope: tests/esp/test_acceptance.py, tests/esp/dns_builder.py (builds a fake DNS zone from a loaded profile), tests/fixtures/esp/ (extra fixtures if needed), tests/api/test_esp_acceptance.py (assignment + run end to end on the fake resolver), docs/CHECKS.md (add the `esp` check section)
Out of scope: app code (a bug found goes back to the GM as a finding), new profile data
Depends on: M6-04, M6-05, M6-06, M6-08, M6-09, M6-10 (profiles that end up not created are simply absent from the parametrization)
Parallel-safe: yes with M6-12 (disjoint files); no with anything still editing tests/fixtures/esp/
Model: sonnet
Acceptance criteria:
- Parametrized over EVERY shipped profile in `profiles/esp/`: the zone builder derives, from the profile itself (no hand-typed vendor values), a "correct" fake zone (all expected records present) and mutated zones (SPF include removed, each DKIM record removed, one CNAME pointing at a non-matching target, return-path missing). Expected: correct zone gives no ESP_* failure findings; each mutation gives exactly its expected finding code; fields under `unverified_fields` produce `ESP_PROFILE_UNVERIFIED` and no verdict on them.
- DNS failure injected on each needed name gives `error`, never `ok`/"missing" (all profiles).
- Two ESPs assigned with a combined SPF over the limit gives `ESP_SPF_COMBINED_OVER_LIMIT`.
- Meta test: every shipped profile has `verified_on`, non-empty https `sources`, and any `unverified` profile lists `unverified_fields`; this is the milestone's "each profile has verified_on + sources" criterion.
- End-to-end API test on a fake resolver: tenant owner assigns an ESP, runs `esp`, sees the findings; a client viewer gets 403; another tenant gets 404. No network anywhere.
- docs/CHECKS.md documents the `esp` check, its finding codes and error semantics.
New i18n keys: none
Status: todo
