# M6-04 ESP profile check (SPF include, DKIM CNAMEs, return-path, tracking domain)
Milestone: M6
Branch: feature/m6-04-esp-profile-check
Files in scope: app/checks/esp_profile.py, tests/checks/test_esp_profile.py, tests/fixtures/esp/ (fake profile and fake DNS fixtures only, extends M6-01 fixtures), locales/en.json, locales/it.json
Out of scope: DB access (checks have no DB handle, `CheckContext`), registering in `load_builtin_checks` (the check needs per-domain input; wiring is M6-06, follow the M5-23 custom-checks pattern), the combined-lookup finding (M6-05), real vendor profiles
Depends on: M6-01
Parallel-safe: yes with M6-02; no with M6-03/M6-05/M6-07..10 (locale files)
Model: opus (DNS check)
Acceptance criteria:
- `EspProfileCheck(profiles, assignments)` implements the `Check` protocol (id `esp`), constructed per domain run with the assigned profiles and the optional per-assignment `return_path_host` / `tracking_host`. It reads DNS only through `ctx.resolver` and the existing helpers (`app/checks/dnsutil.py` `fetch_txt`/`fetch_cname`, `app/checks/spf_tree.py` `resolve_spf` for the SPF include test: an include may be nested, so test the resolved tree, not only the top record).
- Findings (codes listed in a module `CODES` tuple, built with `finding()`; names indicative): `ESP_SPF_INCLUDE_MISSING`, `ESP_DKIM_RECORD_MISSING`, `ESP_DKIM_TARGET_MISMATCH` (CNAME exists but `target_pattern` does not match), `ESP_DKIM_WRONG_TYPE`, `ESP_RETURN_PATH_MISSING`, `ESP_RETURN_PATH_MISMATCH`, `ESP_TRACKING_MISSING` (severity info when `optional`), `ESP_HOST_NOT_CONFIGURED` (return-path or tracking host unknown for this assignment: info, that part not evaluated), `ESP_PROFILE_UNVERIFIED` (info, when the profile is `unverified`), `ESP_DNS_ERROR`, plus the profile's static pitfalls as info findings.
- Error discipline: any DNS failure (SERVFAIL, timeout, REFUSED, blocked, truncated) on a name the check needs gives `evaluated=False` / status `error` with `ESP_DNS_ERROR` naming the name and state; never `ok`, never "missing" (NXDOMAIN/NODATA are the only "missing" cases). A profile with a part listed in `unverified_fields` skips that part and says so.
- Results have one section per assigned ESP in `data` (stable, sorted); zero assigned ESPs gives status `info` with no findings (not `ok`).
- Table-driven tests with fake DNS (no network): each finding, nested SPF include, CNAME chain to a matching target, pattern edge cases, NXDOMAIN vs NODATA vs each error state, optional tracking, unverified field skipped, two ESPs at once, deterministic output.
- Every code has finding.<CODE>.title/detail/remediation in en and it (the i18n completeness test reads `CODES`).
New i18n keys: finding.ESP_*.title/detail/remediation for each code above (en + it); coder lists final codes in the summary
Status: todo
