# M7-03 DNSBL/URIBL engine with refusal and blocked-resolver detection
Milestone: M7
Branch: feature/m7-03-dnsbl-engine
Files in scope: app/checks/dnsbl_engine.py, app/checks/dnsbl_schema.py, tests/checks/test_dnsbl_engine.py, tests/checks/test_dnsbl_schema.py, tests/checks/fixtures/dnsbl_test_lists.yaml (fake lists only, reserved names like example.test)
Out of scope: the shipped `seeds/dnsbl.yaml` (M7-04), check registration, API/CLI/UI (M7-05), locale files, scheduling
Depends on: none
Parallel-safe: yes (new files only)
Model: opus (misreading a refusal as listed or clean is the core correctness risk; GM may downgrade)
Acceptance criteria:
- Schema (strict hand-written loader like app/esp/profile.py: unknown keys, duplicate keys, anchors rejected, size cap): per list id, zone, kind (`ip` or `domain`), IPv4/IPv6 support flags, return-code map (code -> meaning: `listed` with category label, `refused`, `info`), `verified_on`, `sources`, `status: verified|unverified` (unverified requires `unverified_fields`), optional usage policy notes as free text key (no invented numbers).
- Query building: IPv4 reversed octets, IPv6 nibble reversal, domain names IDNA-normalised, name length limits; invalid input -> typed error, no query.
- Interpretation (pure function over the DNS result type from app/dns/types.py): NXDOMAIN -> `not_listed` ; A answer in a mapped `listed` code -> `listed`; mapped `refused` code OR any answer in 127.255.255.0/24 for lists that declare that convention -> `error` reason `refused`; answer outside 127.0.0.0/8, unmapped 127.x code, multiple conflicting codes, NODATA, SERVFAIL, timeout, REFUSED rcode, blocked egress -> `error` with distinct reasons. Never `ok`/`not_listed` on anything but a clean NXDOMAIN (or NODATA only if the list declares it as clean; default is `error`). An unverified list entry never produces `listed`: it yields `error` reason `list_unverified` unless the caller sets an explicit "include unverified" flag, in which case the result is marked unverified.
- Resolver-level blocking: if the first N queries (configurable, default from a constant) to a list all return refused/blocked codes the list is marked `blocked_resolver` for the run and the remaining queries are skipped (no burst against a list that refuses us); status `error`.
- Parallel queries with per-query timeout and a global concurrency cap through the existing DNS layer; per-list rate limiting lives in the scheduler (M7-09), but the engine accepts an injected `acquire(list_id)` async hook (default no-op) so it can be tested.
- Results carry evidence bounded in size; DNS failures are never swallowed.
- Tests table-driven with a fake DNS backend, no network: each rcode/answer shape above, IPv6 nibble form, 127.255.255.x refusal, mixed answers, unverified list, blocked-resolver short-circuit, malformed schema files, hostile input names.
New i18n keys: none (reason codes only; localised in M7-05)
Status: done (merged into dev; commits 6389d34 + 3ebadfb; QA APPROVE round 2)
Outcome:
- Extra outcomes beyond the spec: `info` and `not_applicable`.
- Non-public target IPs -> `not_applicable` / `non_public_address`, no query sent (round 1 fix, privacy).
- Name errors distinguished: `invalid_name` vs `name_too_long`.
- Failing `acquire` hook -> `error` / `rate_limit_error`, without hanging.
- `address_policy` is a test-only seam.
- Unverified lists are not queried unless the include-unverified flag is set.
