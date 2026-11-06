# M3-13 DKIM selector probe engine and check
Milestone: M3
Branch: feature/m3-13-dkim-probe
Files in scope: app/checks/dkim.py, app/checks/registry.py (import line), locales/en.json, locales/it.json (finding.DKIM_* keys), tests/checks/test_dkim_check.py, tests/fixtures/zones/dkim_*.yaml
Out of scope: SSE/HTTP (M3-16), tenant/admin selectors (M5), ESP-specific expectations (M6)
Depends on: M3-02, M3-03, M3-06, M3-12
Parallel-safe: no (locale files, registry)
Model: sonnet
Acceptance criteria:
- `probe_selectors(ctx, domain, selectors) -> AsyncIterator[SelectorResult]` yields each result as soon as it is ready (bounded concurrency constant, ARCHITECTURE section 6; every selector probed, no early stop). `DkimCheck.run` drains the same generator, so SSE and the batch result are identical by construction.
- Per selector: query `<sel>._domainkey.<domain>` TXT, following CNAME delegation chains (max depth 8, loop -> DKIM_CNAME_LOOP, chain recorded in evidence); states `found`, `not_found` (NXDOMAIN/NODATA), `error` (any failure state; never `not_found`).
- Codes: DKIM_NO_SELECTOR_FOUND (info/low: selectors cannot be enumerated, remediation says to add selectors; message must not claim DKIM is absent), DKIM_KEY_SYNTAX_ERROR, DKIM_KEY_REVOKED, DKIM_KEY_WEAK_1024, DKIM_KEY_TOO_SHORT (<1024), DKIM_TEST_MODE (`t=y`), DKIM_MULTIPLE_RECORDS, DKIM_CNAME_LOOP, DKIM_CNAME_CHAIN_LONG, DKIM_PROBE_ERRORS (some selectors could not be evaluated -> status `error` when nothing was found and any selector errored).
- `data["selectors"]` lists every probed selector with state, key type, bits; the UI note "selectors cannot be enumerated" is a documented `data["enumerable"]=False` flag.
- Tests: recorded zones for 2048/1024/ed25519/revoked/t=y/CNAME chain/loop/NXDOMAIN/SERVFAIL; ordering of yielded results; concurrency bound via the fake resolver; no network.
- DNS failure states (SERVFAIL, timeout, refused, blocked) on any lookup the check depends on yield status `error` via CheckResult.build(evaluated=False), never `ok` or a 'missing' finding; table test with recorded failing zones. (DKIM probe, GM rule: failed selectors are always listed in DKIM_PROBE_ERRORS. If at least one selector is `found`, the overall status follows the findings. If none is found and any selector failed, status is `error` (the failed one may be the real selector, so never report DKIM_NO_SELECTOR_FOUND alone). Only when every selector is `not_found` is DKIM_NO_SELECTOR_FOUND emitted.)
- fetch_cname may return state ok with an empty target ('' from a '.' CNAME); treat a falsy target as a malformed delegation (selector state `error`, never `found`/`not_found`); test it (M3-03 QA nit).
New i18n keys: finding.DKIM_*.title/detail/remediation (en + it)
Status: todo
