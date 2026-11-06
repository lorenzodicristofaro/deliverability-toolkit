# M3-08 SPF check: findings, all-mechanism, flattening hints
Milestone: M3
Branch: feature/m3-08-spf-check
Files in scope: app/checks/spf.py, app/checks/registry.py (add the import line only), locales/en.json, locales/it.json (finding.SPF_* keys), tests/checks/test_spf_check.py
Out of scope: UI/API wiring, auto-flattening of records (hints only, no generation of vendor include data), ESP-specific SPF includes (M6)
Depends on: M3-02, M3-07
Parallel-safe: no (locale files, registry)
Model: opus (SPF logic)
Acceptance criteria:
- `SpfCheck(id="spf")` returns `CheckResult` with `data` = tree summary (record, lookup_count, void_count, nodes) and findings with stable codes: SPF_MISSING, SPF_MULTIPLE_RECORDS, SPF_SYNTAX_ERROR, SPF_TOO_MANY_LOOKUPS (>10), SPF_NEAR_LOOKUP_LIMIT (info/low at 9-10, threshold constant), SPF_TOO_MANY_VOID_LOOKUPS (>2), SPF_INCLUDE_LOOP, SPF_INCLUDE_NOT_FOUND, SPF_PLUS_ALL, SPF_QUESTION_ALL, SPF_NEUTRAL_ALL_SOFTFAIL note (`~all` info), SPF_NO_ALL, SPF_REDIRECT_WITH_ALL, SPF_PTR_DEPRECATED, SPF_RECORD_TOO_LONG (over 255-char string chunk / over 512 bytes total UDP risk, thresholds as constants with RFC reference), SPF_RESOLUTION_TRUNCATED.
- Flattening hints: when lookups exceed or approach the limit, finding SPF_FLATTENING_HINT lists the includes ranked by lookups they consume (evidence), says flattening is operationally risky (provider IPs change); no IPs are generated.
- DNS failure anywhere that affects the result -> status `error` plus SPF_DNS_ERROR finding naming the failed name and ResultState; never `ok`/SPF_MISSING (explicit test per ResultState).
- Every finding has en + it title/detail/remediation; a test asserts all `CODES` have keys in both locales and that `it` keys are not copies of `en` for remediation.
- Table-driven tests over the M3-07 zones plus a fully healthy domain (status ok).
- DNS failure states (SERVFAIL, timeout, refused, blocked) on any lookup the check depends on yield status `error` via CheckResult.build(evaluated=False), never `ok` or a 'missing' finding; table test with recorded failing zones.
New i18n keys: finding.SPF_*.title/detail/remediation (en + it), one set per code listed above
Facts from M3-07 (app/checks/spf_tree.py) the check must honour:
- Nodes with syntax_error=True must produce an SPF permerror finding (SPF_SYNTAX_ERROR); their children are not evaluated.
- Void lookups now include redirect targets.
- `a` is void when A is absent; the AAAA state is in TermLookup.states.
- `truncated` implies lookup_count > 10, which is a lower bound. Report it as too-many-lookups (SPF_TOO_MANY_LOOKUPS / SPF_RESOLUTION_TRUNCATED), never ok.
- An include target with no SPF record is permerror (SPF_INCLUDE_NOT_FOUND), not void.
Status: done
