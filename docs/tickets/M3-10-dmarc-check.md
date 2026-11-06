# M3-10 DMARC check: policy findings and org-domain fallback
Milestone: M3
Branch: feature/m3-10-dmarc-check
Files in scope: app/checks/dmarc.py, app/checks/registry.py (import line), locales/en.json, locales/it.json (finding.DMARC_* keys), tests/checks/test_dmarc_check.py, tests/fixtures/zones/dmarc_*.yaml
Out of scope: external report authorization (M3-11), DMARC aggregate report ingestion (M7+), UI/API
Depends on: M3-02, M3-03, M3-05, M3-09
Parallel-safe: no (locale files, registry)
Model: sonnet
Acceptance criteria:
- `DmarcCheck(id="dmarc")` queries `_dmarc.<domain>`; if there is no record and the domain is a subdomain, falls back to `_dmarc.<organizational domain>` and reports `data.found_at` and `data.inherited=True`.
- Multiple DMARC records at a name -> DMARC_MULTIPLE_RECORDS (RFC: treated as no record); non-DMARC TXT at the name ignored.
- Codes: DMARC_MISSING, DMARC_MULTIPLE_RECORDS, DMARC_SYNTAX_ERROR (from parser issues, evidence = issue list), DMARC_POLICY_NONE (info/low), DMARC_POLICY_QUARANTINE (info), DMARC_SUBDOMAIN_POLICY_WEAKER (sp weaker than p), DMARC_PCT_PARTIAL (pct<100 with enforcing policy), DMARC_NO_RUA, DMARC_RUF_PRESENT (info: many receivers ignore ruf; do not state receiver behaviour as fact beyond RFC text), DMARC_ALIGNMENT_STRICT (info), DMARC_INHERITED_FROM_ORG (info), DMARC_DNS_ERROR.
- DNS failure at `_dmarc.` or at the fallback name -> status `error`, never DMARC_MISSING (table test over every ResultState for both lookups).
- All codes have en + it title/detail/remediation; completeness test as in M3-08.
- Table-driven tests: recorded zones for healthy, p=none, subdomain, missing, multiple, malformed, SERVFAIL.
- DNS failure states (SERVFAIL, timeout, refused, blocked) on any lookup the check depends on yield status `error` via CheckResult.build(evaluated=False), never `ok` or a 'missing' finding; table test with recorded failing zones.
New i18n keys: finding.DMARC_*.title/detail/remediation (en + it)
Status: todo
