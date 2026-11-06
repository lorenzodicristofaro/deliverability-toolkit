# M3-11 DMARC external report destination authorization
Milestone: M3
Branch: feature/m3-11-dmarc-external-auth
Files in scope: app/checks/dmarc_external.py, app/checks/dmarc.py (single call site + data field), locales/en.json, locales/it.json (finding.DMARC_EXTERNAL_* keys), tests/checks/test_dmarc_external.py, tests/fixtures/zones/dmarc_external_*.yaml
Out of scope: policy findings (M3-10), report ingestion
Depends on: M3-10
Parallel-safe: no (locale files; edits dmarc.py)
Model: opus (DMARC authorization logic)
Acceptance criteria:
- For each rua/ruf destination whose domain is not the same organizational domain as the checked domain (RFC 7489 section 7.1), query `<domain>._report._dmarc.<destination>` TXT; authorized only if a record starts with `v=DMARC1` (a `*.`-wildcard record is honoured per the RFC; verify the exact RFC text before coding, cite section in code comments).
- Codes: DMARC_EXTERNAL_UNAUTHORIZED (reports will likely be dropped; medium), DMARC_EXTERNAL_AUTH_UNVERIFIED (could not evaluate: DNS failure -> status `error` for that destination, never "unauthorized"), DMARC_EXTERNAL_AUTHORIZED (info, in data only, not a finding), DMARC_EXTERNAL_TOO_MANY_DESTINATIONS (cap on queries per run, constant).
- Same-org destinations (e.g. `dmarc@sub.example.com` for `example.com`) never trigger a query; mixed-case, IDN and trailing-dot destinations normalised; non-mailto schemes skipped with a note.
- `DmarcCheck.data["report_destinations"]` lists destination, external flag, authorized state; status `error` if any external destination could not be evaluated and nothing worse was found.
- Table-driven tests over recorded zones: authorized, missing authorization record, wrong version, wildcard auth, SERVFAIL, timeout, multiple destinations, hostile destination count.
- DNS failure states (SERVFAIL, timeout, refused, blocked) on any lookup the check depends on yield status `error` via CheckResult.build(evaluated=False), never `ok` or a 'missing' finding; table test with recorded failing zones.
New i18n keys: finding.DMARC_EXTERNAL_*.title/detail/remediation (en + it)
Status: todo
