# F-01 Message analysis: authentication per hop view
Milestone: Backlog (maintainer request 2026-11-13; not part of R1)
Branch: feature/f-01-auth-per-hop-view
Scope check: maintainer confirmed it as an analyzer extension (no SPEC scope change).
Files in scope (coder confirms the exact list before coding): app/services/message_alignment.py or a new app/services/message_hops.py, app/services/message_findings.py (info finding), app/parsers/ read-only use of the existing authres/ARC/Received parsers, app/api/v1 message analysis response schema, app/web message analysis template and view, app/cli text output, docs/HEADERS.md, tests/services/test_message_hops.py (new), API/web/CLI tests, locales/en.json + locales/it.json
Out of scope: cryptographic verification of DKIM or ARC signatures, changing `computed_dmarc` rules (R1-22), changing the ARC structure checks (MSG_ARC_INVALID, MSG_ARC_CV_FAIL), trust decisions on authserv-id, any vendor-specific format claim
Depends on: R1-22 (rule: the verdict uses the topmost field)
Parallel-safe: no (shares message_alignment/message_findings and locale files with R1-22 and R1-10)
Model: opus
Description:
- The message analysis shows an "authentication per hop" view. Every Authentication-Results field and every ARC set (ARC-Authentication-Results, ARC-Seal, ARC-Message-Signature, instance `i=`) is placed in order among the Received fields by header position (each MTA prepends, so position encodes hop order).
- Per field: authserv-id and the spf/dkim/dmarc/arc results.
- Where a result changes from pass to fail between hops, add an info finding: "authentication broke after hop N, likely forwarding or list modification" (en + it).
- Authentication-Results fields below the topmost one are shown as "stated by <authserv-id>, not verifiable". Display only: they never feed `computed_dmarc` (R1-22 rule: the verdict uses the topmost field).
- ARC signatures are not cryptographically verified (same as DKIM). Structure checks already exist and are unchanged.
- Verified-fact rule: before coding, the coder checks the RFC 8601 and RFC 8617 text for every claim (field syntax, instance numbering, ordering semantics, cv values) and cites sections in docs/HEADERS.md. No vendor claims.
Acceptance criteria:
- Ordering by header position with interleaved Received fields is correct and pinned by a test.
- Forwarding scenario: pass at hop 1, spf fail after the forwarder -> info finding names the hop.
- Mailing-list scenario: dkim fail after modification -> info finding.
- Forged lower field: shown as "stated by <authserv-id>, not verifiable", and `computed_dmarc` unchanged (test).
- Malformed or unparsed fields: shown as unparsed, no exception, no finding derived from them; table-driven tests.
- Output in web UI, API JSON and CLI text; no input echo beyond the existing bounded excerpts; control characters escaped as elsewhere.
- No network in tests. ruff, mypy, relevant tests green; API endpoint tenancy/permission test if the schema touches an endpoint with auth.
New i18n keys (en + it): hop view title and column labels, "stated by {authserv_id}, not verifiable", finding MSG_AUTH_BROKE_AFTER_HOP title/detail (final key names set by the coder)
Status: split (2026-11-13) into F-01-01 (docs/tickets/F-01-01-hop-view-service.md: service, info finding, R1-22 QA inputs, docs/HEADERS.md) and F-01-02 (docs/tickets/F-01-02-hop-view-surfaces.md: API JSON, web, CLI, i18n, permission tests; depends F-01-01). This file stays as the parent spec; its acceptance criteria are distributed over the children.
Inputs from R1-22 QA (address in this ticket):
- MSG_ALIGNMENT_FAIL text says "Neither the SPF nor a DKIM identifier is aligned" while a lower-field dkim pair shows aligned (app/services/message_findings.py:404-415).
- `_topmost_results` (app/services/message_findings.py:325) still reads per-method results (MSG_DKIM_NOT_PASS / MSG_SPF_NOT_PASS) from lower fields; consistent with option (c), it can only add a warning.
