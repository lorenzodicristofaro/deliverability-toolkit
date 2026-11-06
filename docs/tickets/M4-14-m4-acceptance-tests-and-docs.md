# M4-14 M4 acceptance tests and docs/HEADERS.md
Milestone: M4
Branch: feature/m4-14-acceptance
Files in scope: tests/services/test_acceptance_m4.py, docs/HEADERS.md, TODO.md (M4 lines only, by PM)
Out of scope: new features; fixes found go back to the owning ticket
Depends on: M4-07, M4-11, M4-12, M4-13
Parallel-safe: yes (new files)
Model: sonnet
Acceptance criteria:
- Corpus: every sample in tests/fixtures/messages/MANIFEST.yaml is parsed and the facts recorded in the manifest (hop count, auth methods/results, ARC state, alignment outcome) are asserted. Samples marked `unverified` are asserted only for "parsed without crash and sections present", never for vendor-specific shape; the test report lists which providers are verified vs unverified. If the maintainer has not supplied real Gmail/Outlook/SES/SendGrid/MailUp samples, the milestone is accepted as "parser verified against RFC corpus; provider samples pending" and TODO.md says so.
- Identical results: for each corpus sample the service JSON, the REST endpoint body and the CLI `--format json` are byte-equal; the UI shows the same finding codes and statuses.
- Hostile input table through all three surfaces: oversize, NUL, fold bomb, 500+ headers, deep MIME, 10k Received hops, RFC 2047 junk, invalid and timezone-less dates; all yield 413/422/exit 2 or an `error`/partial result as specified, never a crash or a hang.
- Network guard: sockets blocked for the whole M4 suite; DNS fake asserts zero queries on every surface.
- Permission sweep: all M4 routes in the route-coverage matrix; denied cases (anonymous, foreign tenant, client viewer, `message.analyze` toggle false) never invoke the analyzer.
- No persistence: DB table row counts unchanged after analyses; no content in captured logs.
- i18n completeness: every code in app/services/message_findings.CODES has title/detail/remediation in en and it; every M4 key exists in both locales; scan shows no hardcoded strings in M4 templates/CLI.
- `docs/HEADERS.md`: scope and the offline guarantee (no DNS: what is reported is what the receiving server STATED, signatures are not verified), input limits table, parser behaviour on malformed input, finding code list with severities, permission `message.analyze` and why, CLI usage and exit codes, how to add a corpus sample (sanitization checklist), list of unverified provider samples and what the maintainer must supply.
New i18n keys: none
Notes from M4-07 QA: MANIFEST `alignment` in the ARC entry means identifier alignment, not DMARC alignment (rename to `identifier_alignment` here); RFC 8601 B.3/B.4 Date and Received stamps use a non-RFC 5322 format copied from the RFC, so do not assert date parsing on them; MANIFEST facts are hand-written and must be checked against parser output.
Status: todo
