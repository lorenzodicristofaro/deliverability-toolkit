# M4-08 Alignment analysis (From / Return-Path / DKIM d=)
Milestone: M4
Branch: feature/m4-08-alignment
Files in scope: app/services/message_alignment.py, tests/services/test_message_alignment.py
Out of scope: DNS (the DMARC policy/aspf/adkim of the domain is NOT fetched; defaults relaxed and strict are both reported), parsing, findings text, API/UI/CLI.
Depends on: M4-01, M4-04
Parallel-safe: yes (new files; uses existing app/core/org_domain.py read-only)
Model: sonnet
Acceptance criteria:
- Pure offline function: inputs are the RFC5322.From domain(s), Return-Path / smtp.mailfrom domain, and the DKIM `d=` values taken from (a) Authentication-Results header.d and (b) DKIM-Signature headers present in the message. Uses `app.core.org_domain.organizational_domain`; no other DNS.
- Output per identifier pair (From vs Return-Path, From vs each d=): `relaxed_aligned` and `strict_aligned` booleans, org domain used, plus the stated spf/dkim result from Authentication-Results when present. An `aligned` verdict requires BOTH a stated pass and domain match; a domain match with a non-pass result is reported as `aligned_but_not_passed`. States: aligned | misaligned | unknown (missing/unparseable identifier) | not_evaluated (no usable data). Never `ok` on missing data.
- DKIM-Signature present without a matching Authentication-Results dkim result is reported as `unverified_signature` (signature NOT cryptographically checked; stated in docs).
- InvalidDomainName, IP literals, multiple From addresses, empty Return-Path `<>`, IDN (u-label vs punycode), uppercase, trailing dot, subdomain vs apex, public-suffix domains (`github.io`, `co.uk`) are tested in a table.
- DMARC pass is reported only as the receiver stated it (dmarc=pass in Authentication-Results); alignment computed here is labelled `computed` vs `stated`, and a mismatch between computed and stated is surfaced to M4-09.
New i18n keys: none (codes only; text in M4-09)
Status: todo
