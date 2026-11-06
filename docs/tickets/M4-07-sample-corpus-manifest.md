# M4-07 Sample message corpus and manifest
Milestone: M4
Branch: feature/m4-07-corpus
Files in scope: tests/fixtures/messages/*.eml, tests/fixtures/messages/MANIFEST.yaml, tests/fixtures/messages/README.md, tests/fixtures/test_message_corpus_manifest.py
Out of scope: parsing assertions per sample (M4-14), any parser code.
Depends on: M4-01 (only for the loader used by the manifest test; may start earlier with a plain YAML check)
Parallel-safe: yes (fixtures only)
Model: sonnet
Acceptance criteria:
- Every sample is synthetic or sanitized: only example.com/.net/.org, IPs from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, no real names, mailboxes, message-ids or signatures. A test scans all .eml for non-reserved IPs, non-reserved domains and NUL bytes (allowlist for hostnames inside the manifest).
- MANIFEST.yaml has one entry per sample: file, provider_label (gmail, outlook, ses, sendgrid, mailup, plain-rfc, arc-rfc8617, malformed-*), `status: verified | unverified`, `sources` (URL list), `verified_on` (date), `notes`, and the facts the M4-14 test may assert (expected hop count, auth methods, arc chain state, alignment outcome).
- NO header shape is invented. A provider sample may be `verified` only if the coder finds an official document (provider docs, RFC) showing that header shape and cites URL + verified_on. Otherwise the sample is built only from RFC-defined syntax, marked `status: unverified`, with `sources: []` and note "shape not confirmed against a real message of this provider".
- Guaranteed verifiable set (RFC examples): RFC 8601 Authentication-Results examples, RFC 8617 appendix B ARC example, RFC 5321 Received examples; plus hand-written malformed samples (folding bomb, NUL, no-timezone dates, deep MIME, boundary missing, RFC 2047 junk, oversize header line).
- README.md lists exactly what the MAINTAINER must supply: sanitized real .eml (or header-only) samples from Gmail, Outlook/Microsoft 365, Amazon SES, SendGrid, MailUp, each with the sanitization checklist (replace domains, IPs, message-ids, strip signature b=/bh= values only after keeping their length) and who sanitized them.
- Manifest test: every file in the folder is in the manifest and vice versa; unverified entries have no `sources` claims; verified entries have non-empty sources and a verified_on date.
New i18n keys: none
Status: todo
