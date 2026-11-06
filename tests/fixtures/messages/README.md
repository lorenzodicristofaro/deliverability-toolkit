# Sample message corpus

Fixtures for the message analyzer (M4). `MANIFEST.yaml` has one entry per `.eml`; the test
`tests/fixtures/test_message_corpus_manifest.py` enforces that the folder and manifest match.

## Rules

- Only `example.com`, `example.net`, `example.org` (and subdomains), IPs in `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`. No real names, mailboxes, message-ids
  or signatures. No NUL bytes, except a file whose manifest entry says `contains_nul: true`.
- Extra hostnames are allowed per entry only through `allowed_hostnames` in the manifest.
- `status: verified` needs `sources` (URL list) and `verified_on`. `status: unverified` has
  `sources: []`, `verified_on: null` and the note "shape not confirmed against a real message
  of this provider". Never invent a vendor header shape.
- RFC samples (8601 B.3/B.4, 5321 D.3, 8617 B) are the RFC text, with host names and IPs
  replaced by reserved ones where the RFC used other values. Line endings are LF.
- Malformed samples are hand-written; their `sources` cite the RFC rule being violated.

## What the MAINTAINER must supply

Sanitized real `.eml` (or header-only) samples from each of: Gmail, Outlook/Microsoft 365,
Amazon SES, SendGrid, MailUp. The current `gmail|outlook|ses|sendgrid|mailup-unverified.eml`
files are generic placeholders (RFC syntax only) and must be replaced by them. For each sample
also provide the official document (URL + date checked) that shows the header shape, if one
exists, so the entry can become `verified`, and the name of the person who sanitized it.

Sanitization checklist (tick every item for every sample):

1. Replace every sender/recipient domain with example.com/.net/.org (consistently).
2. Replace every IPv4/IPv6 address with one from the reserved ranges above (consistently).
3. Replace every Message-ID, queue id, tracking id and mailbox/name with a made-up value.
4. DKIM/ARC signatures: record the original length of each `b=` and `bh=` value first, then
   replace it with a made-up string of the SAME length; keep the tag structure (`a=`, `c=`,
   `h=`, `s=`, `d=`) with `d=`/`s=` changed to reserved domains.
5. Remove tracking links, unsubscribe tokens and body text; keep the MIME structure.
6. Search the result for the original domains, IPs and recipient strings: zero hits.
7. Record in the manifest `notes`: provider, date received, sanitized by (name).
