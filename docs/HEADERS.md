# Message header analysis (M4)

## Scope and the offline guarantee

The analyzer takes ONE raw message (or just its header block) that someone pasted, uploaded or
piped in, and explains it: summary, `Received` hops, `Authentication-Results`, ARC chain,
identifier alignment, MIME structure, and a list of findings.

It is strictly offline:

- Results are what the receiving server STATED. An `Authentication-Results` header is text
  written by whoever handled the message; the analyzer reports it as "stated" and never
  treats it as proof.
- Signatures are NOT verified. DKIM and ARC signatures are not checked cryptographically
  (`crypto_checked` is false, ARC `verified` is `None`).
- There are NO DNS lookups and no other network access, on any surface (REST, UI, CLI). No
  keys are fetched, no SPF record is evaluated, no DMARC policy is read.
- Nothing is stored or logged: no database rows, no message content in logs. Pasted text is
  never echoed back, and the `for <address>` clause of a `Received` header is removed.

## Surfaces

| Surface | Entry point | Input |
|---|---|---|
| REST | `POST /api/v1/message/analyze` | raw body, `message/rfc822` or `text/plain` (415 otherwise) |
| UI | `/tools/message` | pasted text, or a file read in the browser (see below) |
| CLI | `dtk analyze <file or -> [--format text\|json] [--lang en\|it]` | file or stdin |

The service JSON, the REST body and the CLI `--format json` output are byte-equal (the CLI
adds exactly one trailing newline). The UI shows the same finding codes and statuses.

UI upload reads the file with `FileReader` as UTF-8, so a non-UTF-8 `.eml` may be mangled; paste
it or use the API or CLI to send the exact bytes.

## Input limits

| Limit | Value | Result |
|---|---|---|
| Raw message | 2 MiB | REST/UI 413, CLI exit 2 |
| Empty input | - | REST/UI 422, CLI exit 2 |
| NUL byte | - | REST/UI 422, CLI exit 2 |
| Header block | 128 KiB | status `error`, finding `MSG_PARSER_LIMIT` |
| Physical header line | 8 KiB | status `error`, `MSG_PARSER_LIMIT` |
| Unfolded header field | 64 KiB | status `error`, `MSG_PARSER_LIMIT` |
| Header count | 500 | status `error`, `MSG_PARSER_LIMIT` |
| `Received` hops | 100 (newest kept, `truncated`); 8 KiB per hop, counted in UTF-8 bytes | partial result |
| MIME depth / parts | 10 / 200 | partial result, `MSG_MIME_TRUNCATED` |
| ARC instances | 50 | structural issue |

An input the analyzer refuses is data: HTTP 200 with status `error`, never a crash. The REST
size check happens while streaming, so an oversized body is never buffered.

## Parser behaviour on malformed input

- Nothing is truncated silently: a cap is reported (`truncated`, `MSG_PARSER_LIMIT`).
- A bare CR is not a line delimiter. 8-bit bytes are decoded as UTF-8 with replacement.
- Broken RFC 2047 encoded-words are kept as text and flagged (`MSG_ENCODED_HEADER_BROKEN`).
- `Authentication-Results`: method and result names are lowercased; `raw` keeps the original text.
  The obsolete pvalue `"x" @ example.com` (whitespace around `@`) is not joined.
- `Received`: unknown or military zones are read as `-0000` with `date_zone_unknown`; a date
  without a zone gives no value, never UTC. 1-digit time fields are accepted (lenient). A keyword
  used as a value (`by id`) gives `missing_clause_value`.
- Dates: the RFC 8601 B.3/B.4 examples use a date format that is not RFC 5322, so they report
  `MSG_DATE_INVALID`; that is expected for those samples and date parsing is not asserted on them.
- MIME: size totals count encoded leaf bytes; the quoted-printable decoded size is an estimate;
  RFC 2231 values are not percent-decoded; a boundary outside bchars gets the `invalid_boundary`
  warning.
- ARC is structural only (no cryptography, `verified` is `None`). A `cv=fail` in any seal takes
  precedence over the other states.
- Alignment: the verdict is relaxed, with strict reported alongside it. With a public suffix only
  an exact match counts. The topmost `Authentication-Results` per method is used. A pass with an
  unknown sibling still computes pass (for example `spf=pass` with an aligned `smtp.mailfrom`
  plus `dkim=pass` without `header.d`).

## Findings

Status follows the severity: high or critical gives `fail`, medium or low gives `warn`, info gives
`info`. An input that could not be evaluated gives `error`, never `ok`. The severities below are
taken from the docstring of `app/services/message_findings.py`.

| Code | Severity | Meaning |
|---|---|---|
| MSG_MISSING_FROM | high | no (or empty) From |
| MSG_MULTIPLE_FROM | high | more than one From |
| MSG_MISSING_DATE | medium | no (or empty) Date |
| MSG_DATE_INVALID | medium | Date cannot be parsed (error-class) |
| MSG_DATE_NO_TIMEZONE | low | Date without zone (error-class) |
| MSG_DATE_FAR_FROM_RECEIVED | medium | Date vs first hop differs by more than 24 h |
| MSG_MISSING_MESSAGE_ID | low | no Message-ID |
| MSG_DUPLICATE_SINGLETON_HEADER | medium | Subject, Date or Message-ID repeated |
| MSG_RECEIVED_NONE | low | no Received header |
| MSG_RECEIVED_UNPARSED | low | hops not parsed (error-class) |
| MSG_RECEIVED_CLOCK_SKEW | low | a hop is older than the previous one |
| MSG_HOP_DELAY_HIGH | low | a hop delay over HOP_DELAY_HIGH_SECONDS |
| MSG_RECEIVED_PRIVATE_IP_ORIGIN | info | first hop address is not global |
| MSG_AUTHRES_MISSING | medium | no Authentication-Results at all |
| MSG_AUTHRES_AUTHSERV_MISMATCH | medium | used results carry different authserv-ids |
| MSG_SPF_NOT_PASS | high / medium / low | stated spf: fail gives high; other results medium; not stated low |
| MSG_DKIM_NOT_PASS | high / medium / low | same rule; no stated dkim pass |
| MSG_DMARC_NOT_PASS | high / medium / low | same rule; stated dmarc is not pass |
| MSG_ALIGNMENT_FAIL | high | computed: no identifier aligned |
| MSG_ALIGNMENT_STATED_MISMATCH | medium | stated dmarc disagrees with computed |
| MSG_UNVERIFIED_DKIM_SIGNATURE | low | DKIM-Signature with no stated result |
| MSG_ARC_INVALID | low | ARC chain structurally invalid |
| MSG_ARC_CV_FAIL | medium | an ARC seal says cv=fail |
| MSG_RETURN_PATH_MISSING | info | no Return-Path |
| MSG_REPLY_TO_DIFFERS | info | Reply-To organizational domain differs |
| MSG_REPLY_TO_UNUSABLE | info | Reply-To has no usable address |
| MSG_LIST_UNSUBSCRIBE_MISSING | info | no List-Unsubscribe |
| MSG_LIST_UNSUBSCRIBE_NO_ONECLICK | info | List-Unsubscribe without RFC 8058 post |
| MSG_ENCODED_HEADER_BROKEN | low | undecodable RFC 2047 encoded-word |
| MSG_MIME_TRUNCATED | low | MIME walk stopped at a cap |
| MSG_NO_TEXT_PART | low | no text/plain part |
| MSG_PARSER_LIMIT | medium | input rejected or capped (error-class) |

## Permission `message.analyze`

A dedicated, tenant-level action. It is separate from `dns.tools` and `check.run` because those
are DNS-oriented or domain-level, while a pasted message belongs to no registered domain and is
content the analyst brings with them. Owner, admin and analyst have it; a client viewer never does
(a feature toggle cannot grant it). It can be denied per user with `{"message.analyze": false}`.
Anonymous gets 401 (a login redirect in the UI), a session whose active tenant is not the user's
gets 404, a denied user gets 403. The permission is checked before the body is read, so a denied
request never reaches the analyzer.

## CLI

`dtk analyze <file|-> [--format text|json] [--lang en|it]` (also `python -m app.cli analyze`).
Exit codes and the trailing newline of the JSON output are documented in `docs/CHECKS.md`
(section "CLI `analyze`").

## Adding a corpus sample

Samples live in `tests/fixtures/messages/` with one entry each in `MANIFEST.yaml`. The acceptance
tests (`tests/services/test_acceptance_m4.py`) parse every sample and assert its `facts`. Facts
are hand-written: check them against the parser output and use the parser vocabulary.

Sanitization checklist (every item, every sample):

1. Replace every sender/recipient domain with example.com/.net/.org (consistently).
2. Replace every IPv4/IPv6 address with one from 192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24 or 2001:db8::/32 (consistently).
3. Replace every Message-ID, queue id, tracking id, mailbox and name with a made-up value.
4. DKIM/ARC `b=` and `bh=`: note the original length, replace with a made-up string of the same
   length; keep the tag structure, with `d=` and `s=` on reserved domains.
5. Remove tracking links, unsubscribe tokens and body text; keep the MIME structure.
6. Search the result for the original domains, IPs and recipients: zero hits.
7. Record in `notes` the provider, the date received and who sanitized it.

A sample is `verified` only with `sources` (official document URL) and `verified_on`; otherwise it
is `unverified` and the tests only assert that it parses with all sections present.

## Unverified provider samples (maintainer to supply)

Status: parser verified against the RFC corpus; provider samples pending.

`gmail`, `outlook`, `ses`, `sendgrid` and `mailup` are generic placeholders built from RFC 8601 and
RFC 5321 syntax only; their header shape is NOT confirmed against a real message. For each, the
maintainer must supply a sanitized real `.eml` (or header-only) sample, the official document (URL
and date checked) that shows the header shape if one exists, and the name of the person who
sanitized it. Until then no vendor-specific behaviour is claimed.
