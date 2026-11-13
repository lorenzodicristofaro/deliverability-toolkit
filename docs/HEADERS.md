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

| Limit | Value | Analysis status | Main finding (severity) | REST / UI HTTP | CLI exit |
|---|---|---|---|---|---|
| Raw message | 2 MiB | not analyzed | - | 413 / 413 | 2 |
| Empty input | - | not analyzed | - | 422 / 422 | 2 |
| NUL byte | - | not analyzed | - | 422 / 422 | 2 |
| Header block | 128 KiB | `error` | `MSG_PARSER_LIMIT` (medium) | 200 / 200 | 2 |
| Physical header line | 8 KiB | `error` | `MSG_PARSER_LIMIT` (medium) | 200 / 200 | 2 |
| Unfolded header field | 64 KiB | `error` | `MSG_PARSER_LIMIT` (medium) | 200 / 200 | 2 |
| Header count | 500 | `error` | `MSG_PARSER_LIMIT` (medium) | 200 / 200 | 2 |
| `Received` hops | 100 (newest kept, `truncated`) | `error` | `MSG_PARSER_LIMIT` (medium) | 200 / 200 | 2 |
| One `Received` hop | 8 KiB, counted in UTF-8 bytes | `error` | `MSG_RECEIVED_UNPARSED` (low), hop warning `hop_too_long` | 200 / 200 | 2 |
| MIME depth | 10 | `error` | `MSG_PARSER_LIMIT` (medium), also `MSG_MIME_TRUNCATED` (low) | 200 / 200 | 2 |
| MIME boundary length | 70 | `error` | `MSG_PARSER_LIMIT` (medium), also `MSG_MIME_TRUNCATED` (low) | 200 / 200 | 2 |
| MIME parts | 200 | `error` | `MSG_PARSER_LIMIT` (medium), also `MSG_MIME_TRUNCATED` (low) | 200 / 200 | 2 |
| ARC instances | 50 (a 51-set chain is read as 50 sets plus ungrouped fields) | `warn` | `MSG_ARC_INVALID` (low) | 200 / 200 | 1 |

Other ARC structural problems behave the same way: a gap in the instance numbers gives `warn`
with `MSG_ARC_INVALID` (low, CLI exit 1), and a seal with `cv=fail` gives `warn` with
`MSG_ARC_CV_FAIL` (medium, CLI exit 1). Observed with the service and the CLI; the UI status
equals the service status. Only the first three rows are refused before analysis; every other
row is data, never a crash. The CLI exit follows the status (`error` gives 2, `warn` or `fail`
gives 1). The REST
size check happens while streaming, so an oversized body is never buffered.

## Parser behaviour on malformed input

- Nothing is truncated silently: a cap is reported (`truncated`, `MSG_PARSER_LIMIT`).
- One rule: any capped input (header, `Received`, MIME parts, MIME depth, boundary length) is
  error-class: `MSG_PARSER_LIMIT` and status `error`. `MSG_MIME_TRUNCATED` is only extra detail.
- A bare CR is not a line delimiter. 8-bit bytes are decoded as UTF-8 with replacement.
- Broken RFC 2047 encoded-words are kept as text and flagged (`MSG_ENCODED_HEADER_BROKEN`).
- `Authentication-Results`: method and result names are lowercased; `raw` keeps the original text.
  The obsolete pvalue `"x" @ example.com` (whitespace around `@`) is not joined.
  An `Authentication-Results` field without an authserv-id is not counted as evaluated and gets
  `MSG_AUTHRES_UNPARSED` (maintainer decision 2026-11-13, strict): the authserv-id is mandatory in the
  RFC 8601 section 2.2 ABNF, and consumers SHOULD NOT interpret results whose authserv-id is not a
  recognised one (sections 2.5 and 4.1).
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
  plus `dkim=pass` without `header.d`). A stated `dkim=none` means the message was not signed
  (RFC 8601 section 2.7.1): its pair is `not_evaluated` with reason `no_signature`, whether or not
  `header.d` is present or usable, and it never blocks the verdict. The computed DMARC result then
  rests on SPF alone: an aligned spf pass gives `pass`, otherwise `fail` (`MSG_ALIGNMENT_FAIL`).
  Other dkim results without a usable `header.d` stay `unknown`. The spf pair uses the first spf
  result that carries `smtp.mailfrom` (one for `smtp.helo` listed before it is skipped); only when
  none does, it falls back to Return-Path with no stated result.
- Lower `Authentication-Results` fields (R1-22, minimal rule, maintainer decision 2026-11-13):
  receivers prepend their field (RFC 8601 section 4.1), so the topmost field is the one most
  likely written by the last receiver; a field below it may have been written by the sender.
  When the topmost field does not carry a method, the result still comes from the topmost field
  that does, but a pair whose stated result comes from a field other than the topmost one
  (`authres_index > 0`) gets the reason `lower_authres_field` and never makes the computed
  DMARC result (RFC 7489 section 3.1 alignment) `pass`. Its state stays visible. When that
  exclusion leaves the computed result other than `pass`, `MSG_ALIGNMENT_LOWER_FIELD_NOT_USED`
  says so. Limits: trust is not decided (RFC 8601 section 2.5 and 4.1 leave it to the
  consumer, which knows its own authserv-id) and no signature is verified, so a forged
  topmost field is not detected either. A legitimate receiver that splits its results over
  several fields (for example spf in one field and dkim in the next) is treated the same way:
  its dkim pass from the second field is not used, which can give a computed `fail`,
  `MSG_ALIGNMENT_FAIL` and `MSG_ALIGNMENT_STATED_MISMATCH` although the receiver stated
  `dmarc=pass`. The per-hop view (section "Per-hop authentication view") is display only and
  does not change this rule.
- `MSG_SPF_NOT_PASS` and `MSG_DKIM_NOT_PASS` (F-01-01, GM decision 2026-11-13, R1-22 QA input):
  they read the results of the topmost field that states the method, which can be a lower
  field. This is display only and unchanged: it selects these warnings and their wording, never
  `computed_dmarc` or the alignment pairs. A lower field can therefore add `MSG_DKIM_NOT_PASS`
  (for example a lower `dkim=fail` when the topmost field states only spf) or leave it out (a
  lower `dkim=pass`); both cases are pinned by a test.

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
| MSG_ALIGNMENT_FAIL | high | computed: no SPF or DKIM result used for the verdict is both stated as pass and aligned (a lower-field pair shown as aligned does not count) |
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
| MSG_MIME_TRUNCATED | low | MIME walk stopped at a cap (detail) |
| MSG_NO_TEXT_PART | low | no text/plain part |
| MSG_PARSER_LIMIT | medium | input rejected or capped (error-class) |
| MSG_AUTHRES_UNPARSED | medium | an Authentication-Results field has no authserv-id or an error-severity parse issue; parameters are issue codes only (error-class) |
| MSG_ALIGNMENT_NOT_EVALUATED | medium | computed DMARC alignment is not evaluated although a field is present; parameters are pair reason codes only (error-class) |
| MSG_ALIGNMENT_LOWER_FIELD_NOT_USED | low | an aligned pass stated in a lower Authentication-Results field was not used and the computed DMARC result is not pass; parameters are the methods and identifier domains |
| MSG_AUTH_BROKE_AFTER_HOP | info | per-hop view: a method stated pass in an older field and a failure-class result in the next newer field that states it; parameters are `method=result` pairs, the newer field's authserv-id and `hop`, the 1-based hop number (Received `index` + 1, as in `MSG_HOP_DELAY_HIGH`) (detail variant `no_hop` when the older field is below every Received field); display only |

## Per-hop authentication view

Section `hops` of the analysis (F-01-01; the API, UI and CLI rendering is F-01-02). Built by
`app/services/message_hops.py` from the already parsed Received, Authentication-Results and
ARC fields; offline, deterministic, no clock. Nothing is verified cryptographically: DKIM and
ARC signatures are not checked, ARC stays structural (`verified` is `None`, `crypto_checked`
is false) and `MSG_ARC_INVALID` / `MSG_ARC_CV_FAIL` are unchanged.

Ordering. Entries are ordered by header position only, never by field type, oldest first
(`order` 0 is the bottommost field; `position` is the byte offset of the field in the message).

- Authentication-Results is added at the top of the message as it transits MTAs that do
  checks, and is a trace field (RFC 8601 section 2.1); it MUST be prepended and MUST NOT be
  reordered (RFC 8601 section 4.1). Received is prepended by each relay (RFC 5321 section 4.4).
  So position indicates where in the handling chain a field was added.
- It is an indication, not proof: RFC 8601 section 4.1 notes that some handlers can only
  append fields (the position signal is then lost) and section 7.3 that fields are sometimes
  reordered en route.
- ARC: an ARC set is the AAR, AMS and AS fields sharing one instance value (RFC 8617 sections
  3.1 and 4.2); instance values start at 1, each new set adds 1, and they give the order in
  which sets were added (RFC 8617 sections 4.2.1 and 5.1), range 1 to 50 (section 4.2.1).
  RFC 8617 does not say where ARC fields are placed in the header. Placing a set among the
  Received fields by the position of its topmost member is a convention of this tool; the
  instance number is shown next to it and decides nothing here.

Each entry has `kind` (`received`, `authres`, `arc_set`), `order`, `position`, `hop`,
`parsed`, `authserv_id`, `authres_index` (0 = topmost Authentication-Results field),
`arc_instance`, `arc_domain` (AS `d=`), `arc_cv`, `results` (the `spf`, `dkim`, `dmarc` and
`arc` method/result pairs stated there), `stated_not_verifiable` and `issues` (codes only).
`hop` of a Received entry is its Received `index` (0 = oldest); for the other kinds it is the
index of the nearest Received field below it, or `null` when there is none. `hops` also carries
`received_truncated` and `arc_truncated`.

- Authentication-Results fields below the topmost one, and every ARC set, have
  `stated_not_verifiable` true: they are shown as stated by their authserv-id, not verifiable.
  The authserv-id identifies the authentication service within the ADMD that did the checks
  (RFC 8601 section 2.5) and consumers SHOULD NOT interpret the field unless that identifier is
  in use within their ADMD (sections 2.5 and 4.1); this tool knows no trusted authserv-id and
  decides no trust. The AAR has the Authentication-Results payload syntax plus the instance tag
  (RFC 8617 section 4.1.1).
- Display only: nothing in this section feeds `computed_dmarc`, the alignment pairs or any
  other finding (R1-22 rule: the verdict uses the topmost field).
- Unparsed entries (`parsed` false): an Authentication-Results field without an authserv-id
  (mandatory in the RFC 8601 section 2.2 ABNF) or with an error-severity parse issue (same rule
  as `MSG_AUTHRES_UNPARSED`), a field the parser rejects (oversized, NUL), an ARC set with a
  missing member or an error, an AAR payload without an authserv-id, and ARC fields that could
  not be grouped (`ungrouped_field`, invalid instance) or repeat an instance
  (`duplicate_instance`; RFC 8617 section 4.2.1 requires exactly one of each field per
  instance). They keep issue codes only: no results, authserv-id or domain. If the
  Authentication-Results section fails, its fields are read one by one here so one bad field
  stays local. A failure of the hop view itself gives `hops` null, `MSG_PARSER_LIMIT` with
  `hops_failed` and status `error`; only `MSG_AUTH_BROKE_AFTER_HOP` is dropped.

`MSG_AUTH_BROKE_AFTER_HOP` (info). Parsed entries that state a method are compared oldest to
newest; when one states `pass` and the next newer one stating the same method states `fail`,
`softfail`, `temperror` or `permerror`, the finding names the hop of the older entry ("broke
after hop N"). N is 1-based, the same number `MSG_HOP_DELAY_HIGH` shows for that hop
(Received `index` + 1); the `hop` field of the entries stays the 0-based `index`. At most one break per method; methods breaking between the same two entries are
reported together. A method counts as pass when any of its results in the entry is `pass`
(several DKIM signatures). `none`, `neutral` and `policy` are not a failure class and reset the
comparison. Result names: dkim RFC 8601 section 2.7.1 (none, pass, fail, policy, neutral,
temperror, permerror), spf RFC 8601 section 2.7.2 (adds softfail), dmarc RFC 7489 section 11.2
(none, pass, fail, temperror, permerror), arc RFC 8617 section 10.1 (none, pass, fail; the
chain validation status of section 4.4). The likely causes named in the text (forwarding, list
modification) are a hint, not a diagnosis; a lower field written by the sender produces the
same pattern.

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
