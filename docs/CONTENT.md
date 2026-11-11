# Content analysis, rules and custom checks (M5)

## Scope and the offline guarantee

The content analyzer takes ONE message's content that someone pasted, uploaded or piped in
(HTML, plain text, a Subject, or a raw `.eml`), and reports structure, links, subject, the
List-Unsubscribe headers and the matches of the content rules, as facts plus `CONTENT_*` findings.

It is offline: no DNS lookups, no sockets, no link is ever fetched, resolved or followed (a link
is parsed and compared as text; fetching would need the guarded client of M7). Nothing is stored:
no database row is written and the content never reaches the logs. It reads tenant data only to
load the effective rules, through the tenant repository.

It is not a `Check`: it needs a tenant session and takes content, not a domain, so it has its own
service (`app/services/content_analysis.py`).

## Surfaces

| Surface | Entry point | Input |
|---|---|---|
| REST | `POST /api/v1/content/analyze` | JSON `{html?, text?, subject?, language?}` (`application/json`) or a raw `.eml` (`message/rfc822`) |
| UI | `/tools/content` | pasted fields, or an `.eml` read in the browser into a textarea |
| CLI | `dtk content --tenant-id N --user-id N [--html F] [--text F] [--eml F] [--subject S] [--lang L] [--json] [--output-lang en\|it]` | files or `-` for stdin (once) |

The service JSON, the REST body and the CLI `--json` output are byte-equal (the CLI adds exactly
one trailing newline). The UI shows the same overall status, section statuses and finding codes.

Language options: unlike `check` and `analyze`, on `dtk content` `--lang` is the CONTENT language
hint (it selects language-specific rules, below) and `--output-lang` is the language of the
output. In the REST body `language` is the content hint too.

Permission: `content.analyze` (owner, admin, analyst; not a client viewer). The permission check
runs before the body is read, so a denied caller never reaches the analyzer. The CLI acts as the
operator named by `--tenant-id` and `--user-id` (these select who acts; they are not
authentication) and exits 77 when denied.

## Inputs and limits

| Limit | Value | Result |
|---|---|---|
| Raw input (all fields together; the `.eml` or the JSON body) | 2 MiB (`MAX_RAW_BYTES`) | REST 413, UI 413, CLI exit 2 |
| Empty input (no html, text or eml) | - | REST 422, UI 422, CLI exit 2 |
| NUL byte in any field | - | REST 422, UI 422, CLI exit 2 |
| Invalid `language` (lowercase code such as `en` or `pt-br`, at most 16 characters) | - | REST 422, UI 422, CLI exit 2 |
| Unsupported content type | only JSON and `message/rfc822` | REST 415 |
| HTML parser | 2,000,000 bytes, 20,000 elements, depth 100, 100 attributes per element | section `error`, `CONTENT_INPUT_CAPPED` |
| Links analyzed | 500 links, 4096 characters per href, 512 characters of visible text per link | section `error`, `CONTENT_INPUT_CAPPED` |
| Subject | first 10,000 characters analyzed | capped flag in the facts |
| List-Unsubscribe | 10 fields, 32 URIs per field, 8192 characters per value, 2048 per URI | the fact is `None` (unknown), never `False` |

The UI form transport cap is `3 * MAX_RAW_BYTES` plus 4096 bytes (percent-encoding); the real
limit is the decoded 2 MiB. The List-Unsubscribe caps and the link and HTML caps are project
choices, not taken from any specification. The REST and CLI limits for the rules engine are in
"ReDoS guard".

A field given explicitly wins over the same value extracted from the `.eml`, so edited HTML can
be checked against the real headers.

## Statuses

Section and overall status: `ok`, `warn`, `fail`, `info`, `error`, `not_evaluated`.

- `error`: the analysis could not evaluate something (a parser cap, an undecodable `.eml`, a
  rule that timed out, a busy or exhausted rules budget). Never `ok`. The whole analysis is
  `error` when any section is.
- `not_evaluated`: the section had no input (no `.eml` means no headers, so List-Unsubscribe is
  `not_evaluated`; no HTML or no Subject likewise) or no enabled rule applied. The overall status
  is `not_evaluated` only when every section is.
- `complete` (separate boolean, false whenever part of the input was skipped): an unreadable link,
  links with no sender domain to compare with, enabled rules left out because they have a
  language and no hint was given, or any `not_evaluated` section. `status` alone does not say
  so. A run without `--eml` has List-Unsubscribe `not_evaluated`, so `complete` is false and the CLI
  exits 1.

CLI exit codes: 0 complete and nothing above info; 1 any warn, fail or `not_evaluated`, or an
incomplete run; 2 status `error` or an input error; 64 usage; 77 denied.

## Finding codes

Severity is the one the code emits. Codes are stable public identifiers. Codes marked advisory
use a threshold chosen by this project (see "Heuristic thresholds").

| Code | Severity | Meaning |
|---|---|---|
| `CONTENT_INPUT_CAPPED` | medium | input capped, rejected or undecodable (error-class) |
| `CONTENT_RULE_ERROR` | medium | rules failed or were left unevaluated (error-class) |
| `CONTENT_RULE_MATCH` | the rule's | one finding per matched rule |
| `CONTENT_LINK_UNEVALUATED` | low | link address unreadable (partial) |
| `CONTENT_MASKED_LINK` | high | link text names another domain |
| `CONTENT_IP_LITERAL_LINK` | high | link host is an IP address |
| `CONTENT_URL_SHORTENER` | medium | link host is on the shortener list |
| `CONTENT_HIDDEN_TEXT` | medium | inline styles that may hide content |
| `CONTENT_SUBJECT_BIDI_OVERRIDE` | medium | bidi override characters in the Subject |
| `CONTENT_SUBJECT_CONTROL_CHARS` | medium | control characters in the Subject |
| `CONTENT_UNSIGNED_UNSUBSCRIBE_HEADER` | medium | One-Click fields in no single DKIM `h=` list |
| `CONTENT_NON_HTTPS_LINK` | low | link uses http |
| `CONTENT_UNALIGNED_LINK_DOMAIN` | low | link domain differs from the sender domains |
| `CONTENT_MANY_LINK_DOMAINS` | low | many distinct link domains (advisory) |
| `CONTENT_MISSING_PLAIN_TEXT` | low | HTML without a plain text version |
| `CONTENT_LOW_TEXT_IMAGE_RATIO` | low | little text per image (advisory) |
| `CONTENT_IMAGES_MISSING_ALT` | low | images without an alt attribute |
| `CONTENT_MALFORMED_HTML` | low | structural HTML problems |
| `CONTENT_GMAIL_CLIP_RISK` | low | HTML size over the clipping heuristic (advisory) |
| `CONTENT_EXCESS_CSS` | low | CSS is most of the HTML (advisory) |
| `CONTENT_SUBJECT_EMPTY` | low | Subject absent or blank |
| `CONTENT_SUBJECT_ALL_CAPS` | low | mostly capitals (advisory) |
| `CONTENT_SUBJECT_PUNCTUATION` | low | runs of `!` or `?` (advisory) |
| `CONTENT_SUBJECT_LONG` | low | long Subject (advisory) |
| `CONTENT_SUBJECT_REPLY_PREFIX` | low | `Re:` without In-Reply-To or References |
| `CONTENT_SUBJECT_MIXED_SCRIPT` | low | one word mixes scripts |
| `CONTENT_NO_LIST_UNSUBSCRIBE` | low | no List-Unsubscribe header |
| `CONTENT_NO_ONE_CLICK` | low | RFC 8058 one-click not offered |
| `CONTENT_HTTP_ONLY_UNSUBSCRIBE` | low | unsubscribe by http only |

Text from the message reaches findings only as hosts, tags and bounded snippets: never a full URL
(it can carry tokens) and never the body.

## Static link analysis (no fetching)

Anchors are collected by the HTML parser and analysed as text (`app/parsers/content_links.py`).
Nothing is fetched, resolved or followed.

- Host extraction loosely follows the WHATWG URL parser for `http`/`https` and protocol-relative
  `//host`, so the reported host is the one a browser would visit: userinfo is everything before
  the last `@` (`http://bank.example@evil.example` goes to `evil.example`), hosts are
  percent-decoded and UTS #46 mapped, a host whose last label is numeric is read as IPv4 in
  decimal/hex/octal/short forms and reported in canonical dotted form, `[...]` is an IPv6 literal.
- Organizational domains come from the Public Suffix List (`app.core.org_domain`).
- Masked-link test: a host is extracted from the visible text only when the token has an explicit
  scheme, starts with `www.`, or ends in a suffix known to the PSL. A heuristic, not a vendor rule.
- `mixed_script` groups Han/Hiragana/Katakana/Hangul as one script; it cannot see single-script
  homographs (an all-Cyrillic label), for which only the `idn` flag is set.
- Link alignment compares link domains with the sender domains (From and DKIM `d=`) of the `.eml`;
  with none, alignment is not evaluated (`complete` is false).
- Shorteners come from `seeds/url_shorteners.yaml` (see "Seed provenance"). A match is a fact, not
  a verdict.

## List-Unsubscribe and One-Click

Facts come from `app/parsers/list_unsubscribe.py`; nothing is fetched or POSTed. Citations (texts
read at rfc-editor.org; vendor requirements are out of scope):

- RFC 2369 section 2 (command syntax): the content is angle-bracket enclosed URLs, comma
  separated, in order of preference; client rules: a field not starting with `<` SHOULD be ignored,
  characters after a bracketed URL SHOULD be ignored unless the first non-whitespace character is
  a comma, and a sub-item that is not a bracketed URL and all later ones SHOULD be ignored.
  Reported as `syntax_error` codes `not_bracketed`, `trailing_text`, `non_uri_item`; the ignored
  part never contributes URIs.
- RFC 2369 section 3: no more than one of each list field in a message (`duplicated`).
- RFC 2369 section 3.2: List-Unsubscribe, with mailto and http examples.
- RFC 8058 section 3.1 (mail senders): one List-Unsubscribe and one List-Unsubscribe-Post field;
  List-Unsubscribe MUST contain one HTTPS URI and MAY contain other non-HTTP/S URIs;
  List-Unsubscribe-Post MUST contain the single key/value pair `List-Unsubscribe=One-Click`; a
  valid DKIM signature MUST cover at least both fields.
- RFC 8058 section 4: both fields MUST be in the `h=` tag of a valid DKIM-Signature; without it
  the receiver SHOULD NOT offer one-click.
- RFC 8058 section 5: ABNF `postarg = "List-Unsubscribe=One-Click"`. ABNF literal strings are
  case insensitive (RFC 5234 section 2.3).
- mailto syntax: RFC 6068 section 2; https authority syntax: RFC 3986 sections 3 and 3.2.

Heuristics and definitions chosen by this project (not taken from the RFCs):

- The One-Click value match is case-insensitive (`post_value_matches_abnf`); the exact-case match
  is exposed as `post_value_exact`.
- `one_click_eligible` requires exactly one List-Unsubscribe field with a parsed `https` URI with a
  valid host, and exactly one List-Unsubscribe-Post field whose value matches the ABNF. DKIM
  coverage is a separate fact (`one_click_signed`).
- The ABNF's allowance of one WSP before the value is not checked (the header parser strips
  surrounding whitespace).
- The parser limits (10 fields, 32 URIs, 8192/2048 characters, 128 characters of the POST echo) are
  project choices.
- Signatures are NOT verified: `signature_verified` is always false. `*_signed` facts only mean
  "named in a DKIM-Signature `h=` list": `false` is reliable (no signature lists the field),
  `true` only means "listed". Unknown coverage is `None`, never "ok".
- `https_uri_present`, `http_uri_present` and `mailto_uri_present` are `None` (unknown) instead of
  `false` when part of the input was not evaluated.
- An https URI whose authority is not introduced by exactly `//` keeps the host a browser would
  use but sets `nonstandard_authority` and does not count for One-Click.

## Rule model

A content rule is a row in `content_rules`:

| Field | Meaning |
|---|---|
| `scope` | `global` (managed by an instance admin, `tenant_id` null) or `tenant` (one tenant) |
| `kind` | `keyword` (case-folded substring, no Unicode normalization) or `regex` |
| `pattern`, `flags` | regex flags allowed: ignorecase, multiline, dotall, verbose, ascii |
| `weight` | 0 to 100; only matched rules score |
| `category` | lowercase slug matching `[a-z0-9][a-z0-9_.-]*` (at most 64 characters); the score is also summed per category |
| `language` | null (all languages) or a lowercase code; see below |
| `enabled`, `severity` | `critical` to `info`; `severity` is the finding severity |
| `title`, `advice` | the text shown with the match (stored, plain text, escaped by renderers) |
| `sources`, `verified_on`, `status` | provenance (`verified` or `unverified`) |
| `seed_key` | links a row to a seed entry (global), or a tenant override of it |

Evaluation:

- Only enabled rules whose `language` is null or equals the hint (exact match after trim and
  lowercase) run. With no hint only null-language rules run, and the run is then `complete: false`
  when enabled rules were left out for that reason; a hint that excludes other languages is a
  choice and stays complete.
- Rules have no target field: each is searched in the Subject, the text and the visible HTML text
  separately, in that order, and stops at its first match.
- Keywords run in-process first; regexes run in the ReDoS guard, highest weight first.
- Tenant merge: only global rows and the tenant's own rows apply. A tenant row overrides a global
  rule only through `seed_key` (never through `name`): `enabled: false` turns the global rule off
  for that tenant, an enabled row applies the tenant's pattern, weight and category. Another
  tenant's rules never apply.
- Score: the sum of the weights of matched rules, capped at 100 (engine default; hard maximum
  1000). When the run is incomplete the score is a lower bound.
- Rule statuses: `matched`, `ok`, `error` (invalid or timed out, no match established),
  `not_evaluated` (budget used up, busy pool, beyond the rule cap, no content, or no match in a
  capped part). A rule `error` makes the section and the overall status `error`.

Admin surfaces (no redeploy or re-seed: every analysis reads the rules from the database):

- REST `/api/v1/rules` (list, create, read, update, delete; tenant scope by default,
  `?scope=global` for instance admins) and `POST /api/v1/rules/test` (try a pattern on a sample).
  UI `/rules`. Writing needs `rules.manage` in the scope (owner and admin for tenant rules,
  instance admin for global rules).
- A global row that came from the seed cannot be deleted (409): disable it. Any accepted edit of a
  seeded row pins it against seed updates (`locally_modified`).
- The sample tester takes at most 32 KiB of sample text, returns at most 20 matches and 120
  characters per snippet, and runs with a 1 s timeout; it reports `timed_out` as an outcome.

## Seed provenance

Knowledge lives in data files with `verified_on` and sources; nothing is invented.

`seeds/content_rules.yaml` (synced into global rows at app start; a key removed from the file
disables the row, never deletes it; rows an instance admin modified are left alone). Three rules,
ALL shipped `enabled: false`:

| Key | Status | Basis |
|---|---|---|
| `subject_fake_reply_forward_prefix` | verified, `verified_on` 2026-11-08 | https://support.google.com/a/answer/81126 (Google "Email sender guidelines", message formatting). Disabled because the rule has no target field and no view of In-Reply-To/References, so as a plain pattern it would also flag real replies |
| `shouting_punctuation` | `unverified` (its `verified_on` is the day the basis was last reviewed, not a confirmation) | generic heuristic, no primary source (runs of three or more `!` or `?`) |
| `all_caps_run` | `unverified` (same: `verified_on` is the last review of the basis) | generic heuristic, no primary source |

`seeds/url_shorteners.yaml` (`verified_on` 2026-11-07): 9 entries. Verified: `bit.ly` (Bitly API
reference, https://dev.bitly.com/api-reference/) and `goo.gl` (Google Developers Blog, URL
Shortener links turned down). `unverified`, awaiting maintainer confirmation against official
documentation: `t.co` (the operator page returned 403 to the check), `tinyurl.com`, `ow.ly`,
`buff.ly`, `lnkd.in`, `is.gd`, `j.mp`. An unverified entry carries no operator.

Display text of seeded rules comes from i18n keys `CONTENT_RULE.<key>.title` and `.advice`
(en and it).

## ReDoS guard design and caps

Admin-supplied regexes are hostile (`app/core/safe_regex.py`). Rules run with the stdlib `re`
engine in a killable worker subprocess (`sys.executable -I -S`): when a rule misses its deadline the
worker is SIGKILLed and reaped, the rule is reported `timed_out`, and a fresh worker runs the rest.
Nothing runs in a thread of the caller's process, so a catastrophic pattern cannot pin a CPU there.
The `regex` package's `timeout=` argument was not used: its documentation does not say how often
the deadline is checked during backtracking (see the module docstring for the page and date).

| Cap | Value |
|---|---|
| Pattern length | 1024 characters; NUL, empty and unsupported flags are rejected at write time |
| Text per search | 1 MiB hard cap (256 KiB default per content part in the engine) |
| Matches per rule | 1000 hard cap (100 default) |
| Per-rule timeout | 0.05 s to 5 s, default 1 s |
| Rules per call | 200 |
| Overall budget of one analysis | 10 s in the engine (hard maximum 15 s), then the remaining rules are `not_evaluated` (`budget_exceeded`) |
| Live workers | 4 per OS process; a call waits at most its per-rule timeout for a slot, then reports `busy` |

A timeout or any incomplete result is a rule `error` (never `ok`) and an `error` section. A loaded
host can turn a slow-but-finite rule into a timeout; that is reported, never hidden. Known
exposure: the worker pool is process-wide, so a tenant admin can keep slots busy and push other
tenants' analyses to `busy` or `not_evaluated` (TODO.md follow-up).

## Custom checks (DNS kinds; http_fetch is deferred to M7)

A custom check is a declarative definition stored per tenant or globally and run with the checks
of a domain. The schema is `app/core/custom_check_schema.py`, the evaluator `app/checks/custom.py`.

Kinds in M5 (all DNS, through the resolver of the run):

| Kind | Definition keys | Result |
|---|---|---|
| `dns_exists` | `name`, `rrtype` | `ok` if a record exists |
| `dns_matches` | `name`, `rrtype`, `pattern` | `ok` if at least one record matches the regex (inline flags such as `(?i)`; no flag key) |
| `dns_value_range` | `name`, `rrtype` (TXT only), `min`, `max` | `ok` if every value is a plain decimal in the range (exact `Decimal` comparison) |

`http_fetch` is a reserved kind. It is refused by the schema (`kind_unavailable`), the REST API
(422), the UI (disabled option; a posted form is refused) and the evaluator, until M7 provides the
guarded outbound client. Nothing outside DNS is fetched in M5.

Rules of the definition:

- `name` is `{domain}` alone, or lowercase ASCII labels followed by `.{domain}`; a label may start with an underscore (for example `_dmarc`); the rendered name
  can only be the target domain or a name under it. IDN is refused. Allowed record types: A, AAAA,
  CAA, CNAME, MX, NS, SOA, SRV, TLSA, TXT. Severity: `low`, `medium` or `high`.
- Ids are `custom:<scope>:<key>` with scope `global` or `tenant`, so a global and a tenant check
  with the same key never collide.
- A definite absence of the record (NXDOMAIN or NODATA) is `CUSTOM_CHECK_FAILED` with the
  configured severity and reason `nxdomain` or `nodata`. A record that exists but fails the test
  is `CUSTOM_CHECK_FAILED` with reason `no_match` (`dns_matches`) or `out_of_range`
  (`dns_value_range`).
- Could not evaluate is `error`, never `ok`: any DNS state other than ok, nxdomain or nodata, a
  regex timeout, a non-numeric value on a range, an invalid stored definition, a name that cannot
  be built, more than 64 records, or a budget that ran out. Codes: `CUSTOM_CHECK_FAILED`,
  `CUSTOM_CHECK_ERROR`, `CUSTOM_KIND_UNAVAILABLE`.
- Budget: all custom checks of one domain run share one 12 s budget (below the 15 s per-check
  deadline of the check service); a check that starts with none left is `error`
  (`run_budget_exceeded`) without a DNS query. At most 50 custom checks query DNS per run: the
  51st and later report `error` without a query, so none silently disappears. Matching against
  one check's records shares a 10 s regex budget, with a 1 s timeout per search.
- Remediation, shown only on `CUSTOM_CHECK_FAILED`: either plain text in `en` and `it` stored with
  the definition (`params["remediation_text"]`, escaped by renderers, never raw HTML), or, for a
  global row only, a `remediation_key` naming a message present in every catalogue. A tenant
  check cannot use a key.
- Roles: tenant checks are written by owner and admin, global checks by instance admin; the dry
  run (`POST /api/v1/custom-checks/test`, UI `/custom-checks`) needs `rules.read` and `check.run`
  on the domain (owner, admin, analyst; never a client viewer).
- A client viewer sees the results of the custom checks of a domain it is assigned to (id, status,
  record name, reason, evidence), but never the stored `pattern` or `min`/`max`, and cannot read
  the definitions.
- Domain runs add the enabled global and own-tenant custom checks after the built-in checks; no
  other tenant's check ever runs. A single custom id is not addressable (422).

## DKIM selector results (M5-20, M5-23b)

Every role that can see a domain, a client viewer included, gets each probed selector's name and
provider in the DKIM result (maintainer decision 2026-11-10); the selector `notes` are admin data
and never reach a result. See `docs/CHECKS.md` for the selector list and its caps.

## Heuristic thresholds (all `unverified`)

No official mailbox provider source has been checked for any of these; none is attributed to a
provider, and their texts say "advisory" (en) and "indicativa" (it). The maintainer is asked to
confirm or replace them against official documentation.

| Constant | Value | Used by |
|---|---|---|
| `GMAIL_CLIP_THRESHOLD_BYTES` | 102,400 | `CONTENT_GMAIL_CLIP_RISK` (the Gmail clipping behaviour is `unverified`) |
| `MIN_VISIBLE_CHARS_PER_IMAGE` | 100 | `CONTENT_LOW_TEXT_IMAGE_RATIO` |
| `MANY_LINK_DOMAINS_THRESHOLD` | 5 | `CONTENT_MANY_LINK_DOMAINS` |
| `EXCESS_CSS_PERCENT`, `EXCESS_CSS_MIN_HTML_BYTES` | 50 percent, 10,240 | `CONTENT_EXCESS_CSS` |
| `SUBJECT_LONG_GRAPHEMES` | 100 | `CONTENT_SUBJECT_LONG` |
| `SUBJECT_CAPS_RATIO`, `SUBJECT_CAPS_MIN_CASED_LETTERS` | 0.7, 8 | `CONTENT_SUBJECT_ALL_CAPS` |
| `SUBJECT_PUNCT_RUN_MIN` | 2 | `CONTENT_SUBJECT_PUNCTUATION` |

Also unverified: the hidden-text candidates (`CONTENT_HIDDEN_TEXT`) are inline-style heuristics,
and the masked-link and mixed-script tests are heuristics (see "Static link analysis").

## Known limits

- Text split across inline tags is not matched as one word by rules (visible text runs are joined
  by a space).
- Rules have no target field, so a rule cannot be limited to the Subject.
- No per-user rate limiting yet.
