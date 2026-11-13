# R1-01 Quadratic regexes on inline style values (ReDoS in the HTML content parser)
Milestone: R1
Branch: feature/r1-01-style-regex-redos
Findings: PARSE-01 (high); also the `_REPLY` note from the review's open questions
Files in scope: app/parsers/content_html.py, app/parsers/content_subject.py, app/services/content_findings.py and locales/en.json + locales/it.json (only if a new reason code is needed), tests/parsers/test_content_html.py, tests/parsers/test_content_subject.py (or the existing subject test file; the coder states which), tests/services/test_content_analysis.py (only for the over-cap status row)
Out of scope: app/core/safe_regex.py, tenant rules engine, the `analyze_content` DB-connection item (TODO M5-15 QA), API/UI routes, any other parser
Depends on: none
Parallel-safe: yes (no shared source file with other R1 tickets; locale files only if a new key is needed: then serialize with other locale-touching tickets)
Model: opus (ReDoS protection)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- The `!important` strip and the zero-length test in `_style_decls` / `_hidden_reasons` are linear string code, no backtracking regex on the style value.
- A per-attribute cap on the analysed style text exists. Over the cap: the hidden-text test for that attribute is NOT run and the result is "not evaluated", error-class (reuse the existing capped / not-evaluated mechanism so the analysis status is error, `complete` false). It must never be reported as "no hidden text".
- `font-size:0`, `0.0px`, `+0em`, `-0`, `.0`, `0%`, `display:none !important` still match as before (table rows).
- Adversarial rows pass using an operation counter or a relative bound (time at n vs 2n within a factor), never a wall-clock threshold: long zero run, long whitespace run before and after `!important`, long digit run in `left`/`top`, 2 MB style attribute.
- `_REPLY` in app/parsers/content_subject.py rewritten so it has no two adjacent `\s*` (quadratic in a whitespace run); behaviour unchanged for existing subject tests; add a row with a 10,000-char whitespace run checked with an operation counter or relative bound.
- `_NEG` and the `charset\s*=\s*` search reviewed; if linear, add a comment and a test row, no change.
- Tests table-driven, malformed input included, no network. ruff, mypy and relevant tests green.
New i18n keys: none expected. If a new reason code needs user text: en + it, listed in the PR.
Status: done
Outcome: reproduced (old regexes ~15-16x growth for 4x input), fixed in merge f9650a3, QA APPROVE, dev CI green.

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location:
  - `app/parsers/content_html.py:140` (`re.sub(r"\s*!important\s*$", "", ...)` in `_style_decls`)
  - `app/parsers/content_html.py:144,155` (`_ZERO = ^[+-]?0*\.?0+(...)?$`, matched on `font-size`)
  - `app/parsers/content_html.py:209` (`_hidden_reasons` runs for every element with a `style` attribute)
  - `app/services/content_analysis.py:746` (`parse_content`) and `:459-466,800` (`_visible_text` parses the same HTML a second time with the same collector)
  - Entry points: `app/api/v1/content.py:179`, `app/web/content.py:173` (`run_in_threadpool`), `app/cli/content.py`
- Problem: two regexes applied to each inline `style` declaration are quadratic in the value length. `0*\.?0+` followed by a failing `$` backtracks over every split of a run of zeros; `\s*!important\s*$` under `re.sub` retries from every position of a whitespace run. The style value has no length cap other than the 2 MB input cap, and these regexes do not go through `app/core/safe_regex.py` (which protects only tenant rules). No deadline; the thread cannot be cancelled; the request keeps its DB connection.
- Evidence (measured on Python 3.12):
  - `_hidden_reasons("font-size:" + "0"*n + "x")`: n=5,000 0.26 s; 10,000 1.05 s; 20,000 4.2 s; 40,000 16.8 s (4x per doubling).
  - `_hidden_reasons("color:a" + " "*n + "b")`: n=10,000 0.04 s; 20,000 0.16 s; 40,000 0.62 s.
  - `parse_content('<p style="color:a' + ' '*40000 + 'b">x</p>', None)` takes 0.63 s for a 40 KB body and is not `capped`.
  - Extrapolated, not run: about 2 MB of zeros is roughly 11 hours per parse, and `analyze_content` parses twice. A 200 KB body is in the range of minutes.
  - A busy thread did not stall the main thread: one busy core and one occupied pool worker per request; it stays busy after the client disconnects.
  - Who can send it: any user with `content.analyze` (API, UI), or an `.eml` whose HTML part carries the attribute.
- Suggested fix: remove both regexes in favour of linear string code: strip a trailing `!important` with `rstrip`/`endswith`/slicing; test "zero length" by scanning characters (optional sign, digits and one dot all zero, optional unit from a fixed set). Review `_NEG` and the `charset\s*=\s*` search the same way (they measured linear). Add a per-attribute cap on the style text analysed (over the cap: skip the hidden-text test and report it as not evaluated, never as "no hidden text"). Consider an overall deadline for the body section.
- Tests to add: adversarial rows for `_hidden_reasons` and `parse_content` (long zero run, long whitespace run before and after `!important`, long digit run in `left`/`top`), asserted with an operation counter or a relative bound, not wall clock (the flaky-timing item in TODO.md applies); rows proving `font-size:0`, `0.0px`, `+0em`, `display:none !important` still match after the rewrite.
- `_REPLY` note (review open question): `SUBJECT_MAX_ANALYSED_CHARS` is 10,000 and `_REPLY` (`app/parsers/content_subject.py:99`) has two adjacent `\s*`, quadratic in a whitespace run. The cap bounds it (`analyze_subject("re" + " "*9990 + "x")` took 0.04 s), not a finding on its own; rewrite it here so the cap is not the only protection.
- Confidence: high.
- Related open items: TODO "Content analysis (M5-15 QA): `analyze_content` keeps a pooled DB connection..." (worse effect, not fixed here), R1-02 (AUTH-01).
