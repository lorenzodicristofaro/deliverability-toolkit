# R1-09 Alignment: dkim=none is "no signature", and spf uses the resinfo that carries smtp.mailfrom
Milestone: R1
Branch: feature/r1-09-alignment-dkim-none-spf-helo
Findings: PARSE-02 (medium)
Files in scope: app/services/message_alignment.py, tests/services/test_message_alignment.py, docs/HEADERS.md (alignment paragraph only), tests/services/test_message_analysis.py (end-to-end rows through `analyze_message`)
Out of scope: app/parsers/authres.py, app/services/message_findings.py (R1-10), the topmost-field rule (PARSE-06, R1-22), any vendor-specific header format claims
Depends on: none
Parallel-safe: no with R1-10 and R1-22 (same module and tests); serialize R1-09 -> R1-10 -> R1-22
Model: opus (interpretation of raw-message parser output; design decision taken by the GM)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- GM decision: RFC 8601 `dkim=none` means the message was not signed. The dkim pair becomes "no signature" (a distinct reason, e.g. `no_signature`, not `unknown`) and must NOT make `computed_dmarc` `not_evaluated`. DMARC then rests on SPF alone: aligned spf pass -> `pass`; otherwise `fail` with `MSG_ALIGNMENT_FAIL`. This holds whether or not `header.d` is present (including `dkim=none header.d=none`, which today gives `invalid_domain_single_label`).
- Other dkim results (`fail`, `neutral`, `policy`, `temperror`, `permerror`, ...) without usable `header.d` stay `unknown`, as today.
- For spf: use the first resinfo that carries `smtp.mailfrom`; fall back to Return-Path with no stated result only if none does. A `smtp.helo`-only spf result keeps the fallback.
- Table rows (From `a@example.com`, Return-Path `a@example.com`): (1) `spf=fail smtp.mailfrom=example.com; dkim=none; dmarc=fail header.from=example.com` -> status fail, `computed_dmarc` fail, `MSG_ALIGNMENT_FAIL`, not error. (2) same with `dkim=none (message not signed) header.d=none` -> same. (3) `dkim=none` plus aligned `spf=pass smtp.mailfrom=example.com` -> `computed_dmarc` pass (must stay pass). (4) `dkim=fail` without `header.d` -> dkim pair `unknown`, `computed_dmarc` `not_evaluated` as today. (5) `spf=pass smtp.helo=mail.example.com; spf=pass smtp.mailfrom=example.com` and the two swapped -> same result, `computed_dmarc` pass. (6) spf with only `smtp.helo` -> fallback as today. (7) `dkim=none` with a second, signed result for another domain -> unchanged precedence rules.
- docs/HEADERS.md alignment paragraph states both rules. No vendor-format claims in code, tests names or docs (provider formats are unverified).
- No new user-facing strings expected (reason codes are internal; if a reason code is rendered, it must already go through an i18n key: check and report).
- No network. ruff, mypy, relevant tests green.
New i18n keys: none expected (state if a reason code is rendered)
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location:
  - `app/services/message_alignment.py:254-256` (a stated dkim result without a usable `header.d` becomes `unknown` / `missing_d` or `invalid_domain_*`)
  - `app/services/message_alignment.py:229-231` (only the first `spf` resinfo is read; if it has no `smtp.mailfrom` the pair falls back to Return-Path with no stated result)
  - `app/services/message_alignment.py:278` (any `unknown` pair gives `computed_dmarc = not_evaluated`)
  - `app/services/message_findings.py:397` (`not_evaluated` with an Authentication-Results field present marks the analysis as not evaluated)
- Problem: the alignment code treats "the receiver stated that there was no DKIM signature" the same as "the identifier could not be read". One such pair makes `computed_dmarc` `not_evaluated`, which makes the whole message status `error`. An unsigned message that fails SPF is a plain DMARC failure, but the analyzer answers "could not evaluate" and never emits `MSG_ALIGNMENT_FAIL`. Same when a receiver lists an spf result for `smtp.helo` before the one for `smtp.mailfrom`: the second, usable result is ignored.
- Evidence (run through `analyze_message`, From `a@example.com`, Return-Path `a@example.com`):
  - `Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=example.com; dkim=none; dmarc=fail header.from=example.com` -> status `error`, `computed_dmarc: not_evaluated`, pairs `spf: aligned_but_not_passed`, `dkim: unknown (missing_d)`. Expected: `fail` with `MSG_ALIGNMENT_FAIL`.
  - `dkim=none (message not signed) header.d=none` -> `dkim: unknown (invalid_domain_single_label)`, status `error`.
  - `...; spf=pass smtp.helo=mail.example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com` (no dkim) -> spf pair `unknown (no_stated_result)`, status `error`. With the two spf entries swapped the status is `warn` and `computed_dmarc` is `pass`.
- Suggested fix: decided (see criteria).
- Tests to add: rows (1)-(7) above in `tests/services/test_message_alignment.py`.
- Confidence: high for the behaviour (reproduced). Medium for how often real receivers write these forms: no provider sample or documentation was checked, and docs/HEADERS.md lists provider samples as unverified.
