# R1-22 Authentication-Results: a lower field must not supply a method the top field omits
Milestone: R1
Branch: feature/r1-22-authres-forged-lower-field
Findings: PARSE-06 (low; design decision needed from the GM before coding)
Files in scope: app/services/message_alignment.py (`_topmost`, dkim pair), app/services/message_findings.py:316-321 (same rule for findings), docs/HEADERS.md, tests/services/test_message_alignment.py, tests/services/test_message_findings.py, locales/en.json + locales/it.json only if a "not used" note is added
Out of scope: app/parsers/authres.py, deciding trust in authserv-id beyond the rule below, vendor-format claims (provider formats unverified)
Depends on: R1-09 (same function; do them in one pass or serialize)
Parallel-safe: no (same modules as R1-09 and R1-10)
Model: opus (interpretation of raw-message parser output with a trust decision)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- DESIGN DECISION FIRST: the coder states the chosen rule before coding and the GM confirms. Options from the review: (a) use results only from the topmost field; (b) use fields with the same authserv-id as the topmost one that sit above the first Received field, and report older fields as "not used"; (c) minimum: mark a pair whose result comes from a field other than index 0 (`authres_index > 0`) and exclude it from `computed_dmarc == pass`. A legitimate receiver that splits results over several fields must still be handled by the chosen rule (pinned by a test).
- Scenario test: top field `mx.example.org; spf=fail smtp.mailfrom=evil.example; dmarc=fail header.from=example.com`, second field `mx.example.org; dkim=pass header.d=example.com`, From `a@example.com` -> the dkim pair does not make `computed_dmarc` pass (today: spf misaligned, dkim aligned, `computed_dmarc` pass); findings and status stay `fail`.
- Legitimate two-field message from one receiver (spf in one field, dkim in the other) pins whichever rule is chosen.
- docs/HEADERS.md states the rule and the limit (trust is not decided; the tool does not verify signatures).
- No network. ruff, mypy, relevant tests green.
New i18n keys: none expected (en + it if a "result not used" finding or note is added)
Status: in-progress (decision: option (c), maintainer agreed 2026-11-13)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/services/message_alignment.py:159-166` (`_topmost`: first field that carries the method), `:253` (dkim), `app/services/message_findings.py:316-321` (same rule for findings).
- Problem: the "topmost field per method" rule falls through to older fields when the newest one does not mention a method. A sender can put its own `Authentication-Results: <id>; dkim=pass header.d=<victim>` in the message. If the receiver's field has no `dkim` entry (unsigned mail), the forged entry is used: the dkim pair shows `aligned` and `computed_dmarc` is `pass`. When the forged field copies the receiver's authserv-id, `MSG_AUTHRES_AUTHSERV_MISMATCH` does not fire. The module docstring states trust is not decided (a documented limit), but the output presents a sender-written value as the receiver's statement.
- Evidence: top field `mx.example.org; spf=fail smtp.mailfrom=evil.example; dmarc=fail header.from=example.com`, second field `mx.example.org; dkim=pass header.d=example.com`, From `a@example.com` -> pairs `spf: misaligned`, `dkim: aligned`; `computed_dmarc: pass`; findings `MSG_DMARC_NOT_PASS`, `MSG_SPF_NOT_PASS`, `MSG_ALIGNMENT_STATED_MISMATCH`. The status is still `fail`, which is why this is low.
- Suggested fix (design decision): see criteria options.
- Tests to add: the scenario above; a legitimate two-field message from one receiver.
- Confidence: medium (behaviour reproduced; whether to change it is a design call; real receivers that split results over several fields were not surveyed).
