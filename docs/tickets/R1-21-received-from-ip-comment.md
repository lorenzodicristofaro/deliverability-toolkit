# R1-21 Received parser: prefer the TCP-info comment address over the HELO literal for from_ip
Milestone: R1
Branch: feature/r1-21-received-from-ip-comment
Findings: PARSE-05 (low)
Files in scope: app/parsers/received.py (lines ~437-445 and the module docstring `from_ip` definition), tests/parsers/test_received.py, app/services/message_analysis.py only if a separate HELO-literal field is added
Out of scope: `MSG_RECEIVED_PRIVATE_IP_ORIGIN` semantics (documentation ranges/CGNAT reported as private: maintainer design question), other Received fields, redaction rules
Depends on: none
Parallel-safe: yes
Model: opus (raw-message parser)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- When the `from` clause has comments containing a valid address literal, `from_ip` is the first literal found in the comments; the HELO literal is used only when no comment has one. Optionally expose the HELO literal as a separate field (state if done; if added, update the analysis view/schema docs and tests).
- `from_ip_reserved` is computed on the address used for `from_ip`.
- Table rows: `from [8.8.8.8] (unknown [10.1.2.3]) by mx.example.org with ESMTP id 1; Tue, 10 Nov 2026 10:00:00 +0000` -> `from_ip=10.1.2.3`, reserved True; literal with a comment that has no literal (`(helo=...)`, existing row near tests/parsers/test_received.py:69) -> HELO literal as before; hostname plus comment literal -> unchanged; IPv6 forms in both positions (`[IPv6:2001:db8::1]`), invalid literal in the comment falls back to the HELO literal, multiple comments, comment literal with trailing text, over-long comment (malformed/hostile input, no exception, bounded work via counter).
- Module docstring updated. Note in the summary that "prefer the comment" has not been validated against real MTA samples (none in the corpus).
- No network. ruff, mypy, relevant tests green.
New i18n keys: none
Status: done (QA APPROVE round 2; merged a349692, branch 30a1b0c; round 1 CHANGES REQUESTED for a helo=[...] comment literal picked as from_ip)
Notes:
- "Prefer the comment literal" and the helo=/ehlo= handling were not checked against real MTA Received samples (RFC 5321 4.4 reasoning only).
- Follow-up (low, needs real samples): `helo= [x]` with a space and `(HELO [x])` without "=" are not recognised as labelled, so `from [8.8.8.8] (helo= [10.1.2.3])` gives 10.1.2.3; consider skipping spaces before "[".

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/parsers/received.py:437-445` (sources are searched in the order: `from` value, then its comments; the first literal wins).
- Problem: in `from [a.b.c.d] (host [w.x.y.z]) by ...` the first literal is what the client said in HELO/EHLO and the comment is the TCP-info written by the receiving server. The parser reports the HELO literal as `from_ip`. A sender can therefore choose the address shown for its hop, and `from_ip_reserved` (which drives `MSG_RECEIVED_PRIVATE_IP_ORIGIN`) is computed on the wrong address (RFC 5321 section 4.4).
- Evidence: `parse_received_values(["from [8.8.8.8] (unknown [10.1.2.3]) by mx.example.org with ESMTP id 1; Tue, 10 Nov 2026 10:00:00 +0000"])` -> `from_ip='8.8.8.8'`, `from_ip_reserved=False`. The address the receiver saw is `10.1.2.3`.
- Suggested fix: when the `from` clause has comments containing a valid literal, prefer the first literal from the comments and use the HELO literal only when no comment has one. Optionally expose the HELO literal as a separate field. Update the module docstring.
- Tests to add: rows above.
- Confidence: high for the behaviour; medium that preferring the comment is right for every MTA layout (no real provider samples exist in the corpus yet).
