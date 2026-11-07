# M5-11 Subject line analysis
Milestone: M5
Branch: feature/m5-11-subject
Files in scope: app/parsers/content_subject.py, tests/parsers/test_content_subject.py
Out of scope: findings/i18n (M5-14), spam-word lists (rules only, M5-12/M5-13).
Depends on: none
Parallel-safe: yes (new parser file only)
Model: sonnet
Acceptance criteria:
- `analyze_subject(subject: str | None, *, limits) -> SubjectFacts`: length (code points and UTF-8 bytes), all-caps ratio (letters only, Unicode aware, caveat for scripts without case), consecutive punctuation (`!!`, `??`), emoji count, leading `Re:`/`Fwd:` without In-Reply-To flag (header passed by caller), empty/whitespace-only, control characters, RFC 2047 encoded words already decoded by M4-01 (this module takes decoded text).
- Thresholds (e.g. long-subject length) are constants in one place and documented as heuristics, NOT vendor guidance (`unverified`; no source claims). Findings (M5-14) must phrase them as advisory.
- Table-driven tests: empty, None, emoji, CJK/Arabic/Hebrew (no case), mixed scripts, 10k-char input (capped), control chars, bidi override characters (flagged).
New i18n keys: none
Status: todo
