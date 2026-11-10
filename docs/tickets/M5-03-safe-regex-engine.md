# M5-03 ReDoS-safe regex runner with enforced timeout
Milestone: M5
Branch: feature/m5-03-safe-regex
Files in scope: app/core/safe_regex.py, pyproject.toml + uv.lock (add `regex` only if chosen), tests/core/test_safe_regex.py
Out of scope: rules, UI, API, any caller (callers are M5-13, M5-18, M5-22).
Depends on: none
Parallel-safe: yes (only ticket touching pyproject/uv.lock in this wave; new file under core)
Model: opus (ReDoS protection)
Context: ARCHITECTURE §9 requires regex rules to run with a timeout (the `regex` module with its `timeout` argument, or a subprocess/worker). The coder must verify the current behaviour of the chosen mechanism in its official documentation (not from memory), record the choice and caveats in the module docstring, and update ARCHITECTURE.md §9 in the same commit if the decision differs from the text.
Acceptance criteria:
- Public API (typed): `compile_checked(pattern, flags) -> CompiledRule` (rejects over-long patterns, NUL, invalid syntax with a typed error, no echo of input) and `search_all(rule, text, *, timeout_s, max_matches, max_text_bytes) -> MatchResult` returning matches, `timed_out: bool`, `truncated: bool`. Never raises on timeout; never returns partial results as complete.
- Hard cap on pattern length, text size, match count and timeout (config constants, with an upper bound a caller cannot exceed).
- TEST PROVES the cut-off: a catastrophic pattern such as `(a+)+$` against `"a"*N + "!"` returns `timed_out=True` within a wall-clock bound (e.g. under 2x timeout + margin) and the process stays responsive; a second test runs it in the same process afterwards to show no leaked hung worker/thread (if a subprocess/worker is used, assert it is killed).
- Table-driven: valid patterns, empty pattern, invalid syntax, catastrophic patterns (nested quantifiers, alternation overlap), huge text, unicode, flags; no network.
- Timeout failure is distinguishable by callers so rules can report `error`, not `ok` (CLAUDE.md non-negotiable).
New i18n keys: none
Status: done
