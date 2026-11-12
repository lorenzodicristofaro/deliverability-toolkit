# R1-20 dtk check text output: escape control characters from DNS data
Milestone: R1
Branch: feature/r1-20-cli-check-escape-controls
Findings: PARSE-04 (low)
Files in scope: app/cli/check.py, app/cli/content.py (move `_visible` out), a small shared CLI helper module (new, e.g. app/cli/_text.py), tests/cli/test_check_cli.py, tests/cli/test_content_cli.py (keep its escaping test green)
Out of scope: JSON output, `dtk analyze` (already uses `excerpt`), the shared `_fail`/`read_bounded` helper refactor (TODO M4-13/M5-17 items), DNS layer decoding
Depends on: none
Parallel-safe: yes
Model: sonnet (output escaping in one CLI module, reuses existing code)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- `_visible` (app/cli/content.py:150) moves to a shared CLI helper; `check.render_text` applies it to every string parameter and every evidence item (lines 78-87), as `content.render_text` does. Behaviour of `dtk content` unchanged.
- Test (copy the parametrized test at tests/cli/test_content_cli.py:446-454 for `check`): a fake zone with `example.com TXT "v=spf1 include:\x1b[2J\x1b[31mFORGED.example.com bogus\x1b]0;title\x07 -all"` and a DMARC `rua` with `\x1b[31m`; rendered text contains no ESC (0x1b), BEL, C1 CSI (U+009B), U+202E, or raw newline injected from evidence or from a parameter; the escaped form is visible.
- JSON output unchanged (control characters remain JSON-escaped as before). No network. ruff, mypy, relevant tests green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/cli/check.py:78-87` (`params` and `"; ".join(f.evidence)` go to `typer.echo` as they are), `app/dns/types.py:76-80` (TXT strings are decoded as latin-1, so every byte including ESC and BEL survives).
- Problem: finding evidence and parameters built from TXT records reach the terminal unchanged in the default `text` format. The domain being checked controls those bytes. `dtk content` escapes them (`_visible`, `app/cli/content.py:150`) and `dtk analyze` gets values through `excerpt`, so `check` is the only CLI command without this protection. JSON output is not affected; the web UI escapes through Jinja.
- Evidence: fake zone with `example.com TXT "v=spf1 include:\x1b[2J\x1b[31mFORGED.example.com bogus\x1b]0;title\x07 -all"` and a DMARC `rua` containing `\x1b[31m`; `render_text(run_checks(["spf","dmarc"], ...), "en")` contains 5 ESC and 2 BEL bytes, e.g. `Evidence: control_character: include:\x1b[2J\x1b[31mFORGED.example.com; ...`. A record can clear the screen, recolour text or set the window title, and so hide or fake lines of the report.
- Suggested fix: move `_visible` to a shared CLI helper and apply it in `check.render_text` to every string parameter and every evidence item.
- Tests to add: the parametrized test at tests/cli/test_content_cli.py:446-454 copied for `check` (ESC, C1 CSI `\x9b`, U+202E, newline in evidence and in a parameter).
- Confidence: high.
- Related TODO: "CLI content (M5-17 QA)" and "CLI analyze (M4-13 QA)" ask for shared CLI helpers; neither mentions escaping in `check`.
