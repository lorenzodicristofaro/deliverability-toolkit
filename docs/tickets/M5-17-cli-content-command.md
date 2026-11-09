# M5-17 CLI: `content` command
Milestone: M5
Branch: feature/m5-17-cli-content
Files in scope: app/cli/content.py, app/cli/main.py (register command), tests/cli/test_content_cli.py, locales/en.json, locales/it.json
Out of scope: importing private helpers from app/cli/check.py (use or create a public shared helper only if the M4 CLI follow-up is done; otherwise copy the minimal error helper and note it in Follow-ups).
Depends on: M5-14, M5-17a
Parallel-safe: no (CLI registry and locale files)
Model: sonnet
Acceptance criteria:
- `content --html FILE --text FILE --subject S --eml FILE --lang xx --json`; `-` reads stdin; size caps and NUL handling same as the API; exit codes consistent with `analyze` (0 ok, non-zero on error-class result or unreadable input).
- `--json` output byte-equal to the API and service JSON for the same input. Text output includes finding evidence lines (do not repeat the M4 CLI nit).
- Runs offline (sockets blocked); tenancy via the same CLI tenant selection as other commands; permission denial test (client viewer cannot run).
- Table tests: missing file, directory, binary file, oversized file, invalid language.
New i18n keys: cli.content.* (help, status label cli.content.status, errors cannot_read/too_large/empty) (en + it)
GM note (maintainer decision 2026-11-09): uses the M5-17a helper with `--tenant-id` and `--user-id` and Action.CONTENT_ANALYZE; a permission denial test covers a client viewer. Exit codes follow `analyze`: 0 ok, 1 warn or fail, 2 error status or bad input, 64 usage, plus the denial code from M5-17a. Overall `ok` with `complete` false exits 1 and the text output says the rules were not evaluated, so scripts cannot read an incomplete run as clean. Copying the small `_fail` and `read_bounded` helpers is acceptable and goes in Follow-ups.
Status: done
