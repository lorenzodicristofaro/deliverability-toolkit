# M4-13 CLI `analyze` command
Milestone: M4
Branch: feature/m4-13-cli
Files in scope: app/cli/analyze.py, app/cli/main.py (register command only), tests/cli/test_analyze.py, locales/en.json, locales/it.json
Out of scope: API/UI, any network. Scope decision: a CLI `analyze` IS in M4 (small, offline, and it gives the acceptance test a third surface to compare against; M3 CLI `check` already exists).
Depends on: M4-10
Parallel-safe: no (cli/main.py and locale files)
Model: sonnet
Acceptance criteria:
- `analyze FILE|-` reads the file or stdin as bytes, caps at MAX_RAW_BYTES while reading (refuses larger without loading it), `--format json|text` (json = `model_dump_json` of M4-10, byte-equal to the API body), `--lang en|it` like `check`.
- Exit codes follow `check` (documented in docs/CHECKS.md pattern): 0 no findings above info, 1 warn/fail findings, 2 error status or unreadable/oversize/NUL input (usage message localized, no input echoed).
- Pure offline test: sockets blocked; missing file, directory, unreadable file, binary garbage, NUL, empty, symlink to /dev/zero (read capped) all covered.
- No hardcoded user strings; text format uses i18n keys.
New i18n keys: cli.analyze.help, cli.analyze.error.not_found, cli.analyze.error.too_large, cli.analyze.error.nul_byte, cli.analyze.error.empty, cli.analyze.summary (en + it)
Status: done
