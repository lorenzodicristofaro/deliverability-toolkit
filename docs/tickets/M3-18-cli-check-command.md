# M3-18 CLI `check` command
Milestone: M3
Branch: feature/m3-18-cli-check
Files in scope: app/cli/__init__.py, app/cli/main.py, app/cli/check.py, pyproject.toml (typer dependency + `[project.scripts]`), uv.lock, tests/cli/__init__.py, tests/cli/test_check_cli.py
Out of scope: tenant-aware commands, login/API-key handling (M10 scoped API keys), persistence, new checks
Depends on: M3-02, M3-08, M3-10, M3-13
Parallel-safe: no (pyproject.toml/uv.lock)
Model: sonnet
Decision: `check` is a tenant-less free check on a domain NAME (like the free DNS tools), run by an operator with shell access to the instance; it does not read tenant data, so it needs no TenantContext and no permission check (the trust boundary is shell access, documented in the command help and docs). It never loads a tenant domain from the DB. Resolver comes from the same env config as the app (`RESOLVER_MODE/RESOLVER_ADDRS`) with the M2-03 egress policy; `--resolver <id>` accepts only ids the DNS tool accepts. Tenant-scoped CLI (API-key based) is deferred to M8 and must reuse the permission model then.
Acceptance criteria:
- Typer app, entry `uv run python -m app.cli check example.com [--only spf,dkim,dmarc] [--format json|text] [--lang en|it] [--selector NAME ...]`; `--selector` adds ad-hoc selectors for this run only.
- `--format json` prints exactly the `CheckResult` list JSON of the M3-02 service (same serializer as the API; byte-equal for the same recorded zone, asserted in M3-19); `text` renders translated findings via `app/core/i18n.py`.
- Exit codes: 0 all ok/info, 1 any warn/fail, 2 any `error` (could not evaluate), 64 usage error (invalid name, unknown check). `error` never exits 0.
- Uses the shared service only; no DB access, no network in tests (fake resolver injected through the same factory seam as the API dependency).
- Tests via Typer's CliRunner: each exit code, json shape, text in en and it, malformed domain, unknown check, DNS failure zone.
New i18n keys: cli.check.* (en + it) for text-mode headings only
Status: todo
