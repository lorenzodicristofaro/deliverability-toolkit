# M5-17a CLI operator tenant and user selection
Milestone: M5
Branch: feature/m5-17a-cli-tenant
Files in scope: new shared module under app/cli/ (coder names it), tests/cli/ (new test file), locales/en.json, locales/it.json, docs/CHECKS.md (CLI trust boundary note)
Out of scope: the `content` command (M5-17); changing `check` and `analyze`, which stay tenant-less and offline; login, passwords, API keys; any new permission action.
Depends on: M5-04
Parallel-safe: no (locale files)
Model: opus
Context (maintainer decision 2026-11-09): today's CLI has no tenant, user or database (`docs/CHECKS.md`: trust boundary is shell access), but ARCHITECTURE.md says the permission layer is used by web, API and CLI alike, and `analyze_content` needs a TenantContext, a session and tenant rules, with M5-25 requiring API and CLI JSON byte-equal.
Acceptance criteria:
- A reusable helper gives a CLI command a database session from the app configuration and, from operator options `--tenant-id N --user-id M`, an active principal and a `TenantContext`, then runs the same `can(principal, action, TenantResource(tenant_id))` as the web layer. Tenant data is accessed only through /repositories with that TenantContext.
- Both options are required by commands that use the helper; there is no default tenant and no fallback to a system context.
- Denials behave as on the web: unknown or inactive user, no or stale membership, foreign tenant, role without the permission. Each is a non-zero exit with a localized message, no traceback and no database or input detail; `check`/`analyze`-style exit codes stay as they are, and permission denial uses a distinct documented exit code. The action is not invoked on denial (spy).
- Failure cases give a clean localized non-zero exit: database unreachable, schema not migrated, missing or malformed configuration.
- Sessions and connections are closed on every exit path.
- Table-driven tests including malformed option values (zero, negative, non-integer, huge), every role, and a two-tenant case, on SQLite and PostgreSQL. Offline apart from the database connection (socket guard allowing only the test database).
- docs/CHECKS.md states honestly: these options select who the command acts as; they are not authentication; anyone with shell access and the database configuration can name any user; the trust boundary remains shell access.
New i18n keys: cli.operator.* (coder lists the final set, en + it)
Status: done
