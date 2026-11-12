# M6-24 CI: pip-audit job on every dev push and PR, plus weekly run
Milestone: M6
Branch: feature/m6-24-pip-audit-ci
Files in scope: .github/workflows/ci.yml, docs/WORKFLOW.md (or the CI doc in use; the coder states which). A new .github/workflows/pip-audit.yml is allowed only if the schedule cannot be added to ci.yml without running the other jobs weekly.
Out of scope: app/, tests/, pyproject.toml, uv.lock, dependency bumps, Dependabot config, CodeQL, secrets
Depends on: M6-21 (merged)
Parallel-safe: yes with M6-23 and M6-25 (disjoint files)
Model: sonnet. QA model: sonnet (CI config only, no secrets; QA checks pins and permissions by hand).

Goal: maintainer approved 2026-11-12. Turn the manual dependency audit into a CI gate. New advisories appear without code changes, so the job must not be skipped on docs-only pushes.

Change:
- Add a `pip-audit` job to .github/workflows/ci.yml, running on every push to dev and every PR, not behind the docs-only path filter that skips the test jobs.
- Command: the existing manual one (see docs/reports/M6.md and docs/HANDOFF.md): `uv export --frozen --format requirements-txt --no-hashes --all-groups > <file>` then `uvx pip-audit==<pinned version> -r <file> --no-deps --disable-pip`. Fails on any known vulnerability. Pin pip-audit to a concrete version the coder confirms exists on PyPI.
- Pin every action by full commit SHA (with a version comment), same style as the other workflows; pin the uv setup the way ci.yml already does.
- Minimal permissions: `contents: read` only. No secrets, no tokens.
- Weekly scheduled run (cron). Scheduled workflows run on the default branch (main); say so in a comment in the workflow, so the schedule only takes effect after the next qa -> main promotion.
- docs/WORKFLOW.md: document the job and how to handle a red pip-audit: bump the dependency, or a documented time-boxed ignore (`--ignore-vuln <GHSA id>`) with the GHSA id, reason and an expiry date in the commit message and a comment next to the flag. No silent ignores.
- Update TODO/HANDOFF wording is the PM's job, not the coder's.

Acceptance criteria:
- Workflow YAML valid (the coder runs an offline YAML parse; actionlint if available).
- Job present for push (dev) and pull_request without a paths-ignore that skips docs-only changes; schedule trigger present with the main-branch comment.
- pip-audit version and all action SHAs pinned; permissions `contents: read`.
- The manual command run locally exits 0 on the current uv.lock (note the output).
- docs/WORKFLOW.md section on red pip-audit present.
- Real proof is the first dev CI run after merge (GM checks).

New i18n keys: none
Status: todo
