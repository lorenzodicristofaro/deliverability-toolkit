# M6-00 CI: fewer billed Actions minutes
Milestone: M6 (infra, before M6 feature tickets)
Branch: feature/m6-00-ci-minutes
Files in scope: .github/workflows/ci.yml, a new .github/workflows/ci-infra.yml if the jobs are split, docs/SETUP.md and docs/WORKFLOW.md (CI description only), tests that read workflow files (if any; grep `ci.yml` in tests/)
Out of scope: app code, test code other than workflow-reading tests, secret-scan.yml, rebuild.yml
Depends on: none
Parallel-safe: yes (no app files)
Model: sonnet
Context (maintainer decision 2026-11-10): a code push to `dev` costs about 27 billed minutes (each job rounded up to a whole minute: test-postgres 10, test-sqlite 8, docker-build 3, integration-unbound 2, unbound-arm64-smoke 2, lint 1, secret-scan 1). Free plan: 2,000 min/month.
Acceptance criteria:
- `qa` pushes no longer run CI: `qa` only receives `dev` commits that are already green. `dev` pushes and pull requests keep running CI unchanged. `main` pushes keep running the FULL CI with every job (no path filtering on `main`).
- docker-build, integration-unbound and unbound-arm64-smoke run on `dev` pushes and pull requests only when a file they depend on changes. Use native `on.<event>.paths` (split them into `ci-infra.yml`), not a third-party action. The coder derives the path list from what each job actually builds and uses: Dockerfile, compose files, Unbound config, dependency files (pyproject.toml, uv.lock), the workflow file itself, and anything the jobs copy or run. The list and the reason for each entry go in a comment at the top of the workflow.
- lint, test-sqlite and test-postgres keep their current triggers and docs-only paths-ignore.
- YAML is valid (parse it with Python yaml in a test or a one-off check). Every `paths`/`paths-ignore` glob is checked against the repository tree, so no pattern matches zero files by mistake.
- docs/SETUP.md and docs/WORKFLOW.md describe which jobs run when. If branch protection names required checks, note that path-filtered workflows report nothing when skipped.
- It cannot be verified on GitHub before 2026-12-21 (local-only period). The coder states that in the ticket, and the first push after that date is the check.
New i18n keys: none
Status: in-review
Note (coder): not verifiable on GitHub before 2026-12-21 (local-only period); the first push after that date is the check. Checked locally: YAML parses, every glob matches at least one tracked file, moved jobs are identical.
