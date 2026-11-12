# R1-27 Run the Docker jobs when app/ or locales/ change (before the release merge)
Milestone: R1
Branch: feature/r1-27-ci-infra-app-trigger
Findings: INFRA-05 (low)
Files in scope: .github/workflows/ci-infra.yml, .github/workflows/ci.yml (only if the PR-to-main option is chosen), docs/WORKFLOW.md section 5 (one line), a static test that parses the workflow (coder states where)
Out of scope: required-checks / ruleset settings (maintainer), action pins, adding jobs unrelated to triggers, the M6-00 GitHub verification (TODO.md "M6-00 follow-ups")
Depends on: none
Parallel-safe: no with R1-25 and R1-26 (ci-infra.yml/workflows); serialize
Model: sonnet (workflow triggers and a docs line)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected: a static test parsing ci-infra.yml that asserts `app/**` and `locales/**` are among the trigger paths, or the PR-to-main path; it fails today because "Deliberately NOT listed: app/, locales/".)
- Choose one and state it: (a) add `app/**` and `locales/**` to the path lists of `ci-infra.yml` (dev pushes and PRs), or (b) run only the single-platform compose smoke on every `dev` push and keep the QEMU multi-arch builds path-filtered, or (c) call `ci-infra.yml` from `ci.yml` for pull requests whose base is `main`, so the release PR always shows the Docker jobs before the merge.
- The comment at ci-infra.yml:26-27 is rewritten: the M6-00 cost reason no longer holds (repository public since 2026-11-11, unlimited minutes: cite TODO/HANDOFF as the source, do not restate as a GitHub fact beyond that).
- Permissions stay `contents: read`; no new secrets; pins unchanged. docs/WORKFLOW.md section 5 updated.
- Honest limit stated in the summary: the trigger behaviour on GitHub cannot be proven locally; proof is the next dev CI run (GM checks). The M6-00 behaviour is itself unverified in TODO.
- ruff, mypy, the static test green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `.github/workflows/ci-infra.yml:26-27` ("Deliberately NOT listed: app/, locales/"), `.github/workflows/ci-infra.yml:30-70`, `.github/workflows/ci.yml:113-115` (`infra` runs on `main` pushes only).
- Problem: `docker-build` (multi-arch build plus compose start and `/healthz`) runs on `dev` and on pull requests only when a Docker-related path changes. A change under `app/` or `locales/` that breaks only inside the container (non-root user, root-owned `/app`, a new directory that is not copied, a startup step needing a writable path) is not seen on `dev`, and not on the `qa` -> `main` pull request unless the same PR touches a listed path. The first run is the `infra` job on `main`, after the merge, and it is not a required check. The exclusion was made in M6-00 to save billed minutes; since 2026-11-11 the repository is public with unlimited minutes, so that reason no longer holds.
- Evidence: scenario: a ticket adds `app/services/x.py` that writes a cache file next to the module. Tests pass on the runner. `dev` and `qa` are green. After the release merge, `infra / docker-build` fails on `main` because `/app` is not writable for user `app`.
- Suggested fix: as in the criteria (a)/(b)/(c).
- Tests to add: none beyond the trigger change. Existing tests check `COPY seeds` and `COPY profiles` only.
- Confidence: high for the trigger behaviour as written; the M6-00 behaviour on GitHub is itself still marked unverified in TODO.md.
- Already tracked: partly (M6-00 decision and TODO "M6-00 follow-ups").
