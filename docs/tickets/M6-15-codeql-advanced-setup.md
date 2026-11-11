# M6-15 CI: CodeQL advanced setup excluding tests
Milestone: M6 (infra, maintainer decision 2026-11-11, run before M6-08)
Branch: feature/m6-15-codeql-advanced
Files in scope: .github/workflows/codeql.yml (new), .github/codeql/codeql-config.yml (new), docs/TESTING.md (CI section), docs/WORKFLOW.md (only the "what runs when" CI paragraph)
Out of scope: ci.yml, ci-infra.yml, secret-scan.yml, rebuild.yml, app code
Depends on: M6-14 (run one at a time)
Parallel-safe: no
Model: sonnet
QA model: opus
Context (maintainer decision 2026-11-11): the repository is now PUBLIC (full history). GitHub-hosted Actions minutes are free and unlimited. Rulesets are active: `protect-qa` (no deletion, no force push) and `protect-main` (no deletion, no force push, PR required with 0 approvals, merge commits only, required checks: lint, test-sqlite, test-postgres, secret-scan). main equals qa (M1-M5) via PR #1. CodeQL default setup reports 8 high alerts in tests/ that are intentional (ReDoS fixtures in tests/.../test_safe_regex.py, HTML/URL assertions in tests/web). Default setup cannot exclude paths.
Acceptance criteria:
- codeql.yml analyses languages python, javascript-typescript, actions (matrix); triggers: push to main, pull_request to main, weekly schedule; workflow permissions minimal: security-events: write, contents: read (plus only what the docs show is required, e.g. actions: read, which is documented for private repos: justify it or omit it for this public repo).
- codeql-config.yml has `paths-ignore: tests` and is referenced via the `config-file` input of the init step.
- Every action pinned to a full 40-char commit SHA with the tag in a trailing comment, each SHA checked with `git ls-remote` against the upstream tag, like ci.yml. Use the current major of github/codeql-action and actions/checkout.
- Inputs (languages, build-mode, config-file, category, etc.) verified against current official GitHub CodeQL docs; the coder lists the doc URLs checked and records anything unverified in this ticket.
- YAML parses (one-off Python yaml check); the paths-ignore entry matches the tests/ directory.
- docs/TESTING.md documents the CodeQL workflow (what, when, why tests are excluded).
New i18n keys: none
HUMAN step (maintainer): switch CodeQL from Default to Advanced setup in Settings -> Advanced Security (Code security) before the next PR to main; otherwise the advanced analysis upload is rejected while default setup is enabled. CodeQL is not a required check in protect-main.
Not verifiable locally: the first run happens on the next PR to main; the coder states this in the ticket.
Status: in-review
Coder note: codeql.yml + codeql-config.yml added, docs updated. First real run = next PR to main (not verifiable locally); the HUMAN step above must be done first.
Pins: actions/checkout 3d3c42e5 (v7.0.1, same as ci.yml); github/codeql-action init+analyze 33d7b85d (release tag v4.39.3; peeled commit of the annotated tag, via git ls-remote).
Docs checked: docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning (languages, config-file, paths-ignore); codeql-action README and init/action.yml at the pinned SHA (security-events: write required; contents: read documented for private repos; inputs languages, build-mode, config-file).
Unverified: build-mode none for python, javascript-typescript, actions (docs page lists none only for C/C++, C#, Java, Rust; its matrix examples show it for javascript-typescript and python; actions not confirmed); actions: read omitted (not found in the docs fetched); contents: read kept for checkout; the workflow-configuration-options docs URL returned 404; actionlint not available.
