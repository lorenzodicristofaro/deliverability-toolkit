# M0-05 GitHub Actions CI
Milestone: M0
Branch: feature/m0-05-github-actions-ci
Files in scope: .github/workflows/ci.yml
Out of scope: release/publish workflows, registry push, PostgreSQL test matrix (needs DB code, M1), Playwright (later), any secret or token
Depends on: M0-02, M0-03, M0-04
Parallel-safe: no (verifies the previous tickets together)
Model: sonnet
Acceptance criteria:
- Triggers on pull_request and push to dev, qa, main. `permissions: contents: read`. No secrets, no `secrets.*` references, no push anywhere.
- Job lint-test: setup uv (official astral action or documented install; pin versions per official docs), `uv sync --frozen`, ruff check, ruff format --check, mypy, pytest -q --tb=short. Same commands as CLAUDE.md Commands.
- Job secret-scan: same scanner as pre-commit (M0-02), run read-only.
- Job docker-build: buildx for linux/amd64 and linux/arm64 with QEMU, `push: false`, no registry login. Plus a smoke step on the native build: `docker compose up -d`, wait for health, check /healthz, `docker compose down -v`.
- Third-party actions pinned (version tag at minimum; full SHA preferred, flag to GM). Action names/versions verified against their official repositories; unverified items listed in the summary.
- YAML lints clean (e.g. actionlint if available); coder cannot prove "green" locally without GitHub, so report that CI is unrun until the human pushes `dev`.
- Note: ARCHITECTURE section 13 says CI also runs pytest on PostgreSQL; deferred to M1 when a DB exists. Add a comment in the workflow.
New i18n keys: none
Status: todo
