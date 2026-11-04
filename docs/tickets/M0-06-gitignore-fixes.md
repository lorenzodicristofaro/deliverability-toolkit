# M0-06 toolchain and health fixes (M0-02 and M0-03 QA follow-ups)
Milestone: M0
Branch: feature/m0-06-toolchain-health-fixes
Files in scope: .gitignore, pyproject.toml, uv.lock, tests/test_health.py, app/web/health.py, CLAUDE.md (Commands section, test line only, and only if that is the option chosen)
Out of scope: any app code, CI, Docker, other pyproject.toml settings
Depends on: M0-02 (merged)
Parallel-safe: no (touches .gitignore and pyproject.toml)
Model: sonnet
Acceptance criteria:
- `data/` is no longer ignored wholesale: ARCHITECTURE puts seed files in /data. Ignore only the runtime data path. The coder must read that path from ARCHITECTURE.md (do not guess); if ARCHITECTURE does not define a runtime data path, stop and report to the GM instead of inventing one.
- `.claude/worktrees/` added to .gitignore.
- Double `-q` removed so pytest prints its summary line: keep `-q` in exactly one place, either `addopts` in pyproject.toml or the CLAUDE.md test command (coder picks one, states which in the summary). `uv run pytest` output shows the summary line (e.g. "1 passed").
- Comment on `extend-exclude = ["*.md"]` in pyproject.toml clarified or the setting removed. QA found ruff does not format Markdown even without it, so the existing comment is misleading; if removed, `uv run ruff check .` and `ruff format --check .` still pass.
- Lint and tests pass: `uv run ruff check . && uv run ruff format --check . && uv run mypy app && uv run pytest`.
New i18n keys: none
- Dev dependency switched from `httpx` to `httpx2` (Starlette 1.10.0 deprecates plain httpx in TestClient; QA confirmed at https://starlette.dev/testclient/). Use `uv remove --dev httpx` and `uv add --dev httpx2`; pytest runs without StarletteDeprecationWarning.
- tests/test_health.py asserts /healthz sets no `set-cookie` header (protects the "unauthenticated, no data exposed" contract once M1 adds sessions).
- HEAD /healthz answers 200 (app/web/health.py), with a test case in tests/test_health.py.
Status: done (QA APPROVE, merged to dev in b4d23c6), except the `data/` item (first acceptance criterion): deferred, waiting on the maintainer: ARCHITECTURE.md is read-only and the seed path vs the runtime /data path needs deciding. Tracked in M0-07.
