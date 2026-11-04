# M0-08 .gitignore DB files and explicit ruff Markdown exclude
Milestone: M0
Branch: feature/m0-08-gitignore-ruff-md
Files in scope: .gitignore, pyproject.toml
Out of scope: app code, CI, Docker, other pyproject.toml settings, ARCHITECTURE.md
Depends on: nothing
Parallel-safe: no (touches .gitignore and pyproject.toml)
Model: sonnet
Acceptance criteria:
- .gitignore: keep `data/`, add `*.db-*`, `*.sqlite-*` and `*.db-journal`.
- Verify first, with the ruff version pinned in uv.lock: run `uv run ruff format --check --diff <file>.md` on a Markdown file in the repo (e.g. ARCHITECTURE.md), ignoring the current exclude (e.g. `--isolated` or an equivalent method). Record the command and an excerpt of the output in the commit message.
- Then exclude `*.md` from ruff explicitly, so it applies to both `ruff check` and `ruff format`. Check the official ruff docs for the right key (`extend-exclude` at `[tool.ruff]` level, or a format-specific one); do not assume, and cite the docs page in the summary. The pyproject comment cites the ruff version and the verification date.
- Lint and test commands from CLAUDE.md green (`uv run ruff check . && uv run ruff format --check . && uv run mypy app && uv run pytest`).
New i18n keys: none
Status: done (QA APPROVE, merged into dev b8971d0)
