# M0-02 uv project and dev toolchain
Milestone: M0
Branch: feature/m0-02-uv-toolchain
Files in scope: pyproject.toml, uv.lock, .python-version, .gitignore, .pre-commit-config.yaml, app/__init__.py, tests/__init__.py, tests/test_smoke.py, CLAUDE.md (Commands section only)
Out of scope: FastAPI/uvicorn dependencies and any app code (M0-03), CI (M0-04), Docker (M0-05), README/LICENSE
Depends on: none
Parallel-safe: no (owns pyproject.toml; M0-03 and later tickets must wait for the merge)
Model: sonnet
Acceptance criteria:
- uv project, `requires-python = ">=3.12"` (ARCHITECTURE section 1: Python 3.12+; exact pin for .python-version is an open question, use 3.12 unless GM says otherwise). Package dir `app/` per ARCHITECTURE section 2; license field `AGPL-3.0-or-later`.
- Dev dependency group: ruff, mypy, pytest, pytest-asyncio (async checks are planned), pre-commit. Config for ruff (lint+format), mypy (strict for `app`), pytest (`testpaths = tests`, quiet output) lives in pyproject.toml.
- `tests/test_smoke.py` imports `app` so pytest has one passing test.
- `.pre-commit-config.yaml`: ruff, ruff-format, mypy (local hook via uv), plus secret scanning (WORKFLOW section 5). Hook repos/revs must be taken from each tool's official repository at implementation time; if the chosen secret scanner version cannot be verified, say so in the summary.
- `.gitignore` covers .venv, __pycache__, .mypy_cache, .ruff_cache, .pytest_cache, *.db, .env.
- CLAUDE.md "Commands" section filled: install (`uv sync`), run (`uv run uvicorn app.main:app --reload`; the module path `app.main:app` is the contract M0-03 must satisfy), test (`uv run pytest -q --tb=short`), lint (`uv run ruff check . && uv run ruff format --check . && uv run mypy app`), pre-commit install, plus a "migrate: not yet available (M1)" line. No other CLAUDE.md edits.
- `uv sync`, ruff, mypy and pytest all pass locally from a clean checkout; uv.lock committed.
New i18n keys: none
Status: done (QA APPROVE, merged to dev in ce47b46; follow-ups in M0-06)
