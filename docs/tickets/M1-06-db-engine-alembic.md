# M1-06 Database engine, session handling and Alembic (SQLite + PostgreSQL)
Milestone: M1
Branch: feature/m1-06-db-engine-alembic
Files in scope: app/core/db.py, app/models/__init__.py, app/models/base.py, alembic.ini, migrations/env.py, migrations/script.py.mako, migrations/versions/ (one baseline), pyproject.toml, uv.lock, Dockerfile (include migrations and run `alembic upgrade head` before start, if not already), tests/test_db.py, tests/conftest.py (create), app/core/config.py, tests/test_settings.py
Out of scope: business tables (M1-10), /readyz, repositories, CI changes (M1-07)
Depends on: M1-01
Parallel-safe: no (pyproject/uv.lock, Dockerfile)
Model: sonnet
Acceptance criteria:
- SQLAlchemy 2.x engine/session factory from `Settings.DATABASE_URL`; sync or async choice stated in the summary (open to GM if it affects later tickets; proposed: sync SQLAlchemy sessions, simplest on both backends).
- SQLite: foreign keys enforced via PRAGMA on connect. PostgreSQL driver added (psycopg, binary wheel for amd64 and arm64: verify wheel availability, mark unverified otherwise).
- Naming convention for constraints set on `Base.metadata` so Alembic diffs are stable on both backends.
- Alembic configured from `Settings`, empty baseline revision; test runs `upgrade head` then `downgrade base` then `upgrade head` on SQLite (temp file) and, when `TEST_DATABASE_URL` is set, on PostgreSQL.
- Container start applies migrations; `docker compose up` still serves /healthz (smoke through existing CI job; coder runs it locally).
- CLAUDE.md "migrate" command line updated by GM after merge (report the exact command: `uv run alembic upgrade head`).
- DATABASE_URL credentials never appear in repr/str of Settings or in logs (SecretStr or masked password); repr test with a postgresql://user:pass@host/db URL (QA follow-up from M1-01).
- No tenant data access in this ticket.
New i18n keys: none
Status: todo
