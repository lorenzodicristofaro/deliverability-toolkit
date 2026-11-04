# M0-04 Dockerfile (multi-arch) and compose.yaml with unbound/postgres profiles
Milestone: M0
Branch: feature/m0-04-docker-compose
Files in scope: Dockerfile, .dockerignore, compose.yaml, docker/unbound/unbound.conf (if needed)
Out of scope: CI workflow (M0-05), app code, pyproject.toml, compose.dev/qa/prod.yaml (later), wiring app to Postgres/Unbound (M1/M2)
Depends on: M0-03
Parallel-safe: no (needs the merged app and uv.lock)
Model: sonnet
Acceptance criteria:
- Single Dockerfile, no arch-specific instructions, builds for linux/amd64 and linux/arm64 (SPEC section on packaging). Uses uv with the committed uv.lock (frozen), runs as non-root, no Node toolchain, exposes the app port, CMD runs `uvicorn app.main:app`. Base image tag and uv install method must be checked against official docs (Docker Hub python image / astral uv docs) at implementation time; note anything unverified.
- compose.yaml: default `docker compose up` starts only the app service, zero config (SPEC: works with SQLite, `DATABASE_URL` default `sqlite:////data/app.db`), named volume mounted at /data, healthcheck hitting /healthz (use python, not curl, unless curl is installed), no secrets in the file (SECRET_KEY/ENCRYPTION_KEY via env/.env, not hardcoded; app does not consume them until M1).
- Optional profile `unbound` and profile `postgres`: separate services only started with `--profile`. Image names/tags, Unbound config and Postgres env vars must come from official documentation; mark UNVERIFIED in a comment and in the summary anything not confirmed. Postgres password via env var with no real default committed (placeholder requiring user input, or a clearly dev-only value flagged to GM).
- `docker compose config` validates for default and with each profile; `docker compose up` then `curl localhost:<port>/healthz` returns 200 (coder reports whether Docker was available to test; if not, say so).
New i18n keys: none
Status: done (QA APPROVE, merged to dev in af1620c)

Runtime UNVERIFIED: no access to the Docker daemon, so none of these were run: image build, `docker compose up`, /healthz, container healthcheck, volume ownership of /data, postgres/unbound profile startup. CI verifies this in M0-05. Follow-ups in M0-07.
