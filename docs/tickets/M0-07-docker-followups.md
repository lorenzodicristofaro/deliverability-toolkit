# M0-07 Docker follow-ups (M0-04 QA findings, M0-06 data/ item)
Milestone: M0
Branch: feature/m0-07-docker-followups
Files in scope: Dockerfile, compose.yaml, docker/unbound/unbound.conf, .gitignore (data/ item), possibly a new image dir if Unbound is self-built
Out of scope: CI workflow (M0-05), app code, editing ARCHITECTURE.md (read-only; maintainer edits it)
Depends on: M0-04, M0-06, maintainer decisions below
Parallel-safe: no
Model: sonnet
Acceptance criteria:
- Unbound: pin the image (currently klutchell/unbound:latest, UNVERIFIED) or replace it with our own image (Debian slim + the unbound package), as the maintainer decides. Verify the config mount path and the option names in unbound.conf against official docs. Add a healthcheck to the unbound service.
- Dockerfile:5/8-10 and compose.yaml:33: mark the python:3.12-slim-trixie, uv:0.13.7 and postgres:17 tags either as verified (with date) or as UNVERIFIED, consistently.
- Dockerfile/.dockerignore: ensure `seeds/` ships at /app/seeds when the directory exists (today it doesn't, so this only needs checking); /data remains the runtime volume. (Decided by maintainer 2026-11-04.)
- ARCHITECTURE.md:128 says "Default in compose: bundled Unbound", which contradicts TODO M0 ("optional unbound profile") and the current compose. The maintainer must decide which is right; code follows that decision.
- Docker runtime checks (build, up, /healthz, healthcheck, volume ownership, profiles) are verified by CI in M0-05, not here.
New i18n keys: none
Status: blocked (waiting on the maintainer: Unbound image decision, ARCHITECTURE.md:128 default). Seed-path item is decided and unblocked.
