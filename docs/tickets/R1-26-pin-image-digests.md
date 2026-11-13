# R1-26 Pin app image bases by digest and add the app image to the rebuild check
Milestone: R1
Branch: feature/r1-26-pin-image-digests
Findings: INFRA-04 (low)
Files in scope: Dockerfile, compose.yaml (`postgres:17` only if the coder pins it; decide separately), .github/workflows/rebuild.yml, docs/UNBOUND.md or a short new maintenance note (coder states which), tests (static test, e.g. tests/test_dockerfile_pins.py)
Out of scope: the Unbound Dockerfile (already pinned), Python/uv version changes, dependency updates
Depends on: none
Parallel-safe: no with R1-25 and R1-29 (compose.yaml / Dockerfile / workflows); serialize
Model: sonnet (mechanical pinning and a workflow step)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected: a static test that every `FROM` and `COPY --from` image reference in both Dockerfiles carries `@sha256:`.)
- `python:3.12-slim-trixie` (Dockerfile:6) and `ghcr.io/astral-sh/uv:0.13.7` (Dockerfile:11) pinned by tag AND index digest; the Dockerfile frontend (`# syntax=docker/dockerfile:1`, line 1) pinned or the choice not to pin documented.
- DIGESTS ARE NOT INVENTED: take them from `docker buildx imagetools inspect <image>` (needs network and Docker). If the coder has no network or Docker, stop and report: the GM or maintainer must supply them. Do not write placeholder digests.
- The app image is added to `rebuild.yml` (weekly no-cache build check, same pins and `contents: read` permissions as the Unbound job).
- Maintenance rule written (date verified, how to refresh), same style as docs/UNBOUND.md "Maintenance rule". `postgres:17` pin decided separately and stated.
- Static test passes; Dockerfile still builds in CI (proof is the first dev CI run).
- ruff, mypy, relevant tests green.
New i18n keys: none
Status: done (QA APPROVE, merged cb7310c; branch a6bea1a; index digests read 2026-11-13 with docker buildx imagetools inspect and re-read by QA; postgres:17 left on the tag; arm64 build proof is CI)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `Dockerfile:1` (`# syntax=docker/dockerfile:1`), `Dockerfile:6` (`python:3.12-slim-trixie`), `Dockerfile:11` (`ghcr.io/astral-sh/uv:0.13.7`), `compose.yaml:41` (`postgres:17`), `.github/workflows/ci.yml:89`, `.github/workflows/rebuild.yml:15-28` (Unbound only), `docker/unbound/Dockerfile:7` (pinned by digest, for comparison).
- Problem: the Unbound image follows a written rule: base pinned by tag and digest, weekly no-cache build check. The app image, which holds the secrets and parses untrusted input, uses moving tags for its base, for the `uv` binary it copies in, and for the Dockerfile frontend. Two builds of the same commit can differ, and a replaced tag is accepted silently. The Python patch version in the image is also not the one the tests run on (CI uses the interpreter chosen by `setup-uv` from `.python-version`).
- Evidence: `Dockerfile:5` records that the tag was "verified 2026-11-04" but nothing fixes that state. `rebuild.yml` builds `docker/unbound` only.
- Suggested fix: pin by index digest, with the same maintenance rule as docs/UNBOUND.md (date, how to refresh); add the app image to `rebuild.yml`; decide separately whether `postgres:17` should be pinned to a minor version. Do not invent digests: take them from `docker buildx imagetools inspect`.
- Tests to add: a static test that every `FROM` and `COPY --from` image reference in both Dockerfiles carries `@sha256:`.
- Confidence: high (read from the files).
- UNVERIFIED EXTERNAL FACT: the digests and whether the pinned tags still exist; must be read from the registry by someone with network access.
