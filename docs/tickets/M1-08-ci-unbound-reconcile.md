# M1-08 Reconcile the CI unbound runtime check with the M0-07 r2 jobs
Milestone: M1
Branch: feature/m1-08-ci-unbound-reconcile
Files in scope: .github/workflows/ci.yml, tests/integration/test_unbound.py (only to add a missing assertion), docs/UNBOUND.md
Out of scope: Postgres job (M1-07), changing the unbound image/config, M2 resolver code
Depends on: M1-04, M1-05, M1-07
Parallel-safe: no (ci.yml)
Model: sonnet
Acceptance criteria:
- Carry-over "CI runtime check of the unbound profile (up, healthy, AD flag, port 5353 unpublished)": produce a four-row mapping in the PR summary (up, healthy, AD flag, 5353 unpublished) to the existing `integration-unbound` / `unbound-arm64-smoke` assertions with file and test name.
- Add only what is missing. If all four are covered, change nothing in ci.yml and say so; do not duplicate jobs.
- New check enabled by M1-04: with `--profile unbound`, the `app` container is attached to `dns` and `172.28.53.2:5353` is reachable from it (test via docker exec using python stdlib socket, no new tools in the image).
- Job timeouts and pinned actions unchanged in style.
- GitHub run is unverified until the GM pushes `dev`.
New i18n keys: none
Status: todo
