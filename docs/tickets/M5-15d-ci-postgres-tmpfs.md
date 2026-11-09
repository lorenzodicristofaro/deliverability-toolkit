# M5-15d PostgreSQL on tmpfs in CI (measured, kept only if faster)
Milestone: M5
Branch: feature/m5-15d-ci-pg-tmpfs
Files in scope: .github/workflows/ci.yml
Out of scope: everything else.
Depends on: M5-15c
Parallel-safe: no
Model: sonnet
Acceptance criteria:
- The CI PostgreSQL service stores its data on tmpfs through service container options (`--tmpfs` on the data directory of the image's major version).
- The health check still gates the job.
- The change is measured on dev CI against the PostgreSQL job duration from M5-15c, and the result is written in this ticket. If it is not faster, the GM reverts it.
New i18n keys: none
Status: todo
