# HANDOFF — 2026-11-13 night (R1 complete, F-01 done)

Resume with `/gm`. Milestone **R1 — Code review fixes 2026-11-12** is complete: all 33 tickets done, QA APPROVE,
merged into `dev` and promoted to `qa` (e1143c1). Report: docs/reports/R1.md.
Backlog **F-01** (per-hop authentication view) is done: F-01-01 6d3bf59 (service, MSG_AUTH_BROKE_AFTER_HOP,
MSG_ALIGNMENT_FAIL reworded, HEADERS.md with RFC 8601/8617 citations), F-01-02 d2d5f40 (REST, web, CLI). Both QA
APPROVE first round; full suite green (PG for F-01-01, SQLite for F-01-02; dev CI covers PG for F-01-02).
F-01 is on `dev` only, not yet in `qa`. Next in TODO.md: **M7**.

## State
- `dev` at the commit carrying this file. `qa` and `main` unchanged (nothing went to qa/main in R1).
- CI: green through d887a1e (R1-28). 8ee174b (R1-25/26/27, pushed by the maintainer, first run of the new
  workflow steps): see "CI on 8ee174b" in docs/reports/R1.md.
- Local test PostgreSQL `dt-test-pg` (Docker Desktop) was used this session for R1-28 and R1-30 QA.
- Permissions (R1-33): commits touching .github/workflows/ are pushed by the maintainer; keep the word "push" out
  of commit messages and compound commands.

## Done this session
- R1-22 854d34e, R1-21 a349692 (round 2), R1-29 77a7e34, R1-28 1ecb89c (round 2), R1-27 7776ecd (round 2),
  R1-25 f48c2d1, R1-26 cb7310c, R1-30 93379be. TODO.md and ticket statuses aligned (R1-15/17/18 had stale lines).
- No ticket failed a second QA round. No escalation needed this session.

## Open maintainer actions
1. QA checklist line for .claude/agents/qa-reviewer.md ("Review steps", new step 5 after
   `   - changes stay inside "Files in scope"`): `5. Flag every change to .github/** or .claude/** in the report
   (including the diff of .claude/settings.json) and require the maintainer's approval before it is pushed; this is a
   blocker until approved.`
2. Optional (R1-30 QA nit): CLAUDE.md dev run command lacks `--no-proxy-headers` (dev-only, loopback).
3. Decide whether to merge `dev` into `qa` now that R1 is complete (GM may do it after a green full suite on dev;
   `main` stays with the maintainer).

## Follow-ups (TODO.md, R1 follow-up list)
R1-21 helo= with a space; R1-22 for F-01; R1-25 CI alembic_version check + comment; R1-26 doc wording; R1-30
fallback warning log, /32 example. All low.

F-01 follow-ups (TODO.md): lower dkim=pass suppresses MSG_DKIM_NOT_PASS (decided: F-01-03); hop numbering 0- vs
1-based on one page; detail_no_hop wording when Received is truncated; RFC 8617 4.2.1 qualifier; test fixture
chaining; template kind label. All low.

## CI status (read first)
- 278bd34: CI green (incl. PostgreSQL tests for F-01), Secret scan green, **CI infra RED** (run 43429085815): step
  "Compose up with postgres profile and wait for healthy" failed after 1 s, `app-1 is unhealthy`. App log: alembic
  connection to postgres refused while postgres was still starting, so the container exited. Cause is R1-25's choice
  (documented `restart: unless-stopped` retry, no wait): `compose up --wait` fails as soon as the app exits and does
  not wait for the restart. 8ee174b passed by timing. Not related to F-01 (default-profile smoke on the same image
  passed). Flaky by design until fixed.
- Fix options (new ticket R1-25b, opus): (a) a short bounded DB wait in the container start before alembic when
  DATABASE_URL is PostgreSQL (fixes real users too; Dockerfile CMD or small script); (b) CI starts postgres first
  (`up -d --wait postgres`, then the app). Prefer (a), possibly plus (b). Workflow changes need the maintainer's push.
  Do not promote dev to qa until CI infra is green.

## Next 3 steps
1. R1-25b: fix the postgres-profile startup race (above), QA, merge; confirm CI infra green; then merge `dev` into `qa`.
2. M7: read TODO.md, restate its acceptance criteria, `pm` splits it into tickets.
3. F-01-03 (maintainer decision 2026-11-13, see TODO.md): per-method findings read only the topmost
   Authentication-Results field; lower fields never suppress MSG_DKIM_NOT_PASS. pm writes the ticket, opus coder.
   Order: R1-25b, F-01-03, then M7.
