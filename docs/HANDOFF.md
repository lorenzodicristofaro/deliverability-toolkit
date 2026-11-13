# HANDOFF — 2026-11-13 evening (R1 code review fixes, parked at 91% usage)

Resume with `/gm`. Current milestone: **R1 — Code review fixes 2026-11-12**
(TODO.md, before M7; tickets docs/tickets/R1-*.md). Backlog item F-01 (auth per hop) sits before M7.

## State
- `dev` at the commit carrying this file; CI green through 4f3a6d7. `qa` and `main` unchanged (nothing goes to qa/main in R1).
- Review source (read-only, never merge): /home/lorenzo/projects/dt-review-2026-11-12, branch review/code-review-2026-11-12.
- Every finding is reproduced by a failing test before any fix; not reproducible -> stop, mark "not reproduced", report.
- Permissions (R1-33): deny rules cover .claude/settings*.json, agents, commands, skills, hooks (also inside worktrees),
  tag pushes, `git push -d`, `git * push*` (this also blocks any git command with " push" after the verb, e.g. a commit
  message: keep the word out of commit messages), `git tag`. Changes to .github/** or .claude/** are approved by the
  maintainer before the push; commits touching .github/workflows/ are pushed by the maintainer (GM token has no
  Workflows permission).
- Maintainer action still open: add the QA checklist line to .claude/agents/qa-reviewer.md ("Review steps", new step 5
  after `   - changes stay inside "Files in scope"`): `5. Flag every change to .github/** or .claude/** in the report
  (including the diff of .claude/settings.json) and require the maintainer's approval before it is pushed; this is a
  blocker until approved.`

## R1 ticket status
- Done (QA APPROVE, merged into dev): R1-01..R1-20, R1-23, R1-24, R1-31, R1-32, R1-33.
  Latest: R1-15 37368b3, R1-17 edb3a63 (round 2), R1-33 cad5215, R1-32 ebdede2, R1-31 4f3a6d7, R1-18 6c1d0a7.
- Parked mid-flow (agents stopped for the usage limit, work kept):
  - R1-21 PARSE-05: branch feature/r1-21-received-from-ip-comment, commit bb139f2 (base 6c1d0a7). Coder done
    (15 rows, tests green). Opus QA was stopped before a verdict: rerun it. Key question for QA: a `helo=[...]`-labelled
    literal inside the comment must not be picked as from_ip (RFC 5321 4.4 TCP-info); vendor formats unverified.
  - R1-22 PARSE-06: branch feature/r1-22-authres-forged-lower-field, commit 8eef9ea (base 4f3a6d7), decision option (c)
    (maintainer agreed). Coder was stopped right after committing: its report is missing. Rerun the relevant tests
    (tests/services, tests/parsers/test_authres*.py, tests/test_i18n.py, message analysis web/API/CLI), check the ticket
    criteria (scenario test, legitimate two-field case explained by a finding, docs/HEADERS.md), then Opus QA.
- Todo: R1-25 (compose postgres profile; touches .github/workflows/ci-infra.yml -> maintainer push), R1-26 (image
  digests; needs registry network; touches rebuild.yml -> maintainer push), R1-27 (ci-infra trigger; workflow ->
  maintainer push), R1-28 (migration lock; PostgreSQL; GM writes the ARCHITECTURE.md note), R1-29 (container hardening),
  R1-30 (TRUSTED_PROXIES, opus; after R1-25 and R1-29: shared compose/.env.example).
- Escalations this milestone: R1-05, R1-08, R1-23, R1-17 (each approved in round 2). No ticket failed a second round.

## Maintainer decisions 2026-11-13
1. PARSE-03 strict (RFC 8601 2.2, 2.5, 4.1); docs/HEADERS.md. 2. CHECKS.md aligned to dmarc.py. 3. AUTH-04 -> R1-30.
4. AUTH-05 -> R1-31 (done). 5. no-store everywhere -> R1-32 (done). 6. INFRA-01/02 -> R1-33 (done; rulesets set by the
   maintainer). 7. R1-22 option (c); per-hop authentication view as backlog F-01 (display only, verdict uses top field).
8. R1-17: ESP detection still associates an include after `all`; the profile check raises ESP_SPF_INCLUDE_AFTER_ALL.

## Findings not reproduced
- None. R1-19 (DNS-07): code path reproduced, real-world trigger unverified; maintainer chose the precautionary rule.

## Next 3 steps
1. R1-22: verify 8eef9ea, Opus QA, merge. R1-21: rerun Opus QA on bb139f2, merge.
2. R1-29, R1-28, R1-25..R1-27 (workflow commits wait for the maintainer's push), then R1-30.
3. At R1 end: full suite on dev, docs/reports/R1.md, maintainer report (fixed / not reproduced / escalated / open).
