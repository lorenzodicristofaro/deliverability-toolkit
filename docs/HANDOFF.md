# HANDOFF — 2026-11-13 (R1 code review fixes, parked on the 5-hour usage limit)

Resume with `/gm`. No coder or QA agent is running. Current milestone: **R1 — Code review fixes 2026-11-12**
(TODO.md, before M7; tickets docs/tickets/R1-*.md). M7 starts after R1.

## State
- `dev` at 07e0a0f (pushed). CI green at 07e0a0f.
- `qa` a4cd8a7 and `main` 9d793cb unchanged (nothing goes to qa/main in R1, maintainer instruction).
- Review source (read-only, never merge): /home/lorenzo/projects/dt-review-2026-11-12, branch review/code-review-2026-11-12.
- Every finding is reproduced by a failing test before any fix; not reproducible -> stop, mark "not reproduced", report.

## R1 ticket status
- Done (QA APPROVE, merged, dev CI green): R1-01 PARSE-01, R1-02 AUTH-01, R1-03 AUTH-02, R1-04 AUTH-03, R1-05 DNS-01,
  R1-06 DNS-02, R1-07 DNS-03, R1-08 DNS-04, R1-09 PARSE-02, R1-10 PARSE-03, R1-11 AUTH-06, R1-19 DNS-07, R1-20 PARSE-04.
- Also done, CI green: R1-24 PARSE-08 (merge 07e0a0f).
- Parked:
  - R1-16 AUTH-11 Cache-Control: branch feature/r1-16-cache-control-no-store, commit e88efe5 (base 33ef234). Opus QA was
    interrupted by the limit; rerun QA from scratch. Open question for QA: the rule keys on the dt_session cookie; check
    surfaces not covered (setup wizard token page, login, any non-cookie API auth) and whether unconditional no-store
    (except /static, /healthz) is simpler; coder did not rerun the full suite after fixing its own tests.
  - R1-23 PARSE-07 One-Click: reproduced (15 failing tests), fix not started/finished; worktree
    .claude/worktrees/agent-a99177c5cde171429 (branch worktree-agent-a99177c5cde171429, base 07e0a0f). Start a new
    coder on the ticket (Sonnet) and point it at that worktree's uncommitted tests, or restart clean.
- Todo (low): R1-12, R1-13 (after R1-02, done), R1-14, R1-15, R1-17, R1-18, R1-21, R1-22 (design decision first),
  R1-25, R1-26 (needs network for digests), R1-27, R1-28 (needs PostgreSQL), R1-29.
- Escalations this milestone: R1-05 (Sonnet fixtures used non-reserved .org domains -> Opus), R1-08 (QA CHANGES
  REQUESTED round 1 -> Opus round 2, approved). No ticket failed a second QA round.

## Findings not reproduced
- None. R1-19 (DNS-07): code path reproduced, real-world trigger unverified; maintainer chose the precautionary rule (a).

## Not ticketed — maintainer decisions open
- INFRA-01, INFRA-02: .claude/settings.json deny rules and push/permission policy; workflow token rights.
- AUTH-05: domain rename vs ESP hosts outside the new domain (clear, rewrite or refuse).
- AUTH-04: folded into TODO "Trusted-proxy setting" (needed before any proxy deployment; per-IP login budget from R1-03
  becomes global behind a proxy until then).
- PARSE-03 leniency: should an Authentication-Results field without authserv-id count as evaluated?
- docs/CHECKS.md vs app/checks/dmarc.py:121-122 (failed external-auth lookup: error vs fail).
- Housekeeping done 2026-11-13: 151 merged agent worktrees removed (branches kept); kept R1-16, R1-23 and two locked merged ones (R1-07, R1-08 round 1).

## Next 3 steps
1. Rerun Opus QA on R1-16 (e88efe5) and finish R1-23.
2. Continue the low tickets in TODO order (R1-12, R1-13, R1-14, ...), one or two coders on disjoint files.
3. At R1 end: full suite on dev, short report docs/reports/R1.md, maintainer report (fixed / not reproduced / escalated / open).
