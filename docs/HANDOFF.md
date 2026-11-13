# HANDOFF — 2026-11-13 (R1 code review fixes)

Resume with `/gm`. Current milestone: **R1 — Code review fixes 2026-11-12**
(TODO.md, before M7; tickets docs/tickets/R1-*.md). M7 starts after R1.

## State
- `dev` at bcc231b (pushed). CI green through ff4cbe3.
- `qa` a4cd8a7 and `main` 9d793cb unchanged (nothing goes to qa/main in R1, maintainer instruction).
- Review source (read-only, never merge): /home/lorenzo/projects/dt-review-2026-11-12, branch review/code-review-2026-11-12.
- Every finding is reproduced by a failing test before any fix; not reproducible -> stop, mark "not reproduced", report.

## R1 ticket status
- Done (QA APPROVE, merged into dev): R1-01..R1-14, R1-16 (ee71e69), R1-19, R1-20, R1-23 (3981ec5), R1-24.
  Latest merges: R1-12 d0af0e6, R1-14 ff4cbe3, R1-13 bcc231b.
- In flight: R1-15 AUTH-10 (in-progress), R1-17 DNS-05 (in-review, round 2).
- Todo: R1-18, R1-21, R1-22 (design decision first), R1-25..R1-29 (R1-26 needs network, R1-28 needs PostgreSQL),
  R1-30, R1-31, R1-32 (new, below).
- Escalations this milestone: R1-05 (Sonnet fixtures used non-reserved .org domains -> Opus), R1-08 (QA CHANGES
  REQUESTED round 1 -> Opus round 2, approved).

## Maintainer decisions 2026-11-13
1. PARSE-03 leniency: STRICT. Authentication-Results without authserv-id is not evaluated (RFC 8601 2.2, 2.5, 4.1); no code
   change; sentence added to docs/HEADERS.md.
2. docs/CHECKS.md aligned to app/checks/dmarc.py (failed external-auth lookup: `error` only without critical/high finding;
   always DMARC_EXTERNAL_AUTH_UNVERIFIED). Done.
3. R1-30 AUTH-04 TRUSTED_PROXIES (opus): check the uvicorn forwarded-allow-ips default in current docs, do not rely on memory.
4. R1-31 AUTH-05 domain rename rewrites ESP host suffixes in the same transaction, notice en+it (sonnet).
5. R1-32 no-store on every response except /static/ and exactly /healthz (sonnet; QA Opus).
6. INFRA-01 / INFRA-02: maintainer decision pending (maintainer reviewing); no ticket.

## Findings not reproduced
- None. R1-19 (DNS-07): code path reproduced, real-world trigger unverified; maintainer chose the precautionary rule (a).

## Notes
- Follow-ups of the merged tickets are listed under "Follow-ups:" in the R1 block of TODO.md.
- Worktree for R1-23 is merged and can be removed; R1-16 branch merged.

## Next 3 steps
1. Finish R1-15 and R1-17 round 2; then R1-18, R1-21, R1-22.
2. R1-30, R1-31, R1-32 (R1-30 after R1-15: shared auth.py/config.py/.env.example); R1-25..R1-29 on disjoint files.
3. At R1 end: full suite on dev, short report docs/reports/R1.md, maintainer report (fixed / not reproduced / escalated / open).
