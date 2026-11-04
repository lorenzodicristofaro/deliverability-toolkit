# HANDOFF — 2026-11-05 (paused: usage limit reached)

Resume with `/gm`.

## Current milestone: M1 — Core platform (auth + multi-tenancy skeleton)
Tickets: docs/tickets/M1-01..M1-20. GM decisions recorded in M1-01 ("GM decisions").

## Ticket status
| Ticket | Status |
|---|---|
| M1-01..M1-11 | done (merged into dev, QA APPROVE, pushed, CI green at d7d394a) |
| M1-12 TenantContext + repositories | changes-requested, fix round 1 in progress when the session paused (branch feature/m1-12-tenant-context-repos). QA blocker: update/add accepted SQL expressions (cross-tenant read reproduced); plus AST-based static check, has_identity guard, filter User.is_active. Check the branch for a new commit after 4bbbdd2; if present send it to qa-reviewer (round 1 delta), else resume the coder with the QA findings. |
| M1-13..M1-20 | todo |

Suggested order after 11/12: 13, 14, 16, 15, 17, 18, 19, 20.

## Maintainer decisions this session
- Instance admin has NO tenant data access via the flag alone; with a membership, exactly what the
  membership allows (ARCHITECTURE §4 item 6). Impersonation: possible future feature, not planned.

## GM decisions this session (not escalated)
- Tenant delete CASCADE; users with memberships cannot be deleted (RESTRICT), deactivate instead (ARCHITECTURE §4 item 7).
- Non-ASCII domain names rejected until M1-18 adds IDNA 2008 (dependency allowed there).

## Follow-ups already routed into tickets
- M1-16: eager locale catalogue validation at startup + Accept-Language 4 KB cap (from M1-09 QA).

## Notes
- `gh run watch` exits 1 with the repo token (no Checks permission): poll `gh run view` instead.
  Optional for the maintainer: add "Checks: read" to the fine-grained token.
- Local `docker compose up` needs SECRET_KEY and ENCRYPTION_KEY (>= 32 chars) in `.env`.

## Next 3 steps
1. Finish M1-12 fix round 1 → QA delta → merge, push, check CI (poll with gh run view).
2. M1-13 (argon2 + sessions, opus), then M1-14 (CSRF + headers).
3. M1-16 templates/dark mode (includes the M1-09 follow-up), then M1-15 login.
