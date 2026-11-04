# HANDOFF — 2026-11-04

Resume with `/gm`.

## Current milestone: M0 — Project setup
All TODO.md items ticked (M0-07 done). Milestone acceptance still **pending**:
- `dev` (including M0-07 rework round 2, merged locally) is NOT pushed; CI has not run on it.
- `dev` is NOT yet merged into `qa`. No milestone report written yet (`docs/reports/M0.md`).

## Tickets
| Ticket | Status | Notes |
|---|---|---|
| M0-01 governance docs | done | CoC contact placeholder (CODE_OF_CONDUCT.md:41): maintainer fills in before public release |
| M0-02 uv toolchain | done | |
| M0-03 /healthz | done | M1 follow-ups in ticket: /docs + /openapi.json unauthenticated; empty SECRET_KEY/ENCRYPTION_KEY must be treated as missing |
| M0-04 Dockerfile + compose | done | runtime verified 2026-11-04 (app only) |
| M0-05 GitHub Actions CI | done | optional nits listed in ticket |
| M0-06 toolchain/health fixes | done | `data/` item resolved by maintainer decision (seeds/) |
| M0-07 Docker follow-ups (own Unbound image) | done | round 2 merged into dev 2026-11-04 (QA APPROVE opus, 62 tests passed, lint clean, not pushed). QA nits moved to M1 in TODO.md (gateway pin in IPAM; mDNS/avahi false-fail on host probe 127.0.0.1:5353) |
| M0-08 gitignore + ruff *.md | done | |
| M0-09 Unbound hardening nits | superseded | folded into M0-07 round 2 |

## Decisions taken (maintainer)
- Seed directory is `seeds/` (image: `/app/seeds`); `/data` stays the runtime volume, `DATABASE_URL=sqlite:////data/app.db` (ARCHITECTURE updated).
- Unbound: own Debian-slim image (tag + digest pinned), non-root, DNSSEC with Debian's trust anchor, qname-minimisation, recursion from root, no forwarders, internal compose network only, listens on port 5353 inside the network and is never published on the host, healthcheck (AD flag), optional `unbound` profile, multi-arch CI build + periodic rebuild, maintenance rule in `docs/UNBOUND.md`. klutchell/unbound dropped (ARCHITECTURE §7 updated).
- No bind mounts of folders outside the project into containers (applies to all services).
- ruff excludes `*.md` explicitly with `force-exclude = true` (verified on ruff 0.17.3).
- QA reviewer runs on opus; coder model per ticket `Model:` line (default sonnet).
- DNSBL for the M0-07 integration test: Spamhaus ZEN (test entry 127.0.0.2), skip on provider block/NXDOMAIN/timeout. M7 open: production DNSBL list and Spamhaus free-use terms (non-commercial, low volume) to be settled in `dnsbl.yaml` with `verified_on`.

## Docker state
Cleanup done: stale images and network removed. Volume `deliverability-toolkit_app-data` left in place.

## Open items for the maintainer
1. Push `dev` to GitHub so CI runs on the M0-07 round 2 changes.
2. CoC enforcement contact: before public release.

## Next 3 steps
1. Maintainer pushes `dev` -> CI green, including the new `integration-unbound` and `unbound-arm64-smoke` jobs (the gateway REFUSED path is first exercised on native Linux there).
2. GM merges `dev` -> `qa`.
3. GM writes `docs/reports/M0.md`.
