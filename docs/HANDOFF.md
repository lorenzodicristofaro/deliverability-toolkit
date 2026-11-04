# HANDOFF — 2026-11-04

Session paused at the maintainer's request (fixing Docker daemon permissions in WSL).
Resume with `/gm`.

## Current milestone: M0 — Project setup
All TODO.md items ticked. Milestone acceptance still **pending**:
- CI has never run on GitHub (needs the human to push `dev`).
- ~~`docker compose up` → `/healthz` 200 not verified locally~~ — verified 2026-11-04 (see M0-04).
`dev` is NOT yet merged into `qa`. No milestone report written yet.

## Tickets
| Ticket | Status | Notes |
|---|---|---|
| M0-01 governance docs | done | CoC contact placeholder (CODE_OF_CONDUCT.md:41): maintainer fills in before public release |
| M0-02 uv toolchain | done | |
| M0-03 /healthz | done | M1 follow-ups in ticket: /docs + /openapi.json unauthenticated; empty SECRET_KEY/ENCRYPTION_KEY must be treated as missing |
| M0-04 Dockerfile + compose | done | runtime verified 2026-11-04 (app only; postgres/unbound profiles not run) |
| M0-05 GitHub Actions CI | done | never run on GitHub; optional nits listed in ticket |
| M0-06 toolchain/health fixes | done | `data/` item resolved by maintainer decision (seeds/) |
| M0-07 Docker follow-ups (own Unbound image) | **rework (round 2)** | round 1 merged into dev (not pushed); maintainer rework 2026-11-04, criteria A-H in ticket; coder sonnet, QA opus; M1 follow-ups kept |
| M0-08 gitignore + ruff *.md | done | |
| M0-09 Unbound hardening nits | superseded | folded into M0-07 round 2 (a, c, d); b obsolete |

## Decisions taken this session (maintainer)
- Seed directory is `seeds/` (image: `/app/seeds`); `/data` stays the runtime volume, `DATABASE_URL=sqlite:////data/app.db` (ARCHITECTURE updated).
- Unbound: own Debian-slim image (tag + digest pinned), non-root, DNSSEC with Debian's trust anchor (verify in package docs), qname-minimisation, recursion from root, no forwarders, internal compose network only, port 53 not published, healthcheck, optional `unbound` profile, multi-arch CI build + periodic rebuild, maintenance rule in `docs/UNBOUND.md`. klutchell/unbound dropped (ARCHITECTURE §7 updated).
- No bind mounts of folders outside the project into containers (applies to all services).
- ruff excludes `*.md` explicitly with `force-exclude = true` (verified on ruff 0.17.3).
- QA reviewer runs on opus; coder model per ticket `Model:` line (default sonnet).

## Open items for the maintainer
1. ~~Fix Docker daemon access in WSL~~ RESOLVED 2026-11-04 (M0-04 runtime verification passed, see ticket).
2. ~~Push `dev` to GitHub so CI runs~~ DONE 2026-11-04; CI on dev green at b499c14 (confirmed by maintainer).
3. CoC enforcement contact: before public release.

## Next 3 steps
1. ~~Check Docker works~~ — done 2026-11-04 (/healthz 200, recorded in M0-04).
2. Run M0-07 rework round 2 (sonnet, then opus QA); confirm DNSBL provider with maintainer.
3. Push → CI green → merge `dev` → `qa`, write `docs/reports/M0.md`.
