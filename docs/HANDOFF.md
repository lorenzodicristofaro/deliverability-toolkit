# HANDOFF — 2026-11-04

Session paused at the maintainer's request (fixing Docker daemon permissions in WSL).
Resume with `/gm`.

## Current milestone: M0 — Project setup
All TODO.md items ticked. Milestone acceptance still **pending**:
- CI has never run on GitHub (needs the human to push `dev`).
- `docker compose up` → `/healthz` 200 not verified locally (daemon socket: permission denied).
`dev` is NOT yet merged into `qa`. No milestone report written yet.

## Tickets
| Ticket | Status | Notes |
|---|---|---|
| M0-01 governance docs | done | CoC contact placeholder (CODE_OF_CONDUCT.md:41): maintainer fills in before public release |
| M0-02 uv toolchain | done | |
| M0-03 /healthz | done | M1 follow-ups in ticket: /docs + /openapi.json unauthenticated; empty SECRET_KEY/ENCRYPTION_KEY must be treated as missing |
| M0-04 Dockerfile + compose | done | runtime unverified (no daemon) |
| M0-05 GitHub Actions CI | done | never run on GitHub; optional nits listed in ticket |
| M0-06 toolchain/health fixes | done | `data/` item resolved by maintainer decision (seeds/) |
| M0-07 Docker follow-ups (own Unbound image) | **todo** | rewritten with maintainer decisions; PM flags network isolation for opus-level review |
| M0-08 gitignore + ruff *.md | done | |

## Decisions taken this session (maintainer)
- Seed directory is `seeds/` (image: `/app/seeds`); `/data` stays the runtime volume, `DATABASE_URL=sqlite:////data/app.db` (ARCHITECTURE updated).
- Unbound: own Debian-slim image (tag + digest pinned), non-root, DNSSEC with Debian's trust anchor (verify in package docs), qname-minimisation, recursion from root, no forwarders, internal compose network only, port 53 not published, healthcheck, optional `unbound` profile, multi-arch CI build + periodic rebuild, maintenance rule in `docs/UNBOUND.md`. klutchell/unbound dropped (ARCHITECTURE §7 updated).
- No bind mounts of folders outside the project into containers (applies to all services).
- ruff excludes `*.md` explicitly with `force-exclude = true` (verified on ruff 0.17.3).
- QA reviewer runs on opus; coder model per ticket `Model:` line (default sonnet).

## Open items for the maintainer
1. Fix Docker daemon access in WSL (docker group or Docker Desktop WSL integration).
2. Push `dev` to GitHub so CI runs (agents never push).
3. CoC enforcement contact: before public release.

## Next 3 steps
1. Check Docker works (`docker compose up --wait`, `curl localhost:8000/healthz`); record the result in M0-04.
2. Run M0-07 (coder → QA on opus, with focus on network isolation and verified Debian/Unbound facts) → merge.
3. After the maintainer's push and green CI: full suite on `dev`, merge `dev` → `qa`, write `docs/reports/M0.md`.
