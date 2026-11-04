# M0-07 Docker follow-ups: own Unbound image, tag verification, seeds
Milestone: M0
Branch: feature/m0-07-docker-followups
Files in scope: docker/unbound/Dockerfile (new), docker/unbound/unbound.conf, compose.yaml, .github/workflows/ci.yml, .github/workflows/rebuild.yml (new, optional: may be folded into ci.yml), docs/UNBOUND.md (new), Dockerfile and .dockerignore (seeds item only)
Out of scope: app code, ARCHITECTURE.md and SPEC.md (read-only; ARCHITECTURE §7 already updated by the GM: Unbound is an optional compose profile, own image, maintenance rule in docs/UNBOUND.md)
Depends on: M0-04, M0-05, M0-06
Parallel-safe: no
Model: sonnet. Flag for GM: the network-isolation part (internal subnet, access-control, no published port 53) is security-relevant; consider opus review/QA for that part, not required by the model rule.
Decisions: maintainer, 2026-11-04.

Acceptance criteria:
Unbound image
- Own image from Debian slim; base pinned by tag AND digest. Install the Debian `unbound` package. klutchell/unbound dropped entirely (no references left).
- Runs as non-root user.
- Configuration lives in the repo: docker/unbound/unbound.conf.
- DNSSEC using Debian's trust anchor. Path and mechanism (unbound-anchor package, /usr/share/dns/root.key, root-auto-trust-anchor-file snippet, or other) must be verified in official Debian docs (packages.debian.org, the package README.Debian, Debian manpages) and cited. Nothing from memory.
- qname-minimisation enabled. Full recursion from the root, no forwarders.
- Listens only on the compose internal network. access-control limited to that network's subnet; the subnet is declared explicitly in compose.yaml and must match unbound.conf. Port 53 is NOT published on the host.
- Healthcheck on the unbound service using only tools present in the image (verify they are installed).
- Stays an optional `unbound` compose profile.
- Maintainer rule, all services: no bind mounts of folders outside the project into containers.

CI
- Multi-arch build (linux/amd64, linux/arm64) of the Unbound image, no push.
- Periodic rebuild via `schedule` to pick up Debian security updates. Cron and frequency documented in docs/UNBOUND.md.

docs/UNBOUND.md
- Maintenance rule: how and when to update the base digest and the package, periodic rebuild, how to verify the trust anchor. Include sources and verified_on.

Existing items kept
- Dockerfile and compose.yaml: python:3.12-slim-trixie, uv:0.13.7 and postgres:17 tags marked consistently as verified (with date) or UNVERIFIED.
- Dockerfile/.dockerignore: `seeds/` ships at /app/seeds once the directory exists (today it does not, so check only); /data remains the runtime volume.

Verification and reporting
- Every Debian/Unbound option and path verified against official docs; anything uncertain marked `unverified` in the file and reported to the GM for maintainer confirmation.
- Lint and tests from CLAUDE.md green; `docker compose --profile unbound config -q` OK.
- Docker runtime checks (up, healthcheck, ownership) are covered by CI in M0-05.

New i18n keys: none
Status: todo
