# M0-07 Docker follow-ups: own Unbound image, tag verification, seeds
Milestone: M0
Branch: feat/M0-07-unbound
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
Status: done (branch feat/M0-07-unbound; QA pending)

## Verification record (2026-11-04, Docker 29.9.2, Linux/WSL2, run locally)
- `docker compose --profile unbound config -q`: OK.
- `docker compose --profile unbound up -d --build --wait --wait-timeout 180`: app and unbound both Healthy;
  `docker compose ps` shows unbound `53/tcp, 53/udp` (no host mapping); `docker port` empty;
  HostConfig PortBindings `{}`.
- Non-root: `id` in container = `uid=100(unbound) gid=101(unbound)`; `/var/lib/unbound/root.key` owned by unbound.
- From a throwaway debian container (bind9-dnsutils) attached only to the `dns` network:
  - `dig @172.28.53.2 +dnssec ietf.org A`: NOERROR, flags `qr rd ra ad`.
  - `dig @172.28.53.2 example.net A`: NOERROR, `ad`.
  - `dig @172.28.53.2 dnssec-failed.org A`: SERVFAIL (validation failure); with `+cd`: NOERROR (confirms it is validation).
- Host side: `127.0.0.1:53` connection refused (the only :53 listeners on the host are WSL's own
  127.0.0.53/127.0.0.54/10.255.255.254 stubs, not Docker); `172.28.53.2:53` not reachable from the host.
- `unbound-control get_option qname-minimisation` in container: `yes`. `dig/drill/curl` are not in the image;
  the healthcheck uses `unbound-control` (from the `unbound` package).
- `docker buildx build --platform linux/arm64` of docker/unbound: succeeded (QEMU, build only).
- Tags verified with `docker buildx imagetools inspect`: python:3.12-slim-trixie, uv:0.13.7, postgres:17 (amd64 + arm64);
  debian:trixie-slim digest sha256:f6b08b09...c3ec4.
- Teardown: `docker compose --profile unbound down -v`, test container and network removed.
- `seeds/` does not exist yet; Dockerfile/.dockerignore unchanged for it (check only).
- Not run here: GitHub Actions (ci.yml unbound step, rebuild.yml); YAML syntax only.
