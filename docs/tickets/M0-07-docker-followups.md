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
Status: done (round 2 merged into dev locally 2026-11-04, QA APPROVE opus 2nd round; tests 62 passed, lint clean; not pushed). Round 1: branch feat/M0-07-unbound, QA APPROVE, merged. Round 2: branch fix/M0-07-unbound-r2.

## Rework round 2 — maintainer 2026-11-04
Branch: fix/M0-07-unbound-r2 (from dev). Model: sonnet. Parallel-safe: no (compose.yaml, ci.yml, app config shared).
Files in scope (adds to round 1): docker/unbound/Dockerfile, docker/unbound/unbound.conf, compose.yaml, .github/workflows/*.yml, docs/UNBOUND.md, README.md (arm64 note only if E takes the "untested" option), app config module that parses RESOLVER_ADDRS (coder locates it), tests/ (unit + new integration dir), pyproject.toml (pytest marker only), locale files en+it (only if a new error string is needed), ARCHITECTURE.md (ONLY the RESOLVER_ADDRS format line, authorized by the maintainer for this commit).
Out of scope: everything else in app code, SPEC.md, other ARCHITECTURE.md content.
Folded in from M0-09 (now superseded): items a, c, d. Item b is obsolete (sysctl removed).

Acceptance criteria:
A. Trust anchor
- Fact (verified 2026-11-04): since 2026-10-11 the root DNSKEY RRset is signed only by KSK-2024, key tag 38696. Sources: https://www.iana.org/news/2026/root-zone-begins-using-new-ksk-2026 ; https://www.icann.org/resources/pages/ksk-rollover . KSK-2017 (tag 20326) revocation is planned for 2027. Record sources and verified_on in docs/UNBOUND.md.
- A1. Automated test (no network; runs against the BUILT image, e.g. `docker run --rm <image> cat <root.key path>`) asserts key tag 38696 is present in root.key. Computing the tag from the DNSKEY record must be done by the test (RFC 4034 App. B) or via a tool in the image; do not grep a hardcoded string only.
- A2. root.key lives in a named volume writable by the `unbound` user so RFC 5011 updates persist; the volume is seeded from the image on first start (named-volume copy-up or an entrypoint step; verify the mechanism works with read_only rootfs, see D-hardening below). Test: after `down` and `up` without `-v`, the file in the volume is retained.
- A3. Healthcheck resolves a DNSSEC-signed name and verifies validation (AD flag), not just process liveness. Use only tools present in the image (verify; add a package only if needed and document). 
- Known risk (document in docs/UNBOUND.md): the healthcheck depends on external resolution, so the container reports unhealthy when the host is offline or egress to root servers is blocked. Document the behaviour, the healthcheck interval/retries/start_period chosen, and that `depends_on: condition: service_healthy` on unbound will block dependents in that case.
B. Port
- Unbound listens on unprivileged port 5353 (udp+tcp) inside the compose network only; never published. Remove the `net.ipv4.ip_unprivileged_port_start` sysctl from compose.yaml and any docs mention.
- `RESOLVER_ADDRS` accepts comma-separated `host:port` entries, including bracketed IPv6 (`[::1]:5353`); an entry without a port keeps the documented default (coder states which default in the parser docstring, 53). Parser lives in the app config; table-driven unit tests cover: IPv4 with/without port, bracketed IPv6 with/without port, unbracketed IPv6 (reject or documented behaviour), port 0 / 65536 / non-numeric, empty entry, empty string, whitespace, hostname vs IP (per current spec). No network in tests.
- ARCHITECTURE.md: update the RESOLVER_ADDRS format line in the same commit.
- Any user-facing error string uses an i18n key (en+it); list new keys below. If errors are only raised at startup as exceptions for operators, still state the choice in the PR.
C. Config audit
- docs/UNBOUND.md gets a table of every unbound.conf option that is not required by this ticket, each with a concrete justification and a link to the official unbound.conf manual (NLnet Labs, https://unbound.docs.nlnetlabs.nl/en/latest/manual/unbound/unbound.conf.html). Options without a concrete reason are removed from unbound.conf.
- Specifically re-evaluate (a) root-hints from file (built-in hints vs file; keep only with a cited reason, including who updates the file) and (b) every harden-* option against the manual (default value, what it protects, whether it is already default). Remove ones that are defaults unless explicit-setting is justified.
- Any claim not verifiable in the manual is marked `unverified`.
D. Integration tests (pytest marker, e.g. `integration`; excluded from the default `uv run pytest -q` run via marker config; run in CI with Docker, the job name documented)
- Tests run from a container on the `dns` network (or equivalent) against the built image and cover: DNSSEC validation (AD on a signed name), SERVFAIL on bad signature (dnssec-failed.org, confirm with +cd NOERROR if feasible), NXDOMAIN, REFUSED for a query from outside the allowed subnet (second network/container or host-side attempt; state the method), and a DNSBL test-entry query.
- DNSBL test entry: semantics (e.g. 127.0.0.2 test point, expected answer) and any restriction on queries from cloud/CI/public-resolver IPs MUST be checked in the chosen provider's official docs and cited. If not verifiable, mark `unverified` in the test and docs/UNBOUND.md, and the test must skip or xfail (not fail CI) on a provider-side block (e.g. answer in 127.255.255.x or REFUSED/timeouts); it must still fail on a local malfunction. Coder proposes provider, GM/maintainer confirms; do not invent.
- Unit run stays offline and unchanged in duration.
E. arm64: either a QEMU smoke test in CI (start the arm64 container, resolve a signed name, check AD) OR arm64 clearly marked "untested" in docs/UNBOUND.md and README. Coder picks one and states it; if smoke test is chosen, a flaky/timeouts policy is documented.
F. Hardening (from M0-09 c, d, a)
- compose.yaml unbound service: `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true`, tmpfs for `/run/unbound` (and any other path found necessary), writable named volume for root.key (A2). Port 5353 needs no capability. If any capability or writable path is needed, add back only the minimum, verified at runtime and documented.
- No fixed `image:` name `deliverability-toolkit-unbound:local`: drop it or tie it to the compose project name.
- docs/UNBOUND.md: cite the dns-root-data README.Debian as read from the .deb (slim image has no /usr/share/doc) and state how it was obtained.
G. Before merge: no leftover containers, networks or volumes from the project (`docker ps -a`, `docker network ls`, `docker volume ls` filtered by the project). GM did this once on 2026-11-04; re-check and record output in the verification record.
H. Generic: `docker compose --profile unbound config -q` OK; lint and default tests green; unbound.conf subnet still matches the compose subnet; no references to port 53 left in docs/compose for the container side (host never publishes). Append a "Round 2 verification record" to this ticket. Anything unverifiable is marked `unverified` and reported to the GM.

New i18n keys (round 2): only if the RESOLVER_ADDRS parser surfaces a user-facing message; coder lists them here (en+it). Expected: none or `config.resolver_addr.invalid`.
Review: security-relevant (isolation, caps, trust anchor); opus QA required for round 2.

## M1 follow-ups (from QA)
- Round 2 optional QA nits (tracked in TODO.md under M1): (a) compose.yaml IPAM should pin `gateway: 172.28.53.1` so the `access-control 172.28.53.1/32 refuse` rule is explicitly tied; (b) host-side test probe on 127.0.0.1:5353 may false-fail on hosts with an mDNS responder (avahi).
- Attach the app service to the `dns` network and point the guarded client at 172.28.53.2.
- Add a CI runtime check of the `unbound` profile (up, healthy, AD flag, port 53 unpublished).
- Awareness: the healthcheck (`unbound-control`) only proves the process is up, not that resolution works.

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

## Round 2 verification record (2026-11-04, Docker 29.9.2, Linux/WSL2, run locally)
Branch fix/M0-07-unbound-r2. New i18n keys: `config.resolver_addr.invalid` (en + it, `locales/`).
The parser raises `ConfigError` (carries the key and the offending entry) at startup for the
operator; there is no end-user UI path, so the message is not translated at raise time.
Parser lives in new `app/core/config.py` (no config module existed); default port 53.
- `docker compose --profile unbound config -q`: OK. `uv run ruff check . && ruff format --check . && mypy app`: clean.
  `uv run pytest -q`: 59 passed, 11 deselected (integration), 0.2 s.
- `uv run pytest -m integration -q -rs`: 11 passed (~40 s), run 3 times; one run skipped the DNSBL
  test (cold-cache SERVFAIL), now retried before skipping.
- `docker compose -p dtkr2 --profile unbound up -d --build --wait`: unbound healthy; `ps` shows
  `5353/tcp, 5353/udp` without host mapping; `PortBindings` `{}`; ReadonlyRootfs true, CapDrop ALL,
  no sysctls, user unbound; no tmpfs needed.
- A2: `lastchange` of both KSKs in the volume's root.key identical after `down`/`up` (without -v);
  after `down -v` it changes (1793828196 -> 1793828205): the test discriminates.
- A1: key tag 38696 (and 20326) computed from the image's /var/lib/unbound/root.key and
  /usr/share/dns/root.key.
- A3: offline behaviour reproduced with a container on an `internal` network: `unhealthy`.
- Variant runs (read-only rootfs, volume on /var/lib/unbound): chroot, do-ip6 not needed;
  username "" avoids an initgroups warning; pidfile "" avoids a read-only error; use-syslog no
  needed for stderr logs.
- E: `scripts/unbound-arm64-smoke.sh` under QEMU: aarch64, NOERROR + AD on attempt 1 (32 s).
- DNSBL: Spamhaus ZEN proposed (docs/UNBOUND.md); real answers received locally.
- Not run here: GitHub Actions (jobs `integration-unbound`, `unbound-arm64-smoke`).
- G: after my teardown (`down -v --rmi local` of my projects) `docker ps -a` is empty. Pre-existing,
  not created by this work and left untouched: volume `deliverability-toolkit_app-data`, network
  `deliverability-toolkit_default`, images `deliverability-toolkit-unbound:local`,
  `deliverability-toolkit-app:latest`, `agent-ac664accc510354ee-app:latest`.
