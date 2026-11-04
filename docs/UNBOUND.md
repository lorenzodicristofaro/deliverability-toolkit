# Unbound (compose profile `unbound`)

Own image, `docker/unbound/Dockerfile`: `debian:trixie-slim` pinned by tag and digest, Debian
`unbound` package, non-root (user `unbound`), recursion from the root (no forwarders),
DNSSEC validation, qname-minimisation. Config: `docker/unbound/unbound.conf`.
Start: `docker compose --profile unbound up -d --wait`.

## Network isolation
- Compose network `dns` (`internal: true`, subnet `172.28.53.0/24`); unbound sits on it at
  `172.28.53.2` and also on the default network for outbound recursion.
- `unbound.conf` listens only on `172.28.53.2` and `127.0.0.1`; `access-control` allows only
  `172.28.53.0/24` and loopback, refuses the rest. Subnet and IP are declared in BOTH
  `compose.yaml` and `unbound.conf`; change them together.
- Port 53 is never published (no `ports:` on the service). To use it, attach a service to
  `dns` and point it at `172.28.53.2`.
- Rule for all services: no bind mounts of folders outside the project.

## Maintenance rule
1. Base image: update `FROM debian:trixie-slim@sha256:...` deliberately, not automatically.
   Get the digest with `docker buildx imagetools inspect debian:trixie-slim` (index digest),
   rebuild, run the verification below, then commit the new digest with the date.
   A new Debian release (e.g. forky) means changing the tag as well; re-verify everything here.
2. Package: `unbound` and `dns-root-data` are not version-pinned, so every no-cache build
   takes the current Debian (security) versions. `.github/workflows/rebuild.yml` rebuilds
   with `--no-cache` every Monday 04:17 UTC (cron `17 4 * * 1`) and on manual dispatch, for
   linux/amd64 and linux/arm64, without pushing. A red run means: investigate before release.
   Deployments must re-run `docker compose --profile unbound build --pull --no-cache`
   regularly (at least with each toolkit release and after Debian security advisories).
3. Trust anchor: see below; re-verify after each base/package update.
4. `ci.yml` builds the image for both architectures on every PR.

## DNSSEC trust anchor
- Package `dns-root-data` ships `/usr/share/dns/root.key` (root KSK as DNSKEY), `root.ds`,
  `root.hints`. Its `README.Debian` states the data comes from data.iana.org/root-anchors
  verified with the ICANN key.
- Package `unbound` ships `/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf` with
  `auto-trust-anchor-file: "/var/lib/unbound/root.key"`. Debian's `/usr/libexec/unbound-helper`
  (`root_trust_anchor_update`) copies `/usr/share/dns/root.key` to that path as user
  `unbound`; the Dockerfile does the same step at build time because there is no init script
  in a container. Unbound then maintains the file itself (RFC 5011).
- State is not persisted: a recreated container starts again from the image's anchor.
- Verify: `docker compose --profile unbound exec unbound unbound-checkconf` is clean and, from a
  client on `dns`, `dig @172.28.53.2 +dnssec ietf.org` returns `ad` and `dnssec-failed.org`
  returns SERVFAIL (see docs/tickets/M0-07-docker-followups.md for a recorded run).

## Sources (verified_on: 2026-11-04)
Read from the installed packages in `debian:trixie-slim` (unbound 1.26.2-0+deb13u1,
dns-root-data 2025080400~deb13u1) via `dpkg -L`, the shipped conf files, the helper script and
`README.Debian` of dns-root-data; `apt-cache policy`. Option semantics: the Unbound manual
`unbound.conf(5)`, https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html.
Not checked online from here; the options were accepted by `unbound-checkconf` and behaved as
described in a live test.

## Unverified (maintainer to confirm)
- `unverified`: Docker's default `net.ipv4.ip_unprivileged_port_start`; we set it explicitly
  via compose `sysctls`, which worked on Docker 29.9.2 (Linux/WSL2). Not tested on other
  runtimes (rootless Docker, Podman, Docker Desktop on macOS).
- `unverified`: that `root-hints: /usr/share/dns/root.hints` and `harden-*` settings are what
  the maintainer wants beyond defaults (accepted and working, but chosen by us).
- `unverified`: `unbound-control` over the unix socket as healthcheck, beyond our live test.
- `unverified`: the digest pin is the multi-arch index digest; the arm64 build was tested
  (QEMU) but the arm64 container was not run.
- The `no-cache` weekly rebuild only checks that the build works; it publishes nothing.
