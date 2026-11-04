# Unbound (compose profile `unbound`)

Own image, `docker/unbound/Dockerfile`: `debian:trixie-slim` pinned by tag and digest, Debian
`unbound` package, non-root (user `unbound`), recursion from the root (no forwarders),
DNSSEC validation, qname-minimisation. Config: `docker/unbound/unbound.conf`.
Start: `docker compose --profile unbound up -d --wait`.
Listens on **5353** (udp+tcp) inside the compose network only; never published.

## Network isolation
- Compose network `dns` (`internal: true`, subnet `172.28.53.0/24`); unbound sits on it at
  `172.28.53.2` and also on the default network for outbound recursion.
- `unbound.conf` listens only on `172.28.53.2` and `127.0.0.1` (port 5353); `access-control`
  allows only `172.28.53.0/24` and loopback, unmatched sources are refused (manual default).
  Subnet and IP are declared in BOTH `compose.yaml` and `unbound.conf`; change them together.
- No `ports:` on the service. To use it, attach a service to `dns` and point it at
  `172.28.53.2:5353` (`RESOLVER_ADDRS=172.28.53.2:5353`, see `app/core/config.py`; the parser's
  default port is 53 when none is given).
- Rule for all services: no bind mounts of folders outside the project.

## Container hardening
`compose.yaml`: `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true`,
user `unbound`. Port 5353 needs no capability and no sysctl. Verified at runtime
(2026-11-04) that **no tmpfs and no added capability are needed**: unbound with `pidfile: ""` and
logging to stderr writes nothing outside `/var/lib/unbound`, which is the named volume
`unbound-data`. (Writing `root.key` needs a writable *directory*: unbound creates a temp file
`root.key.<pid>-...` there and renames it.) The compose image has no fixed `image:` name; compose
names it `<project>-unbound`.

## DNSSEC trust anchor
- Package `dns-root-data` ships `/usr/share/dns/root.key` (root KSKs as DNSKEY), `root.ds`,
  `root.hints`. Package `unbound` ships `/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf`
  with `auto-trust-anchor-file: "/var/lib/unbound/root.key"`. Debian's `/usr/libexec/unbound-helper`
  copies `/usr/share/dns/root.key` to that path as user `unbound`; the Dockerfile does the same
  at build time (no init script in a container). Unbound then maintains the file itself
  (RFC 5011; the manual requires the file to be writable by unbound).
- **Current state (verified 2026-11-04):** since 2026-10-11 the root DNSKEY RRset is signed only
  by KSK-2024, key tag **38696**; revocation of KSK-2017 (tag 20326) is planned for 2027.
  Sources: https://www.iana.org/news/2026/root-zone-begins-using-new-ksk-2026 and
  https://www.icann.org/resources/pages/ksk-rollover .
- The image's `root.key` (dns-root-data 2025080400~deb13u1) contains both 20326 and 38696.
  Integration test `test_image_trust_anchor_has_ksk_2024` asserts 38696 is in the built image,
  computing the tag from the DNSKEY records (RFC 4034 Appendix B, `tests/dnssec_tag.py`, itself
  unit-tested offline against the real file kept in `tests/fixtures/`).
- **Persistence (RFC 5011):** `/var/lib/unbound` is the named volume `unbound-data`. On first use
  Docker copies the image's content (the seeded `root.key`, owned by `unbound`) into the empty
  volume (named-volume copy-up); this works with `read_only: true` because the volume is a
  separate mount. Later RFC 5011 updates stay in the volume across `down`/`up` (without `-v`);
  `test_root_key_survives_down_up` checks that the per-key `lastchange` state is identical after
  `down`/`up`. Consequence: a rebuilt image does NOT replace the volume's `root.key`. If the
  volume is older than the last trust-anchor rollover by more than RFC 5011 allows, unbound can
  no longer validate; recovery is `docker volume rm <project>_unbound-data` (reseeds from the
  image). `down -v` does the same.
- `README.Debian` of `dns-root-data` (the slim image has no `/usr/share/doc`): obtained with
  `apt-get download dns-root-data` in a `debian:trixie-slim` container and
  `dpkg-deb -x dns-root-data_2025080400~deb13u1_all.deb <dir>`, read from
  `usr/share/doc/dns-root-data/README.Debian`. It states: the package contains `root.hints`,
  `root.key` ("the root zone DNSSEC trust anchor(s) as DNSKEY records") and `root.ds`; the source
  data is "downloaded from https://data.iana.org/root-anchors/ and verified using an ICANN public
  key"; and "As long a resolver was initially installed when one of the trust anchors in this
  package was valid, it can securely fetch future trust anchors using the RFC 5011 mechanism."
  It also says resolvers continuously refresh the root server list, so stale hints are
  "not a major concern" (relevant to the root-hints decision below).

## Healthcheck
`drill -D -p 5353 @127.0.0.1 . SOA` piped to a check for the `ad` flag in the response header.
It asks the local server for the root SOA with DO set; AD is only set if unbound validated the
answer with its trust anchor, so the check proves recursion AND DNSSEC validation, not just a live
process. `drill` comes from the Debian package `ldnsutils` (added to the image for this; 4
packages, ~0.7 MB; the slim image has no dig/host/curl). Timing (Dockerfile and `compose.yaml`):
`interval 30s`, `timeout 10s`, `start_period 30s`, `retries 3`.

**Known risk: it depends on external resolution.** With the host offline, or egress to the root
servers blocked, the query times out and the container becomes `unhealthy` (verified: a
container on an `internal` network with no egress reported `unhealthy`, exit code 1 each time).
Time to unhealthy with the compose values: `start_period` 30 s, then 3 failed probes 30 s apart,
roughly 2 minutes. Any service with `depends_on: {unbound: {condition: service_healthy}}` will
not start (and `up --wait` fails) while that holds. The answer to `. SOA` may be served from the
cache (TTL one day) so a short outage after a healthy period is not noticed immediately; that is
accepted. Not used by the app today (M1 attaches it).

## Config audit (`docker/unbound/unbound.conf`)
Manual: https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html (fetched
2026-11-04; the `manual/unbound/unbound.conf.html` URL quoted in the ticket returned 404). Defaults
below are from that page. Options required by the ticket (`port`, `interface`, `access-control`,
`qname-minimisation`) are kept; every other option in the file is here.

| Option kept | Default | Reason |
|---|---|---|
| `username: ""` | `unbound` | Container already starts as `unbound`. Without it unbound logs `unable to initgroups unbound: Operation not permitted` (observed) on every start. |
| `pidfile: ""` | `/usr/local/etc/unbound/unbound.pid` (Debian build: `/run/unbound.pid`) | Read-only rootfs: without it unbound logs `cannot open pidfile /run/unbound.pid: Read-only file system` (observed). |
| `use-syslog: no` | `yes` | No syslog in the container; without it nothing appears in `docker logs` (observed: no output). |
| `access-control: 127.0.0.0/8 allow` | unmatched = refuse | Loopback for the healthcheck. |
| `qname-minimisation: yes` | `yes` | Required by the ticket; explicit so a future default change cannot silently weaken it. |

Removed (no concrete justification, or equal to the default):

| Option | Default | Decision |
|---|---|---|
| `chroot: ""` | manual: `/usr/local/etc/unbound`; Debian build differs (`unverified`) | Not needed: tested without it, starts fine as non-root. |
| `directory`, `logfile: ""` | build default / `""` | Defaults work. |
| `do-ip4/do-udp/do-tcp: yes` | `yes` | Equal to default. |
| `do-ip6: no` | `yes` | Removed: no observable need on the default (IPv4-only) compose network, and on a v6-enabled Docker unbound should be able to use IPv6 for recursion. |
| `access-control: 0.0.0.0/0 refuse` | unmatched sources are refused | Equal to default. |
| `hide-identity`, `hide-version` | `no` | Only allowed clients (the internal subnet) can query; no concrete threat. Removed. |
| `msg-cache-size`, `rrset-cache-size` | `4m` | No sizing data behind 16m/32m. Removed. |
| `harden-glue` | `yes` | Equal to default (trust glue only within authority). |
| `harden-dnssec-stripped` | `yes` | Equal to default (treat a trust-anchored zone as bogus if expected DNSSEC data is missing). |
| other `harden-*` (`harden-below-nxdomain` yes, `harden-short-bufsize` yes, `harden-large-queries` no, `harden-referral-path` no, `harden-algo-downgrade` no) | as listed | Not set. `harden-referral-path` is experimental with extra load; `harden-algo-downgrade` violates RFC 6840 and "may break resolution" per the manual. |
| `root-hints: /usr/share/dns/root.hints` | `""` = built-in hints | Removed. The file is a snapshot from `dns-root-data` that only changes on a rebuild; the built-in hints change with the `unbound` package, which also arrives with a rebuild, so the file adds nothing. Both are only a bootstrap: unbound primes the live root NS set. README.Debian (above) says stale hints are not a concern. `dns-root-data` stays installed for `root.key`. |
| `remote-control:` section (`control-enable`, `control-interface`) | `control-enable: no` | Removed together with the `unbound-control` healthcheck (replaced by the AD check). The Dockerfile deletes Debian's `remote-control.conf` (it enables control on root-owned `/run/unbound.ctl`). |

## Maintenance rule
1. Base image: update `FROM debian:trixie-slim@sha256:...` deliberately, not automatically.
   Get the digest with `docker buildx imagetools inspect debian:trixie-slim` (index digest),
   rebuild, run the verification below, then commit the new digest with the date.
   A new Debian release (e.g. forky) means changing the tag as well; re-verify everything here.
2. Packages: `unbound`, `dns-root-data`, `ldnsutils` are not version-pinned, so every no-cache
   build takes the current Debian (security) versions. `.github/workflows/rebuild.yml` rebuilds
   with `--no-cache` every Monday 04:17 UTC (cron `17 4 * * 1`) and on manual dispatch, for
   linux/amd64 and linux/arm64, without pushing. A red run means: investigate before release.
   Deployments must re-run `docker compose --profile unbound build --pull --no-cache`
   regularly (at least with each toolkit release and after Debian security advisories).
3. Trust anchor: re-verify after each base/package update (`uv run pytest -m integration`
   checks key tag 38696 in the built image). When ICANN revokes KSK-2017 (planned 2027) check the
   two sources above again.
4. `ci.yml` builds the image for both architectures on every PR.

## Tests
- Unit (default `uv run pytest -q`, offline): `tests/test_config.py` (RESOLVER_ADDRS parser),
  `tests/test_dnssec_tag.py` (key-tag algorithm and root.key parser).
- Integration (marker `integration`, excluded by default via `addopts` in `pyproject.toml`):
  `uv run pytest -m integration -q -rs`; needs Docker and outbound DNS. CI job:
  **`integration-unbound`** in `.github/workflows/ci.yml`. Brings up a throwaway compose project
  (unique name; `down -v --rmi local` afterwards) and checks: KSK-2024 in the image; AD on a
  signed name; SERVFAIL on `dnssec-failed.org`, NOERROR with CD set (proves it is validation);
  NXDOMAIN (`<random>.invalid`, answered by the signed root); REFUSED from outside the allowed
  subnet; DNSBL test entry; nothing published on the host (inspect `PortBindings`, host TCP
  connect to `172.28.53.2:53/5353` and `127.0.0.1:5353` fails); read-only rootfs, `cap_drop ALL`,
  no-new-privileges, no sysctls; healthy; root.key persistence across `down`/`up`.
- REFUSED method: the shipped config only listens on `172.28.53.2`/`127.0.0.1`, so a client
  elsewhere would just time out. The test starts a probe from the same image with the shipped
  `unbound.conf` where only the `interface:` lines are replaced by `0.0.0.0`, on the compose
  default network (outside `172.28.53.0/24`), and queries it from a throwaway container on that
  network. The ACL lines under test are the shipped ones.
- **DNSBL provider: Spamhaus ZEN** (`zen.spamhaus.org`), test entry `2.0.0.127.zen.spamhaus.org`
  (the reversed test target 127.0.0.2, "listed in a Spamhaus zone"); `1.0.0.127.zen...` (127.0.0.1)
  is the documented "not listed" target and must be NXDOMAIN. Expected answers are within the
  documented ZEN codes (127.0.0.2/3/4/9/10/11/30). Sources (read 2026-11-04):
  https://www.spamhaus.org/faq/section/DNSBL%20Usage (test targets; `127.255.255.254` = "Query via
  public/open resolver", `127.255.255.255` = "Excessive number of queries"; free use only for
  non-commercial, low-volume use, not from a public resolver; "use your own DNS servers") and
  https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html
  (ZEN codes). Our resolver is a private recursive one, which is what Spamhaus asks for.
  `unverified`: that GitHub-hosted runner IPs are answered normally (cloud ranges may be
  treated as high volume/public); and that the toolkit's use counts as "non-commercial". Behaviour
  in the test: local resolution is asserted first (fails if broken); then a `127.255.255.x`
  answer, SERVFAIL or timeout skips with a reason (provider-side), while a wrong answer for the
  test entry fails. Maintainer to confirm the provider choice.
- A local run on 2026-11-04 (residential network) got real ZEN answers (127.0.0.2, .4, .10).

## arm64
Tested with a QEMU smoke test: `scripts/unbound-arm64-smoke.sh`, CI job
**`unbound-arm64-smoke`** (`docker/setup-qemu-action`, buildx `--platform linux/arm64 --load`):
builds, starts the arm64 container with the static address `172.28.53.2` on a throwaway network,
checks `uname -m` is `aarch64`, resolves `ietf.org` with DO and requires NOERROR + AD. Flaky /
timeout policy: QEMU is slow, so the query is retried 12 times, 10 s apart (tunable with
`ATTEMPTS`/`DELAY`); failure only if it never validates, and the container log tail is printed.
Passed locally on 2026-11-04 (attempt 1). The job runs on every PR; if it proves flaky, first
raise `ATTEMPTS`; do not make it non-blocking without maintainer approval.

## Sources (verified_on: 2026-11-04)
- Read from the installed packages in `debian:trixie-slim` (unbound 1.26.2-0+deb13u1,
  dns-root-data 2025080400~deb13u1, ldnsutils 1.8.4-2+b1): shipped conf files, the helper script,
  `README.Debian` (see above), `apt-cache`.
- Unbound manual: https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html
- IANA and ICANN pages in the trust anchor section; Spamhaus pages in Tests.
- RFC 4034 Appendix B (key tag), RFC 5011 (trust anchor updates).

## Unverified (maintainer to confirm)
- Debian's built-in default for `chroot` (the manual says `/usr/local/etc/unbound`, the Debian
  package evidently differs; tested to work without the option).
- Behaviour on other runtimes (rootless Docker, Podman, Docker Desktop on macOS): named-volume
  copy-up with `read_only`, `cap_drop ALL`. Tested on Docker 29.9.2 (Linux/WSL2) only.
- Spamhaus: runner IP treatment and the non-commercial condition (see Tests).
- The digest pin is the multi-arch index digest.
- The weekly `no-cache` rebuild only checks that the build works; it publishes nothing.
- GitHub Actions jobs (`integration-unbound`, `unbound-arm64-smoke`) were not run here; the same
  commands passed locally.
