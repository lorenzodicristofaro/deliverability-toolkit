# syntax=docker/dockerfile:1
# Local validating, recursive resolver for the toolkit (compose profile "unbound").
# Maintenance rule: docs/UNBOUND.md.

# Base pinned by tag AND digest (index digest of the multi-arch manifest, so amd64 and arm64
# both resolve from it). Verified 2026-11-04 with `docker buildx imagetools inspect`.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# unbound: the resolver (Debian package, /usr/sbin/unbound, /usr/sbin/unbound-control).
# dns-root-data: /usr/share/dns/root.key (trust anchor) and root.hints. It is only a
# "Recommends" of unbound, so it is installed explicitly.
# ldnsutils: `drill`, used only by the HEALTHCHECK (no dig/host/curl in the slim image;
# 4 packages, ~0.7 MB). unbound-control is not used (remote control is off, see unbound.conf).
# Package versions are deliberately not pinned: Debian security updates arrive via rebuild.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unbound dns-root-data ldnsutils \
    && rm -rf /var/lib/apt/lists/* \
    # Drop Debian's remote-control snippet (enables control on /run/unbound.ctl, a root-owned
    # path; unbound's own default is control-enable: no). Keep root-auto-trust-anchor-file.conf.
    && rm /etc/unbound/unbound.conf.d/remote-control.conf \
    # Seed the writable trust anchor exactly like Debian's /usr/libexec/unbound-helper
    # (root_trust_anchor_update): copy /usr/share/dns/root.key to /var/lib/unbound/root.key,
    # as user unbound. Unbound maintains the file itself afterwards (RFC 5011). In compose,
    # /var/lib/unbound is a named volume: Docker copies this seeded content (with ownership)
    # into the empty volume on first use, and later updates then persist (docs/UNBOUND.md).
    && setpriv --reuid=unbound --regid=unbound --clear-groups \
        cp /usr/share/dns/root.key /var/lib/unbound/root.key

COPY unbound.conf /etc/unbound/unbound.conf.d/toolkit.conf
RUN unbound-checkconf

# Non-root; listens on unprivileged port 5353 (no capability, no sysctl needed).
USER unbound
EXPOSE 5353/udp 5353/tcp

# Asks the local server for the root SOA with DO set and requires the AD flag, i.e. proves
# recursion AND DNSSEC validation. Needs egress to the root servers: offline => unhealthy.
# Rationale and timing: docs/UNBOUND.md.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["sh", "-c", "drill -D -p 5353 @127.0.0.1 . SOA | grep -Eq '^;; flags:.* ad[ ;]'"]

CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
