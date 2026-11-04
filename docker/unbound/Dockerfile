# syntax=docker/dockerfile:1
# Local validating, recursive resolver for the toolkit (compose profile "unbound").
# Maintenance rule: docs/UNBOUND.md.

# Base pinned by tag AND digest (index digest of the multi-arch manifest, so amd64 and arm64
# both resolve from it). Verified 2026-11-04 with `docker buildx imagetools inspect`.
FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# unbound: the resolver (Debian package, /usr/sbin/unbound, /usr/sbin/unbound-control).
# dns-root-data: /usr/share/dns/root.key (trust anchor) and root.hints. It is only a
# "Recommends" of unbound, so it is installed explicitly.
# Package versions are deliberately not pinned: Debian security updates arrive via rebuild.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unbound dns-root-data \
    && rm -rf /var/lib/apt/lists/* \
    # Drop Debian's remote-control snippet (unix socket under root-owned /run); our own
    # config declares the control socket. Keep root-auto-trust-anchor-file.conf.
    && rm /etc/unbound/unbound.conf.d/remote-control.conf \
    # Seed the writable trust anchor exactly like Debian's /usr/libexec/unbound-helper
    # (root_trust_anchor_update): copy /usr/share/dns/root.key to /var/lib/unbound/root.key,
    # as user unbound. Unbound maintains the file itself afterwards (RFC 5011).
    && setpriv --reuid=unbound --regid=unbound --clear-groups \
        cp /usr/share/dns/root.key /var/lib/unbound/root.key \
    && install -d -o unbound -g unbound -m 0750 /run/unbound

COPY unbound.conf /etc/unbound/unbound.conf.d/toolkit.conf
RUN unbound-checkconf

# Non-root. Port 53 needs net.ipv4.ip_unprivileged_port_start=0, set in compose.yaml.
USER unbound
EXPOSE 53/udp 53/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["unbound-control", "-s", "/run/unbound/control.sock", "status"]

CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
