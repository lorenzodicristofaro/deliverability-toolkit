# M0-09 Unbound hardening nits (from M0-07 QA)
Milestone: M0
Branch: fix/M0-09-unbound-nits
Files in scope: docs/UNBOUND.md, compose.yaml (unbound service and image name only)
Out of scope: app code, ARCHITECTURE.md and SPEC.md, docker/unbound/Dockerfile, CI workflows, anything not listed in the nits below
Depends on: M0-07
Parallel-safe: no (compose.yaml shared)
Model: sonnet

Scope (only these QA nits):
a. docs/UNBOUND.md lines ~33-34 and ~47-48: cite the dns-root-data README.Debian as read from the .deb (the slim image excludes /usr/share/doc, so it cannot be read in the container). State how it was obtained.
b. docs/UNBOUND.md lines ~55-57: narrow the unverified item. On Docker 29.9.2 the default net.ipv4.ip_unprivileged_port_start is already 0 (verified); only other runtimes (rootless Docker, Podman, Docker Desktop macOS) remain unverified.
c. compose.yaml unbound service: `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true` with tmpfs `/run/unbound` and a writable `/var/lib/unbound` (named volume or tmpfs; no bind mounts outside the project). If binding port 53 or another operation needs a capability, add back only the minimum and document it (verify, do not assume).
d. compose.yaml ~line 57: drop the fixed `image: deliverability-toolkit-unbound:local` or tie it to the project name.

Acceptance criteria:
- Profile `unbound` still starts and is Healthy (`docker compose --profile unbound up -d --build --wait`).
- From a throwaway container on the `dns` network only: `dig @172.28.53.2 +dnssec ietf.org A` returns NOERROR with the `ad` flag.
- Port 53 remains unpublished (`docker port` empty, no PortBindings).
- `docker compose --profile unbound config -q` OK; `uv run pytest -q --tb=short` and lint (ruff, ruff format --check, mypy) green.
- Verification record appended to this ticket.

New i18n keys: none
Status: superseded — folded into M0-07 rework round 2 (items a, c, d folded in; item b obsolete because the sysctl is removed)
