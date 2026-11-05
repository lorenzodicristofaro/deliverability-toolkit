# M2-03 DNS egress policy (what the DNS engine may contact in M2)
Milestone: M2
Branch: feature/m2-03-dns-egress-policy
Files in scope: app/dns/egress.py, app/core/config.py (resolver address validation only), tests/dns/test_egress.py, tests/core/test_config.py (extend; check actual test file name)
Out of scope: the guarded HTTP/SMTP client and general SSRF client (M7), the DNS query code (M2-05), DoH, UI
Depends on: M2-02 (package exists)
Parallel-safe: no (app/core/config.py is shared; runs before M2-05)
Model: opus (anti-SSRF / egress constraint)
Context: CLAUDE.md says all outbound access goes through the guarded client, but that client is M7. ARCHITECTURE section 9 defines it as: resolve first, reject loopback/private/link-local/CGNAT/cloud-metadata ranges, pin the IP. ARCHITECTURE does NOT say how DNS egress is constrained before M7, nor whether the DNS tool may query a user-supplied resolver. This ticket implements the proposed rule below, which is an OPEN QUESTION for the maintainer until confirmed; the ticket must not proceed to merge without the GM relaying the answer, and ARCHITECTURE section 7 needs a line (maintainer/GM edits it, not the coder).
Proposed M2 rule (to be confirmed):
1. Two address classes. TRUSTED (operator-configured): RESOLVER_ADDRS in settings (any address, incl. private/Docker such as 172.28.53.2:5353) and, in `system` mode, the nameservers read from the container's resolv.conf (cannot be policy-checked; documented). UNTRUSTED (anything derived from request input or from DNS data: tool-selected resolver, public-resolver list entries, trace referral/glue/NS addresses): must be globally routable unicast.
2. The DNS engine only ever sends packets to TRUSTED addresses or to UNTRUSTED addresses that passed `is_allowed_untrusted_target`. No hostnames: resolver targets are IP literals (already how RESOLVER_ADDRS is parsed).
3. M2 does NOT accept a free-form resolver IP typed by a user; resolver selection in the tool is by id from the configured set plus the public-resolver data file (M2-07). Free-form input is deferred to M7. (OPEN QUESTION: confirm, or allow free-form public IPs validated by this same function.)
Acceptance criteria:
- `is_allowed_untrusted_target(ip)` rejects: loopback, private (RFC 1918, ULA fc00::/7), link-local (169.254/16 incl. cloud metadata 169.254.169.254, fe80::/10), CGNAT 100.64/10, unspecified, multicast, reserved/benchmarking/documentation ranges, IPv4-mapped/6to4/NAT64/Teredo forms that embed a blocked IPv4, and port 0 / privileged-service ports other than 53 for UNTRUSTED targets (port must be 53 unless the data file says otherwise; decide and test). Use stdlib `ipaddress` plus an explicit named list of networks with a comment citing the registry (IANA special-purpose registries; coder must not invent ranges: mark any range taken from memory `unverified` in a comment and tell the GM).
- `TargetPolicy` object: `check(addr: ResolverAddr, trusted: bool) -> None | BlockReason`; a blocked target maps to `ResultState.blocked` in callers (never to "missing").
- Settings: `resolver_mode=system|custom|unbound` unchanged; add startup validation that `custom` addresses are parsed (already) and logged at INFO with the mode; no new env vars unless needed. If the coder adds one (e.g. a cap on trace depth) it must be documented in ARCHITECTURE section 11 by the GM, not here.
- Tests (table-driven, no network): every range above both v4 and v6 incl. mapped forms, malformed input (empty, hostnames, `1.2.3.4:99999`, `[::1`), trusted private address allowed, same address as untrusted blocked.
- No import of dnspython or sockets in this module (pure functions).
New i18n keys: none (reason codes only; UI keys in M2-13)
Status: todo
Open question for maintainer: see Context (system-mode egress is not policy-checkable; free-form resolver input deferred to M7).

GM decision 2026-11-05: proposed rule CONFIRMED (both open questions): free-form resolver input deferred to M7; UNTRUSTED targets must use port 53. Recorded in ARCHITECTURE section 7. Ticket may merge on QA APPROVE.
