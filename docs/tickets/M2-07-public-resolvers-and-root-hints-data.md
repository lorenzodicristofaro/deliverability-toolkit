# M2-07 Public resolver list and root hints (data files + loader)
Milestone: M2
Branch: feature/m2-07-resolver-data
Files in scope: seeds/dns_resolvers.yaml, seeds/root_hints.yaml, app/dns/knowledge.py (loader + validation), pyproject.toml / uv.lock (ONLY if pyyaml must move to runtime dependencies), tests/dns/test_knowledge.py
Out of scope: using the data (propagation M2-10, trace M2-09), live reachability checks, any network access
Depends on: M2-02, M2-03 (address policy used to validate entries)
Parallel-safe: no (possible pyproject.toml / uv.lock change; serialize after M2-05)
Model: sonnet
Dependency note: pyyaml appears only in the dev dependency group today (check pyproject.toml). If the loader needs it at runtime, move or add it as a runtime dependency; say so in the outcome. Alternative: JSON files, but ARCHITECTURE section 2 lists seeds as YAML.
Never invent vendor configuration: every entry carries `verified_on` (ISO date) and `sources` (official URLs), or `status: unverified` with an empty/partial sources list. The coder lists candidate public resolvers (e.g. Google Public DNS, Cloudflare, Quad9, OpenDNS) ONLY from the operator's official documentation; if the documentation cannot be fetched in the session, the entry is committed as `unverified` and the GM asks the maintainer to confirm before release. No address from memory is marked verified.
Acceptance criteria:
- `seeds/dns_resolvers.yaml`: `resolvers: [{id, name, operator, addresses: [ip...], port: 53, verified_on, sources: [url...], status: verified|unverified, notes_key?}]`. `id` is a slug used by the API/UI.
- `seeds/root_hints.yaml`: the 13 root servers (a..m.root-servers.net, IPv4 + IPv6) with `source: https://www.iana.org/domains/root/files` (IANA named.root, "root hints"), `file_last_modified` as stated in that file, `verified_on`. Coder copies from the official IANA file; if not fetchable, mark `status: unverified` and flag. (Trace M2-09 needs these as its starting point; they are data, not code.)
- Loader validates the schema (reject missing `verified_on`/`sources` unless `status: unverified`, duplicate ids, non-IP addresses, addresses failing the M2-03 untrusted-target policy, empty address list) and exposes `list_public_resolvers()`, `get_resolver(id)`, `root_hints()`. Returns immutable objects. Loaded once, cached.
- A CI-style test warns (xfail-free `warnings.warn` or a dedicated test marked non-fatal) when `verified_on` is older than 12 months (ARCHITECTURE section 8 convention) and fails if `verified_on` is in the future.
- Malformed-file tests table-driven (bad YAML, wrong types, extra keys, unknown status, IPv6 in v4 field, hostnames).
New i18n keys: none (resolver display names come from the file; notes_key optional)
Status: todo
Open question for maintainer: confirm the public resolver entries against operators' official docs when marked `unverified`.
