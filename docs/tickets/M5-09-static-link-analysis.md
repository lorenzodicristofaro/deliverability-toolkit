# M5-09 Static link analysis (no network)
Milestone: M5
Branch: feature/m5-09-link-analysis
Files in scope: app/parsers/content_links.py, seeds/url_shorteners.yaml, the knowledge loader entry for it (follow the dkim_selectors seed loader pattern; coder names the file), tests/parsers/test_content_links.py, tests/knowledge test for the new seed
Out of scope: fetching or resolving any URL, redirect following, reputation lookups (all would need the guarded client, M7), findings/i18n (M5-14).
Depends on: M5-08
Parallel-safe: yes (new parser + new seed file; disjoint from M5-10, M5-11)
Model: sonnet
Decision (GM): link analysis is purely static. No DNS, no HTTP. A test monkeypatches sockets and the DNS backend to fail on any call.
Acceptance criteria:
- `analyze_links(anchors, *, sender_domains, shorteners) -> LinkAnalysis`: per link: scheme, registrable host via the existing public-suffix code (IDNA, punycode/homograph flag where visible text host differs), masked link (visible text looks like a URL/host different from href host), URL shortener (seed match), IP-literal host, non-https, userinfo in URL (`user@host` trick), `javascript:`/`data:` schemes, `mailto:`/`tel:` ignored for domain checks, domain alignment with the sender domain(s) (organizational-domain comparison), tracking-domain consistency (count distinct non-sender link domains; report the dominant one and outliers).
- Sender domains come from the caller (From domain, optional DKIM d=, optional tenant domain); no sender given -> alignment fields are `None` (not "ok").
- Seed `seeds/url_shorteners.yaml` follows the knowledge format with `verified_on`, `sources`. Only include shorteners the coder can source from an official page; anything else is `status: unverified` and the PR summary asks the maintainer to confirm. No invented lists.
- Caps on link count and URL length enforced; over cap -> `capped=True`.
- Table-driven tests incl. malformed URLs, whitespace/control chars in href, uppercase schemes, IDN, IPv6 literal, very long URL, relative URLs, empty href.
New i18n keys: none
Status: todo
