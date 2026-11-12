# R1-19 resolve(): an empty reply without the RA flag is an error, not nodata
Milestone: R1
Branch: feature/r1-19-resolve-no-ra
Findings: DNS-07 (low; confidence low, reproduce first is essential)
Files in scope: app/dns/backends.py (`resolve` recursive path only), tests/dns/test_backends.py, docs/DNS.md
Out of scope: `query_server` (iterative/trace path: no RA expected), egress policy, retry logic, other states
Depends on: none (functional); run after R1-07 because of shared files
Parallel-safe: no (app/dns/backends.py, tests/dns/test_backends.py, docs/DNS.md shared with R1-07)
Model: sonnet (small mapping change in the resolver, not the egress policy)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. Reachability against real deployments is not established: if the supported setups cannot be shown to always set RA, say so in the summary instead of guessing.
- Before the change, check that the supported setups (the Unbound profile, Docker's embedded DNS in `system` mode) always set RA in the repo's own docs/config (docs/UNBOUND.md, unbound.conf, compose.yaml). Do not claim anything about third-party resolvers. If a supported setup might not set RA, STOP and report to the GM before changing behaviour.
- In `resolve()` (recursive path only), a NOERROR or NXDOMAIN reply without RA maps to `error` with a detail code such as `recursion_unavailable`; RA set -> behaviour unchanged. The code is rendered through existing error i18n paths (check if a new label is needed and report).
- Wire-level rows: RA clear + empty NOERROR; RA clear + NXDOMAIN; RA set + NOERROR with data; RA set + empty NOERROR (still `nodata`); RA clear with answer data (state the chosen rule and test it).
- Cache does not store the `error` result as `nodata`. No network. ruff, mypy, relevant tests green. docs/DNS.md updated.
New i18n keys: only if the new detail code is user-visible: en + it, names stated by the coder
Status: parked (maintainer decision)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/dns/backends.py:317-335` (`interpret_response`: NOERROR, no answer, no referral -> `nodata`), `app/dns/backends.py:638-672` (`resolve` never looks at RA).
- Problem: `resolve()` is documented as "for recursive servers only" and turns a referral into `error` (`unexpected_referral`), but a configured server that does not recurse and answers NOERROR with empty answer and authority sections (no RA) is taken as definitive `nodata`. Every check then reports "missing" (`SPF_MISSING`, `DMARC_MISSING`, selector `not_found`) and the cache stores it for 60 s. Whether a real deployment hits this depends on the operator's resolver; most non-recursive servers answer REFUSED or a referral, which are handled.
- Evidence: `interpret_response` on `dns.message.make_response(query)` (NOERROR, RA clear, all sections empty) returns `state=nodata` (reproduced).
- Suggested fix: in `resolve()` (recursive path only, not `query_server`), map a NOERROR/NXDOMAIN reply without RA to `error` with a detail code such as `recursion_unavailable`. Check first that the supported setups always set RA.
- Tests to add: wire-level cases for RA clear with empty NOERROR, RA clear with NXDOMAIN, RA set (unchanged).
- Confidence: low (real-world reachability not established).

## Outcome (GM, 2026-11-12)
Parked, no fix. Code path reproduced (scratch script, no network): a NOERROR reply with RA clear and empty sections gives `nodata`; `resolve()` never reads RA. Not established: whether any supported setup (Unbound profile, `system` mode incl. Docker embedded DNS, custom resolvers) ever returns such a reply. A fix would also need most DNS fixtures (which build replies without RA) to change. Maintainer to choose: (a) precautionary rule — empty NOERROR/NXDOMAIN without RA from a recursive resolver becomes error-class, answers with data trusted; or (b) drop the finding.
