# M1-05 Integration test: host probe on 127.0.0.1:5353 false-fails with mDNS responder
Milestone: M1
Branch: feature/m1-05-probe-mdns-fix
Files in scope: tests/integration/test_unbound.py, tests/integration/stack.py, docs/UNBOUND.md (testing note only)
Out of scope: compose.yaml, docker/unbound/, CI workflow
Depends on: none
Parallel-safe: yes (tests/integration only)
Model: sonnet
Acceptance criteria:
- Carry-over nit (b): the "port not reachable from host" probe (test_unbound.py, loop over `(UNBOUND_IP, 5353), (UNBOUND_IP, 53), ("127.0.0.1", 5353)`) no longer fails when the host runs avahi/mDNS on 5353. Proposed approach: assert the host listener is not our container by checking that port 5353 is not published (`docker port` / inspect already used) and send a DNS query for a known name to 127.0.0.1:5353 that must not return a resolved answer with RA/AD from Unbound; an mDNS responder's non-answer or refusal is tolerated. If no reliable discriminator exists, skip that single probe with a reason when a listener on 127.0.0.1:5353 exists before the stack starts.
- A unit-level test (no docker) of the discriminator helper with table-driven cases: timeout, REFUSED, garbage bytes, valid answer with AD.
- Existing integration tests unchanged otherwise; `uv run pytest -m integration` still passes on a clean host.
- Not verifiable here without an avahi host: the coder states how it was simulated (e.g. a local UDP listener on 5353).
New i18n keys: none
Status: done (merged into dev, QA APPROVE, 156 unit + 11 integration; avahi simulated with a silent UDP listener on 127.0.0.1:5353, a replying avahi not tested; unit test in tests/ by GM-accepted deviation)
