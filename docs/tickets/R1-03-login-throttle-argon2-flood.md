# R1-03 Login throttle: per-IP limit, bounded argon2 concurrency, no reset by eviction
Milestone: R1
Branch: feature/r1-03-login-throttle-argon2-flood
Findings: AUTH-02 (medium); also TODO.md:317 "Per-IP cap on throttle keys, plus a warning log when the table is full" (same file, same concern: ticked when this ticket is done)
Files in scope: app/services/login_throttle.py, app/web/auth.py, app/web/setup.py (shares the throttle), app/core/config.py (only if new limits are settings), .env.example (only for new settings), tests/web/test_login_throttle.py, tests/services/ (new throttle tests), locales/en.json + locales/it.json only if the 429 page gets new text
Out of scope: trusted-proxy setting (AUTH-04, tracked at TODO.md:318, maintainer/later), DB-backed throttle for multi-process (TODO:316), argon2 parameters, password policy
Depends on: none (AUTH-04 changes what "per IP" means; use the peer address as today and note it)
Parallel-safe: yes with R1-02 (disjoint files); serialize with R1-15 only if both touch locales
Model: opus (authentication, throttle design)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried.
- A second, account-independent limit per client IP (attempts per window) is checked BEFORE any password work; over the limit gets the same 429 page as today.
- A process-wide semaphore bounds concurrent argon2 verifications (including `dummy_verify` for unknown accounts); requests over the bound get the same 429 page. Bound and window are named constants (or settings with defaults and `.env.example` lines).
- Evictions are counted against the IP: a flood of new keys from one IP cannot reset the failure counter of its own keys below the limit. Add a warning log when the table is full (no email or IP-identifying value beyond what logging already allows; no account string logged).
- Tests: 200 requests from one IP with 200 different account strings are throttled after N; no more than K verifications run at once (hasher spy with a barrier or counter, no wall clock); a key with four failures is not reset by a flood of new keys from the same IP; the setup-token path shares the new limit; existing throttle tests unchanged and green.
- Existing 429 body stays localized (en + it); no input echoed.
- Tests table-driven, no network, no wall-clock assertions. ruff, mypy, relevant tests green. Tick TODO.md:317 is the PM's job after merge.
New i18n keys: none expected (reuse the 429 page text). If added: en + it.
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/web/auth.py:141-167` (throttle key, then `_login` in the threadpool), `app/services/login_throttle.py:74-80` (key = IP + account), `app/services/login_throttle.py:185-198` (`_make_room` evicts the oldest free key), `app/core/security.py:34,90-97` (library defaults: 64 MiB, 4 lanes; `dummy_verify` for unknown accounts).
- Problem: the throttle is keyed by (IP, account), so a client that sends a different account string on every request never meets a delay: each request has a fresh key with five free attempts. Every such request still runs one full argon2id verification (the dummy one) in the shared threadpool. No per-IP limit, no bound on concurrent verifications: one anonymous client can keep all worker threads busy at 64 MiB each (about 2.5 GiB with the default 40 threads) and starve every sync dependency and route. Also, a flood of new keys evicts free-tier keys of the same IP, which resets a real brute-force counter below five failures.
- Evidence: `login()` calls `throttle.acquire(ip, email)` with the raw form value; `throttle_key("1.2.3.4", "a1@x")` and `throttle_key("1.2.3.4", "a2@x")` differ, both return wait 0, both reach `authenticate` -> `dummy_verify`. In `_make_room` a full table drops `next(iter(free))` first, so 10,000 new keys remove an attacker's own key with four failures on the target account and its count restarts at zero.
- Suggested fix: second account-independent limit per client IP checked before the password work, plus a process-wide semaphore bounding concurrent argon2 verifications (over the bound: same 429 page). Count evictions against the IP so a flood cannot reset its own counters. Files: `app/services/login_throttle.py`, `app/web/auth.py`, `app/web/setup.py`.
- Tests to add: the three tests above.
- Confidence: medium (logic verified by reading; memory and thread exhaustion not load-tested).
- Already tracked: partly. TODO:317 (per-IP cap on throttle keys plus warning log: folded in here) and TODO:316 (DB-backed throttle, not here). New: the argon2 concurrency and memory exhaustion, and the counter reset through eviction.
