# R1-14 Purge expired and revoked session rows
Milestone: R1
Branch: feature/r1-14-session-purge
Findings: AUTH-09 (low)
Files in scope: app/services/auth.py (purge function), app/main.py (startup hook), tests/services/test_auth_sessions.py (or the existing auth service test file; coder states which)
Out of scope: scheduler (M7 will call the function later), migrations, `last_seen_at` throttling (TODO), session lifetime settings
Depends on: none
Parallel-safe: yes (app/main.py is shared with few tickets; check at merge)
Model: opus (authentication code)
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected: a test that creates, revokes and expires sessions and asserts the rows are removed by a purge function that does not exist yet.)
- A purge function in app/services/auth.py deletes rows past `expires_at` and rows revoked for longer than a short grace period (named constant), and keeps live sessions and recently revoked ones. The delete stays in the service (sessions are user-owned, queried there by design); no other module deletes sessions.
- It runs once at startup (failure is logged and does not stop startup, same style as the seed sync) and is callable by a future scheduler. No new setting unless needed.
- Tests, table-driven: purge removes expired and old revoked rows, keeps live and recently revoked rows; a live session still resolves after a purge; a purge with zero rows is a no-op; time is injected (no wall-clock sleeping).
- Works on SQLite and PostgreSQL (run PostgreSQL params if local PG is up).
- ruff, mypy, relevant tests green.
New i18n keys: none
Status: todo

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `app/services/auth.py:166-195` (`create_session`), `:230-268` (revocation only sets `revoked_at`), `app/models/session.py:18-34`, `app/web/auth.py:118-138,203-229` (a row per login and per tenant switch).
- Problem: every login and every tenant switch inserts a `sessions` row; logout, rotation and expiry never delete one. The table and its unique `token_hash` index grow without bound, and every authenticated request looks a row up in it. No purge at startup, no scheduled job, no CLI command.
- Evidence: no `delete(UserSession)` or `DELETE FROM sessions` anywhere in `app/` (only writes are the insert in `create_session` and the two `update(UserSession)` in `revoke_session` / `revoke_all_sessions`).
- Suggested fix: delete rows past `expires_at` or revoked for longer than a short grace period; run at startup now and from the scheduler when M7 adds one. Keep the delete in `app/services/auth.py`. Files: `app/services/auth.py`, `app/main.py`, later the scheduler.
- Tests to add: purge removes expired and old revoked rows and keeps live ones; a live session still resolves after a purge.
- Confidence: high.
- Related TODO: "Throttle the `last_seen_at` write in resolve_session" is a different item.
