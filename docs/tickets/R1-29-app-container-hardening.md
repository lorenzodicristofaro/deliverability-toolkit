# R1-29 Harden the app container (cap_drop, no-new-privileges, init, read_only if workable)
Milestone: R1
Branch: feature/r1-29-app-container-hardening
Findings: INFRA-07 (low); related TODO: "safe_regex (M5-13 QA): a worker is orphaned if the parent is SIGKILLed" (`init: true` is an addition to it, does not close it)
Files in scope: compose.yaml (app service), tests/test_compose_config.py, install docs (docs/SETUP.md; coder states which)
Out of scope: forwarding env settings (R1-04), postgres profile (R1-25), trusted-proxy/TLS support (TODO.md:318), the safe_regex RLIMIT/PDEATHSIG item
Depends on: R1-04 (same file; serialize)
Parallel-safe: no with R1-04, R1-25, R1-26 (compose.yaml)
Model: sonnet
Acceptance criteria:
- Reproduce first: before changing app code, add a test that reproduces the finding and fails on dev 06869fb. If it cannot be reproduced, stop without a fix and report "not reproduced" with what was tried. (Expected: static assertions in tests/test_compose_config.py for the three keys on the `app` service.)
- App service gets `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]` and `init: true`.
- `read_only: true` with a `tmpfs` for `/tmp` is tried; keep it only if the compose smoke and an upload/analysis path still work. Docker cannot be run by every coder: if it cannot be verified locally, do NOT enable `read_only` blindly; leave it out and say so (the CI compose smoke on dev is the proof for the other three keys).
- Install docs state that port 8000 is plain HTTP and should sit behind a TLS proxy, and show the `127.0.0.1:8000:8000` form for that case (describe it as an option; do not claim proxy header behaviour, the trusted-proxy setting is TODO.md:318).
- Static test pins the three keys; existing compose tests green. ruff, mypy, relevant tests green.
New i18n keys: none
Status: done (QA APPROVE, merged 77a7e34, branch 3d74abf; read_only left out, unverified without Docker; runtime proof is the CI compose smoke)

## Review details (copied from the code review of 2026-11-12, dev 06869fb)
- Location: `compose.yaml:10-37` (app) compared with `compose.yaml:70-72` (unbound: `cap_drop: [ALL]`, `no-new-privileges`, `read_only`), `compose.yaml:12-13` (`"8000:8000"`).
- Problem: the app is the component that parses untrusted `.eml`, MIME and HTML and runs regex worker subprocesses, yet it keeps Docker's default capabilities, allows privilege gain, and has a writable root filesystem. It has no `init`, so uvicorn is PID 1 and orphaned regex workers are not reaped by an init process. The port is published on every host interface over plain HTTP; together with AUTH-03 a default install serves the login and setup wizard to the whole LAN without TLS.
- Evidence: the `app` service block contains no `cap_drop`, `security_opt`, `read_only` or `init` key.
- Suggested fix: add `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]` and `init: true`. Try `read_only: true` with a `tmpfs` for `/tmp` and keep it only if the compose smoke and an upload test pass. State in the install docs that port 8000 is plain HTTP and should sit behind a TLS proxy, and show the `127.0.0.1:8000:8000` form.
- Tests to add: static assertions in `tests/test_compose_config.py` for the three keys; the existing CI compose smoke proves the app still starts.
- Confidence: high for the missing keys; medium for `read_only` being workable (not tried).
