# M1-03 Structured JSON logging
Milestone: M1
Branch: feature/m1-03-structured-logging
Files in scope: app/core/logging.py, app/main.py (one call to configure logging), tests/test_logging.py
Out of scope: Prometheus /metrics, /readyz, audit log, per-check metrics
Depends on: M1-01
Parallel-safe: no (app/main.py)
Model: sonnet
Acceptance criteria:
- stdlib logging configured to emit one JSON object per line (timestamp, level, logger, message, request_id when present) at `Settings.LOG_LEVEL`; no new dependency.
- Middleware assigns a request id (generated; an incoming header is not trusted unless it matches a strict charset/length) and logs method, path, status, duration. Query strings are not logged.
- Redaction test: values of SECRET_KEY/ENCRYPTION_KEY, `Authorization`, `Cookie` and `password` fields never reach log output.
- uvicorn access/error loggers routed through the same formatter.
- Tests capture logs; no network.
New i18n keys: none (logs are for operators, not translated)
Status: todo
