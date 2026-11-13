# M7-14b Secret encryption service
Milestone: M7
Branch: feature/m7-14b-secrets-crypto
Files in scope: app/core/secrets_crypto.py, app/core/config.py (ENCRYPTION_KEY validation only, if needed), pyproject.toml/uv.lock (`cryptography`, if not already a dependency), ARCHITECTURE.md (section 9 secrets paragraph), docs/SETUP.md (ENCRYPTION_KEY note and rotation procedure), tests/core/test_secrets_crypto.py
Out of scope: any model or caller (M7-15), UI
Depends on: none
Parallel-safe: yes with tickets that do not touch app/core/config.py or ARCHITECTURE.md (not M7-01, M7-09, M7-14, M7-16)
Model: opus
Acceptance criteria:
- `encrypt(plaintext: str) -> str` and `decrypt(token: str) -> str` using Fernet from `cryptography` (check its current docs), key(s) from ENCRYPTION_KEY via MultiFernet: first key encrypts, all keys decrypt, so rotation = prepend a new key; `rotate(token)` re-encrypts under the primary key.
- Invalid or missing key at startup/first use -> typed `SecretsConfigError`; wrong key, tampered or malformed token -> typed `SecretDecryptError` (no plaintext, no key material, no token in the message or logs).
- Plaintext never logged or put in exception text or repr; test with captured logs.
- ARCHITECTURE section 9 records the choice (Fernet, MultiFernet rotation) and the rotation procedure; docs/SETUP.md explains generating a key, comma-separated multi-key syntax as implemented, rotation steps and that losing the key loses stored secrets.
- Tests table-driven, no network: round trip, unicode, empty string, rotation old->new, removed old key fails typed, tamper, garbage, bad key format, multi-key.
New i18n keys: none
Status: todo
