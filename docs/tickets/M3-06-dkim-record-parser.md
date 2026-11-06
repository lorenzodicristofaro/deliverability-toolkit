# M3-06 DKIM key record parser
Milestone: M3
Branch: feature/m3-06-dkim-parser
Files in scope: app/parsers/dkim.py, tests/parsers/test_dkim.py (plus pyproject.toml/uv.lock ONLY if a dependency is truly needed, see below)
Out of scope: DNS, selector probing, findings (M3-13)
Depends on: M3-04 (tests/parsers package init)
Parallel-safe: yes with M3-05 (pyproject only if dependency added: then no)
Model: opus (parses DNS-sourced text and key material)
Acceptance criteria:
- `parse_dkim_key(text) -> DkimKey` never raising: tags `v` (DKIM1, optional), `k` (rsa|ed25519, default rsa), `p` (base64, whitespace tolerated inside), `t` (flags `y`, `s`), `h`, `s`, `n`; unknown tags kept; issues list as in M3-04.
- `p=` empty -> `revoked=True` (not a syntax error). Missing `p` -> issue.
- Key length: RSA modulus bits derived from the SubjectPublicKeyInfo DER (also accept the bare RSAPublicKey form); ed25519 recognised by 32-byte key. Prefer a small hand-written bounded DER reader; add `cryptography` only if the coder shows it is needed, and say so in the report (pyproject is then touched, serialize).
- Bad base64, truncated DER, absurd lengths, `k=` and key mismatch, key length unknown -> issues, `bits=None`.
- Input bounded (record up to 4096 chars, DER up to 2048 bytes).
- Table-driven tests with real-shaped 1024/2048/4096-bit RSA keys generated in the test (no real customer keys), ed25519, revoked, test mode `t=y`, and at least 25 malformed inputs.
New i18n keys: none
Status: todo
