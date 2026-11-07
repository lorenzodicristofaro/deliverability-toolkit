# M4-02 MIME structure and size breakdown parser
Milestone: M4
Branch: feature/m4-02-mime-parser
Files in scope: app/parsers/mime.py, tests/parsers/test_mime.py
Out of scope: header block splitting (M4-01, imported), findings, API/UI/CLI, DNS, network, DB.
Depends on: M4-01
Parallel-safe: yes (new files; imports M4-01 only after it is merged, so schedule after it)
Model: opus
Acceptance criteria:
- Pure offline, bytes in, frozen `MimeSummary` out: tree of parts (content-type, charset, disposition, filename presence only, transfer-encoding, encoded size, estimated decoded size, depth) plus totals (headers bytes, body bytes, per-part bytes, text vs html vs attachment vs inline-image bytes).
- Caps with boundary tests: MAX_MIME_DEPTH (10), MAX_MIME_PARTS (200), MAX_BOUNDARY_LEN (70, RFC 2046). Over cap: stop descending, mark `truncated=True` with a warning code; never raise on hostile structure, never recurse unboundedly (iterative or depth-guarded).
- No decompression bombs: attachments are NEVER decoded, decompressed or unpacked (no zip/gzip/tar/image parsing). Decoded size is computed arithmetically from encoded length (base64: len*3/4 minus padding; quoted-printable: upper bound) and labelled `estimated`. Test: a 1 MiB base64 part is summarized without allocating a decoded copy (assert by monkeypatching `base64.b64decode` to raise).
- Malformed cases table: missing boundary parameter, duplicate boundary, boundary appearing in nested part, missing closing boundary, preamble/epilogue junk, nested message/rfc822 (depth counted), multipart with zero parts, bogus charset, Content-Type with unterminated quote, RFC 2231 continued filename, NUL bytes in body (tolerated in body, counted), invalid Content-Transfer-Encoding, 8bit in a 7bit part (warning).
- Reports presence of text/plain and text/html alternatives (needed by M5 later, informational only).
- Table-driven tests, no network.
New i18n keys: none
Status: done
