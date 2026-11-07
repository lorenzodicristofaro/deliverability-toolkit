# M4-04 Authentication-Results parser (RFC 8601)
Milestone: M4
Branch: feature/m4-04-authres-parser
Files in scope: app/parsers/authres.py, tests/parsers/test_authres.py
Out of scope: re-evaluating SPF/DKIM/DMARC (no DNS; M4 only REPORTS what the receiving server wrote), trust decisions beyond what is listed below, API/UI/CLI.
Depends on: M4-01
Parallel-safe: yes (new files)
Model: opus
Acceptance criteria:
- Pure offline. The parser never queries DNS and never verifies signatures; it reports the stated results. Stated in the docstring and in M4-14 docs.
- Parses every `Authentication-Results` header (multiple allowed) per RFC 8601: authserv-id, optional version, `none` form, and resinfo entries `method[/version]=result` with optional `reason=` and ptype.property=value pairs (header.d, header.i, header.s, header.from, header.b, smtp.mailfrom, smtp.helo, policy.*, dmarc `header.from`, etc.). Comments in parentheses are stripped, quoted strings handled.
- Recognised methods get typed fields: spf, dkim, dmarc, arc, plus a generic list for others (iprev, auth, dkim-adsp...). Unknown method or result value is kept verbatim and flagged `unknown_value`, never rejected.
- Output per header: authserv_id, ordered resinfo list, raw, position. Provides `by_method()` helper preserving order and duplicates (several dkim results are normal).
- Trust note encoded in the model: a header is `trusted_position=True` only when it appears above (newer than) the topmost Received added by the receiving host is NOT decided here; the parser just exposes position and authserv_id so M4-08/09 can warn on forged/duplicate authserv-ids (RFC 8601 section 5, 7.1). No vendor claims.
- Malformed table: missing authserv-id, unterminated quote or comment, missing `=`, empty result, duplicate method with conflicting results, semicolon garbage, 10k resinfo entries (cap MAX_RESINFO 200, flagged truncated), NUL, RFC 2047 junk, uppercase results, unknown ptype.
- Examples cited from RFC 8601 section 2.7 / appendix B are used as fixtures (source noted in the test comment); other fixtures synthetic with example.com.
New i18n keys: none
Status: done
