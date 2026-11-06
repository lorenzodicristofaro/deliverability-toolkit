# M4-05 ARC chain parser and structural validation (RFC 8617)
Milestone: M4
Branch: feature/m4-05-arc-parser
Files in scope: app/parsers/arc.py, tests/parsers/test_arc.py
Out of scope: cryptographic verification of ARC-Seal / ARC-Message-Signature (needs DNS public keys; NOT done in M4), API/UI/CLI.
Depends on: M4-01, M4-04 (reuses the tag=value / authres parsing for ARC-Authentication-Results)
Parallel-safe: no (imports M4-04 helpers; serialize after it)
Model: opus
Acceptance criteria:
- Pure offline: no DNS, no signature verification. Output states `verified=None` / `crypto_checked=False` so consumers cannot mistake structure for validity. Stated in the docstring.
- Groups ARC-Seal (AS), ARC-Message-Signature (AMS) and ARC-Authentication-Results (AAR) by instance `i=`; parses tags (a, b presence only, bh presence only, d, s, i, cv, t, h, c) with tag-list grammar (folding whitespace inside b=/bh= tolerated; value of b/bh NOT retained beyond a length).
- Structural validation per RFC 8617 section 5: instances start at 1, contiguous, no gaps/duplicates, max 50 (RFC limit; cap enforced), each instance has exactly one AS/AMS/AAR, cv=none only at i=1, cv=fail anywhere marks chain `failed`, missing/invalid cv value, instance not a positive integer, i above 50. Result enum: none | structurally_valid | invalid | cv_fail.
- Each instance exposes sealer domain (d=), selector (s=), cv, timestamp (invalid t= -> None with warning), and the AAR-embedded results (reused authres parser) so the original authentication state at each hop is visible.
- Malformed table: duplicate instance, gap, i=0, i=-1, i=abc, i=51, missing tags, unknown a= algorithm (kept, flagged), truncated header, huge tag values (cap per header 8 KiB, already in M4-01), NUL.
- Fixtures: RFC 8617 appendix B example headers (cited) and synthetic ones on example.com.
New i18n keys: none
Status: todo
