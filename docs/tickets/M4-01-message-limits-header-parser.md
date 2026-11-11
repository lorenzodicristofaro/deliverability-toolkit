# M4-01 Raw message limits and header block parser
Milestone: M4
Branch: feature/m4-01-header-parser
Files in scope: app/parsers/message.py, tests/parsers/test_message.py
Out of scope: Received/Authentication-Results/ARC/MIME parsing (M4-02..05), API/UI/CLI, DB, DNS, network. Persistence decision for all of M4: NOTHING is stored (no table, no migration, no cache, no log of content); analysis is request-scoped, so no NUL-before-DB concern exists. Any later ticket adding storage must reject NUL first.
Depends on: none
Parallel-safe: yes (new files only)
Model: opus
Acceptance criteria:
- Pure offline: no DNS, no network, no filesystem, no DB. Input is `bytes`; output is a frozen model `HeaderBlock` (ordered list of (name, raw_value, decoded_value, position) plus `body_offset`, `warnings`).
- Module-level cap constants, each tested at the boundary and boundary+1: MAX_RAW_BYTES (2 MiB), MAX_HEADER_BYTES (128 KiB), MAX_HEADER_COUNT (500), MAX_HEADER_LINE (8 KiB; RFC 5322 line limit 998 is only a warning). Over a cap: raise `MessageTooLarge` / `TooManyHeaders` (stable `code`, no echo of input); never truncate silently.
- Accepts CRLF, bare LF and mixed endings; accepts a leading mbox `From ` line (ignored, warned); accepts headers-only input with no blank line; handles unfolding (obs-fold, folded line starting with tab/space, 10k-line fold bomb is capped).
- NUL bytes anywhere in the header block: `InvalidMessage(code="nul_byte")`. Lone CR, bytes > 0x7F in headers (non-UTF-8 and UTF-8 both), header with no colon, empty name, name with space before colon, duplicate headers: all kept in order and reported as warnings, never raising except for the cases above.
- RFC 2047 encoded-words decoded into `decoded_value` (B and Q, utf-8/iso-8859-1/unknown charset, mixed with plain text, truncated `=?utf-8?b?`, invalid base64, charset bomb); raw value always preserved; decode failure leaves raw text and a warning.
- Table-driven tests with the malformed cases above; no network (existing socket guard).
- Helper `get_all(name)` is case-insensitive; the original order and duplicates of Received are preserved.
New i18n keys: none (parser emits stable warning codes only; user text comes in M4-09)
Status: done
