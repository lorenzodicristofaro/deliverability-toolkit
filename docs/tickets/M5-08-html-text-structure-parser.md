# M5-08 HTML/text structural parser (offline)
Milestone: M5
Branch: feature/m5-08-html-structure
Files in scope: app/parsers/content_html.py, tests/parsers/test_content_html.py
Out of scope: link classification (M5-09), findings/i18n (M5-14), rules (M5-13), any network, new dependencies (use stdlib `html.parser`; if the coder believes a dependency is needed, stop and ask the GM).
Depends on: none
Parallel-safe: yes (new parser file only)
Model: sonnet (hostile input: tests below are mandatory)
Acceptance criteria:
- `parse_content(html: str | None, text: str | None, *, limits) -> ContentStructure` (frozen dataclasses, no I/O). Facts only, no verdicts: text length, visible text length, image count, images missing/empty `alt`, text-to-image ratio inputs, has_plain_text_part, byte size of html and text (utf-8), count of anchors with raw (text, href) pairs for M5-09, inline style bytes and `<style>` bytes, hidden-text candidates (display:none, visibility:hidden, font-size:0, color equal to background where both are literal inline values, off-screen positioning), malformed-HTML indicators (unclosed/unbalanced tags, unknown nesting), doctype/charset presence.
- Gmail clipping: report size in bytes against a threshold constant of 102 KB (102,400 bytes as stated in SPEC §4.5 "near 102 KB"); constant is documented as a heuristic, not a vendor guarantee (`unverified` until the maintainer confirms against Gmail docs).
- Limits: input size, element count, nesting depth, attribute count, all enforced while parsing; exceeding any gives a typed `capped=True` result with the reason (consumers turn it into an error-class finding, same rule as M5-02), never silent truncation.
- Never resolves URLs, never loads images, never executes scripts; `<script>`/`<style>` content excluded from visible text.
- Table-driven tests including malformed input: truncated tags, unterminated comments/attributes, deeply nested divs, huge attribute values, invalid entities, NUL, mixed encodings, empty input, html-only, text-only.
New i18n keys: none
Status: done
