"""Offline structural parser for the HTML and plain-text parts of a message (M5-08).

Facts only, no verdicts: findings, i18n and link classification live in later tickets
(M5-09, M5-13, M5-14). Stdlib ``html.parser`` only. No I/O: URLs are never resolved,
images never loaded, scripts never executed.

Resource limits are enforced while parsing. Exceeding any of them yields a result with
``capped=True`` and ``cap_reason`` set (consumers turn that into an error-class finding);
partial facts gathered so far are returned, nothing is silently truncated.

Hidden-text detection only looks at literal inline ``style`` values. It reports
candidates, not proof: stylesheets are not evaluated. The off-screen rule (a negative
``left``/``top`` of at least 500 units on an absolutely/fixed positioned element, or a
negative ``text-indent`` of that size) is a heuristic and `unverified`, like the Gmail
clipping constant: no vendor documentation has been checked for it.

Default limits (2 MB input, 20k elements, depth 100, 100 attributes per element) are
conservative bounds chosen to keep parsing cheap on hostile input while comfortably
exceeding real marketing emails; consumers may pass their own ``ContentLimits``.

The parser never decodes bytes: input is already ``str`` and only the declared charset
(meta tag) is reported. Malformed-HTML indicators: "unknown nesting" is covered by
``unbalanced_end_tags`` (end tag with no matching open tag, or closing past unclosed tags).
An unexpected parser exception yields ``capped=True`` with ``cap_reason="parser_error"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser

# Heuristic threshold from SPEC section 4.5 ("near 102 KB"), not a vendor guarantee.
# unverified: the maintainer has not yet confirmed the Gmail clipping behaviour against
# official Gmail documentation.
GMAIL_CLIP_THRESHOLD_BYTES = 102_400

# Heuristic: a negative offset at least this large (px-like units) counts as off-screen.
OFFSCREEN_THRESHOLD = 500

_VOID = frozenset(
    [
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    ]
)
# End tags may legally be omitted for these, so a missing close is not malformed.
_OPTIONAL_END = frozenset(
    [
        "html",
        "head",
        "body",
        "p",
        "li",
        "dt",
        "dd",
        "tr",
        "td",
        "th",
        "thead",
        "tbody",
        "tfoot",
        "option",
        "optgroup",
        "colgroup",
    ]
)
_SKIP_TEXT = frozenset({"script", "style", "title", "head"})


@dataclass(frozen=True)
class ContentLimits:
    max_input_bytes: int = 2_000_000
    max_elements: int = 20_000
    max_depth: int = 100
    max_attributes: int = 100  # per element


@dataclass(frozen=True)
class HiddenCandidate:
    tag: str
    # display_none, visibility_hidden, font_size_zero, color_matches_background, offscreen
    reason: str


@dataclass(frozen=True)
class ContentStructure:
    capped: bool = False
    # input_size, element_count, nesting_depth, attribute_count
    cap_reason: str | None = None
    # None when not measured (input_size cap); then *_at_least holds len(str), a lower bound.
    html_bytes: int | None = 0
    text_bytes: int | None = 0
    html_bytes_at_least: int | None = None
    text_bytes_at_least: int | None = None
    text_length: int = 0
    has_plain_text_part: bool = False
    has_html_part: bool = False
    visible_text_length: int = 0
    image_count: int = 0
    images_missing_alt: int = 0  # no alt attribute
    images_empty_alt: int = 0  # alt present but blank
    anchors: tuple[tuple[str, str | None], ...] = ()  # raw (text, href); None if no href
    inline_style_bytes: int = 0
    style_tag_bytes: int = 0
    hidden_candidates: tuple[HiddenCandidate, ...] = ()
    malformed: tuple[str, ...] = ()
    has_doctype: bool = False
    charset: str | None = None
    has_nul: bool = False
    gmail_clip_threshold_bytes: int = GMAIL_CLIP_THRESHOLD_BYTES
    exceeds_gmail_clip_threshold: bool = False  # heuristic, unverified


class _Capped(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _style_decls(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in style.split(";"):
        name, sep, value = part.partition(":")
        if sep:
            out[name.strip().lower()] = re.sub(r"\s*!important\s*$", "", value.strip().lower())
    return out


_ZERO = re.compile(r"^[+-]?0*\.?0+(px|pt|em|rem|%|ex|pc|cm|mm|in)?$")
_NEG = re.compile(r"^-\s*(\d+(?:\.\d+)?)(px|pt|em|rem|ex|pc|cm|mm|in|%)?$")


def _hidden_reasons(style: str) -> list[str]:
    d = _style_decls(style)
    reasons: list[str] = []
    if d.get("display") == "none":
        reasons.append("display_none")
    if d.get("visibility") in ("hidden", "collapse"):
        reasons.append("visibility_hidden")
    if "font-size" in d and _ZERO.match(d["font-size"]):
        reasons.append("font_size_zero")
    bg = d.get("background-color") or d.get("background")
    fg = d.get("color")
    if fg and bg and fg == bg and fg not in ("inherit", "initial", "transparent"):
        reasons.append("color_matches_background")
    for prop in ("left", "top", "text-indent"):
        m = _NEG.match(d.get(prop, ""))
        positioned = prop == "text-indent" or d.get("position") in ("absolute", "fixed")
        if m and positioned and float(m.group(1)) >= OFFSCREEN_THRESHOLD:
            reasons.append("offscreen")
            break
    return reasons


class _Collector(HTMLParser):
    def __init__(self, limits: ContentLimits) -> None:
        super().__init__(convert_charrefs=True)
        self.limits = limits
        self.elements = 0
        self.stack: list[str] = []
        self.unbalanced_end = 0
        self.visible = 0
        self.images = 0
        self.no_alt = 0
        self.empty_alt = 0
        self.anchors: list[tuple[str, str | None]] = []
        self._anchor: tuple[list[str], str | None] | None = None
        self.inline_style = 0
        self.style_tag = 0
        self.hidden: list[HiddenCandidate] = []
        self.doctype = False
        self.charset: str | None = None

    def flush_anchor(self) -> None:
        if self._anchor is not None:
            parts, href = self._anchor
            self.anchors.append((" ".join("".join(parts).split()), href))
            self._anchor = None

    def handle_decl(self, decl: str) -> None:
        if decl.strip().lower().startswith("doctype"):
            self.doctype = True

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], *, selfclose: bool) -> None:
        self.elements += 1
        if self.elements > self.limits.max_elements:
            raise _Capped("element_count")
        if len(attrs) > self.limits.max_attributes:
            raise _Capped("attribute_count")
        a = {k.lower(): (v or "") for k, v in attrs}
        style = a.get("style")
        if style is not None:
            self.inline_style += len(style.encode("utf-8", "replace"))
            self.hidden.extend(HiddenCandidate(tag, r) for r in _hidden_reasons(style))
        if tag == "img":
            self.images += 1
            if "alt" not in a:
                self.no_alt += 1
            elif not a["alt"].strip():
                self.empty_alt += 1
        elif tag == "meta":
            if a.get("charset", "").strip():
                self.charset = a["charset"].strip().lower()
            elif a.get("http-equiv", "").lower() == "content-type":
                m = re.search(r"charset\s*=\s*([^\s;\"']+)", a.get("content", ""), re.I)
                if m:
                    self.charset = m.group(1).lower()
        elif tag == "a":
            self.flush_anchor()
            self._anchor = ([], a.get("href") if "href" in a else None)
        if tag not in _VOID and not selfclose:
            if len(self.stack) + 1 > self.limits.max_depth:
                raise _Capped("nesting_depth")
            self.stack.append(tag)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, selfclose=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, selfclose=True)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID:
            return
        if tag == "a":
            self.flush_anchor()
        if tag in self.stack:
            idx = len(self.stack) - 1 - self.stack[::-1].index(tag)
            self.unbalanced_end += sum(1 for t in self.stack[idx + 1 :] if t not in _OPTIONAL_END)
            del self.stack[idx:]
        else:
            self.unbalanced_end += 1

    def handle_data(self, data: str) -> None:
        if "style" in self.stack:
            self.style_tag += len(data.encode("utf-8", "replace"))
        if self._anchor is not None:
            self._anchor[0].append(data)
        if not _SKIP_TEXT.intersection(self.stack):
            self.visible += len("".join(data.split()))


def parse_content(
    html: str | None, text: str | None, *, limits: ContentLimits | None = None
) -> ContentStructure:
    lim = limits or ContentLimits()
    # len(str) <= UTF-8 bytes, so a longer string is certainly over the cap: skip encoding.
    too_long = len(html or "") > lim.max_input_bytes or len(text or "") > lim.max_input_bytes
    html_bytes: int | None = 0
    text_bytes: int | None = 0
    if too_long:
        html_bytes = text_bytes = None
    else:
        html_bytes = len(html.encode("utf-8", "replace")) if html else 0
        text_bytes = len(text.encode("utf-8", "replace")) if text else 0
    base: dict[str, object] = {
        "html_bytes": html_bytes,
        "text_bytes": text_bytes,
        "html_bytes_at_least": len(html or "") if too_long else None,
        "text_bytes_at_least": len(text or "") if too_long else None,
        "text_length": len(text) if text else 0,
        "has_plain_text_part": bool(text and text.strip()),
        "has_html_part": bool(html and html.strip()),
        "exceeds_gmail_clip_threshold": (html_bytes or 0) > GMAIL_CLIP_THRESHOLD_BYTES,
    }
    if (
        too_long
        or (html_bytes or 0) > lim.max_input_bytes
        or (text_bytes or 0) > lim.max_input_bytes
    ):
        return ContentStructure(capped=True, cap_reason="input_size", **base)  # type: ignore[arg-type]
    if not html or not html.strip():
        return ContentStructure(**base)  # type: ignore[arg-type]

    has_nul = "\x00" in html
    src = html.replace("\x00", "�")
    c = _Collector(lim)
    malformed: list[str] = []
    capped: str | None = None
    try:
        c.feed(src)
        c.close()
    except _Capped as e:
        capped = e.reason
    except Exception:  # parser must never raise on hostile input
        malformed.append("parser_error")
        capped = "parser_error"
    c.flush_anchor()

    if capped is None:
        if src.count("<!--") > src.count("-->"):
            malformed.append("unterminated_comment")
        if src.rfind("<") > src.rfind(">") and re.match(r"</?[A-Za-z!]", src[src.rfind("<") :]):
            malformed.append("truncated_tag")
        if any(t not in _OPTIONAL_END for t in c.stack):
            malformed.append("unclosed_tags")
        if c.unbalanced_end:
            malformed.append("unbalanced_end_tags")
    return ContentStructure(
        capped=capped is not None,
        cap_reason=capped,
        visible_text_length=c.visible,
        image_count=c.images,
        images_missing_alt=c.no_alt,
        images_empty_alt=c.empty_alt,
        anchors=tuple(c.anchors),
        inline_style_bytes=c.inline_style,
        style_tag_bytes=c.style_tag,
        hidden_candidates=tuple(c.hidden),
        malformed=tuple(malformed),
        has_doctype=c.doctype,
        charset=c.charset,
        has_nul=has_nul,
        **base,  # type: ignore[arg-type]
    )
