"""Declarative custom check definitions (M5-22): the single validator.

It lives in `app.core`, not `app.checks`, because `app.repositories` must run it on every write
path and repositories only depend on core, models and DNS types, never on checks. It is pure: no
database, no DNS, no I/O. Limits and enumerations come from `app.models.custom_check`.

Definition keys, per kind (anything else is refused as `unknown_key`):
- `dns_exists`: `name`, `rrtype`;
- `dns_matches`: `name`, `rrtype`, `pattern` (through `compile_checked`, no flag key: use inline
  flags such as `(?i)`);
- `dns_value_range`: `name`, `rrtype` (TXT only: no other type's rdata is a bare number), `min`,
  `max` (numbers, not bool, finite, min <= max).

`http_fetch` is a known kind that is not available yet (M7, guarded outbound client):
`parse_definition` raises `KindUnavailable`.

Name template rule (one rule, no normalisation): `{domain}` alone, or lowercase ASCII labels
followed by `.{domain}`. Each label is letters, digits and inner hyphens with one optional leading
underscore. So `{domain}` appears exactly once and last, and the rendered name can only be the
target domain or a name under it. Uppercase is refused, not folded. IDN is refused in both forms,
U-label (`idn`, any non-ASCII character) and A-label (`xn--`); the target domain itself may be IDN.
Templates are never passed to `str.format`: the prefix is concatenated, so format-spec tricks
cannot run, and they are refused anyway.

Every error carries a field and a stable reason, never the value.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

from app.core.domain_names import (
    MAX_DOMAIN_LENGTH,
    MAX_LABEL_LENGTH,
    InvalidDomainName,
    to_ascii_domain,
    to_dns_name,
)
from app.core.safe_regex import CompiledRule, RegexRuleError, compile_checked
from app.models.custom_check import (
    KINDS,
    MAX_REMEDIATION_LENGTH,
    REMEDIATION_LANGUAGES,
    RESERVED_KINDS,
)

CustomSeverity = Literal["low", "medium", "high"]

# Narrower than the column enumeration on purpose (M5-22 acceptance criteria).
SEVERITIES: Final[tuple[str, ...]] = ("low", "medium", "high")
# Subset of app.dns.types.ALLOWED_RDTYPES that makes sense under a tenant's own domain.
RRTYPES: Final = frozenset({"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TLSA", "TXT"})
PLACEHOLDER: Final = "{domain}"
MAX_TEMPLATE_LENGTH: Final = MAX_DOMAIN_LENGTH
# json.dumps defaults (ASCII), the same measure as the DB column, so non-ASCII costs more.
MAX_DEFINITION_JSON_LENGTH: Final = 4096
# Largest magnitude a double represents exactly; bounds also the huge-int case.
MAX_RANGE_MAGNITUDE: Final = 2**53

_LABEL: Final = re.compile(r"_?[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_SHORTEST_DOMAIN: Final = "a.co"  # dry run: a template must fit under at least this domain
_KEYS: Final[dict[str, frozenset[str]]] = {
    "dns_exists": frozenset({"name", "rrtype"}),
    "dns_matches": frozenset({"name", "rrtype", "pattern"}),
    "dns_value_range": frozenset({"name", "rrtype", "min", "max"}),
}


class DefinitionInvalid(ValueError):
    """A definition was refused. Carries a field and a stable reason, never the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"custom check {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class KindUnavailable(DefinitionInvalid):
    """A known kind that cannot be used yet (`http_fetch`, M7)."""

    def __init__(self) -> None:
        super().__init__("kind", "kind_unavailable")


class NameRenderError(ValueError):
    """The final record name cannot be built for this target; never queried, never truncated."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"custom check record name rejected: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ParsedDefinition:
    """A validated definition. Built per run; never stored."""

    kind: str
    name_template: str
    rrtype: str
    rule: CompiledRule | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None


def _reject_chars(field: str, value: str, *, allowed_controls: str = "") -> None:
    if "\x00" in value:
        raise DefinitionInvalid(field, "nul")
    if any(unicodedata.category(c) == "Cs" for c in value):
        raise DefinitionInvalid(field, "surrogate")
    if any(unicodedata.category(c) == "Cc" and c not in allowed_controls for c in value):
        raise DefinitionInvalid(field, "control_char")


def _template_prefix(template: object) -> str:
    """Validate a name template; return the literal text before the placeholder."""
    field = "definition.name"
    if not isinstance(template, str):
        raise DefinitionInvalid(field, "not_a_string")
    if template == "":
        raise DefinitionInvalid(field, "empty")
    if len(template) > MAX_TEMPLATE_LENGTH:
        raise DefinitionInvalid(field, "too_long")
    _reject_chars(field, template)
    if any(c.isspace() for c in template):
        raise DefinitionInvalid(field, "whitespace")
    if not template.isascii():
        raise DefinitionInvalid(field, "idn")
    rest = template.replace(PLACEHOLDER, "")
    if "{" in rest or "}" in rest:
        raise DefinitionInvalid(field, "bad_placeholder")
    count = template.count(PLACEHOLDER)
    if count == 0:
        raise DefinitionInvalid(field, "placeholder_missing")
    if count > 1:
        raise DefinitionInvalid(field, "placeholder_repeated")
    if template.startswith(".") or template.endswith("."):
        raise DefinitionInvalid(field, "dots")
    prefix = template.removesuffix(PLACEHOLDER)
    if prefix == "":
        return prefix
    # Refuses "{domain}.evil.example" (not last) and "foo{domain}" (a sibling of the domain).
    if not prefix.endswith("."):
        raise DefinitionInvalid(field, "placeholder_position")
    if rest != rest.lower():
        raise DefinitionInvalid(field, "uppercase")
    for label in prefix[:-1].split("."):
        if label == "":
            raise DefinitionInvalid(field, "dots")
        if label.removeprefix("_").startswith("xn--"):
            raise DefinitionInvalid(field, "idn")
        if len(label) > MAX_LABEL_LENGTH or not _LABEL.fullmatch(label):
            raise DefinitionInvalid(field, "label")
    try:
        to_dns_name(prefix + _SHORTEST_DOMAIN)
    except InvalidDomainName:
        raise DefinitionInvalid(field, "too_long") from None
    return prefix


def render_name(template: object, domain: object) -> str:
    """The name to query, or `NameRenderError`. Revalidates `template`; a name that would overflow
    253 bytes is an error, never a truncated query."""
    prefix = _template_prefix(template)
    try:
        ascii_domain = to_ascii_domain(domain)
    except InvalidDomainName:
        raise NameRenderError("invalid_domain") from None
    try:
        name = to_dns_name(prefix + ascii_domain)
    except InvalidDomainName as exc:
        reason = "name_too_long" if exc.reason == "length" else "name_invalid"
        raise NameRenderError(reason) from None
    if name != ascii_domain and not name.endswith("." + ascii_domain):
        raise NameRenderError("name_invalid")
    return name


def _rrtype(value: object) -> str:
    if not isinstance(value, str):
        raise DefinitionInvalid("definition.rrtype", "not_a_string")
    if value not in RRTYPES:
        raise DefinitionInvalid("definition.rrtype", "invalid_choice")
    return value


def _rule(value: object) -> CompiledRule:
    field = "definition.pattern"
    if isinstance(value, str):
        _reject_chars(field, value, allowed_controls="\n\t")
    try:
        return compile_checked(cast(str, value))
    except RegexRuleError as exc:
        raise DefinitionInvalid(field, f"regex_{exc.reason.value}") from None


def _number(field: str, value: object) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise DefinitionInvalid(field, "not_a_number")
    if isinstance(value, float) and not math.isfinite(value):
        raise DefinitionInvalid(field, "not_finite")
    if abs(value) > MAX_RANGE_MAGNITUDE:
        raise DefinitionInvalid(field, "out_of_bounds")
    return value


def parse_definition(kind: object, definition: object) -> ParsedDefinition:
    """Validate `definition` for `kind`. Accepts any mapping (stored records are frozen).

    Raises `KindUnavailable` for `http_fetch` and `DefinitionInvalid` for anything else refused.
    A regex is compiled through `compile_checked` on every call.
    """
    if isinstance(kind, str) and kind in RESERVED_KINDS:
        raise KindUnavailable
    if not isinstance(kind, str) or kind not in KINDS:
        raise DefinitionInvalid("kind", "invalid_choice")
    if not isinstance(definition, Mapping):
        raise DefinitionInvalid("definition", "not_an_object")
    if not definition:
        raise DefinitionInvalid("definition", "empty")
    allowed = _KEYS[kind]
    for key in definition:
        if not isinstance(key, str):
            raise DefinitionInvalid("definition", "non_string_key")
        if key not in allowed:
            raise DefinitionInvalid("definition", "unknown_key")
    for key in sorted(allowed - definition.keys()):
        raise DefinitionInvalid(f"definition.{key}", "required")

    _template_prefix(definition["name"])
    rule = _rule(definition["pattern"]) if kind == "dns_matches" else None
    minimum = maximum = None
    if kind == "dns_value_range":
        minimum = _number("definition.min", definition["min"])
        maximum = _number("definition.max", definition["max"])
        if minimum > maximum:
            raise DefinitionInvalid("definition.min", "min_above_max")
    rrtype = _rrtype(definition["rrtype"])
    if kind == "dns_value_range" and rrtype != "TXT":
        raise DefinitionInvalid("definition.rrtype", "range_requires_txt")
    parsed = ParsedDefinition(
        kind=kind,
        name_template=definition["name"],
        rrtype=rrtype,
        rule=rule,
        minimum=minimum,
        maximum=maximum,
    )
    # Every value is a validated, capped scalar here, so dumps cannot fail or be expensive.
    if len(json.dumps(dict(definition))) > MAX_DEFINITION_JSON_LENGTH:
        raise DefinitionInvalid("definition", "too_large")
    return parsed


def validate_severity(value: object) -> CustomSeverity:
    if not isinstance(value, str) or value not in SEVERITIES:
        raise DefinitionInvalid("severity", "invalid_choice")
    return cast(CustomSeverity, value)


def validate_remediation_text(value: object) -> dict[str, str]:
    """Plain text in every supported language, multi-line, length-capped. Renderers escape it."""
    field = "remediation_text"
    if not isinstance(value, Mapping):
        raise DefinitionInvalid(field, "not_an_object")
    if set(value.keys()) != set(REMEDIATION_LANGUAGES):
        raise DefinitionInvalid(field, "languages")
    result: dict[str, str] = {}
    for lang in REMEDIATION_LANGUAGES:
        text = value[lang]
        if not isinstance(text, str):
            raise DefinitionInvalid(field, "not_a_string")
        if text == "":
            raise DefinitionInvalid(field, "empty")
        if len(text) > MAX_REMEDIATION_LENGTH:
            raise DefinitionInvalid(field, "too_long")
        _reject_chars(field, text, allowed_controls="\n\t")
        if not text.strip():
            raise DefinitionInvalid(field, "whitespace")
        result[lang] = text
    return result
