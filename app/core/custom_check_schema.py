"""Declarative custom check definitions (M5-22, M7-02): the single validator.

It lives in `app.core`, not `app.checks`, because `app.repositories` must run it on every write
path and repositories only depend on core, models and DNS types, never on checks. It is pure: no
database, no DNS, no I/O. Limits and enumerations come from `app.models.custom_check`.

Definition keys, per kind (anything else is refused as `unknown_key`):
- `dns_exists`: `name`, `rrtype`;
- `dns_matches`: `name`, `rrtype`, `pattern` (through `compile_checked`, no flag key: use inline
  flags such as `(?i)`);
- `dns_value_range`: `name`, `rrtype` (TXT only: no other type's rdata is a bare number), `min`,
  `max` (numbers, not bool, finite, min <= max);
- `http_fetch` (M7-02): `host` and `expected_status` (required), `scheme`, `path`,
  `body_pattern`, `max_body_bytes`, `header` (`{name, pattern?}`); see "HTTP fetch" below.

Name template rule (one rule, no normalisation): `{domain}` alone, or lowercase ASCII labels
followed by `.{domain}`. Each label is letters, digits and inner hyphens with one optional leading
underscore. So `{domain}` appears exactly once and last, and the rendered name can only be the
target domain or a name under it. Uppercase is refused, not folded. IDN is refused in both forms,
U-label (`idn`, any non-ASCII character) and A-label (`xn--`); the target domain itself may be IDN.
Templates are never passed to `str.format`: the prefix is concatenated, so format-spec tricks
cannot run, and they are refused anyway.

HTTP fetch (`http_fetch`): the URL is never a free string. It is built by construction from
- `scheme`: `https` (default), or `http` only when the definition says so;
- `host`: a host template under the name template rule, except that labels are host names (no
  leading underscore): `{domain}` or `labels.{domain}`, so the host can only be the target domain
  or a name under it, never an arbitrary host;
- `path` (default `/`): starts with `/` (not `//`), at most MAX_PATH_LENGTH characters from `_PATH`
  (no `{ } @ \\ % #`, whitespace or control characters; a `?query` is allowed);
- no port: the scheme's default port is always used.
`render_url` builds `scheme://host/path` for a target and revalidates the host on every run; the
evaluator also re-parses the URL with the guarded client's policy before fetching.
`expected_status` holds 1 to MAX_EXPECTED_STATUS distinct integers in 100..599; `body_pattern`
and `header.pattern` go through `compile_checked`; `max_body_bytes` is 1..MAX_HTTP_BODY_BYTES
(default DEFAULT_HTTP_BODY_BYTES, below the client's own cap); `header.name` is one of
HTTP_HEADER_NAMES (lowercase), the response headers the guarded client returns.

`remediation_key` (global rows only) must name a message present in every supported catalogue
(`validate_remediation_key`), so a finding that carries it always renders; checked by the admin
service on write and by the evaluator on every run.

Every error carries a field and a stable reason, never the value.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

from app.core.domain_names import (
    MAX_DOMAIN_LENGTH,
    MAX_LABEL_LENGTH,
    InvalidDomainName,
    to_ascii_domain,
    to_dns_name,
)
from app.core.i18n import SUPPORTED_LANGUAGES, load_catalogue
from app.core.safe_regex import CompiledRule, RegexRuleError, compile_checked
from app.models.custom_check import (
    KINDS,
    MAX_REMEDIATION_KEY_LENGTH,
    MAX_REMEDIATION_LENGTH,
    REMEDIATION_LANGUAGES,
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

# --- http_fetch (M7-02); all project choices, not vendor facts ---
HTTP_FETCH: Final = "http_fetch"
HTTP_SCHEMES: Final = ("https", "http")
DEFAULT_SCHEME: Final = "https"
DEFAULT_PATH: Final = "/"
MAX_PATH_LENGTH: Final = 512
MAX_EXPECTED_STATUS: Final = 10
DEFAULT_HTTP_BODY_BYTES: Final = 64 * 1024
# Below the guarded client's 1 MiB default (`FetchLimits.max_body_bytes`, pinned by a test). A body
# decoded with replacement characters is at most three times this, under safe_regex.MAX_TEXT_BYTES.
MAX_HTTP_BODY_BYTES: Final = 256 * 1024
# A subset of `app.net.guarded_http.RESPONSE_HEADER_ALLOWLIST` (pinned by a test): any other
# response header never reaches a check, so naming it could never match.
HTTP_HEADER_NAMES: Final = frozenset(
    {
        "cache-control",
        "content-language",
        "content-length",
        "content-type",
        "etag",
        "expires",
        "last-modified",
        "location",
        "retry-after",
    }
)

_LABEL: Final = re.compile(r"_?[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_HOST_LABEL: Final = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")
# RFC 3986 unreserved and sub-delims plus ":", "/" and "?"; never "%", "@", "#", "\", "{" or "}".
_PATH: Final = re.compile(r"/(?!/)[A-Za-z0-9\-._~!$&'()*+,;=:/?]*")
# The repository's format for remediation_key (app.repositories.custom_checks).
_I18N_KEY: Final = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+")
_SHORTEST_DOMAIN: Final = "a.co"  # dry run: a template must fit under at least this domain
_KEYS: Final[dict[str, frozenset[str]]] = {
    "dns_exists": frozenset({"name", "rrtype"}),
    "dns_matches": frozenset({"name", "rrtype", "pattern"}),
    "dns_value_range": frozenset({"name", "rrtype", "min", "max"}),
    HTTP_FETCH: frozenset(
        {"scheme", "host", "path", "expected_status", "body_pattern", "max_body_bytes", "header"}
    ),
}
_REQUIRED: Final[dict[str, frozenset[str]]] = {
    **_KEYS,
    HTTP_FETCH: frozenset({"host", "expected_status"}),
}
_HEADER_KEYS: Final = frozenset({"name", "pattern"})


class DefinitionInvalid(ValueError):
    """A definition was refused. Carries a field and a stable reason, never the value."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"custom check {field} rejected: {reason}")
        self.field = field
        self.reason = reason


class NameRenderError(ValueError):
    """The final record name or URL cannot be built for this target; never queried or fetched,
    never truncated."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"custom check record name rejected: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ParsedDefinition:
    """A validated DNS definition. Built per run; never stored."""

    kind: str
    name_template: str
    rrtype: str
    rule: CompiledRule | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None


@dataclass(frozen=True, slots=True)
class HttpFetchDefinition:
    """A validated `http_fetch` definition. Built per run; never stored."""

    scheme: str
    host_template: str
    path: str
    expected_status: tuple[int, ...]
    max_body_bytes: int
    body_rule: CompiledRule | None = None
    header_name: str | None = None
    header_rule: CompiledRule | None = None
    kind: str = HTTP_FETCH


def _reject_chars(field: str, value: str, *, allowed_controls: str = "") -> None:
    if "\x00" in value:
        raise DefinitionInvalid(field, "nul")
    if any(unicodedata.category(c) == "Cs" for c in value):
        raise DefinitionInvalid(field, "surrogate")
    if any(unicodedata.category(c) == "Cc" and c not in allowed_controls for c in value):
        raise DefinitionInvalid(field, "control_char")


def _template_prefix(
    template: object, field: str = "definition.name", label_rule: re.Pattern[str] = _LABEL
) -> str:
    """Validate a name (or host) template; return the literal text before the placeholder."""
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
        if len(label) > MAX_LABEL_LENGTH or not label_rule.fullmatch(label):
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


def render_host(template: object, domain: object) -> str:
    """The host to fetch from: the target domain or a host name under it, or `NameRenderError`.
    Revalidates `template` with the host label rule."""
    prefix = _template_prefix(template, "definition.host", _HOST_LABEL)
    try:
        ascii_domain = to_ascii_domain(domain)
    except InvalidDomainName:
        raise NameRenderError("invalid_domain") from None
    if len(prefix + ascii_domain) > MAX_DOMAIN_LENGTH:  # both ASCII: the exact wire length
        raise NameRenderError("name_too_long")
    try:
        host = to_ascii_domain(prefix + ascii_domain)
    except InvalidDomainName:
        raise NameRenderError("name_invalid") from None
    if host != ascii_domain and not host.endswith("." + ascii_domain):
        raise NameRenderError("name_invalid")
    return host


def render_url(parsed: HttpFetchDefinition, domain: object) -> tuple[str, str]:
    """(url, host) for `domain`: built from the validated parts, never from a free string."""
    host = render_host(parsed.host_template, domain)
    return f"{parsed.scheme}://{host}{parsed.path}", host


def _rrtype(value: object) -> str:
    if not isinstance(value, str):
        raise DefinitionInvalid("definition.rrtype", "not_a_string")
    if value not in RRTYPES:
        raise DefinitionInvalid("definition.rrtype", "invalid_choice")
    return value


def _rule(value: object, field: str = "definition.pattern") -> CompiledRule:
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


def _integer(field: str, value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DefinitionInvalid(field, "not_an_integer")
    if not low <= value <= high:
        raise DefinitionInvalid(field, "out_of_range")
    return value


def _keys(field: str, value: Mapping[Any, Any], allowed: frozenset[str]) -> None:
    for key in value:
        if not isinstance(key, str):
            raise DefinitionInvalid(field, "non_string_key")
        if key not in allowed:
            raise DefinitionInvalid(field, "unknown_key")


def _scheme(value: object) -> str:
    if not isinstance(value, str):
        raise DefinitionInvalid("definition.scheme", "not_a_string")
    if value not in HTTP_SCHEMES:
        raise DefinitionInvalid("definition.scheme", "invalid_choice")
    return value


def _path(value: object) -> str:
    field = "definition.path"
    if not isinstance(value, str):
        raise DefinitionInvalid(field, "not_a_string")
    if value == "":
        raise DefinitionInvalid(field, "empty")
    if len(value) > MAX_PATH_LENGTH:
        raise DefinitionInvalid(field, "too_long")
    _reject_chars(field, value)
    if any(c.isspace() for c in value):
        raise DefinitionInvalid(field, "whitespace")
    if not value.startswith("/") or value.startswith("//"):
        raise DefinitionInvalid(field, "path_start")
    if not _PATH.fullmatch(value):
        raise DefinitionInvalid(field, "path_chars")
    return value


def _expected_status(value: object) -> tuple[int, ...]:
    field = "definition.expected_status"
    if isinstance(value, str | bytes) or not isinstance(value, list | tuple):
        raise DefinitionInvalid(field, "not_a_list")
    if not value:
        raise DefinitionInvalid(field, "empty")
    if len(value) > MAX_EXPECTED_STATUS:
        raise DefinitionInvalid(field, "too_many")
    statuses = tuple(_integer(field, v, 100, 599) for v in value)
    if len(set(statuses)) != len(statuses):
        raise DefinitionInvalid(field, "duplicate")
    return statuses


def _header(value: object) -> tuple[str, CompiledRule | None]:
    field = "definition.header"
    if not isinstance(value, Mapping):
        raise DefinitionInvalid(field, "not_an_object")
    _keys(field, value, _HEADER_KEYS)
    if "name" not in value:
        raise DefinitionInvalid(f"{field}.name", "required")
    name = value["name"]
    if not isinstance(name, str):
        raise DefinitionInvalid(f"{field}.name", "not_a_string")
    if name not in HTTP_HEADER_NAMES:
        raise DefinitionInvalid(f"{field}.name", "invalid_choice")
    if "pattern" not in value:
        return name, None
    return name, _rule(value["pattern"], f"{field}.pattern")


def _http_fetch(definition: Mapping[str, Any]) -> HttpFetchDefinition:
    _template_prefix(definition["host"], "definition.host", _HOST_LABEL)
    # An optional key that is present is validated: null is refused like any other wrong type.
    header_name, header_rule = (None, None)
    if "header" in definition:
        header_name, header_rule = _header(definition["header"])
    body_rule = None
    if "body_pattern" in definition:
        body_rule = _rule(definition["body_pattern"], "definition.body_pattern")
    size = DEFAULT_HTTP_BODY_BYTES
    if "max_body_bytes" in definition:
        size = _integer(
            "definition.max_body_bytes", definition["max_body_bytes"], 1, MAX_HTTP_BODY_BYTES
        )
    return HttpFetchDefinition(
        scheme=_scheme(definition.get("scheme", DEFAULT_SCHEME)),
        host_template=definition["host"],
        path=_path(definition.get("path", DEFAULT_PATH)),
        expected_status=_expected_status(definition["expected_status"]),
        max_body_bytes=size,
        body_rule=body_rule,
        header_name=header_name,
        header_rule=header_rule,
    )


def _plain(value: object) -> object:
    """Plain JSON copy of a validated value (stored definitions come back frozen)."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def parse_definition(kind: object, definition: object) -> ParsedDefinition | HttpFetchDefinition:
    """Validate `definition` for `kind`. Accepts any mapping (stored records are frozen).

    Raises `DefinitionInvalid` for anything refused. A regex is compiled through `compile_checked`
    on every call. `http_fetch` gives an `HttpFetchDefinition`, the DNS kinds a
    `ParsedDefinition`.
    """
    if not isinstance(kind, str) or kind not in KINDS:
        raise DefinitionInvalid("kind", "invalid_choice")
    if not isinstance(definition, Mapping):
        raise DefinitionInvalid("definition", "not_an_object")
    if not definition:
        raise DefinitionInvalid("definition", "empty")
    _keys("definition", definition, _KEYS[kind])
    for key in sorted(_REQUIRED[kind] - definition.keys()):
        raise DefinitionInvalid(f"definition.{key}", "required")

    parsed = _http_fetch(definition) if kind == HTTP_FETCH else _dns(kind, definition)
    # Every value is a validated, capped scalar (or a short list/object of them) here, so dumps
    # cannot fail or be expensive.
    if len(json.dumps(_plain(definition))) > MAX_DEFINITION_JSON_LENGTH:
        raise DefinitionInvalid("definition", "too_large")
    return parsed


def _dns(kind: str, definition: Mapping[str, Any]) -> ParsedDefinition:
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
    return ParsedDefinition(
        kind=kind,
        name_template=definition["name"],
        rrtype=rrtype,
        rule=rule,
        minimum=minimum,
        maximum=maximum,
    )


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


def validate_remediation_key(value: object) -> str:
    """An i18n key present in every supported catalogue, so the finding renders in each language.
    Format errors are `invalid_format`, a key some catalogue lacks is `unknown_key`."""
    field = "remediation_key"
    if not isinstance(value, str):
        raise DefinitionInvalid(field, "not_a_string")
    if len(value) > MAX_REMEDIATION_KEY_LENGTH or not _I18N_KEY.fullmatch(value):
        raise DefinitionInvalid(field, "invalid_format")
    if any(value not in load_catalogue(lang) for lang in SUPPORTED_LANGUAGES):
        raise DefinitionInvalid(field, "unknown_key")
    return value
