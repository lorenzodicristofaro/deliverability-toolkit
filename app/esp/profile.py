"""ESP profiles: one YAML file per email service provider in `profiles/esp/` (M6-01).

Follows the `app.dns.knowledge` pattern: the hand-written strict validator below IS the schema
(no JSON Schema, unknown keys rejected everywhere), results are immutable and loaded once per
directory (cached), no network access. The contributor guide (M6-12) documents this shape:

    id: example-esp                 # slug [a-z0-9][a-z0-9-]{0,39}, equal to the file name
    name: Example ESP
    homepage: https://esp.example.com
    spf:
      includes: [spf.esp.example.com]          # host names, may be empty
    dkim:
      selectors:                               # may be empty
        - {name: s1, type: cname, target_pattern: "s1.dkim.*.esp.example.com"}
        - {name: k1, type: txt}
    return_path: {type: cname, optional: false, notes_key: esp.example.return_path}  # optional
    tracking_domain: {type: cname, optional: true}                                     # optional
    pitfalls:                                  # optional, static advisory entries only
      - {code: ESP_EXAMPLE_ESP_LINK_BRANDING, notes_key: esp.example.link, severity: low}
    verified_on: 2026-11-02                    # mandatory, never in the future
    sources: [https://docs.esp.example.com/dns]  # mandatory, non-empty, https
    status: verified                           # verified | unverified
    unverified_fields: [return_path]           # required (non-empty) iff status is unverified

Decisions:
- `target_pattern` is a restricted glob, never a regex and never evaluated as code: lowercase
  labels where a label that is exactly `*` matches exactly one DNS label; the last two labels
  must be literal. Only a `cname` selector may carry one.
- Pitfalls carry no condition (the sketch's free-text `when:` is rejected: no expression
  evaluation of data, GM decision 2026-11-10). `code` is `ESP_<ID>_<NAME>` upper snake.
- `unverified_fields` names the parts the maintainer could not confirm against official docs;
  checks must skip them (`EspProfile.is_verified`). Allowed paths: `spf.includes`,
  `dkim.selectors`, `dkim.selectors.<name>`, `return_path`, `tracking_domain`, `pitfalls`,
  `pitfalls.<code>`; each must name something present in the profile.
- Files are parsed with a `yaml.SafeLoader` subclass that additionally rejects duplicate keys,
  anchors/aliases and merge keys; each file is capped at MAX_FILE_BYTES.
- The directory load is all-or-nothing: one bad file raises, no partial result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any, Final, get_args
from urllib.parse import urlsplit

import yaml  # type: ignore[import-untyped]

from app.checks.models import Severity
from app.dns.knowledge import KnowledgeError, _check_keys, _date, _fail, _status, _str

PROFILES_DIR: Final = Path(__file__).resolve().parents[2] / "profiles" / "esp"
PROFILE_SUFFIX: Final = ".yaml"

MAX_FILE_BYTES: Final = 64 * 1024
MAX_PROFILES: Final = 200
MAX_INCLUDES: Final = 20
MAX_SELECTORS: Final = 20
MAX_PITFALLS: Final = 30
MAX_SOURCES: Final = 10
MAX_UNVERIFIED_FIELDS: Final = 50
MAX_NAME_LENGTH: Final = 100
MAX_URL_LENGTH: Final = 2048
MAX_NOTES_KEY_LENGTH: Final = 128
MAX_CODE_LENGTH: Final = 80
MAX_HOSTNAME_LENGTH: Final = 253
MAX_LABEL_LENGTH: Final = 63

SELECTOR_TYPES: Final = ("cname", "txt")
RECORD_TYPES: Final = ("cname", "txt", "mx")
SEVERITIES: Final[tuple[str, ...]] = get_args(Severity)

_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
# LDH label; host names (not selector names) may carry ONE leading underscore (`_spf`).
_LABEL: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_HOST_LABEL: Final = re.compile(r"_?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_NOTES_KEY: Final = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+")
_CODE_NAME: Final = re.compile(r"[A-Z0-9]+(?:_[A-Z0-9]+)*")

_TOP_REQUIRED: Final = {"id", "name", "homepage", "spf", "dkim", "verified_on", "sources", "status"}
_TOP_OPTIONAL: Final = frozenset(
    {"return_path", "tracking_domain", "pitfalls", "unverified_fields"}
)


class EspProfileError(KnowledgeError):
    """An ESP profile file is missing, unparsable or violates the profile schema."""


@dataclass(frozen=True, slots=True)
class TargetPattern:
    """Restricted glob over DNS names: a `*` label matches exactly one DNS label."""

    labels: tuple[str, ...]

    def __str__(self) -> str:
        return ".".join(self.labels)

    def matches(self, name: object) -> bool:
        """True if `name` (case-insensitive, one optional trailing dot) fits the pattern."""
        if not isinstance(name, str) or not name.isascii() or len(name) > MAX_HOSTNAME_LENGTH + 1:
            return False
        name = name.lower()
        if name.endswith("."):
            name = name[:-1]
        parts = name.split(".")
        if len(parts) != len(self.labels):
            return False
        for want, got in zip(self.labels, parts, strict=True):
            if want == "*":
                if len(got) > MAX_LABEL_LENGTH or not _HOST_LABEL.fullmatch(got):
                    return False
            elif want != got:
                return False
        return True


@dataclass(frozen=True, slots=True)
class DkimSelector:
    name: str
    type: str
    target_pattern: TargetPattern | None = None


@dataclass(frozen=True, slots=True)
class RecordExpectation:
    """Expected DNS setup for the return-path or tracking domain."""

    type: str
    optional: bool
    notes_key: str | None = None


@dataclass(frozen=True, slots=True)
class Pitfall:
    code: str
    notes_key: str
    severity: str


@dataclass(frozen=True, slots=True)
class EspProfile:
    id: str
    name: str
    homepage: str
    spf_includes: tuple[str, ...]
    dkim_selectors: tuple[DkimSelector, ...]
    return_path: RecordExpectation | None
    tracking_domain: RecordExpectation | None
    pitfalls: tuple[Pitfall, ...]
    verified_on: date
    sources: tuple[str, ...]
    status: str
    unverified_fields: frozenset[str]

    def is_verified(self, field: str) -> bool:
        """False if `field` (e.g. `dkim.selectors.s1`) or one of its parents is unverified.

        Checks must not evaluate a field for which this returns False."""
        parts = field.split(".")
        return not any(
            ".".join(parts[:n]) in self.unverified_fields for n in range(1, len(parts) + 1)
        )


# --- YAML -------------------------------------------------------------------------------------


class _StrictLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader that rejects duplicate mapping keys, anchors/aliases and merge keys."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None, None, "anchors and aliases are not allowed", event.start_mark
            )
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise yaml.composer.ComposerError(
                None, None, "anchors and aliases are not allowed", event.start_mark
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[object] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None, None, "merge keys are not allowed", key_node.start_mark
                )
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:  # unhashable key: SafeConstructor reports it
                continue
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
        return super().construct_mapping(node, deep=deep)


def _load_yaml(path: Path) -> object:
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise EspProfileError(f"{path.name}: cannot read: {exc}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise EspProfileError(f"{path.name}: file larger than {MAX_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise EspProfileError(f"{path.name}: cannot parse: {exc}") from exc
    except RecursionError:  # deeply nested flow collections still fit under the size cap
        raise EspProfileError(f"{path.name}: cannot parse: nesting too deep") from None


# --- field validators ---------------------------------------------------------------------------


def _list(value: object, where: str, maximum: int, *, non_empty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        raise _fail(where, "must be a list")
    if non_empty and not value:
        raise _fail(where, "must not be empty")
    if len(value) > maximum:
        raise _fail(where, f"at most {maximum} entries")
    return value


def _text(value: object, where: str, maximum: int) -> str:
    text = _str(value, where)
    if len(text) > maximum:
        raise _fail(where, f"at most {maximum} characters")
    if not text.isprintable():
        raise _fail(where, "must not contain control characters")
    return text


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(where, "must be true or false")
    return value


def _choice(value: object, where: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise _fail(where, f"must be one of {choices}")
    return value


def _hostname(value: object, where: str) -> str:
    """Canonical host name: lowercase ASCII, no trailing dot, no scheme, port or wildcard."""
    name = _text(value, where, MAX_HOSTNAME_LENGTH)
    labels = name.split(".")
    if len(labels) < 2:
        raise _fail(where, f"must be a host name with at least two labels: {name!r}")
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH or not _HOST_LABEL.fullmatch(label):
            raise _fail(where, f"invalid host name label in {name!r}")
    if labels[-1].isdigit():
        raise _fail(where, f"last label must not be numeric: {name!r}")
    return name


def _target_pattern(value: object, where: str) -> TargetPattern:
    text = _text(value, where, MAX_HOSTNAME_LENGTH)
    labels = text.split(".")
    if len(labels) < 2:
        raise _fail(where, f"must have at least two labels: {text!r}")
    for label in labels:
        if label == "*":
            continue
        if len(label) > MAX_LABEL_LENGTH or not _HOST_LABEL.fullmatch(label):
            raise _fail(where, f"invalid label in {text!r} (`*` must be a whole label)")
    if "*" in labels[-2:]:
        raise _fail(where, f"the last two labels must be literal: {text!r}")
    if labels[-1].isdigit():
        raise _fail(where, f"last label must not be numeric: {text!r}")
    return TargetPattern(tuple(labels))


def _https_url(value: object, where: str) -> str:
    url = _text(value, where, MAX_URL_LENGTH)
    if " " in url or not url.isascii():
        raise _fail(where, f"must be an ASCII URL without spaces: {url!r}")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise _fail(where, f"not a valid URL: {url!r}") from None
    if parts.scheme != "https" or not url.startswith("https://"):
        raise _fail(where, f"must be an https URL: {url!r}")
    if parts.username is not None or parts.password is not None or port is not None:
        raise _fail(where, f"must not carry credentials or a port: {url!r}")
    _hostname(parts.hostname, f"{where} host")
    if parts.netloc != parts.hostname:
        raise _fail(where, f"host must be lowercase: {url!r}")
    return url


def _notes_key(value: object, where: str) -> str:
    key = _text(value, where, MAX_NOTES_KEY_LENGTH)
    if not _NOTES_KEY.fullmatch(key):
        raise _fail(where, f"must be a dotted i18n key: {key!r}")
    return key


def _record(value: object, where: str) -> RecordExpectation:
    e = _check_keys(value, where, {"type"}, frozenset({"optional", "notes_key"}))
    return RecordExpectation(
        type=_choice(e["type"], f"{where}.type", RECORD_TYPES),
        optional=_bool(e["optional"], f"{where}.optional") if "optional" in e else False,
        notes_key=_notes_key(e["notes_key"], f"{where}.notes_key") if "notes_key" in e else None,
    )


def _selectors(value: object, where: str) -> tuple[DkimSelector, ...]:
    out: list[DkimSelector] = []
    seen: set[str] = set()
    for i, raw in enumerate(_list(value, where, MAX_SELECTORS)):
        w = f"{where}[{i}]"
        e = _check_keys(raw, w, {"name", "type"}, frozenset({"target_pattern"}))
        name = _text(e["name"], f"{w}.name", MAX_LABEL_LENGTH)
        if not _LABEL.fullmatch(name):
            raise _fail(f"{w}.name", f"must be a lowercase DNS label: {name!r}")
        if name in seen:
            raise _fail(f"{w}.name", f"duplicate selector {name!r}")
        seen.add(name)
        kind = _choice(e["type"], f"{w}.type", SELECTOR_TYPES)
        pattern = None
        if "target_pattern" in e:
            if kind != "cname":
                raise _fail(f"{w}.target_pattern", "only a cname selector has a target")
            pattern = _target_pattern(e["target_pattern"], f"{w}.target_pattern")
        out.append(DkimSelector(name=name, type=kind, target_pattern=pattern))
    return tuple(out)


def _pitfalls(value: object, where: str, profile_id: str) -> tuple[Pitfall, ...]:
    prefix = f"ESP_{profile_id.upper().replace('-', '_')}_"
    out: list[Pitfall] = []
    seen: set[str] = set()
    for i, raw in enumerate(_list(value, where, MAX_PITFALLS)):
        w = f"{where}[{i}]"
        if isinstance(raw, dict) and "when" in raw:
            raise _fail(f"{w}.when", "conditions are not supported (pitfalls are static advice)")
        e = _check_keys(raw, w, {"code", "notes_key", "severity"})
        code = _text(e["code"], f"{w}.code", MAX_CODE_LENGTH)
        if not code.startswith(prefix) or not _CODE_NAME.fullmatch(code[len(prefix) :]):
            raise _fail(f"{w}.code", f"must be {prefix}<NAME> in upper snake case: {code!r}")
        if code in seen:
            raise _fail(f"{w}.code", f"duplicate code {code!r}")
        seen.add(code)
        out.append(
            Pitfall(
                code=code,
                notes_key=_notes_key(e["notes_key"], f"{w}.notes_key"),
                severity=_choice(e["severity"], f"{w}.severity", SEVERITIES),
            )
        )
    return tuple(out)


def _sources(value: object, where: str) -> tuple[str, ...]:
    urls = tuple(
        _https_url(u, f"{where}[{i}]")
        for i, u in enumerate(_list(value, where, MAX_SOURCES, non_empty=True))
    )
    if len(set(urls)) != len(urls):
        raise _fail(where, "duplicate source")
    return urls


def _unverified_fields(value: object, where: str, present: set[str]) -> frozenset[str]:
    out: set[str] = set()
    for i, raw in enumerate(_list(value, where, MAX_UNVERIFIED_FIELDS, non_empty=True)):
        field = _text(raw, f"{where}[{i}]", MAX_CODE_LENGTH + 20)
        if field not in present:
            raise _fail(f"{where}[{i}]", f"names no field present in this profile: {field!r}")
        if field in out:
            raise _fail(f"{where}[{i}]", f"duplicate entry {field!r}")
        out.add(field)
    return frozenset(out)


# --- profiles -----------------------------------------------------------------------------------


def _parse(data: object, file_id: str, today: date) -> EspProfile:
    d = _check_keys(data, "profile", _TOP_REQUIRED, _TOP_OPTIONAL)
    pid = _str(d["id"], "id")
    if not _ID.fullmatch(pid):
        raise _fail("id", f"must match [a-z0-9][a-z0-9-]{{0,39}}: {pid!r}")
    if pid != file_id:
        raise _fail("id", f"must equal the file name {file_id!r}: {pid!r}")
    spf = _check_keys(d["spf"], "spf", {"includes"})
    includes = tuple(
        _hostname(h, f"spf.includes[{i}]")
        for i, h in enumerate(_list(spf["includes"], "spf.includes", MAX_INCLUDES))
    )
    if len(set(includes)) != len(includes):
        raise _fail("spf.includes", "duplicate host name")
    dkim = _check_keys(d["dkim"], "dkim", {"selectors"})
    selectors = _selectors(dkim["selectors"], "dkim.selectors")
    return_path = _record(d["return_path"], "return_path") if "return_path" in d else None
    tracking = _record(d["tracking_domain"], "tracking_domain") if "tracking_domain" in d else None
    pitfalls = _pitfalls(d["pitfalls"], "pitfalls", pid) if "pitfalls" in d else ()
    status = _status(d["status"], "status")

    present: set[str] = set()
    if includes:
        present.add("spf.includes")
    if selectors:
        present.add("dkim.selectors")
        present.update(f"dkim.selectors.{s.name}" for s in selectors)
    if return_path is not None:
        present.add("return_path")
    if tracking is not None:
        present.add("tracking_domain")
    if pitfalls:
        present.add("pitfalls")
        present.update(f"pitfalls.{p.code}" for p in pitfalls)
    unverified: frozenset[str] = frozenset()
    if "unverified_fields" in d:
        if status != "unverified":
            raise _fail("unverified_fields", "only allowed with status: unverified")
        unverified = _unverified_fields(d["unverified_fields"], "unverified_fields", present)
    elif status == "unverified":
        raise _fail("unverified_fields", "status: unverified needs the list of unverified fields")

    return EspProfile(
        id=pid,
        name=_text(d["name"], "name", MAX_NAME_LENGTH),
        homepage=_https_url(d["homepage"], "homepage"),
        spf_includes=includes,
        dkim_selectors=selectors,
        return_path=return_path,
        tracking_domain=tracking,
        pitfalls=pitfalls,
        verified_on=_date(d["verified_on"], "verified_on", today),
        sources=_sources(d["sources"], "sources"),
        status=status,
        unverified_fields=unverified,
    )


def parse_esp_profile(data: object, file_id: str, today: date | None = None) -> EspProfile:
    """Validate one decoded profile document; `file_id` is the file name without `.yaml`."""
    try:
        return _parse(data, file_id, today or date.today())
    except EspProfileError:
        raise
    except KnowledgeError as exc:
        raise EspProfileError(f"{file_id}{PROFILE_SUFFIX}: {exc}") from None


def check_unique_ids(profiles: tuple[EspProfile, ...]) -> None:
    seen: set[str] = set()
    for p in profiles:
        if p.id in seen:
            raise EspProfileError(f"duplicate profile id {p.id!r}")
        seen.add(p.id)


def _profile_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise EspProfileError(f"profile directory not found: {directory}")
    files: list[Path] = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.name.startswith("."):
            continue  # .gitkeep and editor files
        if entry.is_symlink() or not entry.is_file() or entry.suffix != PROFILE_SUFFIX:
            raise EspProfileError(
                f"unexpected entry {entry.name!r}: only regular *{PROFILE_SUFFIX} files allowed"
            )
        files.append(entry)
    if len(files) > MAX_PROFILES:
        raise EspProfileError(f"at most {MAX_PROFILES} profiles")
    return files


def read_esp_profiles(directory: Path, today: date | None = None) -> tuple[EspProfile, ...]:
    """Load and validate every profile in `directory` (uncached; all-or-nothing, sorted by id)."""
    profiles = tuple(
        parse_esp_profile(_load_yaml(f), f.name[: -len(PROFILE_SUFFIX)], today)
        for f in _profile_files(directory)
    )
    check_unique_ids(profiles)
    return profiles


@cache
def _cached(directory: Path) -> tuple[EspProfile, ...]:
    return read_esp_profiles(directory)


def load_esp_profiles(directory: Path = PROFILES_DIR) -> tuple[EspProfile, ...]:
    """The validated profiles in `directory`, loaded once per path."""
    return _cached(directory)


def get_esp_profile(profile_id: str, directory: Path = PROFILES_DIR) -> EspProfile | None:
    for p in load_esp_profiles(directory):
        if p.id == profile_id:
            return p
    return None
