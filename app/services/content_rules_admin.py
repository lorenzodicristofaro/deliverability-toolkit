"""Content rules administration (M5-18): list, read, create, update, delete, test on a sample.

Two scopes, chosen by the caller and authorized with `can()` BEFORE any repository is built:
- `tenant` (default): reads need `rules.read` on the active tenant and see the global rows plus
  that tenant's rows; writes need `rules.manage` on the active tenant and reach only its rows.
  `tenant_id` always comes from the `TenantContext`, never from the request.
- `global`: every verb needs `rules.manage` on the global scope (the instance admin flag), needs
  no active tenant, and reaches only global rows.

Outcomes: a rule that is missing, of another tenant or malformed is `RuleNotFound` (404), as is a
tenant-scoped call with no active tenant. A denied permission is `ScopeForbidden` (403), and so is
a tenant-path write to a global row: that row is visible to the caller, who may not change it.

Deliberate seed semantics:
- Every accepted edit of a seeded global row sets `locally_modified`, so the next seed sync keeps
  the edit (the repository's `update` does not set it). That includes a PATCH whose values happen
  to equal the current ones: the admin has taken ownership of the row.
- A seeded global row cannot be deleted (`SeededRuleNotDeletable`, 409). The seed sync would
  recreate it, and tenant overrides would silently stop overriding in between. Disabling it is
  the supported way to turn it off, and survives the sync because that edit is locally modified.
  Global rows without a seed_key are deleted normally; no override can reference them.
- Tenant overrides are keyed by `seed_key` (`merge_tenant_rules`), so editing a global row changes
  what other tenants run while an override keeps replacing it for its own tenant.

`test_pattern` stores nothing and touches no repository. A search that did not finish is never
reported as "no match": see `RuleTestOutcome`. It can block for several seconds, so async callers
run it in a worker thread.

Audit: writes log the actor, rule id and scope only. Patterns and samples are never logged.
Field checks are the repository's own, so its limits and reasons are not restated here.
"""

from __future__ import annotations

import enum
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy.orm import Session

from app.core.permissions import (
    Action,
    Principal,
    RuleScope,
    RuleScopeResource,
    TenantResource,
    can,
)
from app.core.safe_regex import RegexRuleError, SearchFailure, compile_checked, search_all
from app.core.tenancy import TenantContext
from app.repositories import GlobalContentRuleRepository, repo_for
from app.repositories.base import DEFAULT_LIMIT
from app.repositories.content_rules import (
    TENANT_FIELDS,
    ContentRuleInvalid,
    ContentRuleRecord,
    ContentRuleRepository,
    SeedKeyTaken,
    _clean_values,
    _text,
)
from app.services.content_rules_engine import _evidence, _find_keyword, _fold, _keyword_is_valid

logger = logging.getLogger("app.rules")

MAX_SAMPLE_BYTES: Final = 32 * 1024
MAX_TEST_MATCHES: Final = 20
MAX_SNIPPET_CHARS: Final = 120
TEST_TIMEOUT_S: Final = 1.0

# seed_key is owned by the seed sync on global rows; on tenant rows it declares an override.
GLOBAL_WRITE_FIELDS: Final = TENANT_FIELDS - {"seed_key"}
_TEST_FIELDS: Final = frozenset({"kind", "pattern", "flags", "sample"})

NOT_FOUND_KEY: Final = "api.rules.error.not_found"
SCOPE_FORBIDDEN_KEY: Final = "api.rules.error.scope_forbidden"
SEED_KEY_TAKEN_KEY: Final = "api.rules.error.seed_key_taken"
SEEDED_DELETE_KEY: Final = "api.rules.error.seeded_delete"
INVALID_FIELD_KEY: Final = "api.rules.error.invalid_field"
INVALID_PATTERN_KEY: Final = "api.rules.error.invalid_pattern"
PATTERN_TOO_LONG_KEY: Final = "api.rules.error.pattern_too_long"
INVALID_WEIGHT_KEY: Final = "api.rules.error.invalid_weight"
INVALID_LANGUAGE_KEY: Final = "api.rules.error.invalid_language"
SAMPLE_TOO_LARGE_KEY: Final = "api.rules.error.sample_too_large"
TIMED_OUT_KEY: Final = "api.rules.error.timed_out"
BUSY_KEY: Final = "api.rules.error.busy"
TEST_FAILED_KEY: Final = "api.rules.error.test_failed"


def field_key(field: str, reason: str) -> str:
    """The i18n key of a rejected field."""
    if field == "pattern":
        return PATTERN_TOO_LONG_KEY if reason == "too_long" else INVALID_PATTERN_KEY
    if field == "sample" and reason == "too_long":
        return SAMPLE_TOO_LARGE_KEY
    return {"weight": INVALID_WEIGHT_KEY, "language": INVALID_LANGUAGE_KEY}.get(
        field, INVALID_FIELD_KEY
    )


class RulesAdminError(Exception):
    """Base error. `status` is the HTTP status, `key` the i18n key; never carries user input."""

    status = 500
    key = "ui.error.server.detail"


class RuleNotFound(RulesAdminError):
    status = 404
    key = NOT_FOUND_KEY


class ScopeForbidden(RulesAdminError):
    status = 403
    key = SCOPE_FORBIDDEN_KEY


class SeedKeyConflict(RulesAdminError):
    status = 409
    key = SEED_KEY_TAKEN_KEY


class SeededRuleNotDeletable(RulesAdminError):
    status = 409
    key = SEEDED_DELETE_KEY


class RuleFieldInvalid(RulesAdminError):
    """A rejected field: its name and a stable reason code, never its value."""

    status = 422

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason
        self.key = field_key(field, reason)


class RuleTestStatus(enum.StrEnum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    TIMED_OUT = "timed_out"  # no verdict: the search ran out of time
    BUSY = "busy"  # no verdict: every worker slot is taken, retry later
    ERROR = "error"  # no verdict: the worker failed
    INVALID = "invalid"  # the pattern or flags were rejected and nothing ran


@dataclass(frozen=True, slots=True)
class RuleTestMatch:
    start: int
    end: int | None  # None when case folding changed the length of a keyword's text
    snippet: str | None  # bounded; None when nothing printable surrounds the match


@dataclass(frozen=True, slots=True)
class RuleTestOutcome:
    status: RuleTestStatus
    matches: tuple[RuleTestMatch, ...] = ()
    truncated: bool = False  # more matches exist than are listed
    key: str | None = None  # i18n key explaining a status without a verdict
    reason: str | None = None  # stable code of an `invalid` status

    @property
    def timed_out(self) -> bool:
        return self.status is RuleTestStatus.TIMED_OUT


def _snippet(sample: str, start: int) -> str | None:
    return _evidence(sample, start, MAX_SNIPPET_CHARS)


class ContentRulesAdminService:
    """One request's rule operations. `ctx` is None when the session has no active tenant."""

    def __init__(self, db: Session, ctx: TenantContext | None, principal: Principal) -> None:
        self._db = db
        self._ctx = ctx
        self._principal = principal

    # --- authorization ------------------------------------------------------------------------

    def _tenant_id(self) -> int:
        if self._ctx is None:
            raise RuleNotFound
        return self._ctx.tenant_id

    def check_read(self, scope: RuleScope) -> None:
        """Global: `rules.manage` on the global scope. Tenant: `rules.read`. No repository use."""
        if scope is RuleScope.GLOBAL:
            self.check_manage(scope)
        elif not can(self._principal, Action.RULES_READ, TenantResource(self._tenant_id())):
            raise ScopeForbidden

    def check_manage(self, scope: RuleScope) -> None:
        """`rules.manage` on `scope`, the tenant always being the context's. No repository use."""
        tenant_id = None if scope is RuleScope.GLOBAL else self._tenant_id()
        if not can(self._principal, Action.RULES_MANAGE, RuleScopeResource(scope, tenant_id)):
            raise ScopeForbidden

    def check_write(self, scope: RuleScope, rule_id: object) -> None:
        """Router pre-check: the caller may change this rule, whatever the body says."""
        self._writable(scope, rule_id)

    # --- helpers ------------------------------------------------------------------------------

    def _tenant_store(self) -> ContentRuleRepository:
        assert self._ctx is not None  # guaranteed by the permission checks
        return repo_for(self._ctx, self._db).content_rules

    def _store(self, scope: RuleScope) -> ContentRuleRepository | GlobalContentRuleRepository:
        if scope is RuleScope.GLOBAL:
            return GlobalContentRuleRepository(self._db)
        return self._tenant_store()

    def _writable(self, scope: RuleScope, rule_id: object) -> ContentRuleRecord:
        self.check_manage(scope)
        current = self._store(scope).get(rule_id)
        if current is None:
            raise RuleNotFound
        if scope is RuleScope.TENANT and current.scope != RuleScope.TENANT.value:
            raise ScopeForbidden
        return current

    @staticmethod
    def _payload(scope: RuleScope, data: Mapping[str, Any]) -> dict[str, Any]:
        """Only fields the API may set. Unknown names (scope, tenant_id, locally_modified...) are
        rejected without being echoed."""
        allowed = GLOBAL_WRITE_FIELDS if scope is RuleScope.GLOBAL else TENANT_FIELDS
        if not data:
            raise RuleFieldInvalid("body", "empty")
        if any(name not in allowed for name in data):
            raise RuleFieldInvalid("body", "unknown_field")
        return dict(data)

    @staticmethod
    def _check_keyword(kind: object, pattern: object) -> None:
        """The engine reports a blank keyword as a broken rule: refuse to store one. Every other
        rejection of the value (empty, too long, NUL...) stays with the repository."""
        if kind == "keyword" and isinstance(pattern, str) and pattern and not pattern.strip():
            raise RuleFieldInvalid("pattern", "invalid_keyword")

    def _audit(self, event: str, rule_id: int, scope: RuleScope) -> None:
        logger.info(
            "content rule changed",
            extra={
                "event": f"rules.{event}",
                "actor": self._principal.user_id,
                "rule_id": rule_id,
                "rule_scope": scope.value,
            },
        )

    # --- reads --------------------------------------------------------------------------------

    def list_rules(
        self, scope: RuleScope, *, limit: int = DEFAULT_LIMIT, offset: int = 0
    ) -> Sequence[ContentRuleRecord]:
        self.check_read(scope)
        return self._store(scope).list(limit=limit, offset=offset)

    def get_rule(self, scope: RuleScope, rule_id: object) -> ContentRuleRecord:
        self.check_read(scope)
        record = self._store(scope).get(rule_id)
        if record is None:
            raise RuleNotFound
        return record

    # --- writes -------------------------------------------------------------------------------

    def create(self, scope: RuleScope, data: Mapping[str, Any]) -> ContentRuleRecord:
        self.check_manage(scope)
        values = self._payload(scope, data)
        self._check_keyword(values.get("kind"), values.get("pattern"))
        try:
            if scope is RuleScope.GLOBAL:
                record = GlobalContentRuleRepository(self._db).create(
                    values, actor=self._principal.user_id
                )
            else:
                record = self._tenant_store().create(values)
        except ContentRuleInvalid as exc:
            self._db.rollback()
            raise RuleFieldInvalid(exc.field, exc.reason) from None
        except SeedKeyTaken:
            self._db.rollback()
            raise SeedKeyConflict from None
        self._db.commit()
        self._audit("created", record.id, scope)
        return record

    def update(
        self, scope: RuleScope, rule_id: object, data: Mapping[str, Any]
    ) -> ContentRuleRecord:
        current = self._writable(scope, rule_id)
        values = self._payload(scope, data)
        self._check_keyword(
            values.get("kind", current.kind), values.get("pattern", current.pattern)
        )
        if scope is RuleScope.GLOBAL and current.seed_key is not None:
            values["locally_modified"] = True
        try:
            record = self._store(scope).update(current.id, values)
        except ContentRuleInvalid as exc:
            self._db.rollback()
            raise RuleFieldInvalid(exc.field, exc.reason) from None
        except SeedKeyTaken:
            self._db.rollback()
            raise SeedKeyConflict from None
        if record is None:  # deleted concurrently
            raise RuleNotFound
        self._db.commit()
        self._audit("updated", record.id, scope)
        return record

    def delete(self, scope: RuleScope, rule_id: object) -> None:
        current = self._writable(scope, rule_id)
        if scope is RuleScope.GLOBAL and current.seed_key is not None:
            raise SeededRuleNotDeletable
        if not self._store(scope).delete(current.id):
            raise RuleNotFound
        self._db.commit()
        self._audit("deleted", current.id, scope)

    # --- test on a sample -----------------------------------------------------------------------

    @staticmethod
    def _sample(value: object) -> str:
        try:
            sample = _text("sample", value, MAX_SAMPLE_BYTES)
        except ContentRuleInvalid as exc:
            raise RuleFieldInvalid(exc.field, exc.reason) from None
        if len(sample.encode("utf-8")) > MAX_SAMPLE_BYTES:
            raise RuleFieldInvalid("sample", "too_long")
        return sample

    def test_pattern(self, scope: RuleScope, data: Mapping[str, Any]) -> RuleTestOutcome:
        """Run a pattern on a sample. Stores nothing, touches no repository, logs nothing."""
        self.check_manage(scope)
        if any(name not in _TEST_FIELDS for name in data):
            raise RuleFieldInvalid("body", "unknown_field")
        try:
            kind = _clean_values({"kind": data.get("kind")}, TENANT_FIELDS)["kind"]
        except ContentRuleInvalid as exc:
            raise RuleFieldInvalid(exc.field, exc.reason) from None
        sample = self._sample(data.get("sample"))
        try:
            cleaned = _clean_values(
                {"pattern": data.get("pattern"), "flags": data.get("flags", 0)}, TENANT_FIELDS
            )
        except ContentRuleInvalid as exc:
            key = field_key("pattern", exc.reason)
            return RuleTestOutcome(RuleTestStatus.INVALID, key=key, reason=exc.reason)
        if kind == "keyword":
            return self._test_keyword(cleaned["pattern"], sample)
        return self._test_regex(cleaned["pattern"], cleaned["flags"], sample)

    @staticmethod
    def _test_keyword(pattern: str, sample: str) -> RuleTestOutcome:
        if not _keyword_is_valid(pattern):
            return RuleTestOutcome(
                RuleTestStatus.INVALID, key=INVALID_PATTERN_KEY, reason="invalid_keyword"
            )
        needle = pattern.casefold()
        haystack, offsets = _fold(sample)
        # Same matching as the engine, whose default is word_boundary=True.
        found = _find_keyword(haystack, needle, True, False)
        if found is None:
            return RuleTestOutcome(RuleTestStatus.NO_MATCH)
        start = found if offsets is None else offsets[found]
        end = None if offsets is not None else found + len(needle)
        match = RuleTestMatch(start, end, _snippet(sample, start))
        return RuleTestOutcome(RuleTestStatus.MATCHED, (match,))

    @staticmethod
    def _test_regex(pattern: str, flags: int, sample: str) -> RuleTestOutcome:
        try:
            compiled = compile_checked(pattern, flags)
        except RegexRuleError as exc:
            reason = exc.reason.value
            key = field_key("pattern", reason)
            return RuleTestOutcome(RuleTestStatus.INVALID, key=key, reason=reason)
        result = search_all(
            compiled,
            sample,
            timeout_s=TEST_TIMEOUT_S,
            max_matches=MAX_TEST_MATCHES,
            max_text_bytes=MAX_SAMPLE_BYTES,
        )
        if result.timed_out:
            return RuleTestOutcome(RuleTestStatus.TIMED_OUT, key=TIMED_OUT_KEY)
        if result.failure is SearchFailure.BUSY:
            return RuleTestOutcome(RuleTestStatus.BUSY, key=BUSY_KEY)
        if result.failure is not None:
            return RuleTestOutcome(RuleTestStatus.ERROR, key=TEST_FAILED_KEY)
        matches = tuple(
            RuleTestMatch(m.start, m.end, _snippet(sample, m.start)) for m in result.matches
        )
        status = RuleTestStatus.MATCHED if matches else RuleTestStatus.NO_MATCH
        return RuleTestOutcome(status, matches, truncated=result.truncated)
