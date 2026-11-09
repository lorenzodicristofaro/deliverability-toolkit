"""M5-18 content rules admin service: authorization, seed and override semantics, sample tests.

Runs on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL. The regex worker is a local
subprocess; no network.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import create_db_engine, create_session_factory
from app.core.permissions import MembershipGrant, Principal, RuleScope
from app.core.safe_regex import _WORKER_SLOTS, MAX_LIVE_WORKERS, Match, MatchResult, SearchFailure
from app.core.tenancy import TenantContext
from app.models import MembershipRole, Tenant, User
from app.models.content_rule import ContentRule
from app.repositories import GlobalContentRuleRepository, repo_for
from app.services import content_rules_admin as admin
from app.services.content_analysis import load_tenant_rules
from app.services.content_rules_admin import (
    ContentRulesAdminService,
    RuleFieldInvalid,
    RuleNotFound,
    RulesAdminError,
    RuleTestStatus,
    ScopeForbidden,
    SeededRuleNotDeletable,
    SeedKeyConflict,
)
from app.services.content_rules_engine import merge_tenant_rules
from app.services.seed_sync import sync_content_rules
from tests.support.socket_guard import db_endpoint, install

KEY = "k" * 40
SEED_KEY = "all_caps_run"
SECRET = "SECRET-PATTERN-7301"
GLOBAL = RuleScope.GLOBAL
TENANT = RuleScope.TENANT


def rule(**overrides: Any) -> dict[str, Any]:
    return {
        "name": "Rule",
        "kind": "keyword",
        "pattern": "free money",
        "weight": 10,
        "category": "spam",
        "severity": "low",
        "title": "A title",
        **overrides,
    }


@dataclass
class World:
    db: Session
    tenant_a: int
    tenant_b: int
    users: dict[str, int]

    def principal(self, who: str) -> Principal:
        roles = {
            "owner": MembershipRole.OWNER,
            "admin": MembershipRole.ADMIN,
            "analyst": MembershipRole.ANALYST,
            "viewer": MembershipRole.CLIENT_VIEWER,
        }
        if who == "root":
            return Principal(self.users["root"], True, is_instance_admin=True)
        grant = MembershipGrant(self.tenant_a, roles[who])
        return Principal(self.users[who], True, False, self.tenant_a, (grant,))

    def service(self, who: str) -> ContentRulesAdminService:
        ctx = None if who == "root" else TenantContext(self.tenant_a, self.users[who])
        return ContentRulesAdminService(self.db, ctx, self.principal(who))

    def b_service(self) -> ContentRulesAdminService:
        grant = MembershipGrant(self.tenant_b, MembershipRole.OWNER)
        principal = Principal(self.users["b_owner"], True, False, self.tenant_b, (grant,))
        ctx = TenantContext(self.tenant_b, self.users["b_owner"])
        return ContentRulesAdminService(self.db, ctx, principal)

    def seeded(self) -> Any:
        record = GlobalContentRuleRepository(self.db).get_by_seed_key(SEED_KEY)
        assert record is not None
        return record

    def rows(self) -> int:
        self.db.expire_all()
        return int(self.db.scalar(select(func.count()).select_from(ContentRule)) or 0)

    def effective(self, tenant_id: int) -> list[Any]:
        ctx = TenantContext(tenant_id, None)
        return merge_tenant_rules(load_tenant_rules(ctx, self.db), tenant_id=tenant_id)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "content rules admin", db_endpoint())


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    db = create_session_factory(engine)()
    try:
        a, b = Tenant(name="A", slug="a"), Tenant(name="B", slug="b")
        names = ("owner", "admin", "analyst", "viewer", "root", "b_owner")
        users = {n: User(email=f"{n}@example.com") for n in names}
        db.add_all([a, b, *users.values()])
        db.commit()
        sync_content_rules(db)
        db.commit()
        yield World(db, a.id, b.id, {n: u.id for n, u in users.items()})
    finally:
        db.close()
        engine.dispose()


@pytest.fixture
def repository_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Records every repository construction made by the service."""
    calls: list[str] = []

    def spy(name: str) -> Any:
        def build(*_a: Any, **_k: Any) -> Any:
            calls.append(name)
            raise AssertionError("the repository was reached after a denial")

        return build

    monkeypatch.setattr(admin, "repo_for", spy("repo_for"))
    monkeypatch.setattr(admin, "GlobalContentRuleRepository", spy("global"))
    return calls


# --- authorization -------------------------------------------------------------------------------

VERBS = ("list", "get", "create", "update", "delete", "test")


def _invoke(service: ContentRulesAdminService, verb: str, scope: RuleScope) -> Any:
    sample = {"kind": "keyword", "pattern": "x", "sample": "x"}
    return {
        "list": lambda: service.list_rules(scope),
        "get": lambda: service.get_rule(scope, 1),
        "create": lambda: service.create(scope, rule()),
        "update": lambda: service.update(scope, 1, {"weight": 1}),
        "delete": lambda: service.delete(scope, 1),
        "test": lambda: service.test_pattern(scope, sample),
    }[verb]()


DENIED = [
    *[("analyst", TENANT, v, ScopeForbidden) for v in ("create", "update", "delete", "test")],
    *[("viewer", TENANT, v, ScopeForbidden) for v in VERBS],
    *[(who, GLOBAL, v, ScopeForbidden) for who in ("owner", "admin", "analyst") for v in VERBS],
    # The instance admin flag adds nothing on a tenant path: there is no active tenant here.
    *[("root", TENANT, v, RuleNotFound) for v in VERBS],
]


@pytest.mark.parametrize(("who", "scope", "verb", "error"), DENIED)
def test_denial_never_reaches_a_repository(
    world: World,
    repository_spy: list[str],
    who: str,
    scope: RuleScope,
    verb: str,
    error: type[RulesAdminError],
) -> None:
    with pytest.raises(error):
        _invoke(world.service(who), verb, scope)
    assert repository_spy == []


@pytest.mark.parametrize("verb", VERBS)
def test_inactive_user_is_denied_before_any_repository(
    world: World, repository_spy: list[str], verb: str
) -> None:
    grant = MembershipGrant(world.tenant_a, MembershipRole.OWNER)
    principal = Principal(world.users["owner"], False, False, world.tenant_a, (grant,))
    ctx = TenantContext(world.tenant_a, world.users["owner"])
    with pytest.raises(ScopeForbidden):
        _invoke(ContentRulesAdminService(world.db, ctx, principal), verb, TENANT)
    assert repository_spy == []


def test_stale_context_for_another_tenant_is_denied(
    world: World, repository_spy: list[str]
) -> None:
    """The permission resource follows the context: a principal active in A gets nothing in B."""
    ctx = TenantContext(world.tenant_b, world.users["owner"])
    service = ContentRulesAdminService(world.db, ctx, world.principal("owner"))
    with pytest.raises(ScopeForbidden):
        service.create(TENANT, rule())
    assert repository_spy == []


@pytest.mark.parametrize("who", ["owner", "admin"])
def test_tenant_rule_takes_its_tenant_from_the_context(world: World, who: str) -> None:
    record = world.service(who).create(TENANT, rule())
    assert (record.scope, record.tenant_id) == ("tenant", world.tenant_a)
    assert record.created_by == world.users[who]


@pytest.mark.parametrize("name", ["tenant_id", "scope", "id", "locally_modified", "created_by"])
@pytest.mark.parametrize("verb", ["create", "update"])
def test_reserved_fields_are_rejected(world: World, verb: str, name: str) -> None:
    service = world.service("owner")
    target = service.create(TENANT, rule())
    before = world.rows()
    with pytest.raises(RuleFieldInvalid) as caught:
        if verb == "create":
            service.create(TENANT, rule(**{name: world.tenant_b}))
        else:
            service.update(TENANT, target.id, {name: world.tenant_b})
    assert (caught.value.field, caught.value.reason) == ("body", "unknown_field")
    assert world.rows() == before
    assert service.get_rule(TENANT, target.id).tenant_id == world.tenant_a


@pytest.mark.parametrize("name", ["seed_key", "sources", "status", "verified_on"])
def test_global_create_cannot_claim_seed_owned_fields(world: World, name: str) -> None:
    with pytest.raises(RuleFieldInvalid) as caught:
        world.service("root").create(GLOBAL, rule(**{name: "x"}))
    assert caught.value.reason == "unknown_field"


@pytest.mark.parametrize("verb", ["get", "update", "delete"])
def test_foreign_tenant_rule_is_not_found(world: World, verb: str) -> None:
    foreign = world.b_service().create(TENANT, rule(name="B private"))
    service = world.service("owner")
    with pytest.raises(RuleNotFound):
        if verb == "get":
            service.get_rule(TENANT, foreign.id)
        elif verb == "update":
            service.update(TENANT, foreign.id, {"weight": 1})
        else:
            service.delete(TENANT, foreign.id)
    assert world.b_service().get_rule(TENANT, foreign.id) == foreign


def test_global_path_does_not_reach_tenant_rows(world: World) -> None:
    tenant_rule = world.service("owner").create(TENANT, rule())
    root = world.service("root")
    with pytest.raises(RuleNotFound):
        root.get_rule(GLOBAL, tenant_rule.id)
    with pytest.raises(RuleNotFound):
        root.delete(GLOBAL, tenant_rule.id)
    assert all(r.scope == "global" for r in root.list_rules(GLOBAL))


@pytest.mark.parametrize("verb", ["update", "delete"])
def test_global_row_is_read_only_on_the_tenant_path(world: World, verb: str) -> None:
    seeded = world.seeded()
    owner = world.service("owner")
    assert owner.get_rule(TENANT, seeded.id) == seeded
    with pytest.raises(ScopeForbidden):
        if verb == "update":
            owner.update(TENANT, seeded.id, {"weight": 1})
        else:
            owner.delete(TENANT, seeded.id)
    assert world.seeded() == seeded


@pytest.mark.parametrize("value", [None, 0, -1, True, "1", 2**31, 2**63])
def test_malformed_ids_are_not_found(world: World, value: object) -> None:
    with pytest.raises(RuleNotFound):
        world.service("owner").get_rule(TENANT, value)


def test_analyst_reads_global_and_own_rows_only(world: World) -> None:
    own = world.service("owner").create(TENANT, rule(name="Own"))
    foreign = world.b_service().create(TENANT, rule(name="Foreign"))
    ids = {r.id for r in world.service("analyst").list_rules(TENANT, limit=1000)}
    assert own.id in ids
    assert world.seeded().id in ids
    assert foreign.id not in ids


# --- seed sync and locally_modified --------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [{"weight": 77}, {"pattern": "[A-Z]+"}, {"enabled": True}, {"severity": "high"}],
    ids=lambda c: next(iter(c)),
)
def test_edit_of_a_seeded_rule_survives_the_seed_sync(world: World, change: dict[str, Any]) -> None:
    root = world.service("root")
    edited = root.update(GLOBAL, world.seeded().id, change)
    assert edited.locally_modified is True
    result = sync_content_rules(world.db)
    world.db.commit()
    world.db.expire_all()
    assert SEED_KEY in result.kept_local
    survived = world.seeded()
    for name, value in change.items():
        assert getattr(survived, name) == value


def test_without_the_flag_the_seed_sync_reverts_the_edit(world: World) -> None:
    """Why the service sets it: the repository alone does not protect the edit."""
    GlobalContentRuleRepository(world.db).update(world.seeded().id, {"weight": 77})
    sync_content_rules(world.db)
    world.db.commit()
    world.db.expire_all()
    assert world.seeded().weight != 77


def test_edit_of_an_admin_authored_global_rule_is_not_flagged(world: World) -> None:
    root = world.service("root")
    created = root.create(GLOBAL, rule())
    assert created.created_by == world.users["root"]
    assert root.update(GLOBAL, created.id, {"weight": 3}).locally_modified is False


def test_tenant_rule_edits_are_never_flagged(world: World) -> None:
    owner = world.service("owner")
    created = owner.create(TENANT, rule())
    assert owner.update(TENANT, created.id, {"weight": 3}).locally_modified is False


def test_seeded_global_rule_cannot_be_deleted(world: World) -> None:
    seeded = world.seeded()
    before = world.rows()
    with pytest.raises(SeededRuleNotDeletable):
        world.service("root").delete(GLOBAL, seeded.id)
    assert world.rows() == before
    assert world.seeded() == seeded


def test_disabling_is_how_a_seeded_rule_stays_off(world: World) -> None:
    root = world.service("root")
    enabled = root.update(GLOBAL, world.seeded().id, {"enabled": True})
    root.update(GLOBAL, enabled.id, {"enabled": False})
    sync_content_rules(world.db)
    world.db.commit()
    world.db.expire_all()
    assert world.seeded().enabled is False
    assert world.seeded().locally_modified is True


def test_admin_authored_global_rule_is_deleted_and_stays_deleted(world: World) -> None:
    root = world.service("root")
    created = root.create(GLOBAL, rule())
    root.delete(GLOBAL, created.id)
    sync_content_rules(world.db)
    world.db.commit()
    with pytest.raises(RuleNotFound):
        root.get_rule(GLOBAL, created.id)


# --- tenant overrides ----------------------------------------------------------------------------


def _override(world: World) -> Any:
    return world.service("owner").create(
        TENANT, rule(name="Local", seed_key=SEED_KEY, pattern="override", enabled=False)
    )


def test_override_keeps_replacing_a_global_row_that_was_edited(world: World) -> None:
    override = _override(world)
    edited = world.service("root").update(GLOBAL, world.seeded().id, {"weight": 42})
    a_rules = {r.id: r for r in world.effective(world.tenant_a)}
    assert override.id in a_rules
    assert edited.id not in a_rules
    b_rules = {r.id: r for r in world.effective(world.tenant_b)}
    assert b_rules[edited.id].weight == 42
    assert override.id not in b_rules


def test_refused_delete_leaves_the_override_in_force(world: World) -> None:
    override = _override(world)
    with pytest.raises(SeededRuleNotDeletable):
        world.service("root").delete(GLOBAL, world.seeded().id)
    effective_ids = {r.id for r in world.effective(world.tenant_a)}
    assert override.id in effective_ids
    assert world.seeded().id not in effective_ids


def test_deleting_an_override_brings_the_global_rule_back(world: World) -> None:
    override = _override(world)
    world.service("owner").delete(TENANT, override.id)
    assert world.seeded().id in {r.id for r in world.effective(world.tenant_a)}


def test_override_of_an_unknown_seed_key_is_rejected(world: World) -> None:
    with pytest.raises(RuleFieldInvalid) as caught:
        world.service("owner").create(TENANT, rule(seed_key="no_such_rule"))
    assert (caught.value.field, caught.value.reason) == ("seed_key", "unknown")


def test_second_override_of_a_seed_key_conflicts_and_the_session_stays_usable(world: World) -> None:
    _override(world)
    owner = world.service("owner")
    before = world.rows()
    with pytest.raises(SeedKeyConflict):
        owner.create(TENANT, rule(seed_key=SEED_KEY))
    assert world.rows() == before


# --- validation ----------------------------------------------------------------------------------

BAD_FIELDS: list[tuple[dict[str, Any], str, str, str]] = [
    ({"kind": "regex", "pattern": "("}, "pattern", "invalid_syntax", "invalid_pattern"),
    ({"kind": "regex", "pattern": "a" * 1025}, "pattern", "too_long", "pattern_too_long"),
    ({"pattern": "a" * 1025}, "pattern", "too_long", "pattern_too_long"),
    ({"pattern": ""}, "pattern", "empty", "invalid_pattern"),
    ({"pattern": "   "}, "pattern", "invalid_keyword", "invalid_pattern"),
    ({"pattern": 7}, "pattern", "not_a_string", "invalid_pattern"),
    ({"pattern": "a\x00b"}, "pattern", "nul", "invalid_pattern"),
    ({"pattern": "a\ud800b"}, "pattern", "surrogate", "invalid_pattern"),
    (
        {"kind": "regex", "pattern": "a", "flags": 1 << 20},
        "flags",
        "unsupported_flags",
        "invalid_field",
    ),
    ({"weight": -1}, "weight", "out_of_range", "invalid_weight"),
    ({"weight": 101}, "weight", "out_of_range", "invalid_weight"),
    ({"weight": True}, "weight", "not_an_int", "invalid_weight"),
    ({"weight": "9"}, "weight", "not_an_int", "invalid_weight"),
    ({"weight": 2**40}, "weight", "out_of_range", "invalid_weight"),
    ({"language": "not a language"}, "language", "invalid_format", "invalid_language"),
    ({"language": "e\x00n"}, "language", "nul", "invalid_language"),
    ({"language": "x" * 17}, "language", "too_long", "invalid_language"),
    ({"category": "Not A Slug"}, "category", "invalid_format", "invalid_field"),
    ({"category": "sp\x00am"}, "category", "nul", "invalid_field"),
    ({"name": "x" * 201}, "name", "too_long", "invalid_field"),
    ({"name": "a\x00b"}, "name", "nul", "invalid_field"),
    ({"name": "a\udfffb"}, "name", "surrogate", "invalid_field"),
    ({"title": "a\x00b"}, "title", "nul", "invalid_field"),
    ({"advice": "a\ud800"}, "advice", "surrogate", "invalid_field"),
    ({"kind": "glob"}, "kind", "invalid_choice", "invalid_field"),
    ({"severity": "huge"}, "severity", "invalid_choice", "invalid_field"),
    ({"enabled": "yes"}, "enabled", "not_a_bool", "invalid_field"),
    ({"title": None}, "title", "required", "invalid_field"),
]


@pytest.mark.parametrize(("change", "field", "reason", "key"), BAD_FIELDS)
@pytest.mark.parametrize("verb", ["create", "update"])
def test_invalid_fields_are_rejected_before_the_database(
    world: World, verb: str, change: dict[str, Any], field: str, reason: str, key: str
) -> None:
    owner = world.service("owner")
    target = owner.create(TENANT, rule())
    before = world.rows()
    with pytest.raises(RuleFieldInvalid) as caught:
        if verb == "create":
            owner.create(TENANT, rule(**change))
        else:
            owner.update(TENANT, target.id, change)
    assert (caught.value.field, caught.value.reason) == (field, reason)
    assert caught.value.key == f"api.rules.error.{key}"
    assert world.rows() == before
    assert owner.get_rule(TENANT, target.id) == target


@pytest.mark.parametrize("name", ["name", "kind", "pattern", "weight", "category", "severity"])
def test_required_fields_on_create(world: World, name: str) -> None:
    values = rule()
    del values[name]
    with pytest.raises(RuleFieldInvalid) as caught:
        world.service("owner").create(TENANT, values)
    assert (caught.value.field, caught.value.reason) == (name, "required")


def test_empty_update_is_rejected_and_does_not_flag_the_row(world: World) -> None:
    with pytest.raises(RuleFieldInvalid) as caught:
        world.service("root").update(GLOBAL, world.seeded().id, {})
    assert caught.value.reason == "empty"
    assert world.seeded().locally_modified is False


def test_invalid_edit_does_not_flag_a_seeded_row(world: World) -> None:
    with pytest.raises(RuleFieldInvalid):
        world.service("root").update(GLOBAL, world.seeded().id, {"weight": 1000})
    world.db.expire_all()
    assert world.seeded().locally_modified is False


def test_rejected_pattern_is_not_echoed(world: World) -> None:
    with pytest.raises(RuleFieldInvalid) as caught:
        world.service("owner").create(TENANT, rule(kind="regex", pattern=f"({SECRET}"))
    assert SECRET not in str(caught.value)


def test_switching_kind_revalidates_the_stored_pattern(world: World) -> None:
    owner = world.service("owner")
    created = owner.create(TENANT, rule(pattern="(unbalanced"))
    with pytest.raises(RuleFieldInvalid) as caught:
        owner.update(TENANT, created.id, {"kind": "regex"})
    assert caught.value.reason == "invalid_syntax"


# --- test on a sample ----------------------------------------------------------------------------


def regex(pattern: str, sample: str = "hello world", **extra: Any) -> dict[str, Any]:
    return {"kind": "regex", "pattern": pattern, "sample": sample, **extra}


def keyword(pattern: str, sample: str) -> dict[str, Any]:
    return {"kind": "keyword", "pattern": pattern, "sample": sample}


@pytest.mark.parametrize(
    ("body", "status", "count"),
    [
        (regex("wor"), RuleTestStatus.MATCHED, 1),
        (regex("l"), RuleTestStatus.MATCHED, 3),
        (regex("zzz"), RuleTestStatus.NO_MATCH, 0),
        (regex("WORLD", flags=2), RuleTestStatus.MATCHED, 1),
        (keyword("WORLD", "hello world"), RuleTestStatus.MATCHED, 1),
        (keyword("wor", "hello world"), RuleTestStatus.NO_MATCH, 0),  # engine word boundaries
        (keyword("zzz", "hello world"), RuleTestStatus.NO_MATCH, 0),
    ],
)
def test_sample_outcomes(
    world: World, body: dict[str, Any], status: RuleTestStatus, count: int
) -> None:
    outcome = world.service("owner").test_pattern(TENANT, body)
    assert outcome.status is status
    assert len(outcome.matches) == count
    assert outcome.timed_out is False


@pytest.mark.parametrize(
    ("body", "reason", "key"),
    [
        (regex("("), "invalid_syntax", "invalid_pattern"),
        (regex("a" * 1025), "too_long", "pattern_too_long"),
        (regex(""), "empty", "invalid_pattern"),
        (regex("a\x00b"), "nul", "invalid_pattern"),
        (regex("a\ud800"), "surrogate", "invalid_pattern"),
        (regex(None), "not_a_string", "invalid_pattern"),  # type: ignore[arg-type]
        (regex("a", flags=1 << 20), "unsupported_flags", "invalid_pattern"),
        (regex("a", flags="i"), "not_an_int", "invalid_pattern"),
        (keyword("   ", "x"), "invalid_keyword", "invalid_pattern"),
    ],
)
def test_rejected_pattern_is_invalid_not_no_match(
    world: World, body: dict[str, Any], reason: str, key: str
) -> None:
    outcome = world.service("owner").test_pattern(TENANT, body)
    assert outcome.status is RuleTestStatus.INVALID
    assert outcome.reason == reason
    assert outcome.key == f"api.rules.error.{key}"
    assert outcome.matches == ()


@pytest.mark.parametrize(
    ("body", "field", "reason", "key"),
    [
        (regex("a", "x" * (32 * 1024 + 1)), "sample", "too_long", "sample_too_large"),
        (regex("a", "é" * (16 * 1024 + 1)), "sample", "too_long", "sample_too_large"),
        (regex("a", ""), "sample", "empty", "invalid_field"),
        (regex("a", "a\x00"), "sample", "nul", "invalid_field"),
        (regex("a", "a\ud800"), "sample", "surrogate", "invalid_field"),
        ({"kind": "regex", "pattern": "a"}, "sample", "not_a_string", "invalid_field"),
        ({"pattern": "a", "sample": "a"}, "kind", "invalid_choice", "invalid_field"),
        (
            {"kind": "glob", "pattern": "a", "sample": "a"},
            "kind",
            "invalid_choice",
            "invalid_field",
        ),
        ({**regex("a"), "tenant_id": 2}, "body", "unknown_field", "invalid_field"),
    ],
)
def test_rejected_test_request(
    world: World, body: dict[str, Any], field: str, reason: str, key: str
) -> None:
    with pytest.raises(RuleFieldInvalid) as caught:
        world.service("owner").test_pattern(TENANT, body)
    assert (caught.value.field, caught.value.reason) == (field, reason)
    assert caught.value.key == f"api.rules.error.{key}"


def test_sample_at_the_cap_runs(world: World) -> None:
    outcome = world.service("owner").test_pattern(TENANT, regex("a", "a" * (32 * 1024)))
    assert outcome.status is RuleTestStatus.MATCHED
    assert outcome.truncated is True


@pytest.mark.parametrize(
    ("result", "status", "key"),
    [
        (
            MatchResult((), True, False, SearchFailure.TIMEOUT),
            RuleTestStatus.TIMED_OUT,
            "api.rules.error.timed_out",
        ),
        (
            MatchResult((), True, False, SearchFailure.BATCH_DEADLINE),
            RuleTestStatus.TIMED_OUT,
            "api.rules.error.timed_out",
        ),
        (
            MatchResult((), False, False, SearchFailure.BUSY),
            RuleTestStatus.BUSY,
            "api.rules.error.busy",
        ),
        (
            MatchResult((), False, False, SearchFailure.WORKER_FAILED),
            RuleTestStatus.ERROR,
            "api.rules.error.test_failed",
        ),
        (
            MatchResult((), False, True, SearchFailure.TEXT_TOO_LARGE),
            RuleTestStatus.ERROR,
            "api.rules.error.test_failed",
        ),
        (
            MatchResult((Match(0, 1, "h"),), False, True, None),
            RuleTestStatus.MATCHED,
            None,
        ),
    ],
    ids=["timeout", "batch-deadline", "busy", "worker-failed", "too-large", "truncated"],
)
def test_search_results_map_to_honest_outcomes(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    result: MatchResult,
    status: RuleTestStatus,
    key: str | None,
) -> None:
    monkeypatch.setattr(admin, "search_all", lambda *_a, **_k: result)
    outcome = world.service("owner").test_pattern(TENANT, regex("a"))
    assert outcome.status is status
    assert outcome.key == key
    assert outcome.timed_out is (status is RuleTestStatus.TIMED_OUT)
    assert outcome.truncated is (status is RuleTestStatus.MATCHED)


def test_catastrophic_pattern_times_out_quickly(world: World) -> None:
    started = time.monotonic()
    outcome = world.service("owner").test_pattern(TENANT, regex("(a+)+$", "a" * 40 + "!"))
    assert time.monotonic() - started < 6
    assert outcome.status is RuleTestStatus.TIMED_OUT
    assert outcome.timed_out is True
    assert outcome.matches == ()


def test_saturated_worker_pool_is_busy_not_a_timeout(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(admin, "TEST_TIMEOUT_S", 0.05)
    held = 0
    try:
        for _ in range(MAX_LIVE_WORKERS):
            assert _WORKER_SLOTS.acquire(timeout=5)
            held += 1
        outcome = world.service("owner").test_pattern(TENANT, regex("hello"))
    finally:
        for _ in range(held):
            _WORKER_SLOTS.release()
    assert outcome.status is RuleTestStatus.BUSY
    assert outcome.timed_out is False


def test_snippets_and_match_count_are_bounded(world: World) -> None:
    long_match = world.service("owner").test_pattern(TENANT, regex(".+", "x" * 5000))
    assert len(long_match.matches[0].snippet or "") <= admin.MAX_SNIPPET_CHARS
    many = world.service("owner").test_pattern(TENANT, regex("a", "a " * 500))
    assert len(many.matches) == admin.MAX_TEST_MATCHES
    assert many.truncated is True


def test_keyword_offsets_with_case_folding_that_changes_length(world: World) -> None:
    outcome = world.service("owner").test_pattern(TENANT, keyword("strasse", "die STRAßE hier"))
    assert outcome.status is RuleTestStatus.MATCHED
    assert outcome.matches[0].start == 4
    assert outcome.matches[0].end is None


def test_sample_test_stores_and_logs_nothing(
    world: World, repository_spy: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    body = regex(SECRET, f"text {SECRET} text")
    outcome = world.service("owner").test_pattern(TENANT, body)
    assert outcome.status is RuleTestStatus.MATCHED
    assert repository_spy == []
    assert SECRET not in "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)


# --- audit ---------------------------------------------------------------------------------------


def test_writes_are_audited_without_the_pattern(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="app.rules")
    owner = world.service("owner")
    created = owner.create(TENANT, rule(pattern=SECRET))
    owner.update(TENANT, created.id, {"pattern": f"{SECRET}-2"})
    owner.delete(TENANT, created.id)
    records = [r for r in caplog.records if r.name == "app.rules"]
    assert [r.__dict__["event"] for r in records] == [
        "rules.created",
        "rules.updated",
        "rules.deleted",
    ]
    for record in records:
        assert record.__dict__["actor"] == world.users["owner"]
        assert record.__dict__["rule_id"] == created.id
        assert record.__dict__["rule_scope"] == "tenant"
    assert SECRET not in "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)


def test_failed_write_is_not_audited(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="app.rules")
    with pytest.raises(RuleFieldInvalid):
        world.service("owner").create(TENANT, rule(weight=-1))
    assert not [r for r in caplog.records if r.name == "app.rules"]


def test_repo_for_builds_the_store_with_the_request_context(world: World) -> None:
    """The tenant path uses the ordinary context-bound repository, nothing wider."""
    ctx = TenantContext(world.tenant_a, world.users["owner"])
    created = world.service("owner").create(TENANT, rule())
    assert repo_for(ctx, world.db).content_rules.get(created.id) == created
