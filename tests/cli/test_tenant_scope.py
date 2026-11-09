"""M5-17a: operator tenant and user selection for CLI commands.

The helper is driven through a test-only Typer command under the real `_UsageGroup`, because its
first production user arrives in M5-17. Offline apart from the test database (socket guard); every
test also checks that the engine was disposed with no connection still checked out.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

import pytest
import typer
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import NoResultFound, OperationalError
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from app.cli import tenant_scope
from app.cli.main import _UsageGroup
from app.cli.tenant_scope import (
    EXIT_DENIED,
    MAX_OPERATOR_ID,
    OperatorScope,
    TenantIdOption,
    UserIdOption,
    operator_scope,
)
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.permissions import Action, TenantResource, can
from app.core.tenancy import TenantContext
from app.models import DomainAccess, Membership, MembershipRole, Tenant, User
from app.repositories import repo_for
from app.web.deps import _build
from tests.support.socket_guard import db_endpoint, install

KEY = "k" * 40
SECRET = "hunter-secret-marker"
PARAM = "bound-parameter-marker"
LOGGER = "app.cli.tenant_scope"
TENANT_A = "Agency Alpha"
TENANT_B = "Zanzibar Confidential"
DOMAIN_A = "alpha.example"
DOMAIN_B = "zanzibar.example"
UNKNOWN_ID = 999_999
EXIT_ERROR = 2
EXIT_USAGE = 64

runner = CliRunner()


@dataclass
class _Spy:
    scopes: list[OperatorScope] = field(default_factory=list)


_spy = _Spy()
_probe_app = typer.Typer(cls=_UsageGroup, add_completion=False, rich_markup_mode=None)


@_probe_app.callback()
def _root() -> None:
    """Keeps `probe` a named subcommand, as in the real app."""


@_probe_app.command("probe")
def _probe(
    tenant_id: TenantIdOption,
    user_id: UserIdOption,
    action: Annotated[str, typer.Option("--action")] = Action.CONTENT_ANALYZE.value,
    lang: Annotated[str, typer.Option("--lang")] = i18n.DEFAULT_LANGUAGE,
    fail: Annotated[str, typer.Option("--fail")] = "",
) -> None:
    with operator_scope(tenant_id, user_id, Action(action), lang=lang) as scope:
        _spy.scopes.append(scope)
        repos = repo_for(scope.ctx, scope.session)
        tenant = repos.tenant.get()
        assert tenant is not None
        typer.echo(tenant.name)
        typer.echo(",".join(d.name for d in repos.domains.list()))
        if fail == "exit":
            raise typer.Exit(5)
        if fail == "boom":
            raise RuntimeError("boom")
        if fail == "db":
            raise OperationalError("SELECT secret", {"param": PARAM}, Exception(SECRET))
        if fail == "bug":
            raise NoResultFound("a programming error")


@dataclass
class World:
    url: str
    tenants: dict[str, int]
    users: dict[str, int]
    domain_a: int


def _member(
    db: Session,
    tenant: int,
    user: User,
    role: MembershipRole,
    toggles: dict[str, Any] | None = None,
) -> Membership:
    membership = Membership(
        tenant_id=tenant, user_id=user.id, role=role, feature_toggles=toggles or {}
    )
    db.add(membership)
    db.flush()
    return membership


def _seed(url: str) -> World:
    engine = create_db_engine(url)
    db = create_session_factory(engine)()
    try:
        tenant_a = Tenant(name=TENANT_A, slug="alpha")
        tenant_b = Tenant(name=TENANT_B, slug="zanzibar")
        names = (
            "owner",
            "admin",
            "analyst",
            "viewer",
            "viewer_unassigned",
            "disabled",
            "no_membership",
            "stale",
            "foreign",
            "toggled",
            "both",
            "ia_no_membership",
            "ia_analyst",
            "ia_viewer",
        )
        users = {
            who: User(
                email=f"{who.replace('_', '-')}@example.org",
                is_active=who != "disabled",
                is_instance_admin=who.startswith("ia_"),
            )
            for who in names
        }
        db.add_all([tenant_a, tenant_b, *users.values()])
        db.flush()
        a, b = tenant_a.id, tenant_b.id
        roles = {
            "owner": MembershipRole.OWNER,
            "admin": MembershipRole.ADMIN,
            "analyst": MembershipRole.ANALYST,
            "viewer": MembershipRole.CLIENT_VIEWER,
            "viewer_unassigned": MembershipRole.CLIENT_VIEWER,
            "disabled": MembershipRole.OWNER,
            "ia_analyst": MembershipRole.ANALYST,
            "ia_viewer": MembershipRole.CLIENT_VIEWER,
            "both": MembershipRole.OWNER,
        }
        memberships = {who: _member(db, a, users[who], role) for who, role in roles.items()}
        _member(db, a, users["toggled"], MembershipRole.ANALYST, {"content.analyze": False})
        _member(db, b, users["foreign"], MembershipRole.OWNER)
        _member(db, b, users["both"], MembershipRole.CLIENT_VIEWER)
        db.delete(_member(db, a, users["stale"], MembershipRole.OWNER))
        domain_a = repo_for(TenantContext(a, None), db).domains.create(DOMAIN_A).id
        repo_for(TenantContext(b, None), db).domains.create(DOMAIN_B)
        db.add(
            DomainAccess(membership_id=memberships["viewer"].id, domain_id=domain_a, tenant_id=a)
        )
        db.commit()
        return World(
            url,
            {"a": a, "b": b, "unknown": UNKNOWN_ID},
            {who: user.id for who, user in users.items()} | {"unknown": UNKNOWN_ID},
            domain_a,
        )
    finally:
        db.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _strict_i18n() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "the CLI tenant scope suite", db_endpoint())


@pytest.fixture(autouse=True)
def _reset_spy() -> None:
    _spy.scopes.clear()


@dataclass
class _Opened:
    engine: Engine
    checked_out_at_dispose: list[int] = field(default_factory=list)


@pytest.fixture(autouse=True)
def opened(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[_Opened]]:
    """Every engine the helper opens; each must end disposed with no connection left out."""
    records: list[_Opened] = []
    real = tenant_scope.engine_from_settings

    def spy(settings: Settings) -> Engine:
        engine = real(settings)
        record = _Opened(engine)
        real_dispose = engine.dispose

        def dispose(*args: Any, **kwargs: Any) -> None:
            record.checked_out_at_dispose.append(engine.pool.checkedout())  # type: ignore[attr-defined]
            real_dispose(*args, **kwargs)

        monkeypatch.setattr(engine, "dispose", dispose)
        records.append(record)
        return engine

    monkeypatch.setattr(tenant_scope, "engine_from_settings", spy)
    yield records
    assert [r.checked_out_at_dispose for r in records] == [[0]] * len(records)


def _set_env(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)


@pytest.fixture
def world(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> World:
    _set_env(monkeypatch, migrated_db_url)
    return _seed(migrated_db_url)


def _invoke(tenant: int | str, user: int | str, *extra: str) -> Any:
    args = ["probe", "--tenant-id", str(tenant), "--user-id", str(user), *extra]
    return runner.invoke(_probe_app, args)


def _assert_clean(result: Any, code: int, message: str) -> None:
    """A clean failure: the exact localized message on stderr, nothing else, no traceback."""
    assert result.exit_code == code, result.output
    assert result.stderr.strip() == message
    assert result.stdout == ""
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert _spy.scopes == []


CONTENT = Action.CONTENT_ANALYZE.value
READ = Action.TENANT_READ.value
USERS = Action.USER_MANAGE.value
MANAGE = Action.TENANT_MANAGE.value

# (user, tenant, action, allowed)
CASES = [
    # Every role, on an action only some roles hold.
    ("owner", "a", CONTENT, True),
    ("admin", "a", CONTENT, True),
    ("analyst", "a", CONTENT, True),
    ("viewer", "a", CONTENT, False),
    ("owner", "a", READ, True),
    ("admin", "a", READ, True),
    ("analyst", "a", READ, True),
    ("viewer", "a", READ, True),
    ("viewer_unassigned", "a", READ, True),
    ("owner", "a", USERS, True),
    ("admin", "a", USERS, True),
    ("analyst", "a", USERS, False),
    ("viewer", "a", USERS, False),
    ("owner", "a", MANAGE, True),
    ("admin", "a", MANAGE, False),
    ("analyst", "a", MANAGE, False),
    ("viewer", "a", MANAGE, False),
    # Unknown, disabled, stale, foreign.
    ("unknown", "a", CONTENT, False),
    ("owner", "unknown", CONTENT, False),
    ("disabled", "a", CONTENT, False),
    ("disabled", "a", READ, False),
    ("no_membership", "a", READ, False),
    ("stale", "a", READ, False),
    ("foreign", "a", READ, False),
    ("owner", "b", READ, False),
    # A per-user toggle only denies.
    ("toggled", "a", CONTENT, False),
    ("toggled", "a", READ, True),
    # The instance admin flag adds nothing inside a tenant: the membership role decides.
    ("ia_no_membership", "a", READ, False),
    ("ia_no_membership", "a", CONTENT, False),
    ("ia_analyst", "a", CONTENT, True),
    ("ia_viewer", "a", CONTENT, False),
    # The role is per tenant.
    ("both", "a", CONTENT, True),
    ("both", "b", CONTENT, False),
    ("both", "b", READ, True),
    ("foreign", "b", CONTENT, True),
    # Actions that are not tenant-level are denied on a TenantResource, for anyone.
    ("owner", "a", Action.CHECK_RUN.value, False),
    ("owner", "a", Action.DOMAIN_READ.value, False),
    ("ia_no_membership", "a", Action.INSTANCE_MANAGE.value, False),
]


@pytest.mark.parametrize(("user", "tenant", "action", "allowed"), CASES)
def test_access_matches_the_web_layer(
    world: World, user: str, tenant: str, action: str, allowed: bool
) -> None:
    result = _invoke(world.tenants[tenant], world.users[user], "--action", action)

    engine = create_db_engine(world.url)
    try:
        with create_session_factory(engine)() as db:
            row = db.scalars(select(User).where(User.id == world.users[user])).one_or_none()
            # app.web.deps._resolve: no live user means anonymous, then _build.
            auth = (
                None
                if row is None or row.is_active is not True
                else _build(db, row, 1, world.tenants[tenant])
            )
    finally:
        engine.dispose()
    web_allowed = (
        auth is not None
        and auth.active_tenant_id == world.tenants[tenant]
        and can(auth.principal, action, TenantResource(world.tenants[tenant]))
    )
    assert web_allowed is allowed, "the expectation in CASES disagrees with the web layer"

    if not allowed:
        _assert_clean(result, EXIT_DENIED, t(tenant_scope.DENIED_KEY))
        return
    assert result.exit_code == 0, result.output
    assert len(_spy.scopes) == 1
    scope = _spy.scopes[0]
    assert auth is not None
    assert scope.principal == auth.principal
    assert scope.ctx == TenantContext(world.tenants[tenant], world.users[user])


def test_client_viewer_gets_assigned_domains_like_the_web(world: World) -> None:
    result = _invoke(world.tenants["a"], world.users["viewer"], "--action", READ)
    assert result.exit_code == 0, result.output
    assert _spy.scopes[0].principal.memberships[0].domain_ids == frozenset({world.domain_a})

    _spy.scopes.clear()
    result = _invoke(world.tenants["a"], world.users["viewer_unassigned"], "--action", READ)
    assert result.exit_code == 0, result.output
    assert _spy.scopes[0].principal.memberships[0].domain_ids == frozenset()


@pytest.mark.parametrize(
    ("user", "tenant", "own_name", "own_domain", "foreign_name", "foreign_domain"),
    [
        ("both", "a", TENANT_A, DOMAIN_A, TENANT_B, DOMAIN_B),
        ("both", "b", TENANT_B, DOMAIN_B, TENANT_A, DOMAIN_A),
    ],
)
def test_tenant_data_is_scoped_to_the_selected_tenant(
    world: World,
    user: str,
    tenant: str,
    own_name: str,
    own_domain: str,
    foreign_name: str,
    foreign_domain: str,
) -> None:
    result = _invoke(world.tenants[tenant], world.users[user], "--action", READ)
    assert result.exit_code == 0, result.output
    assert result.stdout.split("\n")[:2] == [own_name, own_domain]
    assert foreign_name not in result.output
    assert foreign_domain not in result.output


@pytest.mark.parametrize(("lang", "code"), [("en", "en"), ("it", "it"), ("xx", "en")])
def test_denial_is_localized(world: World, lang: str, code: str) -> None:
    result = _invoke(world.tenants["a"], world.users["viewer"], "--lang", lang)
    _assert_clean(result, EXIT_DENIED, t(tenant_scope.DENIED_KEY, code))


def test_every_denial_is_the_same_message(world: World) -> None:
    denials = [
        (world.tenants["a"], world.users["unknown"]),
        (world.tenants["unknown"], world.users["owner"]),
        (world.tenants["a"], world.users["disabled"]),
        (world.tenants["b"], world.users["owner"]),
        (world.tenants["a"], world.users["viewer"]),
    ]
    outputs = {(r.exit_code, r.stderr) for r in (_invoke(*denial) for denial in denials)}
    assert len(outputs) == 1


MALFORMED = [
    "0",
    "-1",
    "abc",
    "1.5",
    "",
    "1_000",
    "+1",
    " 1",
    "1 ",
    "1\n",
    "٣",
    "１",
    "0x1",
    "007",
    str(MAX_OPERATOR_ID + 1),
    str(2**63 - 1),
    str(2**63),
    str(2**64),
    "9" * 30,
    "9" * 5000,
]


@pytest.mark.parametrize("value", MALFORMED)
@pytest.mark.parametrize("option", ["tenant", "user"])
def test_malformed_ids_are_a_usage_error_before_the_database(
    world: World, opened: list[_Opened], option: str, value: str
) -> None:
    valid_tenant, valid_user = world.tenants["a"], world.users["owner"]
    result = _invoke(value, valid_user) if option == "tenant" else _invoke(valid_tenant, value)
    _assert_clean(result, EXIT_USAGE, t("cli.check.error.usage"))
    assert opened == []


@pytest.mark.parametrize(
    "args",
    [
        ["probe"],
        ["probe", "--tenant-id", "1"],
        ["probe", "--user-id", "1"],
        ["probe", "--tenant-id", "--user-id", "1"],
    ],
)
def test_both_options_are_required(opened: list[_Opened], args: list[str]) -> None:
    result = runner.invoke(_probe_app, args)
    _assert_clean(result, EXIT_USAGE, t("cli.check.error.usage"))
    assert opened == []


@pytest.mark.parametrize("bad", [0, -1, MAX_OPERATOR_ID + 1, 2**64, True, "1", None, 1.0], ids=repr)
@pytest.mark.parametrize("position", ["tenant", "user"])
def test_helper_rejects_malformed_ids_when_called_directly(
    opened: list[_Opened], position: str, bad: Any
) -> None:
    tenant, user = (bad, 1) if position == "tenant" else (1, bad)
    with (
        pytest.raises(typer.Exit) as excinfo,
        operator_scope(tenant, user, Action.TENANT_READ),
    ):
        pytest.fail("the block must not run")
    assert excinfo.value.exit_code == EXIT_USAGE
    assert opened == []


def test_largest_valid_id_is_a_clean_denial(world: World) -> None:
    """The boundary value really is bound to the database (PostgreSQL: INTEGER)."""
    denied = t(tenant_scope.DENIED_KEY)
    _assert_clean(_invoke(MAX_OPERATOR_ID, world.users["owner"]), EXIT_DENIED, denied)
    _assert_clean(_invoke(world.tenants["a"], MAX_OPERATOR_ID), EXIT_DENIED, denied)


def test_ids_above_the_column_range_would_reach_the_driver(world: World) -> None:
    """Why MAX_OPERATOR_ID exists. On PostgreSQL the bind is cast to INTEGER and overflows."""
    engine = create_db_engine(world.url)
    try:
        with create_session_factory(engine)() as db:
            stmt = select(User).where(User.id == MAX_OPERATOR_ID + 1)
            if engine.dialect.name == "postgresql":
                with pytest.raises(Exception, match="out of range"):
                    db.scalars(stmt).one_or_none()
            else:
                assert db.scalars(stmt).one_or_none() is None
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("variable", "value", "setting"),
    [
        ("SECRET_KEY", None, "SECRET_KEY"),
        ("ENCRYPTION_KEY", None, "ENCRYPTION_KEY"),
        ("SECRET_KEY", SECRET, "SECRET_KEY"),
        ("RESOLVER_MODE", SECRET, "RESOLVER_MODE"),
        ("DATABASE_URL", "", "DATABASE_URL"),
        ("DATABASE_URL", f"not a url {SECRET}", "DATABASE_URL"),
        ("DATABASE_URL", f"nosuchdb://u:{SECRET}@host/db", "DATABASE_URL"),
        ("DATABASE_URL", f"mysql://u:{SECRET}@host/db", "DATABASE_URL"),
        ("DATABASE_URL", f"postgresql://u:{SECRET}@host:notaport/db", "DATABASE_URL"),
    ],
)
@pytest.mark.parametrize("lang", ["en", "it"])
def test_bad_configuration_exits_cleanly_without_values(
    monkeypatch: pytest.MonkeyPatch,
    opened: list[_Opened],
    variable: str,
    value: str | None,
    setting: str,
    lang: str,
) -> None:
    _set_env(monkeypatch, "sqlite:///unused.db")
    if value is None:
        monkeypatch.delenv(variable)
    else:
        monkeypatch.setenv(variable, value)
    result = _invoke(1, 1, "--lang", lang)
    _assert_clean(result, EXIT_ERROR, t(tenant_scope.CONFIG_KEY, lang, setting=setting))
    assert SECRET not in result.output
    assert opened == []


def test_resolver_entry_is_not_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_env(monkeypatch, "sqlite:///unused.db")
    monkeypatch.setenv("RESOLVER_ADDRS", SECRET)
    result = _invoke(1, 1)
    assert result.exit_code == EXIT_ERROR
    assert SECRET not in result.output


def test_unreachable_database(
    db_backend: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    opened: list[_Opened],
    caplog: pytest.LogCaptureFixture,
) -> None:
    url = (
        f"sqlite:///{tmp_path}/missing-directory/{SECRET}.db"
        if db_backend == "sqlite"
        # A closed loopback port: libpq is refused at once and nothing leaves the host.
        else f"postgresql://ci:{SECRET}@127.0.0.1:1/ci_test"
    )
    _set_env(monkeypatch, url)
    with caplog.at_level(logging.INFO, logger=LOGGER):
        result = _invoke(1, 1)
    _assert_clean(result, EXIT_ERROR, t(tenant_scope.DATABASE_KEY))
    assert SECRET not in result.output
    assert SECRET not in caplog.text
    assert [r.getMessage() for r in caplog.records if r.name == LOGGER] == [
        "cli.operator database error class=OperationalError"
    ]
    assert len(opened) == 1


def test_schema_not_migrated(db_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_env(monkeypatch, db_url)
    _assert_clean(_invoke(1, 1), EXIT_ERROR, t(tenant_scope.SCHEMA_KEY))


def test_partially_migrated_schema(db_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_env(monkeypatch, db_url)
    engine = create_db_engine(db_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
    finally:
        engine.dispose()
    _assert_clean(_invoke(1, 1), EXIT_ERROR, t(tenant_scope.DATABASE_KEY))


def test_driver_error_inside_the_block_is_exit_2_and_logs_only_the_class(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = _invoke(world.tenants["a"], world.users["owner"], "--fail", "db")
    assert result.exit_code == EXIT_ERROR
    assert result.stderr.strip() == t(tenant_scope.DATABASE_KEY)
    records = [r for r in caplog.records if r.name == LOGGER]
    assert [r.getMessage() for r in records] == [
        "cli.operator database error class=OperationalError"
    ]
    # Below WARNING: without logging configured, logging.lastResort would print it on stderr.
    assert records[0].levelno == logging.INFO
    assert records[0].exc_info is None
    for leaked in (SECRET, PARAM, "SELECT"):
        assert leaked not in result.output
        assert leaked not in caplog.text
        assert leaked not in str(vars(records[0]))


def test_other_sqlalchemy_error_inside_the_block_propagates_as_a_bug(
    world: World, opened: list[_Opened], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        result = _invoke(world.tenants["a"], world.users["owner"], "--fail", "bug")
    assert isinstance(result.exception, NoResultFound)
    assert t(tenant_scope.DATABASE_KEY) not in result.output
    assert [r for r in caplog.records if r.name == LOGGER] == []
    assert len(opened) == 1


def test_exit_from_the_block_keeps_its_code(world: World, opened: list[_Opened]) -> None:
    result = _invoke(world.tenants["a"], world.users["owner"], "--fail", "exit")
    assert result.exit_code == 5
    assert len(opened) == 1


def test_unexpected_error_in_the_block_still_closes(world: World, opened: list[_Opened]) -> None:
    result = _invoke(world.tenants["a"], world.users["owner"], "--fail", "boom")
    assert isinstance(result.exception, RuntimeError)
    assert len(opened) == 1


def test_help_describes_both_options() -> None:
    result = runner.invoke(_probe_app, ["probe", "--help"])
    assert result.exit_code == 0
    assert "--tenant-id" in result.output
    assert "--user-id" in result.output
