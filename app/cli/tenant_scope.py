"""Operator tenant and user selection for CLI commands that read tenant data (M5-17a).

`--tenant-id` and `--user-id` select who a command acts as. They are NOT authentication: the
trust boundary stays shell access plus the database configuration (docs/CHECKS.md). What they do
guarantee is that a command gets exactly the access the named user has on the web: the principal
is built from the same repositories and the same `can()` runs. Until a public loader exists, the
loading below mirrors `app.web.deps._build`; tests/cli/test_tenant_scope.py fails if they diverge.

Exit codes: 2 could not evaluate (configuration, database, schema), 64 usage error (as `check`
and `analyze`), 77 permission denied. Every denial prints the same message, so the CLI does not
tell an unknown user from a foreign tenant, as the web answers 404 for all of them.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Annotated

import typer
from sqlalchemy import Engine, inspect, select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.cli.check import EXIT_ERROR, EXIT_USAGE, _fail
from app.core import i18n
from app.core.config import ConfigError, Settings
from app.core.db import create_session_factory, engine_from_settings
from app.core.i18n import t
from app.core.permissions import Action, Principal, TenantResource, can, is_domain_restricted
from app.core.tenancy import TenantContext
from app.models import User
from app.repositories import UserMembershipsRepository, principal_from_models, repo_for

logger = logging.getLogger(__name__)

# sysexits.h EX_NOPERM, next to EXIT_USAGE (EX_USAGE); 0, 1 and 2 already carry check results.
EXIT_DENIED = 77

# users.id and tenants.id are 32-bit Integer columns and the PostgreSQL driver casts binds to
# INTEGER, so a larger value is a DataError, not a miss. `coerce_id` allows 63 bits: not enough.
MAX_OPERATOR_ID = 2**31 - 1

CONFIG_KEY = "cli.operator.error.config"
DATABASE_KEY = "cli.operator.error.database"
DENIED_KEY = "cli.operator.error.denied"
INVALID_ID_KEY = "cli.operator.error.invalid_id"
SCHEMA_KEY = "cli.operator.error.schema"

# Stricter than int(), which also takes "1_000", "+1", " 1" and non-ASCII digits. An operator id
# selects an identity, so only its plain decimal form is accepted.
_ID_TEXT = re.compile(r"[1-9][0-9]{0,9}")


def parse_operator_id(value: str) -> int:
    """Typer parser for the id options; a malformed value is a usage error (exit 64)."""
    if _ID_TEXT.fullmatch(value) is None or int(value) > MAX_OPERATOR_ID:
        raise typer.BadParameter(t(INVALID_ID_KEY))
    return int(value)


# Declared without a default in a command signature, so both options are required.
TenantIdOption = Annotated[
    int,
    typer.Option(
        "--tenant-id",
        parser=parse_operator_id,
        metavar="N",
        help=t("cli.operator.opt.tenant_id"),
    ),
]
UserIdOption = Annotated[
    int,
    typer.Option(
        "--user-id",
        parser=parse_operator_id,
        metavar="M",
        help=t("cli.operator.opt.user_id"),
    ),
]


@dataclass(frozen=True, slots=True)
class OperatorScope:
    """What a command may use inside `operator_scope`. Tenant data goes through
    `repo_for(scope.ctx, scope.session)`; the session is closed when the block ends.

    Repositories scope by tenant only. Filtering for domain-restricted roles is the caller's job:
    a client viewer holds `tenant.read`, yet `repos.domains.list()` returns every domain of the
    tenant. A command that lists or reads domains must use `app.services.domains.DomainService`,
    which filters by grant as the web does.
    """

    session: Session
    ctx: TenantContext
    principal: Principal


def _valid_id(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_OPERATOR_ID


def _engine(lang: str) -> Engine:
    """The app's engine from the environment. Prints a setting name at most, never a value."""
    try:
        return engine_from_settings(Settings())
    except ConfigError as exc:
        raise _fail(CONFIG_KEY, EXIT_ERROR, lang, setting=exc.params.get("name", exc.key)) from None
    except (SQLAlchemyError, ImportError, ValueError):  # unparsable URL or unavailable driver
        raise _fail(CONFIG_KEY, EXIT_ERROR, lang, setting="DATABASE_URL") from None


def _load(db: Session, tenant_id: int, user_id: int) -> tuple[TenantContext, Principal] | None:
    """Context and principal of an active user holding a membership in the tenant, else None.
    The instance admin flag adds nothing here: without a membership there is no context."""
    user = db.scalars(select(User).where(User.id == user_id)).one_or_none()
    if user is None or user.is_active is not True:
        return None
    if UserMembershipsRepository(db, user.id).get_for_tenant(tenant_id) is None:
        return None
    ctx = TenantContext(tenant_id=tenant_id, principal=user.id)
    repos = repo_for(ctx, db)
    membership = repos.memberships.get_by_user(user.id)
    if membership is None:
        return None
    principal = principal_from_models(user, [membership], [], tenant_id)
    if is_domain_restricted(membership.role):
        grant = dataclasses.replace(
            principal.memberships[0],
            domain_ids=repos.domain_access.domain_ids_for_user(user.id),
        )
        principal = dataclasses.replace(principal, memberships=(grant,))
    return ctx, principal


@contextmanager
def operator_scope(
    tenant_id: int, user_id: int, action: Action, *, lang: str = i18n.DEFAULT_LANGUAGE
) -> Iterator[OperatorScope]:
    """Yield the scope of `user_id` in `tenant_id` if `can()` allows `action` on that tenant.

    Otherwise raises `typer.Exit` with a localized message before the block runs: 64 for a
    malformed id (no database is opened), 2 if the configuration, database or schema cannot be
    used, 77 when denied. A driver error (`DBAPIError`) raised inside the block also becomes exit
    2; any other exception, including other SQLAlchemy errors such as `NoResultFound`, is a bug and
    propagates. The session and engine are closed on every path.

    The check is always on a `TenantResource`, so `action` must be tenant-level. A domain-, rule-
    or instance-scoped action (`check.run`, `domain.read`, `rules.manage`, ...) fails closed: it
    exits 77 for every user, so a wrong action passed here looks like a denial.
    """
    if not (_valid_id(tenant_id) and _valid_id(user_id)):
        raise _fail(INVALID_ID_KEY, EXIT_USAGE, lang)
    engine = _engine(lang)
    try:
        with create_session_factory(engine)() as db:
            if not inspect(db.connection()).has_table(User.__tablename__):
                raise _fail(SCHEMA_KEY, EXIT_ERROR, lang)
            loaded = _load(db, tenant_id, user_id)
            if loaded is None or not can(loaded[1], action, TenantResource(tenant_id)):
                raise _fail(DENIED_KEY, EXIT_DENIED, lang)
            yield OperatorScope(session=db, ctx=loaded[0], principal=loaded[1])
    except DBAPIError as exc:
        # The class name only: the text of a DBAPIError holds the SQL and its parameters. INFO
        # because the CLI configures no logging, and WARNING and above would reach stderr through
        # logging.lastResort, next to the localized message.
        logger.info("cli.operator database error class=%s", type(exc).__name__)
        raise _fail(DATABASE_KEY, EXIT_ERROR, lang) from None
    finally:
        engine.dispose()
