"""M1-10 core tenancy models and migration 0002. Every DB test runs on SQLite and, when
TEST_DATABASE_URL is set, on PostgreSQL (via the shared DB fixtures); the schema is always
built by Alembic, never by create_all, so the migration itself is what gets tested."""

import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

from app.core.db import create_db_engine, create_session_factory
from app.models import Base, Domain, DomainAccess, Membership, MembershipRole, Tenant, User
from app.models.domain import normalize_domain_name
from app.models.user import normalize_email

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
CORE_TABLES = {"users", "tenants", "memberships", "domains", "domain_access"}

# Seed: two tenants, one user member of both, one user with no membership, the same domain name
# in both tenants, a client viewer (membership 3) with access to domains 1 and 3 of tenant 1.
SEED = [
    "INSERT INTO tenants (id, name, slug) VALUES (1, 'Tenant A', 'a'), (2, 'Tenant B', 'b')",
    "INSERT INTO users (id, email) VALUES (1, 'one@example.com'), (2, 'two@example.com'), "
    "(3, 'three@example.com')",
    "INSERT INTO memberships (id, user_id, tenant_id, role) VALUES "
    "(1, 1, 1, 'owner'), (2, 1, 2, 'client_viewer'), (3, 2, 1, 'client_viewer')",
    "INSERT INTO domains (id, tenant_id, name) VALUES "
    "(1, 1, 'example.com'), (2, 2, 'example.com'), (3, 1, 'example.org')",
    "INSERT INTO domain_access (membership_id, domain_id, tenant_id) VALUES (3, 1, 1), (3, 3, 1)",
]


def _cfg() -> Config:
    return Config(str(ROOT / "alembic.ini"))


@pytest.fixture
def migrated(migrated_db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    monkeypatch.setenv("DATABASE_URL", migrated_db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    engine = create_db_engine(migrated_db_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def seeded(migrated: Engine) -> Engine:
    with migrated.begin() as conn:
        for statement in SEED:
            conn.execute(text(statement))
        if migrated.dialect.name == "postgresql":
            # Explicit ids do not advance PG sequences; without this, later inserts would fail
            # on the primary key instead of the constraint under test.
            for table in ("tenants", "users", "memberships", "domains"):
                conn.execute(
                    text(
                        f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                        f"(SELECT MAX(id) FROM {table}))"
                    )
                )
    return migrated


def _count(engine: Engine, table: str, where: str = "1=1") -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(f"SELECT COUNT(*) FROM {table} WHERE {where}")).scalar_one())


# --- migration ---------------------------------------------------------------------------------


def test_upgrade_downgrade_roundtrip(real_migrations_engine: Engine) -> None:
    assert set(inspect(real_migrations_engine).get_table_names()) >= CORE_TABLES
    command.downgrade(_cfg(), "0001")
    assert not CORE_TABLES & set(inspect(real_migrations_engine).get_table_names())
    command.downgrade(_cfg(), "base")
    command.upgrade(_cfg(), "head")
    assert set(inspect(real_migrations_engine).get_table_names()) >= CORE_TABLES


def test_no_autogenerate_diff_after_upgrade(real_migrations_engine: Engine) -> None:
    with real_migrations_engine.connect() as conn, warnings.catch_warnings():
        # SQLite cannot reflect expression indexes (uq_users_email_lower); Alembic skips them
        # with a warning. PostgreSQL compares them. Uniqueness is tested below on both.
        warnings.filterwarnings("ignore", message=".*expression-based index.*")
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


# --- constraints (raw SQL: the database must enforce them, not the ORM) -------------------------

T = "INSERT INTO tenants (name, slug) VALUES "
U = "INSERT INTO users (email) VALUES "
M = "INSERT INTO memberships (user_id, tenant_id, role) VALUES "
D = "INSERT INTO domains (tenant_id, name) VALUES "
A = "INSERT INTO domain_access (membership_id, domain_id, tenant_id) VALUES "

VIOLATIONS = [
    ("duplicate domain in same tenant", D + "(1, 'example.com')"),
    ("domain with null tenant_id", D + "(NULL, 'x.example')"),
    ("domain with unknown tenant", D + "(99, 'x.example')"),
    ("domain name not lowercase", D + "(1, 'Upper.Example')"),
    ("domain name empty", D + "(1, '')"),
    ("domain name null", D + "(1, NULL)"),
    ("membership with null tenant_id", M + "(2, NULL, 'analyst')"),
    ("membership with unknown user", M + "(99, 2, 'analyst')"),
    ("duplicate membership (user, tenant)", M + "(1, 1, 'analyst')"),
    ("membership with invalid role", M + "(2, 2, 'superuser')"),
    ("membership with null role", M + "(2, 2, NULL)"),
    ("domain_access with null tenant_id", A + "(1, 3, NULL)"),
    ("cross-tenant domain_access (membership tenant)", A + "(3, 2, 1)"),
    ("cross-tenant domain_access (domain tenant)", A + "(3, 2, 2)"),
    ("domain_access with unknown domain", A + "(3, 99, 1)"),
    ("domain_access with unknown membership", A + "(99, 1, 1)"),
    ("duplicate domain_access", A + "(3, 1, 1)"),
    ("duplicate email, different case", U + "('ONE@Example.com')"),
    ("user with null email", U + "(NULL)"),
    ("duplicate tenant slug", T + "('Other', 'a')"),
    ("tenant with null slug", T + "('Other', NULL)"),
    # Users are deactivated, not deleted: memberships restrict the delete.
    ("delete user with memberships", "DELETE FROM users WHERE id = 2"),
    ("delete user with memberships in two tenants", "DELETE FROM users WHERE id = 1"),
    # Key changes under existing references (ON UPDATE NO ACTION) must not move rows across
    # tenants or orphan access rows.
    ("move membership with access rows", "UPDATE memberships SET tenant_id = 2 WHERE id = 3"),
    ("move domain with access rows", "UPDATE domains SET tenant_id = 2 WHERE id = 3"),
    (
        "change domain_access tenant",
        "UPDATE domain_access SET tenant_id = 2 WHERE membership_id = 3 AND domain_id = 1",
    ),
    (
        "point domain_access at another tenant's domain",
        "UPDATE domain_access SET domain_id = 2 WHERE membership_id = 3 AND domain_id = 1",
    ),
    ("change referenced tenant id", "UPDATE tenants SET id = 99 WHERE id = 1"),
    ("change referenced membership id", "UPDATE memberships SET id = 99 WHERE id = 3"),
]

ALLOWED = [
    ("same domain name in another tenant", D + "(2, 'example.org')"),
    ("same-tenant domain_access", A + "(1, 3, 1)"),
    ("user in a second tenant", M + "(2, 2, 'analyst')"),
    ("distinct email", U + "('four@example.com')"),
]


@pytest.mark.parametrize(("case", "statement"), VIOLATIONS, ids=[c for c, _ in VIOLATIONS])
def test_constraint_violation_rejected(seeded: Engine, case: str, statement: str) -> None:
    with pytest.raises(IntegrityError), seeded.begin() as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(("case", "statement"), ALLOWED, ids=[c for c, _ in ALLOWED])
def test_valid_insert_accepted(seeded: Engine, case: str, statement: str) -> None:
    with seeded.begin() as conn:
        assert conn.execute(text(statement)).rowcount == 1


def test_server_defaults(seeded: Engine) -> None:
    with seeded.connect() as conn:
        user = conn.execute(
            text("SELECT password_hash, language, is_instance_admin, is_active FROM users")
        ).first()
        language = conn.execute(text("SELECT language FROM tenants WHERE id = 1")).scalar_one()
    assert user is not None
    assert user.password_hash is None
    assert user.language == "en"
    assert user.is_instance_admin in (False, 0)
    assert user.is_active in (True, 1)
    assert language == "en"
    factory = create_session_factory(seeded)
    with factory() as session:
        membership = session.get(Membership, 1)
        assert membership is not None
        assert membership.feature_toggles == {}
        assert membership.role is MembershipRole.OWNER


# --- delete behaviour: cascade, no orphans ------------------------------------------------------

DELETES = [
    # (statement, expected remaining rows per table)
    (
        "DELETE FROM tenants WHERE id = 1",
        {"tenants": 1, "users": 3, "memberships": 1, "domains": 1, "domain_access": 0},
    ),
    (
        "DELETE FROM users WHERE id = 3",  # no memberships: allowed
        {"tenants": 2, "users": 2, "memberships": 3, "domains": 3, "domain_access": 2},
    ),
    (
        "DELETE FROM domains WHERE id = 1",
        {"tenants": 2, "users": 3, "memberships": 3, "domains": 2, "domain_access": 1},
    ),
    (
        "DELETE FROM memberships WHERE id = 3",
        {"tenants": 2, "users": 3, "memberships": 2, "domains": 3, "domain_access": 0},
    ),
    (
        "DELETE FROM domains WHERE id = 2",
        {"tenants": 2, "users": 3, "memberships": 3, "domains": 2, "domain_access": 2},
    ),
]


@pytest.mark.parametrize(("statement", "expected"), DELETES, ids=[s for s, _ in DELETES])
def test_delete_cascades_without_orphans(
    seeded: Engine, statement: str, expected: dict[str, int]
) -> None:
    with seeded.begin() as conn:
        conn.execute(text(statement))
    assert {table: _count(seeded, table) for table in expected} == expected
    orphans = {
        "memberships": "tenant_id NOT IN (SELECT id FROM tenants) "
        "OR user_id NOT IN (SELECT id FROM users)",
        "domains": "tenant_id NOT IN (SELECT id FROM tenants)",
        "domain_access": "membership_id NOT IN (SELECT id FROM memberships) "
        "OR domain_id NOT IN (SELECT id FROM domains) "
        "OR tenant_id NOT IN (SELECT id FROM tenants)",
    }
    assert {table: _count(seeded, table, where) for table, where in orphans.items()} == {
        "memberships": 0,
        "domains": 0,
        "domain_access": 0,
    }


# --- ORM ----------------------------------------------------------------------------------------


def test_orm_roundtrip(migrated: Engine) -> None:
    factory = create_session_factory(migrated)
    with factory.begin() as session:
        tenant = Tenant(name="Agency", slug="agency")
        user = User(email="Viewer@Example.com", is_instance_admin=True)
        session.add_all([tenant, user])
        session.flush()
        membership = Membership(
            user_id=user.id,
            tenant_id=tenant.id,
            role=MembershipRole.CLIENT_VIEWER,
            feature_toggles={"content_analysis": False},
        )
        domain = Domain(tenant_id=tenant.id, name=" Mail.Example.COM. ")
        session.add_all([membership, domain])
        session.flush()
        session.add(
            DomainAccess(membership_id=membership.id, domain_id=domain.id, tenant_id=tenant.id)
        )
    with factory() as session:
        stored = session.scalars(select(Membership)).one()
        assert stored.role is MembershipRole.CLIENT_VIEWER
        assert stored.feature_toggles == {"content_analysis": False}
        assert session.scalars(select(Domain.name)).one() == "mail.example.com"
        assert session.scalars(select(User.is_instance_admin)).one() is True


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("Example.COM", "example.com"),
        ("  example.com.  ", "example.com"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("a" * 63 + ".com", "a" * 63 + ".com"),
    ],
)
def test_normalize_domain_name(raw: str, expected: str) -> None:
    assert normalize_domain_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        ".",
        "example..com",
        ".example.com",
        "example.com..",
        "a" * 64 + ".com",
        ("a" * 62 + ".") * 4 + "com",  # 255 chars
        "bücher.de",  # U-label: must be converted to an A-label by the caller
        "exa mple.com",
        "example.com" + chr(0x200B),  # zero-width space
        "exa/mple.com",
    ],
)
def test_normalize_domain_name_rejects_malformed(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain_name(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("user@example.com", "user@example.com"),
        ("  User@Example.COM \n", "user@example.com"),
        ("ÉLODIE@Exemple.fr", "élodie@exemple.fr"),
        ("STRASSE@example.de", "strasse@example.de"),
        ("Straße@example.de", "straße@example.de"),  # lower(), not casefold(): no ß -> ss
        ('"a@b"@example.com', '"a@b"@example.com'),
        ("jos\u00e9@example.com", "jos\u00e9@example.com"),  # Unicode local part
        ("a" * 242 + "@example.com", "a" * 242 + "@example.com"),  # 254 chars: the cap
        (" " + "a" * 242 + "@example.com\t", "a" * 242 + "@example.com"),  # cap after strip
    ],
)
def test_normalize_email(raw: str, expected: str) -> None:
    assert normalize_email(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "user.example.com",
        "@example.com",
        "user@",
        "@",
        "us er@example.com",
        "user@example.com\x00",  # NUL: PostgreSQL text rejects it
        "us\x00er@example.com",
        "user@exa\x01mple.com",  # other C0 controls
        "user@example.com\x7f",  # DEL
        "user@exa\x85mple.com",  # C1
        "user@example.com\ud800",  # lone surrogate
        "a" * 243 + "@example.com",  # 255 chars: over the cap
    ],
)
def test_normalize_email_rejects_malformed(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_email(raw)


def test_email_uniqueness_non_ascii_case_via_orm(migrated: Engine) -> None:
    """SQLite's lower() folds only ASCII; the ORM validator makes the index hold anyway."""
    factory = create_session_factory(migrated)
    with factory.begin() as session:
        session.add(User(email="élodie@exemple.fr"))
    with pytest.raises(IntegrityError), factory.begin() as session:
        session.add(User(email="ÉLODIE@exemple.fr"))
