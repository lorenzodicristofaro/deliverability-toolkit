"""M1-17 first-run setup wizard: token lifecycle, redirect gate, validation, single admin.

DB tests run on SQLite and, when TEST_DATABASE_URL is set, on PostgreSQL (shared `db_url`
fixture); the schema is built by Alembic. A fast argon2 hasher keeps the suite quick. No network.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.security import SESSION_COOKIE_NAME, verify_password
from app.main import create_app
from app.models import InstanceSetup, Membership, MembershipRole, Tenant, User, UserSession
from app.services import setup as svc
from app.services.auth import SessionPolicy
from app.services.login_throttle import LoginThrottle
from app.web import auth as web_auth
from app.web.templating import APP_NAME

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 40
PASSWORD = "correct horse battery staple"
FAST = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
POLICY = SessionPolicy.from_settings(
    Settings(secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
)
HTML = {"Accept": "text/html"}


def _pw(n: int) -> str:
    """An n-character password that is not on the bundled blocklist."""
    return ("Kv7q" * 40)[:n]


LISTED = "1qaz2wsx3edc4rfv"  # an entry of the bundled common-password list


def _both(value: str) -> dict[str, str]:
    """Password and confirmation form fields with the same value."""
    return {"password": value, "password_confirm": value}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Env:
    db_url: str
    factory: sessionmaker[Session]
    caplog: pytest.LogCaptureFixture

    def app(self, log_level: str = "INFO") -> FastAPI:
        application = create_app(
            Settings(  # type: ignore[call-arg]
                database_url=self.db_url, secret_key=KEY, encryption_key=KEY, log_level=log_level
            )
        )
        application.state.login_throttle = LoginThrottle(clock=Clock())
        return application

    def records(self) -> list[logging.LogRecord]:
        """Records of the fixture setup (app startup) and of the test itself."""
        return self.caplog.get_records("setup") + self.caplog.get_records("call")

    def tokens(self) -> list[str]:
        found = []
        for record in self.records():
            if getattr(record, "event", None) == "setup.token_issued":
                assert record.levelno == logging.WARNING
                found.append(str(record.args[1]))  # type: ignore[index]
        return found

    def db(self) -> Session:
        return self.factory()


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def env(
    db_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> Iterator[Env]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    monkeypatch.setattr(web_auth, "PASSWORD_HASHER", FAST)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    caplog.set_level(logging.DEBUG)
    engine = create_db_engine(db_url)
    try:
        yield Env(db_url, create_session_factory(engine), caplog)
    finally:
        engine.dispose()


@dataclass
class Running:
    client: TestClient
    app: FastAPI
    token: str


@pytest.fixture
def running(env: Env) -> Iterator[Running]:
    application = env.app()
    with TestClient(application) as client:
        (token,) = env.tokens()
        yield Running(client, application, token)
    engine = getattr(application.state, "db_engine", None)
    if engine is not None:
        engine.dispose()


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def _form(r: Running, **overrides: str) -> dict[str, str]:
    data = {
        "csrf_token": _csrf(r.client.get("/setup").text),
        "setup_token": r.token,
        "email": "Admin@Example.com",
        "password": PASSWORD,
        "password_confirm": PASSWORD,
        "tenant_name": "Agency One",
    }
    data.update(overrides)
    return data


def _post(r: Running, **overrides: str) -> Any:
    return r.client.post("/setup", data=_form(r, **overrides), follow_redirects=False)


def _count(env: Env, model: Any) -> int:
    with env.db() as db:
        return int(db.scalar(select(func.count()).select_from(model)) or 0)


def _setup_row(env: Env) -> InstanceSetup | None:
    with env.db() as db:
        return db.scalars(select(InstanceSetup)).one_or_none()


# --- token issuance -------------------------------------------------------------------------------


def test_token_logged_once_at_warning_and_only_its_hash_stored(env: Env, running: Running) -> None:
    records = [r for r in env.records() if running.token in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert "/setup" in records[0].getMessage()
    row = _setup_row(env)
    assert row is not None and row.completed_at is None
    assert row.token_hash == hashlib.sha256(running.token.encode()).hexdigest()
    with env.db() as db:
        dump = " ".join(str(v) for v in db.execute(text("SELECT * FROM instance_setup")).one())
    assert running.token not in dump
    # Further requests do not log the token again.
    running.client.get("/setup")
    running.client.get("/", headers=HTML, follow_redirects=False)
    assert len([r for r in env.records() if running.token in r.getMessage()]) == 1


def test_restart_before_setup_regenerates_token(env: Env) -> None:
    first = env.app()
    with TestClient(first):
        pass
    second = env.app()
    with TestClient(second) as client:
        old, new = env.tokens()
        assert old != new
        r = Running(client, second, old)
        response = _post(r)
        assert response.status_code == 400
        assert "valid setup token is required" in response.text
        assert _count(env, User) == 0
        r.token = new
        assert _post(r).status_code == 303
    for application in (first, second):
        engine = getattr(application.state, "db_engine", None)
        if engine is not None:
            engine.dispose()


def test_no_token_and_404_when_a_user_already_exists(env: Env) -> None:
    with env.db() as db:
        db.add(User(email="existing@example.com"))
        db.commit()
    application = env.app()
    with TestClient(application) as client:
        assert env.tokens() == []
        assert client.get("/setup").status_code == 404
        token = _csrf(client.get("/login").text)
        assert client.get("/login", headers=HTML).status_code == 200  # no redirect to /setup
        response = client.post("/setup", data={"csrf_token": token, "setup_token": "x" * 43})
        assert response.status_code == 404
    assert _setup_row(env) is None
    assert application.state.db_engine is not None
    application.state.db_engine.dispose()


# --- redirect gate --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/"), ("GET", "/login"), ("GET", "/nope"), ("HEAD", "/login"), ("GET", "/static")],
)
def test_ui_routes_redirect_to_setup_while_pending(
    running: Running, method: str, path: str
) -> None:
    response = running.client.request(method, path, headers=HTML, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/setup"
    assert "content-security-policy" in response.headers


def test_post_routes_redirect_to_setup_while_pending(running: Running) -> None:
    token = _csrf(running.client.get("/setup").text)
    for path in ("/login", "/logout", "/tenants/switch"):
        response = running.client.post(path, data={"csrf_token": token}, follow_redirects=False)
        assert (response.status_code, response.headers["location"]) == (303, "/setup"), path


@pytest.mark.parametrize("path", ["/healthz", "/static/app.css", "/setup"])
def test_exempt_paths_are_not_redirected(running: Running, path: str) -> None:
    assert running.client.get(path, headers=HTML, follow_redirects=False).status_code == 200


def test_language_switch_works_on_setup_page(running: Running) -> None:
    token = _csrf(running.client.get("/setup").text)
    response = running.client.post(
        "/language",
        data={"csrf_token": token, "lang": "it", "next": "/setup"},
        follow_redirects=False,
    )
    assert (response.status_code, response.headers["location"]) == (303, "/setup")
    assert "Configurazione iniziale" in running.client.get("/setup").text


def test_gate_lets_requests_through_when_db_unavailable(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    url = f"sqlite:///{tmp_path / 'missing-dir' / 'app.db'}"
    application = create_app(
        Settings(database_url=url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    )
    with TestClient(application) as client:
        assert client.get("/nope", headers=HTML).status_code == 404
        assert client.get("/nope", headers=HTML).status_code == 404
    warnings = [r for r in caplog.records if getattr(r, "event", "") == "setup.state_unavailable"]
    assert len(warnings) == 1
    assert "OperationalError" in warnings[0].getMessage()
    application.state.db_engine.dispose()


# --- successful setup -----------------------------------------------------------------------------


def test_setup_creates_admin_tenant_owner_and_logs_in(env: Env, running: Running) -> None:
    response = _post(running)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert SESSION_COOKIE_NAME in response.cookies
    with env.db() as db:
        user = db.scalars(select(User)).one()
        assert user.email == "admin@example.com"
        assert user.is_instance_admin is True
        assert user.password_hash is not None and user.password_hash.startswith("$argon2id$")
        assert verify_password(user.password_hash, PASSWORD, FAST)
        tenant = db.scalars(select(Tenant)).one()
        assert (tenant.name, tenant.slug) == ("Agency One", "agency-one")
        membership = db.scalars(select(Membership)).one()
        assert (membership.user_id, membership.tenant_id) == (user.id, tenant.id)
        assert membership.role is MembershipRole.OWNER
        session = db.scalars(select(UserSession)).one()
        assert (session.user_id, session.active_tenant_id) == (user.id, tenant.id)
        row = db.scalars(select(InstanceSetup)).one()
        assert row.completed_at is not None
        assert row.token_hash is None  # token invalidated
        assert row.admin_user_id == user.id
    # Logged in: the authenticated logout works; the gate is gone.
    assert running.client.get("/login", headers=HTML, follow_redirects=False).status_code == 200


def test_setup_without_tenant_name(env: Env, running: Running) -> None:
    assert _post(running, tenant_name="   ").status_code == 303
    assert _count(env, Tenant) == 0
    assert _count(env, Membership) == 0
    with env.db() as db:
        assert db.scalars(select(UserSession)).one().active_tenant_id is None


def test_setup_is_404_forever_and_token_invalid_after_setup(env: Env, running: Running) -> None:
    form = _form(running)
    assert running.client.post("/setup", data=form, follow_redirects=False).status_code == 303
    assert running.client.get("/setup").status_code == 404
    form["email"] = "second@example.com"
    running.client.cookies.delete(SESSION_COOKIE_NAME)  # anonymous again: double-submit CSRF
    replay = running.client.post("/setup", data=form, follow_redirects=False)
    assert replay.status_code == 404
    assert _count(env, User) == 1
    with env.db() as db:
        assert svc.verify_setup_token(db, running.token) is False
        assert svc.issue_setup_token(db) is None
    # A fresh process (restart) after setup: still 404, no token logged.
    issued = len(env.tokens())
    application = env.app()
    with TestClient(application) as client:
        assert client.get("/setup").status_code == 404
    assert len(env.tokens()) == issued
    application.state.db_engine.dispose()


# --- token, CSRF, throttle ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "wrong",
        "x" * 43,
        "x" * 44,
        "é" * 43,
        "\x00" * 43,
        "a" * 42 + "\x00",
        "<script>",
    ],
)
def test_wrong_or_malformed_token_is_refused(env: Env, running: Running, token: str) -> None:
    response = _post(running, setup_token=token)
    assert response.status_code == 400
    assert "valid setup token is required" in response.text
    assert _count(env, User) == 0
    assert _setup_row(env) is not None and _setup_row(env).token_hash is not None  # type: ignore[union-attr]


def test_missing_token_field_is_refused(env: Env, running: Running) -> None:
    form = _form(running)
    del form["setup_token"]
    assert running.client.post("/setup", data=form).status_code == 400
    assert _count(env, User) == 0


def test_setup_requires_csrf(env: Env, running: Running) -> None:
    form = _form(running)
    del form["csrf_token"]
    assert running.client.post("/setup", data=form).status_code == 403
    form["csrf_token"] = "forged"
    assert running.client.post("/setup", data=form).status_code == 403
    assert _count(env, User) == 0


def test_oversized_body_is_refused(env: Env, running: Running) -> None:
    response = _post(running, tenant_name="a" * 5000)
    assert response.status_code == 413
    assert _count(env, User) == 0


def test_token_attempts_are_throttled(env: Env, running: Running) -> None:
    statuses = [_post(running, setup_token="x" * 43).status_code for _ in range(6)]
    assert statuses[:5] == [400] * 5
    assert statuses[5] == 429
    response = _post(running)  # even the right token waits
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
    assert _count(env, User) == 0


# --- validation -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"password": "a" * 14, "password_confirm": "a" * 14}, "too short"),
        ({"password": "", "password_confirm": ""}, "too short"),
        ({"password": "a" * 129, "password_confirm": "a" * 129}, "too long"),
        ({"password_confirm": PASSWORD + "x"}, "do not match"),
        ({"password_confirm": ""}, "do not match"),
        ({"email": ""}, "valid email"),
        ({"email": "not-an-email"}, "valid email"),
        ({"email": "a@"}, "valid email"),
        ({"email": "a b@example.com"}, "valid email"),
        ({"email": "admin\x00@example.com"}, "valid email"),
        ({"email": "admin@exa\x01mple.com"}, "valid email"),
        ({"email": "admin@example.com\x7f"}, "valid email"),
        ({"email": "ad​min@example.com"}, "valid email"),
        ({"email": "a" * 310 + "@example.com"}, "valid email"),
        ({"email": "a" * 243 + "@example.com"}, "valid email"),  # 255 > MAX_EMAIL_LENGTH
        (_both(LISTED.upper()), "too common"),
        (_both("admin@example.com"), "too common"),
        ({"tenant_name": "Agency\x00One"}, "invalid characters"),
        ({"tenant_name": "Agency\nOne"}, "invalid characters"),
        ({"tenant_name": "Agency\x1bOne"}, "invalid characters"),
        ({"tenant_name": "a" * 201}, "invalid characters"),
    ],
)
def test_validation_errors(
    env: Env, running: Running, overrides: dict[str, str], message: str
) -> None:
    response = _post(running, **overrides)
    assert response.status_code == 400
    assert message in response.text
    assert _count(env, User) == 0
    assert _count(env, Tenant) == 0
    row = _setup_row(env)
    assert row is not None and row.token_hash is not None  # token still usable


def test_validation_reports_every_error_in_italian(running: Running) -> None:
    running.client.cookies.set("dt_lang", "it")
    response = _post(running, email="x", password="short", password_confirm="other")
    assert response.status_code == 400
    for fragment in ("email valido", "troppo corta", "non coincidono"):
        assert fragment in response.text


@pytest.mark.parametrize(
    ("password", "ok"),
    [
        (_pw(14), False),
        (_pw(15), True),
        ("é" * 15, True),  # code points, not bytes
        ("🔑" * 15, True),
        ("a b c d e f g h", True),  # spaces allowed, no composition rules
        (_pw(128), True),
        (_pw(129), False),
    ],
)
def test_password_length_policy(password: str, ok: bool) -> None:
    data, errors = svc.validate_setup_form(
        "a@example.com", password, password, "", app_name=APP_NAME
    )
    assert (data is not None) is ok
    assert bool(errors) is not ok


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Agency One", "agency-one"),
        ("  Città  di Nàpoli!! ", "citta-di-napoli"),
        ("日本", "tenant"),
        ("---", "tenant"),
        ("a" * 100, "a" * 63),
        ("a" * 62 + " b", "a" * 62),
    ],
)
def test_slugify(name: str, slug: str) -> None:
    assert svc.slugify(name) == slug


def test_setup_input_repr_hides_password() -> None:
    data, _ = svc.validate_setup_form("a@example.com", PASSWORD, PASSWORD, "", app_name=APP_NAME)
    assert PASSWORD not in repr(data)


@pytest.mark.parametrize(
    ("password", "email", "blocked"),
    [
        ("1qaz2wsx3edc4rfv", "a@example.com", True),  # on the bundled list
        ("1QAZ2WSX3EDC4RFV", "a@example.com", True),  # case-insensitive
        ("qwerty 123456789", "a@example.com", True),  # whitespace ignored
        ("admin@example.com", "admin@example.com", True),  # equal to the email
        ("my admin@example.com pass", "admin@example.com", True),  # contains the email
        ("ADMINISTRATOR", "administrator@example.com", True),  # equal to the local part
        ("xx-sysadmin-2026-xx", "sysadmin@example.com", True),  # contains the local part
        ("bob is not my password", "bob@example.com", False),  # local part < 4: equality only
        ("bob", "bob@example.com", True),
        ("Deliverability Toolkit 2026!", "a@example.com", True),  # app name
        ("mydeliverabilitytoolkit", "a@example.com", True),  # app name, no space
        (_pw(20), "kv7q@example.com", True),  # contains the local part (4 chars)
        (PASSWORD, "admin@example.com", False),
        (_pw(20), "admin@example.com", False),
    ],
)
def test_password_blocklist(password: str, email: str, blocked: bool) -> None:
    assert svc.is_blocklisted(password, email=email, app_name=APP_NAME) is blocked


def test_bundled_blocklist_has_provenance_and_entries() -> None:
    raw = svc.COMMON_PASSWORDS_FILE.read_text(encoding="utf-8")
    assert "source: SecLists" in raw and "MIT" in raw and "verified_on:" in raw
    entries = svc.common_passwords()
    assert len(entries) > 10_000
    assert all(e == e.casefold() and len(e) >= svc.PASSWORD_MIN_LENGTH for e in entries)
    assert not any(e.startswith("#") for e in entries)


def test_common_password_rejected_in_italian(running: Running) -> None:
    running.client.cookies.set("dt_lang", "it")
    response = _post(running, **_both(LISTED))
    assert response.status_code == 400
    assert "troppo comune" in response.text


@pytest.mark.parametrize(
    ("email", "shown"),
    [
        ("admin\x00@example.com", False),
        ("admin@exa\x01mple.com", False),
        ("a" * 243 + "@example.com", False),
        ("not-an-email", False),
        ("admin@example.com", True),
    ],
)
def test_rejected_email_is_not_echoed(running: Running, email: str, shown: bool) -> None:
    response = _post(running, email=email, password=_pw(10), password_confirm=_pw(10))
    assert response.status_code == 400
    assert ('value="admin@example.com"' in response.text) is shown
    assert 'id="setup-email" name="email" type="email" autocomplete="username" required' in (
        response.text
    )
    if not shown:
        assert re.search(r'maxlength="254" value=""', response.text)


def test_email_field_maxlength_is_max_email_length(running: Running) -> None:
    assert 'maxlength="254"' in running.client.get("/setup").text
    data, _ = svc.validate_setup_form(
        "a" * 242 + "@example.com", PASSWORD, PASSWORD, "", app_name=APP_NAME
    )
    assert data is not None  # exactly 254 characters


# --- logs -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("level", ["ERROR", "CRITICAL"])
def test_token_reaches_operator_whatever_log_level(
    env: Env, capsys: pytest.CaptureFixture[str], level: str
) -> None:
    root = logging.getLogger()
    handlers, root_level = list(root.handlers), root.level
    application = env.app(log_level=level)
    try:
        with TestClient(application) as client:
            client.get("/healthz")
    finally:
        root.handlers[:] = handlers
        root.setLevel(root_level)
        application.state.db_engine.dispose()
    (token,) = env.tokens()
    err = capsys.readouterr().err
    lines = [line for line in err.splitlines() if token in line]
    assert len(lines) == 1
    assert '"level": "WARNING"' in lines[0]
    assert '"logger": "app.setup.token"' in lines[0]
    assert '"logger": "app.request"' not in err  # INFO lines are still filtered out


# --- logs: secrets --------------------------------------------------------------------------------


def test_no_password_or_token_in_logs(env: Env, running: Running) -> None:
    _post(running, password_confirm="mismatch-" + PASSWORD)
    _post(running, setup_token="x" * 43)
    assert _post(running).status_code == 303
    texts = [f"{r.getMessage()} {r.__dict__}" for r in env.records()]
    assert not any(PASSWORD in t for t in texts)
    assert sum(running.token in t for t in texts) == 1  # only the issuance line


# --- single admin: DB-enforced --------------------------------------------------------------------


def _issue(env: Env) -> str:
    with env.db() as db:
        token = svc.issue_setup_token(db)
        db.commit()
    assert token is not None
    return token


def _input(email: str) -> svc.SetupInput:
    data, errors = svc.validate_setup_form(email, PASSWORD, PASSWORD, "", app_name=APP_NAME)
    assert data is not None, errors
    return data


def test_concurrent_setups_create_exactly_one_admin(env: Env) -> None:
    token = _issue(env)
    workers = 6
    barrier = threading.Barrier(workers)
    results: list[svc.SetupResult] = []
    lock = threading.Lock()

    def run(i: int) -> None:
        with env.db() as db:
            barrier.wait()
            result = svc.complete_setup(
                db, _input(f"admin{i}@example.com"), token, secret_key=SecretStr(KEY),
                policy=POLICY, hasher=FAST,
            )  # fmt: skip
        with lock:
            results.append(result)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    outcomes = sorted(r.outcome.value for r in results)
    assert outcomes == ["already_done"] * (workers - 1) + ["completed"]
    assert _count(env, User) == 1
    assert _count(env, UserSession) == 1
    with env.db() as db:
        assert db.scalar(select(func.count()).where(User.is_instance_admin.is_(True))) == 1


def test_claim_is_enforced_by_the_database_not_app_checks(env: Env) -> None:
    """Both callers pass every application-level check first; only the DB decides."""
    token = _issue(env)
    digest = hashlib.sha256(token.encode()).hexdigest()
    sessions = [env.db(), env.db()]
    try:
        for db in sessions:
            assert svc.setup_required(db) and svc.verify_setup_token(db, token)
            db.rollback()
        barrier = threading.Barrier(2)
        claimed: list[bool] = []

        def claim(db: Session) -> None:
            barrier.wait()
            won = svc.claim_setup(db, digest, now=datetime.now(UTC))
            claimed.append(won)
            db.commit() if won else db.rollback()

        threads = [threading.Thread(target=claim, args=(db,)) for db in sessions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        assert sorted(claimed) == [False, True]
    finally:
        for db in sessions:
            db.close()


@pytest.mark.parametrize(
    "values",
    [
        {"id": 2},
        {"id": 1, "completed_at": datetime.now(UTC), "token_hash": "a" * 64},
    ],
)
def test_singleton_constraints(env: Env, values: dict[str, Any]) -> None:
    with env.db() as db:
        db.add(InstanceSetup(**values))
        with pytest.raises(IntegrityError):
            db.commit()


def test_second_singleton_row_refused(env: Env) -> None:
    _issue(env)
    with env.db() as db:
        db.add(InstanceSetup(id=1))
        with pytest.raises(IntegrityError):
            db.commit()


def test_complete_setup_after_completion_creates_nothing(env: Env) -> None:
    token = _issue(env)
    with env.db() as db:
        first = svc.complete_setup(
            db, _input("one@example.com"), token, secret_key=SecretStr(KEY), policy=POLICY,
            hasher=FAST,
        )  # fmt: skip
        second = svc.complete_setup(
            db, _input("two@example.com"), token, secret_key=SecretStr(KEY), policy=POLICY,
            hasher=FAST,
        )  # fmt: skip
    assert first.outcome is svc.SetupOutcome.COMPLETED
    assert second.outcome is svc.SetupOutcome.ALREADY_DONE
    assert _count(env, User) == 1


def test_complete_setup_with_malformed_token(env: Env) -> None:
    _issue(env)
    with env.db() as db:
        for token in (None, 123, "", "x" * 43):
            result = svc.complete_setup(
                db, _input("one@example.com"), token, secret_key=SecretStr(KEY), policy=POLICY,
                hasher=FAST,
            )  # fmt: skip
            assert result.outcome is svc.SetupOutcome.TOKEN_INVALID
    assert _count(env, User) == 0
