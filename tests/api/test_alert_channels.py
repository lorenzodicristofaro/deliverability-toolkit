"""M7-15 alert channel routes through the real app and middleware: `/api/v1/alert-channels`.

The routes are also in the M1-20 matrix (tests/tenancy/test_matrix.py) and the id range guard
(tests/tenancy/test_id_range.py); this file adds the per-role table, toggles, cross-tenant 404s,
validation errors, secrets that never come back (responses and captured logs are searched), the
test send with its rate limit, and the wire format. No network: the channel is a fake.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.v1.alert_channels import MAX_CHANNELS, alert_channel_clock, alert_registry
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.core.i18n import t
from app.core.secrets_crypto import SecretCipher
from app.core.tenancy import TenantContext
from app.main import create_app
from app.models import AlertChannel, AlertDelivery, AlertRule, Membership
from app.repositories import repo_for
from app.services.alert_dispatch import ChannelRegistry, SendResult, open_secrets
from tests.api.test_domains import B_SECRET_NAME, KEY, World, _seed, call
from tests.services.test_alert_dispatch import FakeChannel
from tests.support.socket_guard import db_endpoint, install

NOW = datetime(2026, 11, 18, 9, 30, tzinfo=UTC)
LIST = "/api/v1/alert-channels"
FERNET = Fernet.generate_key().decode()
SECRET_URL = "https://hooks.example.com/services/T0-PRIVATE-PATH"
SIGNING = "signing-secret-value-0123456789"
WEBHOOK = {
    "kind": "webhook",
    "name": "Ops hook",
    "secrets": {"url": SECRET_URL, "signing_secret": SIGNING},
}
EMAIL = {"kind": "email", "name": "Ops mail", "config": {"recipients": ["ops@example.com"]}}
NOT_FOUND = {"detail": t("alert.channel.error.not_found", "en")}
FORBIDDEN = {"detail": t("api.error.forbidden", "en")}
WRITERS = ("owner", "admin")
DENIED = ("analyst", "viewer")


class _FixedClock:
    def now(self) -> datetime:
        return NOW


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "alert channels API", db_endpoint())


@pytest.fixture
def fake() -> FakeChannel:
    return FakeChannel()


def _world(
    url: str, monkeypatch: pytest.MonkeyPatch, encryption_key: str, fake: FakeChannel
) -> Any:
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", encryption_key)
    engine = create_db_engine(url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=url, secret_key=KEY, encryption_key=encryption_key)  # type: ignore[call-arg]
    application = create_app(settings)
    application.dependency_overrides[alert_channel_clock] = _FixedClock
    application.dependency_overrides[alert_registry] = lambda: ChannelRegistry({"webhook": fake})
    return engine, db, application, (tenant_a, tenant_b, users, domains, settings)


@pytest.fixture
def world(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, fake: FakeChannel
) -> Iterator[World]:
    engine, db, application, seeded = _world(migrated_db_url, monkeypatch, FERNET, fake)
    tenant_a, tenant_b, users, domains, settings = seeded
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- helpers ------------------------------------------------------------------------------------


def one(cid: int) -> str:
    return f"{LIST}/{cid}"


def seed_channel(w: World, tenant: str = "a", name: str = "seeded") -> int:
    """A webhook channel written through the repository with a real sealed secret."""
    from app.services.alert_dispatch import seal_secrets

    token, names = seal_secrets(SecretCipher(FERNET), {"url": SECRET_URL})
    record = repo_for(TenantContext(w.tenant_id(tenant), None), w.db).alert_channels.create(
        kind="webhook", name=name, enabled=True, config={}, secret_token=token,
        secret_fields=names, now=NOW,
    )  # fmt: skip
    w.db.commit()
    return record.id


def channel_rows(w: World) -> list[tuple[Any, ...]]:
    w.db.expire_all()
    w.db.rollback()
    rows = w.db.execute(
        select(
            AlertChannel.tenant_id, AlertChannel.name, AlertChannel.enabled, AlertChannel.config,
            AlertChannel.secret, AlertChannel.secret_fields,
        ).order_by(AlertChannel.id)
    ).all()  # fmt: skip
    w.db.rollback()
    return [tuple(r) for r in rows]


def set_toggles(w: World, who: str, toggles: dict[str, Any]) -> None:
    membership = w.db.scalars(select(Membership).where(Membership.user_id == w.users[who])).one()
    membership.feature_toggles = toggles
    w.db.commit()


def no_secret(response: Any, caplog: pytest.LogCaptureFixture) -> None:
    logs = "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    for secret in (SECRET_URL, "T0-PRIVATE-PATH", SIGNING):
        assert secret not in response.text
        assert secret not in logs


# --- CRUD round trip ----------------------------------------------------------------------------


@pytest.mark.parametrize("who", WRITERS)
def test_crud_round_trip_never_returns_secrets(
    world: World, caplog: pytest.LogCaptureFixture, who: str
) -> None:
    caplog.set_level(logging.DEBUG)
    created = call(world, who, "POST", LIST, json=WEBHOOK)
    assert created.status_code == 201, created.text
    body = created.json()
    cid = body["id"]
    assert body == {
        "id": cid,
        "kind": "webhook",
        "name": "Ops hook",
        "enabled": True,
        "config": {},
        "secrets": {"signing_secret": "********", "url": "********"},
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
    }
    no_secret(created, caplog)
    stored = channel_rows(world)[0]
    assert stored[0] == world.tenant_a
    assert SECRET_URL not in stored[4] and SIGNING not in stored[4]
    assert open_secrets(SecretCipher(FERNET), stored[4]) == WEBHOOK["secrets"]

    for response in (call(world, who, "GET", LIST), call(world, who, "GET", one(cid))):
        assert response.status_code == 200
        no_secret(response, caplog)
    assert call(world, who, "GET", LIST).json()["items"] == [body]

    patched = call(world, who, "PATCH", one(cid), json={"enabled": False, "name": "Renamed"})
    assert patched.status_code == 200
    assert (patched.json()["enabled"], patched.json()["name"]) == (False, "Renamed")
    assert channel_rows(world)[0][4] == stored[4]  # secrets untouched without `secrets`

    new_secrets = {"url": "https://other.example.com/hook"}
    patched = call(world, who, "PATCH", one(cid), json={"secrets": new_secrets})
    assert patched.json()["secrets"] == {"url": "********"}
    assert open_secrets(SecretCipher(FERNET), channel_rows(world)[0][4]) == new_secrets
    no_secret(patched, caplog)

    deleted = call(world, who, "DELETE", one(cid))
    assert deleted.status_code == 204
    assert channel_rows(world) == []
    assert call(world, who, "GET", one(cid)).json() == NOT_FOUND


def test_email_channel_has_config_and_no_secret(world: World) -> None:
    response = call(world, "owner", "POST", LIST, json=EMAIL)
    assert response.status_code == 201
    assert response.json()["config"] == {"recipients": ["ops@example.com"]}
    assert response.json()["secrets"] == {}
    assert channel_rows(world)[0][4] is None


def test_delete_also_removes_rules_and_deliveries(world: World) -> None:
    cid = seed_channel(world)
    repo_for(TenantContext(world.tenant_a, None), world.db).alert_rules.add("new_listing", cid)
    world.db.commit()
    assert call(world, "owner", "DELETE", one(cid)).status_code == 204
    world.db.rollback()
    assert world.db.scalar(select(func.count()).select_from(AlertRule)) == 0
    assert world.db.scalar(select(func.count()).select_from(AlertDelivery)) == 0


# --- permissions and tenancy --------------------------------------------------------------------


def _routes(cid: int) -> list[tuple[str, str, Any]]:
    return [
        ("GET", LIST, None),
        ("POST", LIST, WEBHOOK),
        ("GET", one(cid), None),
        ("PATCH", one(cid), {"enabled": False}),
        ("DELETE", one(cid), None),
        ("POST", one(cid) + "/test", None),
    ]


@pytest.mark.parametrize("who", DENIED)
def test_analyst_and_client_viewer_are_refused_everywhere(
    world: World, caplog: pytest.LogCaptureFixture, who: str
) -> None:
    cid = seed_channel(world)
    before = channel_rows(world)
    for method, path, body in _routes(cid):
        response = call(world, who, method, path, json=body)
        assert (response.status_code, response.json()) == (403, FORBIDDEN), (method, path)
        assert "seeded" not in response.text
        no_secret(response, caplog)
    assert channel_rows(world) == before


@pytest.mark.parametrize("who", ["anon", *WRITERS, *DENIED])
def test_anonymous_401_and_no_tenant_404(world: World, who: str) -> None:
    cid = seed_channel(world)
    for method, path, body in _routes(cid):
        if who == "anon":
            assert call(world, who, method, path, json=body).status_code == 401
        else:
            # A session whose active tenant is B, where the tenant A user has no membership.
            response = call(world, who, method, path, json=body, tenant="b")
            assert (response.status_code, response.json()) == (404, NOT_FOUND), (method, path)


@pytest.mark.parametrize("who", WRITERS)
def test_other_tenants_channel_is_404_and_untouched(
    world: World, caplog: pytest.LogCaptureFixture, who: str
) -> None:
    b_channel = seed_channel(world, tenant="b", name=B_SECRET_NAME)
    before = channel_rows(world)
    for method, path, body in _routes(b_channel)[2:]:
        response = call(world, who, method, path, json=body)
        assert (response.status_code, response.json()) == (404, NOT_FOUND), (method, path)
        assert B_SECRET_NAME not in response.text
        no_secret(response, caplog)
    listed = call(world, who, "GET", LIST)
    assert listed.json() == {"items": []}
    assert channel_rows(world) == before


@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.0", "2147483648", "9" * 50])
def test_malformed_ids_are_404(world: World, value: str) -> None:
    for method, path, body in _routes(1)[2:]:
        path = path.replace("/1", f"/{value}", 1)
        response = call(world, "owner", method, path, json=body)
        assert (response.status_code, response.json()) == (404, NOT_FOUND), (method, path)


def test_toggle_denies_owner_and_true_grants_nothing(world: World) -> None:
    cid = seed_channel(world)
    set_toggles(world, "owner", {"alert.manage": False})
    for method, path, body in _routes(cid):
        assert call(world, "owner", method, path, json=body).status_code == 403
    set_toggles(world, "analyst", {"alert.manage": True})
    assert call(world, "analyst", "GET", LIST).status_code == 403


def test_mutations_need_csrf(world: World) -> None:
    cid = seed_channel(world)
    for method, path, body in _routes(cid)[1:]:
        if method == "GET":
            continue
        assert call(world, "owner", method, path, json=body, csrf=False).status_code == 403


def test_smuggled_tenant_id_is_rejected(world: World) -> None:
    response = call(world, "owner", "POST", LIST, json={**WEBHOOK, "tenant_id": world.tenant_b})
    assert response.status_code == 422
    assert channel_rows(world) == []


# --- validation ---------------------------------------------------------------------------------

INVALID = [
    ({**WEBHOOK, "kind": "sms"}, "kind", "unknown_kind"),
    ({**WEBHOOK, "name": ""}, "name", "length"),
    ({**WEBHOOK, "name": "x\ny"}, "name", "control_character"),
    ({**WEBHOOK, "secrets": {}}, "url", "required"),
    ({**WEBHOOK, "secrets": {"url": "http://hooks.example.com/x"}}, "url", "scheme_not_allowed"),
    ({**WEBHOOK, "secrets": {"url": "https://169.254.169.254/latest"}}, "url", "blocked"),
    ({**WEBHOOK, "secrets": {"url": SECRET_URL, "signing_secret": "short"}}, "signing_secret",
     "malformed"),
    ({**WEBHOOK, "secrets": {"url": SECRET_URL, "extra": "x"}}, "secrets", "unknown_field"),
    ({**WEBHOOK, "config": {"x": 1}}, "config", "unknown_field"),
    ({**EMAIL, "config": {"recipients": ["bad"]}}, "recipients", "malformed"),
    ({**EMAIL, "config": {}}, "recipients", "required"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("body", "field", "reason"), INVALID, ids=[f"{c[1]}-{c[2]}" for c in INVALID]
)
def test_rejected_fields_are_422_without_echo(
    world: World, body: dict[str, Any], field: str, reason: str
) -> None:
    response = call(world, "owner", "POST", LIST, json=body)
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert (detail["field"], detail["reason"]) == (field, reason)
    assert detail["message"] == t(detail["key"], "en")
    for value in ("169.254.169.254", "hooks.example.com", "short", "x\ny"):
        assert value not in response.text
    assert channel_rows(world) == []


@pytest.mark.parametrize(
    "content",
    [b"not json", b'{"kind": "webhook", "kind": "email", "name": "x"}', b"[]",
     b'{"kind": 5, "name": "x"}', b'{"name": "x"}',
     b'{"kind": "email", "name": "x", "enabled": 1}'],
)  # fmt: skip
def test_malformed_bodies_are_422(world: World, content: bytes) -> None:
    response = call(world, "owner", "POST", LIST, content=content)
    assert response.status_code == 422
    assert channel_rows(world) == []


def test_patch_rules(world: World) -> None:
    cid = seed_channel(world)
    other = seed_channel(world, name="other")
    for body in ({"kind": "email"}, {"name": None}, {"enabled": "no"}):
        assert call(world, "owner", "PATCH", one(cid), json=body).status_code == 422
    taken = call(world, "owner", "PATCH", one(cid), json={"name": "other"})
    assert taken.status_code == 409
    assert taken.json() == {"detail": t("alert.channel.error.name_taken", "en")}
    bad_url = call(world, "owner", "PATCH", one(other), json={"secrets": {"url": "ftp://x"}})
    assert bad_url.json()["detail"]["field"] == "url"
    # A missing channel is 404 whatever the body.
    assert call(world, "owner", "PATCH", one(999_999), json={"kind": 5}).status_code == 404


def test_duplicate_name_is_409(world: World) -> None:
    assert call(world, "owner", "POST", LIST, json=WEBHOOK).status_code == 201
    response = call(world, "admin", "POST", LIST, json={**WEBHOOK, "name": " Ops hook "})
    assert response.status_code == 409
    assert len(channel_rows(world)) == 1


def test_per_tenant_cap(world: World) -> None:
    for i in range(MAX_CHANNELS):
        seed_channel(world, name=f"c{i}")
    response = call(world, "owner", "POST", LIST, json=WEBHOOK)
    assert response.status_code == 422
    assert response.json()["detail"]["key"] == "alert.channel.error.limit_reached"


def test_bad_encryption_key_is_503_only_where_secrets_are_needed(
    migrated_db_url: str, monkeypatch: pytest.MonkeyPatch, fake: FakeChannel
) -> None:
    engine, db, application, seeded = _world(migrated_db_url, monkeypatch, "k" * 40, fake)
    tenant_a, tenant_b, users, domains, settings = seeded
    try:
        with TestClient(application) as client:
            w = World(client, db, settings, tenant_a, tenant_b, users, domains)
            unavailable = {"detail": t("alert.channel.error.encryption_unavailable", "en")}
            response = call(w, "owner", "POST", LIST, json=WEBHOOK)
            assert (response.status_code, response.json()) == (503, unavailable)
            assert call(w, "owner", "POST", LIST, json=EMAIL).status_code == 201
            assert call(w, "owner", "GET", LIST).status_code == 200
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


# --- test send ----------------------------------------------------------------------------------


def test_test_send_reports_outcome_and_is_rate_limited(
    world: World, fake: FakeChannel, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    cid = seed_channel(world)
    other = seed_channel(world, name="other")
    path = one(cid) + "/test"
    ok = call(world, "owner", "POST", path)
    assert ok.status_code == 200
    assert ok.json() == {"outcome": "ok", "code": "ok", "message": t("alert.channel.test.ok", "en")}
    assert fake.calls[0][2].secrets == {"url": SECRET_URL}
    fake.result = SendResult.permanent("http_4xx")
    refused = call(world, "admin", "POST", path)
    assert refused.json()["outcome"] == "permanent" and refused.json()["code"] == "http_4xx"
    fake.exc = RuntimeError(SECRET_URL)
    crashed = call(world, "owner", "POST", path)
    assert crashed.json()["code"] == "internal_error"
    no_secret(crashed, caplog)
    limited = call(world, "owner", "POST", path)
    assert limited.status_code == 429
    assert limited.json() == {"detail": t("alert.channel.error.rate_limited", "en")}
    assert int(limited.headers["retry-after"]) > 0
    assert len(fake.calls) == 3
    fake.exc = None
    assert call(world, "owner", "POST", one(other) + "/test").status_code == 200  # per channel
    assert world.db.scalar(select(func.count()).select_from(AlertDelivery)) == 0


def test_test_send_on_unregistered_kind(world: World) -> None:
    response = call(world, "owner", "POST", LIST, json={**EMAIL, "name": "mail"})
    cid = response.json()["id"]
    sent = call(world, "owner", "POST", one(cid) + "/test")
    assert sent.json()["outcome"] == "permanent"
    assert sent.json()["code"] == "channel_unavailable"


def test_permission_label_exists() -> None:
    for lang in ("en", "it"):
        assert "permission.alert.manage" in i18n.load_catalogue(lang)
