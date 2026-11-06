"""M3-17 Authentication tab: tenancy/permissions through the real app, server-side SPF/DMARC
rendering in en and it, DNS failure as `error` (never "missing"), hostile DNS text, CSP and the
absence of inline script. Fake resolver only: no network. The generated tenancy matrix
(tests/tenancy/test_matrix.py) also covers the route.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.dns_tools import dns_backend
from app.core import i18n
from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory
from app.main import create_app
from app.models import Membership
from tests.api.test_domains import B_SECRET_NAME, KEY, ROOT, World, _seed, call
from tests.support.dns_backend import fake_backend

HOSTILE = "v=spf1 <script>alert(1)</script> -all"
GOOD_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@assigned.example"

ZONES: dict[str, list[dict[str, Any]]] = {
    "default": [
        # assigned.example: a hostile SPF text and a valid DMARC record
        {"name": "assigned.example", "type": "TXT", "ttl": 300, "rdata": [HOSTILE]},
        {"name": "_dmarc.assigned.example", "type": "TXT", "ttl": 300, "rdata": [GOOD_DMARC]},
        # unassigned.example: every lookup fails
        {"name": "unassigned.example", "type": "TXT", "state": "servfail", "rcode": 2},
        {"name": "_dmarc.unassigned.example", "type": "TXT", "state": "timeout"},
    ]
}
HTML = {"Accept": "text/html"}


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def world(db_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("SECRET_KEY", KEY)
    monkeypatch.setenv("ENCRYPTION_KEY", KEY)
    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")
    engine = create_db_engine(db_url)
    db = create_session_factory(engine)()
    tenant_a, tenant_b, users, domains = _seed(db)
    settings = Settings(database_url=db_url, secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    application = create_app(settings)
    backend, _ = fake_backend(ZONES)
    application.dependency_overrides[dns_backend] = lambda: backend
    try:
        with TestClient(application, raise_server_exceptions=True) as client:
            yield World(client, db, settings, tenant_a, tenant_b, users, domains)
    finally:
        db.close()
        app_engine = getattr(application.state, "db_engine", None)
        if app_engine is not None:
            app_engine.dispose()
        engine.dispose()


def apath(world: World, which: str) -> str:
    return f"/domains/{world.domains[which]}/authentication"


def get(world: World, who: str, path: str, **kw: Any) -> Any:
    return call(world, who, "GET", path, headers=kw.pop("headers", HTML), **kw)


def set_toggles(world: World, user: str, toggles: dict[str, bool]) -> None:
    membership = world.db.scalars(
        select(Membership).where(Membership.user_id == world.users[user])
    ).one()
    membership.feature_toggles = toggles
    world.db.commit()


# --- tenancy and permissions --------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_assigned_domain_renders_for_every_role(world: World, who: str) -> None:
    r = get(world, who, apath(world, "assigned"))
    assert r.status_code == 200
    assert 'data-testid="check-spf"' in r.text and 'data-testid="check-dmarc"' in r.text
    assert "/authentication/dkim/stream" in r.text


@pytest.mark.parametrize(("who", "status"), [("owner", 200), ("analyst", 200), ("viewer", 404)])
def test_unassigned_domain(world: World, who: str, status: int) -> None:
    assert get(world, who, apath(world, "unassigned")).status_code == status


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_tenant_a_cannot_open_tenant_b_domain(world: World, who: str) -> None:
    r = get(world, who, apath(world, "other"))
    assert r.status_code == 404
    assert B_SECRET_NAME not in r.text


def test_foreign_active_tenant_is_404(world: World) -> None:
    assert get(world, "analyst", apath(world, "assigned"), tenant="b").status_code == 404


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_check_run_toggle_false_is_403_and_tab_hidden(world: World, who: str) -> None:
    set_toggles(world, who, {"check.run": False})
    r = get(world, who, apath(world, "assigned"))
    assert r.status_code == 403
    assert "check-spf" not in r.text
    detail = get(world, who, f"/domains/{world.domains['assigned']}")
    assert detail.status_code == 200
    assert "tab-authentication" not in detail.text


@pytest.mark.parametrize("domain_id", ["999999", "abc", "-1", "1" * 40])
def test_unknown_or_malformed_domain_id_is_404(world: World, domain_id: str) -> None:
    assert get(world, "owner", f"/domains/{domain_id}/authentication").status_code == 404


def test_anonymous_redirects_to_login(world: World) -> None:
    world.client.cookies.clear()
    r = world.client.get(apath(world, "assigned"), headers=HTML, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")


@pytest.mark.parametrize("who", ["owner", "admin", "analyst", "viewer"])
def test_tab_link_visible_with_permission(world: World, who: str) -> None:
    r = get(world, who, f"/domains/{world.domains['assigned']}")
    assert f'href="/domains/{world.domains["assigned"]}/authentication"' in r.text
    assert 'data-testid="tab-authentication"' in r.text


# --- rendering ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lang", "needles"),
    [
        ("en", ("Authentication of assigned.example", "Critical", "DMARC")),
        ("it", ("Autenticazione di assigned.example", "SPF", "DMARC")),
    ],
)
def test_renders_in_both_languages_without_missing_keys(
    world: World, lang: str, needles: tuple[str, ...]
) -> None:
    r = get(
        world,
        "owner",
        apath(world, "assigned"),
        headers={**HTML, "Accept-Language": lang},
    )
    assert r.status_code == 200  # strict i18n mode raises on any missing key
    for needle in needles[:1]:
        assert needle in r.text
    assert 'lang="' + lang + '"' in r.text
    assert 'data-testid="check-dmarc"' in r.text


def test_findings_have_severity_title_and_status(world: World) -> None:
    text = get(world, "owner", apath(world, "assigned")).text
    assert re.search(r'<li data-code="SPF_[A-Z_]+" data-severity="[a-z]+">', text)
    assert 'data-testid="status-spf"' in text


def test_dns_failure_renders_error_not_missing(world: World) -> None:
    text = get(world, "owner", apath(world, "unassigned")).text
    for check in ("spf", "dmarc"):
        section = text.split(f'data-testid="check-{check}"')[1].split("</section>")[0]
        assert 'data-status="error"' in text
        assert "Could not evaluate" in section
        assert 'role="alert"' in section
    assert "This is not the same as a missing record" in text


def test_dns_failure_in_italian(world: World) -> None:
    text = get(
        world,
        "owner",
        apath(world, "unassigned"),
        headers={**HTML, "Accept-Language": "it"},
    ).text
    assert "Impossibile valutare" in text


def test_hostile_dns_text_is_escaped(world: World) -> None:
    text = get(world, "owner", apath(world, "assigned")).text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


# --- CSP and scripts ----------------------------------------------------------------------------


def test_csp_holds_and_no_inline_script(world: World) -> None:
    r = get(world, "owner", apath(world, "assigned"))
    assert "script-src 'self'" in r.headers["content-security-policy"]
    scripts = re.findall(r"<script\b[^>]*>", r.text)
    assert scripts, "expected external script tags"
    assert all(" src=" in tag for tag in scripts)
    assert "/static/js/dkim_stream.js" in r.text
    assert not re.search(r"<script\b[^>]*>\s*[^<\s]", r.text)  # no script body
    assert not re.search(r"\son\w+=", r.text)  # no inline event handlers
    assert "htmx" not in r.text.lower()


def test_noscript_note_and_static_file(world: World) -> None:
    r = get(world, "owner", apath(world, "assigned"))
    assert 'data-testid="dkim-noscript"' in r.text
    js = world.client.get("/static/js/dkim_stream.js")
    assert js.status_code == 200
    assert "close()" in js.text and '"done"' in js.text and '"error"' in js.text
