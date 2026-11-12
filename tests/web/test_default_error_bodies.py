"""R1-12 framework default error bodies: a validation error never echoes the submitted value,
unknown paths / wrong methods are translated, and an oversized small form gets a localized 413
page instead of an empty response. Fake resolver only: no network."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Annotated, Any
from urllib.parse import quote

import pytest
from fastapi import Query

from app.core import i18n
from app.core.i18n import t
from app.web.templating import MAX_FORM_BYTES
from tests.api.test_domains import call
from tests.web.test_checks_stream import world as world  # noqa: PLC0414  (fixture)
from tests.web.test_domains_ui import get, post
from tests.web.test_setup import _form, _post
from tests.web.test_setup import env as env  # noqa: PLC0414  (fixture)
from tests.web.test_setup import running as running  # noqa: PLC0414  (fixture)

PAD = "ZQXJ" * 1100  # far over every cap; never allowed in a response body
LONG_NAME = "A" * 1030
IT = {"Accept-Language": "it"}
EN = {"Accept-Language": "en"}


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


# --- (1) validation errors ---------------------------------------------


@pytest.mark.parametrize(("lang", "headers"), [("it", IT), ("en", EN)])
@pytest.mark.parametrize("accept", ["text/event-stream", "text/html", "*/*"])
def test_overlong_sse_name_is_a_translated_422_without_the_value(
    world: Any, lang: str, headers: dict[str, str], accept: str
) -> None:
    r = get(world, "analyst", f"/tools/dkim/stream?name={LONG_NAME}", Accept=accept, **headers)
    assert r.status_code == 422
    assert LONG_NAME not in r.text
    assert "string_too_long" not in r.text and "at most" not in r.text
    assert t("tools.dns.invalid_name", lang) in r.text


def test_overlong_sse_name_requires_permission_first(world: Any) -> None:
    """403 for a viewer and 401 for anonymous win over the length check (order unchanged)."""
    anon = world.client.get(
        f"/tools/dkim/stream?name={LONG_NAME}",
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert anon.status_code in (401, 303, 302)
    viewer = get(world, "viewer", f"/tools/dkim/stream?name={LONG_NAME}")
    assert viewer.status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/domains?limit=" + LONG_NAME,
        "/api/v1/domains/" + LONG_NAME,
    ],
)
def test_framework_validation_error_has_no_input_for_api_clients(world: Any, path: str) -> None:
    r = call(world, "owner", "GET", path, headers=IT)
    assert LONG_NAME not in r.text
    assert "input" not in r.text and "string_too_long" not in r.text


@pytest.mark.parametrize("lang", ["it", "en"])
@pytest.mark.parametrize("html", [False, True])
def test_request_validation_handler_is_generic_and_translated(
    world: Any, lang: str, html: bool
) -> None:
    """A parameter that fails FastAPI validation: generic translated body, no `input` echo."""

    @world.client.app.get("/__probe", include_in_schema=False)
    def probe(n: Annotated[int, Query(le=10)]) -> dict[str, int]:
        return {"n": n}

    accept = "text/html" if html else "application/json"
    r = world.client.get(
        f"/__probe?n={PAD[:40]}", headers={"Accept": accept, "Accept-Language": lang}
    )
    assert r.status_code == 422
    assert PAD[:40] not in r.text and "int_parsing" not in r.text
    assert html or "input" not in r.text
    if html:
        assert t("ui.error.invalid_request.title", lang) in r.text
    else:
        assert r.json() == {"detail": t("api.error.invalid_request", lang)}


# --- (2) default 404 / 405 bodies ---------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "status", "key"),
    [
        ("GET", "/api/v1/nope", 404, "api.error.not_found"),
        ("PUT", "/api/v1/domains", 405, "api.error.method_not_allowed"),
    ],
)
@pytest.mark.parametrize("lang", ["it", "en"])
def test_default_404_405_json_is_translated(
    world: Any, method: str, path: str, status: int, key: str, lang: str
) -> None:
    r = call(world, "owner", method, path, headers={"Accept-Language": lang})
    assert r.status_code == status
    assert r.json() == {"detail": t(key, lang)}


def test_405_keeps_the_allow_header(world: Any) -> None:
    r = call(world, "owner", "PUT", "/api/v1/domains", headers=IT)
    assert r.status_code == 405
    assert "GET" in r.headers["allow"]


def test_unknown_api_path_anonymous_is_translated(world: Any) -> None:
    r = world.client.get("/api/v1/nope", headers=IT)
    assert r.status_code in (401, 404)
    assert r.json()["detail"] not in ("Not Found", "Method Not Allowed", "Unauthorized")


@pytest.mark.parametrize("lang", ["it", "en"])
def test_wrong_method_on_a_web_page_is_a_translated_html_page(world: Any, lang: str) -> None:
    r = world.client.put("/healthz", headers={"Accept": "text/html", "Accept-Language": lang})
    assert r.status_code == 405
    assert t("ui.error.method_not_allowed.title", lang) in r.text
    assert "allow" in r.headers


def test_html_404_still_translated(world: Any) -> None:
    r = world.client.get("/nope", headers={"Accept": "text/html", **IT})
    assert r.status_code == 404
    assert t("ui.error.not_found.title", "it") in r.text


def test_error_responses_keep_security_headers_and_no_store(world: Any) -> None:
    r = call(world, "owner", "GET", "/api/v1/nope", headers=IT)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in r.headers["cache-control"]
    page = get(world, "owner", f"/tools/dkim/stream?name={LONG_NAME}")
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in page.headers["cache-control"]


# --- (3) oversized small forms ---------------------------------------------

# (who, path with {unassigned} placeholder)
SMALL_FORMS = [
    ("anon", "/language"),
    ("anon", "/login"),
    ("owner", "/tenants/switch"),
    ("owner", "/domains"),
    ("owner", "/domains/{unassigned}/rename"),
    ("analyst", "/tools/dns/lookup"),
    ("analyst", "/tools/dns/reverse"),
    ("analyst", "/tools/dns/trace"),
    ("analyst", "/tools/dns/propagation"),
]


@pytest.mark.parametrize(("who", "path"), SMALL_FORMS)
@pytest.mark.parametrize(("lang", "headers"), [("it", IT), ("en", EN)])
def test_oversized_small_form_is_a_localized_413_page(
    world: Any, who: str, path: str, lang: str, headers: dict[str, str]
) -> None:
    body = b"name=" + b"a" * (MAX_FORM_BYTES + 1)
    r = post(
        world,
        who,
        path.format(unassigned=world.domains["unassigned"]),
        content=body,
        **headers,
    )
    assert r.status_code == 413
    assert r.text.strip(), "blank 413 page"
    assert t("ui.error.too_large.title", lang) in r.text
    assert t("ui.error.too_large.detail", lang) in r.text
    assert "a" * 100 not in r.text
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["x-content-type-options"] == "nosniff"


# --- MAX_FORM_BYTES sizing ---------------------------------------------


def test_form_cap_fits_the_setup_maxima() -> None:
    """Two 128-character passwords, a 200-character tenant name and a 254-character email,
    all worst-case (4-byte characters, 12 bytes once percent-encoded), plus the fixed fields."""
    wide = "\U00020000"  # CJK extension B: 4 UTF-8 bytes
    fields = {
        "csrf_token": "c" * 100,
        "setup_token": "s" * 64,
        "email": "e" * 254,
        "password": wide * 128,
        "password_confirm": wide * 128,
        "tenant_name": wide * 200,
    }
    encoded = "&".join(f"{k}={quote(v)}" for k, v in fields.items())
    assert len(encoded.encode()) <= MAX_FORM_BYTES
    assert re.fullmatch(r"[A-Za-z0-9%=&_.~-]+", encoded)


# --- first-run setup ---------------------------------------------


def test_setup_with_maximum_length_cjk_values_succeeds(env: Any, running: Any) -> None:
    password = "漢字仮名交じり文" * 16  # 128 characters, 9 bytes each once percent-encoded
    assert len(password) == 128
    r = _post(running, password=password, password_confirm=password, tenant_name="東京" * 100)
    assert r.status_code == 303, r.text[:300]


@pytest.mark.parametrize("lang", ["it", "en"])
def test_setup_oversized_form_is_a_localized_413_page(env: Any, running: Any, lang: str) -> None:
    r = running.client.post(
        "/setup",
        data=_form(running, tenant_name="a" * 20000),
        headers={"Accept-Language": lang, "Accept": "text/html"},
        follow_redirects=False,
    )
    assert r.status_code == 413
    assert t("ui.error.too_large.title", lang) in r.text
    assert "a" * 100 not in r.text
