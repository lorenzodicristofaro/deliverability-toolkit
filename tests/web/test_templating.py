"""M1-16 base template, static files, language switch, error pages, contrast. No network."""

from __future__ import annotations

import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from jinja2 import ChoiceLoader, DictLoader

from app.core import i18n
from app.core.config import Settings
from app.core.i18n import MissingKeyError, load_catalogue
from app.main import create_app
from app.web import templating
from app.web.templating import STATIC_DIR, TEMPLATES_DIR, env, render, safe_next

KEY = "k" * 40
PAGE = "t_page.html"


@pytest.fixture(autouse=True)
def _strict_mode() -> Iterator[None]:
    i18n.set_strict(True)
    yield
    i18n.set_strict(False)
    i18n._warned.clear()


@pytest.fixture
def app() -> Iterator[FastAPI]:
    original = env.loader
    assert original is not None
    env.loader = ChoiceLoader(
        [
            DictLoader(
                {
                    PAGE: '{% extends "base.html" %}{% block content %}<p id="x">{{ x }}</p>'
                    "{% endblock %}",
                    "t_missing.html": '{{ t("no.such.key") }}',
                }
            ),
            original,
        ]
    )
    application = create_app(
        Settings(secret_key=KEY, encryption_key=KEY)  # type: ignore[call-arg]
    )

    @application.get("/t/page", response_class=HTMLResponse)
    def page(request: Request, x: str = "hello") -> HTMLResponse:
        return render(request, PAGE, x=x)

    @application.get("/t/missing")
    def missing(request: Request) -> HTMLResponse:
        return render(request, "t_missing.html")

    @application.get("/t/boom")
    def boom() -> None:
        raise RuntimeError("secret-detail-do-not-leak")

    yield application
    env.loader = original


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class _Audit(HTMLParser):
    """Collects what the CSP forbids: inline scripts, inline styles, event-handler attributes."""

    def __init__(self) -> None:
        super().__init__()
        self.problems: list[str] = []
        self.scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = {k for k, _ in attrs}
        if tag == "script":
            self.scripts += 1
            if "src" not in names:
                self.problems.append("inline <script>")
        if tag == "style":
            self.problems.append("<style>")
        for name in names:
            if name == "style" or name.startswith("on"):
                self.problems.append(f"{tag}[{name}]")


def _audit(html: str) -> _Audit:
    audit = _Audit()
    audit.feed(html)
    return audit


def _csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


# --- rendering ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("accept", "lang", "skip", "home"),
    [
        ("en", "en", "Skip to main content", "Home"),
        ("it-IT,it;q=0.9", "it", "Vai al contenuto principale", "Home"),
        ("fr", "en", "Skip to main content", "Home"),
        ("\x00;;;", "en", "Skip to main content", "Home"),
    ],
)
def test_base_renders_in_language(
    client: TestClient, accept: str, lang: str, skip: str, home: str
) -> None:
    html = client.get("/t/page", headers={"Accept-Language": accept.encode("latin-1")}).text
    assert f'<html lang="{lang}">' in html
    assert f'<a class="skip-link" href="#main">{skip}</a>' in html
    assert home in html
    assert 'id="main"' in html


@pytest.mark.parametrize(
    "payload",
    ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "&lt;b&gt;", "{{ 7*7 }}"],
)
def test_injected_markup_is_escaped(client: TestClient, payload: str) -> None:
    html = client.get("/t/page", params={"x": payload}).text
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "49" not in html.split('id="x"')[1][:40]
    audit = _audit(html)
    assert audit.problems == []


@pytest.mark.parametrize("path", ["/t/page", "/nope"])
def test_no_inline_script_or_style(client: TestClient, path: str) -> None:
    html = client.get(path, headers={"Accept": "text/html"}).text
    audit = _audit(html)
    assert audit.scripts == 1  # theme.js, external
    assert audit.problems == []


def test_missing_translation_key_fails_in_tests(client: TestClient) -> None:
    with TestClient(client.app, raise_server_exceptions=True) as c, pytest.raises(MissingKeyError):
        c.get("/t/missing")


def test_every_template_key_exists_in_both_catalogues() -> None:
    used: set[str] = set()
    for path in TEMPLATES_DIR.rglob("*.html"):
        used |= set(re.findall(r"""\bt\(\s*["']([^"']+)["']""", path.read_text(encoding="utf-8")))
    assert used, "no t() calls found: scanner broken"
    for lang in ("en", "it"):
        assert used - load_catalogue(lang).keys() == set(), lang


# --- static files ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "content_type"),
    [("/static/app.css", "text/css"), ("/static/theme.js", "javascript")],
)
def test_static_files_served(client: TestClient, path: str, content_type: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert content_type in response.headers["content-type"]
    assert "content-security-policy" in response.headers


@pytest.mark.parametrize("path", ["/static/nope.css", "/static/../app/main.py", "/static/%2e%2e/x"])
def test_static_missing_or_traversal_is_404(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404


def test_keyboard_focus_and_skip_link_styles_exist() -> None:
    css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
    assert ":focus-visible" in css
    assert ".skip-link:focus" in css
    assert "prefers-color-scheme: dark" in css


# --- language switch ------------------------------------------------------------------------


def test_language_post_without_csrf_token_is_refused(client: TestClient) -> None:
    response = client.post("/language", data={"lang": "it"}, follow_redirects=False)
    assert response.status_code == 403
    assert "dt_lang" not in response.cookies


def test_language_post_with_forged_token_is_refused(client: TestClient) -> None:
    client.get("/t/page")
    response = client.post("/language", data={"lang": "it", "csrf_token": "x"})
    assert response.status_code == 403


def test_language_switch_sets_cookie_and_cookie_beats_accept_language(client: TestClient) -> None:
    token = _csrf_from(client.get("/t/page").text)  # sets the anonymous dt_csrf cookie
    response = client.post(
        "/language",
        data={"lang": "it", "csrf_token": token, "next": "/t/page"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/t/page"
    cookie = response.headers["set-cookie"]
    assert "dt_lang=it" in cookie
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
    page = client.get("/t/page", headers={"Accept-Language": "en"}).text
    assert '<html lang="it">' in page
    assert 'aria-current="true"' in page


def test_language_form_carries_the_csrf_token_in_the_page(client: TestClient) -> None:
    html = client.get("/t/page").text
    assert '<form class="lang-switch" method="post" action="/language">' in html
    assert len(_csrf_from(html)) > 40
    assert "dt_csrf" in client.cookies


@pytest.mark.parametrize(
    "body",
    [
        {"lang": "fr"},
        {"lang": ""},
        {},
        {"lang": "IT"},  # catalogue names are lowercase; unknown values are ignored
    ],
)
def test_language_switch_ignores_unsupported_values(
    client: TestClient, body: dict[str, str]
) -> None:
    token = _csrf_from(client.get("/t/page").text)
    response = client.post("/language", data={**body, "csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "dt_lang" not in response.headers.get("set-cookie", "")


def test_language_post_header_token_and_bad_utf8(client: TestClient) -> None:
    token = _csrf_from(client.get("/t/page").text)
    response = client.post(
        "/language",
        content=b"lang=\xff\xfe",
        headers={"X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    big = client.post(
        "/language",
        content=b"lang=it&pad=" + b"a" * 9000,
        headers={"X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert big.status_code == 413


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/domains", "/domains"),
        ("/a?b=c", "/a?b=c"),
        (None, "/"),
        ("", "/"),
        ("//evil.test", "/"),
        ("https://evil.test", "/"),
        ("/\\evil.test", "/"),
        ("evil", "/"),
        ("/a\r\nSet-Cookie: x=y", "/"),
        ("/a\x00", "/"),
        # Percent-encoded variants must not become non-local after decoding.
        ("/%2F%2Fevil.test", "/"),
        ("/%2f%2fevil.test", "/"),
        ("/%5Cevil.test", "/"),
        ("/%5cevil.test", "/"),
        ("/%252F%252Fevil.test", "/"),  # double encoded
        ("/%25252F%25252Fevil.test", "/"),  # triple encoded: beyond the decode budget
        ("%2F%2Fevil.test", "/"),
        ("/%0d%0aSet-Cookie:x", "/"),
        ("/a%20b", "/a%20b"),
        ("/search?q=%2F", "/search?q=%2F"),
    ],
)
def test_safe_next(value: str | None, expected: str) -> None:
    assert safe_next(value) == expected


def test_language_cookie_is_secure_with_https_base_url() -> None:
    application = create_app(
        Settings(  # type: ignore[call-arg]
            secret_key=KEY, encryption_key=KEY, base_url="https://toolkit.example"
        )
    )

    @application.get("/t/page", response_class=HTMLResponse)
    def page(request: Request) -> HTMLResponse:
        return render(request, "errors/404.html")

    with TestClient(application, base_url="https://testserver") as c:
        token = _csrf_from(c.get("/t/page").text)
        response = c.post(
            "/language", data={"lang": "it", "csrf_token": token}, follow_redirects=False
        )
    assert response.status_code == 303
    cookie = response.headers["set-cookie"]
    assert "dt_lang=it" in cookie and "Secure" in cookie


def test_brand_is_the_app_name_global(client: TestClient) -> None:
    html = client.get("/t/page").text
    assert env.globals["app_name"] == templating.APP_NAME
    assert f"<title>{templating.APP_NAME}</title>" in html
    assert f'<a class="brand" href="/">{templating.APP_NAME}</a>' in html
    base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
    assert templating.APP_NAME not in base


def test_anonymous_page_has_no_logout_form(client: TestClient) -> None:
    html = client.get("/t/page").text
    assert 'action="/logout"' not in html
    assert 'href="/logout"' not in html


def test_render_without_settings_raises_a_clear_error(app: FastAPI) -> None:
    with TestClient(app, raise_server_exceptions=True) as c:
        del app.state.settings
        with pytest.raises(RuntimeError, match="app.state.settings"):
            c.get("/t/page")


def test_language_cookie_garbage_is_ignored(client: TestClient) -> None:
    for raw in ["dt_lang=fr", "dt_lang=", "\x00=;;", "dt_lang=it; dt_lang=en"]:
        page = client.get("/t/page", headers={"Cookie": raw, "Accept-Language": "en"})
        assert page.status_code == 200
    assert templating.request_language({"type": "http", "headers": []}) == "en"


# --- error pages ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("accept", "title"),
    [("en", "Page not found"), ("it", "Pagina non trovata")],
)
def test_404_page_is_translated(client: TestClient, accept: str, title: str) -> None:
    response = client.get("/nope", headers={"Accept": "text/html", "Accept-Language": accept})
    assert response.status_code == 404
    assert f"<h1>{title}</h1>" in response.text
    assert response.headers["content-type"].startswith("text/html")
    assert "content-security-policy" in response.headers


def test_404_for_api_clients_stays_json(client: TestClient) -> None:
    response = client.get("/nope", headers={"Accept": "application/json"})
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found."}


@pytest.mark.parametrize(
    ("accept", "title"),
    [("en", "Something went wrong"), ("it", "Si è verificato un problema")],
)
def test_500_page_is_translated_keeps_headers_and_leaks_nothing(
    client: TestClient, accept: str, title: str
) -> None:
    response = client.get("/t/boom", headers={"Accept-Language": accept})
    assert response.status_code == 500
    assert f"<h1>{title}</h1>" in response.text
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-frame-options"] == "DENY"
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert "secret-detail" not in response.text
    assert "RuntimeError" not in response.text
    assert "csrf_token" not in response.text
    assert _audit(response.text).problems == []


def test_500_falls_back_to_plain_response_when_rendering_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(scope: object) -> bytes:
        raise RuntimeError("template broken")

    monkeypatch.setattr(templating, "render_server_error", fail)
    response = client.get("/t/boom")
    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["x-frame-options"] == "DENY"


# --- WCAG AA contrast (computed from the palette in app.css) ----------------------------------


def _luminance(hex_colour: str) -> float:
    def channel(c: int) -> float:
        s = c / 255
        return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4

    r, g, b = (int(hex_colour[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _palette(block_start: str) -> dict[str, str]:
    css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
    start = css.index(block_start)
    body = css[css.index("{", start) + 1 : css.index("}", start)]
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6});", body))


# (foreground, background, minimum): 4.5 for text, 3.0 for non-text UI (WCAG 2.1 1.4.3 / 1.4.11)
PAIRS = [
    ("text", "bg", 4.5),
    ("text", "surface", 4.5),
    ("muted", "bg", 4.5),
    ("muted", "surface", 4.5),
    ("link", "bg", 4.5),
    ("link", "surface", 4.5),
    ("on-accent", "accent", 4.5),
    ("focus", "bg", 3.0),
    ("focus", "surface", 3.0),
    ("border", "bg", 3.0),
    ("border", "surface", 3.0),
]


@pytest.mark.parametrize("block", [":root {", ':root[data-theme="dark"] {'])
@pytest.mark.parametrize(("fg", "bg", "minimum"), PAIRS)
def test_palette_meets_wcag_aa(block: str, fg: str, bg: str, minimum: float) -> None:
    palette = _palette(block)
    assert contrast(palette[fg], palette[bg]) >= minimum


def test_media_query_dark_palette_equals_data_theme_dark() -> None:
    css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
    media = _palette(':root:not([data-theme="light"]) {')
    assert media == _palette(':root[data-theme="dark"] {')
    assert css.count("prefers-color-scheme: dark") >= 2


def test_contrast_helper_known_values() -> None:
    assert round(contrast("#000000", "#ffffff"), 2) == 21.0
    assert round(contrast("#777777", "#ffffff"), 2) == 4.48


def test_theme_js_is_a_plain_static_file() -> None:
    source = Path(STATIC_DIR / "theme.js").read_text(encoding="utf-8")
    assert "eval(" not in source and "innerHTML" not in source
