import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/docs"),
        ("GET", "/redoc"),
        ("GET", "/openapi.json"),
        ("HEAD", "/openapi.json"),
        ("GET", "/docs/oauth2-redirect"),
        ("GET", "/docs/"),
        ("GET", "/openapi.json/"),
    ],
)
def test_api_docs_not_served_to_anonymous(method: str, path: str) -> None:
    assert client.request(method, path).status_code == 404


def test_healthz_still_ok() -> None:
    assert client.get("/healthz").status_code == 200
