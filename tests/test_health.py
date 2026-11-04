import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz_ok() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [("POST", "/healthz", 405), ("GET", "/nope", 404), ("GET", "/healthz/x", 404)],
)
def test_healthz_other_requests(method: str, path: str, status: int) -> None:
    response = client.request(method, path)
    assert response.status_code == status


def test_healthz_head_ok() -> None:
    response = client.head("/healthz")
    assert response.status_code == 200


def test_healthz_sets_no_cookie() -> None:
    response = client.get("/healthz")
    assert "set-cookie" not in response.headers
