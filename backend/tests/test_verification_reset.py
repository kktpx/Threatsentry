import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.deps.auth import get_current_user_id
from backend.api.routers.websites import get_database
from backend.core.config import Settings
from backend.main import create_app
from backend.tests.scanner.test_runner import MockDatabase


@pytest.fixture
def mock_db() -> MockDatabase:
    def site(site_id: str, user: str) -> dict:
        return {
            "id": site_id, "user_id": user, "name": site_id, "url": "https://example.com",
            "normalized_origin": "https://example.com", "verification_token": "old-token",
            "verification_status": "VERIFIED", "verified_at": "2026-09-12T00:00:00+00:00",
        }

    return MockDatabase({
        "websites": [site("web-1", "user-1"), site("web-busy", "user-1"), site("web-other", "user-2")],
        "scan_jobs": [{"id": "scan-1", "user_id": "user-1", "website_id": "web-busy", "status": "RUNNING"}],
    })


@pytest.fixture
def client(mock_db: MockDatabase) -> TestClient:
    app: FastAPI = create_app(Settings(_env_file=None))
    app.dependency_overrides[get_current_user_id] = lambda: "user-1"
    app.dependency_overrides[get_database] = lambda: mock_db
    return TestClient(app)


def test_reset_issues_new_token_and_revokes_verification(client: TestClient) -> None:
    response = client.post("/api/websites/web-1/verification/reset")

    assert response.status_code == 200
    body = response.json()
    assert body["verification_status"] == "UNVERIFIED"
    assert body["verified_at"] is None
    assert body["verification_token"] != "old-token"


def test_reset_rejects_other_users_website(client: TestClient) -> None:
    assert client.post("/api/websites/web-other/verification/reset").status_code == 404


def test_reset_rejects_while_scan_is_active(client: TestClient) -> None:
    assert client.post("/api/websites/web-busy/verification/reset").status_code == 409
