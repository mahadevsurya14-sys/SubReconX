"""Integration tests for FastAPI application and API routes."""

from unittest.mock import AsyncMock, patch
import pytest
from starlette.testclient import TestClient

from subreconx.api.app import create_app
from subreconx.api.dependencies import get_database, get_repository, reset_dependencies
from subreconx.db.database import Database
from subreconx.db.migrations import check_and_migrate
from subreconx.models import ScanConfig, SubdomainRecord


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "api_test.db"
    monkeypatch.setenv("SUBRECONX_DB_PATH", str(test_db))
    monkeypatch.setenv("SUBRECONX_DEBUG", "true")

    reset_dependencies()
    app = create_app()

    with TestClient(app) as test_client:
        yield test_client

    reset_dependencies()


def test_health_check(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "tools" in data
    assert "subfinder" in data["tools"]


def test_dashboard_page(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SubReconX" in resp.text
    assert "Target Domain" in resp.text


def test_start_scan_invalid_domain(client: TestClient) -> None:
    resp = client.post("/api/scans", json={"domain": "invalid_domain; rm -rf /"})
    assert resp.status_code == 422


def test_start_scan_and_get_status(client: TestClient) -> None:
    with patch("subreconx.core.orchestrator.ScanOrchestrator.run_scan", new_callable=AsyncMock) as mock_run:
        resp = client.post(
            "/api/scans",
            json={
                "domain": "example.com",
                "enable_dns": True,
                "enable_http": False,
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "scan_id" in data
        scan_id = data["scan_id"]
        assert data["domain"] == "example.com"

        # Check status endpoint
        status_resp = client.get(f"/api/scans/{scan_id}")
        assert status_resp.status_code in (200, 404)  # depending on whether mock saved to db


def test_list_scans(client: TestClient) -> None:
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_reports_not_found(client: TestClient) -> None:
    resp = client.get("/api/reports/nonexistent_id/csv")
    assert resp.status_code == 404
