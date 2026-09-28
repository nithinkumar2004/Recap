"""Tests for Release Captain FastAPI endpoints."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_analyze_and_approve_flow():
    payload = {
        "repository": "myorg/sample-app",
        "base_ref": "v1.0.0",
        "head_ref": "main"
    }
    # 1. Trigger Analysis
    res = client.post("/api/v1/releases/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    release_id = data["release_id"]
    assert "proposed_version" in data
    assert data["status"] in ("AWAITING_APPROVAL", "BLOCKED")

    # 2. Get Release Status
    res_get = client.get(f"/api/v1/releases/{release_id}")
    assert res_get.status_code == 200
    details = res_get.json()
    assert details["repository"] == "myorg/sample-app"

    # 3. Approve Release
    res_app = client.post(
        f"/api/v1/releases/{release_id}/approve",
        json={"actor": "lead-maintainer", "decision": "APPROVE"}
    )
    assert res_app.status_code == 200
    assert res_app.json()["status"] == "APPROVED"
