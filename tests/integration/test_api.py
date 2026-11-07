from fastapi.testclient import TestClient

from prototype.legacy.api import create_app
from prototype.legacy.seed import sample_terms


def test_login_dashboard_approve(tmp_path):
    app = create_app(tmp_path, password="test-password")
    client = TestClient(app)
    assert client.get("/api/dashboard").status_code == 401
    assert (
        client.post(
            "/api/session", json={"officer_id": "seller-trader", "password": "wrong"}
        ).status_code
        == 401
    )
    login = client.post(
        "/api/session",
        json={"officer_id": "seller-trader", "password": "test-password"},
    )
    headers = {"Authorization": "Bearer " + login.json()["token"]}
    dashboard = client.get("/api/dashboard", headers=headers).json()
    assert len(dashboard["trades"]) == 3
    t = dashboard["trades"][0]
    task = t["tasks"][0]
    response = client.post(
        f"/api/trades/{t['trade_id']}/tasks/{task['task_id']}/decision",
        headers=headers,
        json={"decision": "approve", "reason": "", "what_hash": task["what_hash"]},
    )
    assert response.status_code == 200
    assert response.json()["state"] == "GAPS_OPEN"
    assert client.get("/api/audit", headers=headers).json()["chain_valid"]
    assert (
        client.post("/api/trades", headers=headers, json=sample_terms()).status_code
        == 409
    )


def test_production_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("EXCHANGE_MODE", "production")
    import pytest

    with pytest.raises(RuntimeError, match="Production startup disabled"):
        create_app(tmp_path, password="test")
