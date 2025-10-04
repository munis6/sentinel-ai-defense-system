# test_app.py

import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

# ✅ TC_SCHEMA_001_ValidPayload
def test_schema_valid_payload(client):
    payload = {
        "alert_id": "TC001",
        "timestamp": "2025-10-03T11:50:00Z",
        "source_system": "SentinelOne",
        "alert_type": "brute_force",
        "severity": "high",
        "risk_score": 85,
        "affected_assets": ["finance-server-01"],
        "raw_log": "login failed from IP 10.0.0.5",
        "status": "open"
    }
    response = client.post("/alerts", json=payload)
    assert response.status_code == 200
    assert response.get_json()["message"] == "Alert received"

# ❌ TC_SCHEMA_002_MissingFields
def test_schema_missing_fields(client):
    payload = {
        "alert_id": "TC002",
        "timestamp": "2025-10-03T11:50:00Z",
        "severity": "high",
        "risk_score": 85,
        "affected_assets": ["finance-server-01"],
        "raw_log": "login failed",
        "status": "open"
        # Missing: source_system, alert_type
    }
    response = client.post("/alerts", json=payload)
    assert response.status_code == 400
    assert "Missing fields" in response.get_json()["error"]

# ❌ TC_SCHEMA_003_InvalidEnum
def test_schema_invalid_enum(client):
    payload = {
        "alert_id": "TC003",
        "timestamp": "2025-10-03T11:50:00Z",
        "source_system": "SentinelOne",
        "alert_type": "brute_force",
        "severity": "urgent",  # Invalid enum
        "risk_score": 85,
        "affected_assets": ["finance-server-01"],
        "raw_log": "login failed",
        "status": "open"
    }
    response = client.post("/alerts", json=payload)
    assert response.status_code == 400
    assert "Invalid enum value" in response.get_json()["error"]

# ❌ TC_SCHEMA_004_InvalidType
def test_schema_invalid_type(client):
    payload = {
        "alert_id": "TC004",
        "timestamp": "2025-10-03T11:50:00Z",
        "source_system": "SentinelOne",
        "alert_type": "brute_force",
        "severity": "high",
        "risk_score": "high",  # Should be int
        "affected_assets": ["finance-server-01"],
        "raw_log": "login failed",
        "status": "open"
    }
    response = client.post("/alerts", json=payload)
    assert response.status_code == 400
    assert "Invalid type" in response.get_json()["error"]

# ❌ TC_SCHEMA_005_BadTimestamp
def test_schema_bad_timestamp(client):
    payload = {
        "alert_id": "TC005",
        "timestamp": "Oct 3, 2025 11:50 AM",  # Malformed ISO
        "source_system": "SentinelOne",
        "alert_type": "brute_force",
        "severity": "high",
        "risk_score": 85,
        "affected_assets": ["finance-server-01"],
        "raw_log": "login failed",
        "status": "open"
    }
    response = client.post("/alerts", json=payload)
    assert response.status_code == 400
    assert "Invalid timestamp format" in response.get_json()["error"]
