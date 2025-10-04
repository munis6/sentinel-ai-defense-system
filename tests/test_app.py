import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from app import app

API_HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": "your-secure-api-key"
}

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
    response = client.post("/alerts", json=payload, headers=API_HEADERS)
    assert response.status_code == 200
    assert response.get_json()["message"] == "Alert received"

# ✅ TC_SCHEMA_002_MissingFields
def test_schema_missing_fields(client):
    payload = {
        "alert_id": "TC002",
        "timestamp": "2025-10-03T11:50:00Z",
        "severity": "high",
        "risk_score": 85,
        "affected_assets": ["finance-server-01"],
        "raw_log": "login failed",
        "status": "open"
    }
    response = client.post("/alerts", json=payload, headers=API_HEADERS)
    assert response.status_code == 422
    assert "Missing fields" in response.get_json()["error"]

# ✅ TC_SCHEMA_003_InvalidEnum
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
    response = client.post("/alerts", json=payload, headers=API_HEADERS)
    assert response.status_code == 422
    assert "Invalid severity value" in response.get_json()["error"]

# ✅ TC_SCHEMA_004_InvalidType
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
    response = client.post("/alerts", json=payload, headers=API_HEADERS)
    assert response.status_code == 422
    assert "risk_score must be numeric" in response.get_json()["error"]

# ✅ TC_SCHEMA_005_BadTimestamp
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
    response = client.post("/alerts", json=payload, headers=API_HEADERS)
    assert response.status_code == 422
    assert "Invalid timestamp format" in response.get_json()["error"]

# ✅ TC_AUTH_006_MissingAPIKey
def test_missing_api_key(client):
    payload = {
        "alert_id": "TC006",
        "timestamp": "2025-10-03T11:50:00Z",
        "source_system": "BankX",
        "alert_type": "suspicious_transfer",
        "severity": "high",
        "risk_score": 90,
        "affected_assets": ["bank-server-01"],
        "raw_log": "unauthorized access attempt",
        "status": "open"
    }
    response = client.post("/alerts", json=payload)
    assert response.status_code == 403
    assert "Missing or invalid API key" in response.get_json()["error"]

# ✅ TC_METHOD_007_InvalidMethod
def test_invalid_method(client):
    response = client.get("/alerts")
    assert response.status_code == 405
    assert "Method Not Allowed" in response.get_data(as_text=True)

# ✅ TC_HEADER_008_MissingContentType
def test_missing_content_type(client):
    payload = '{"alert_id": "TC008"}'
    response = client.post("/alerts", data=payload, headers={"x-api-key": "your-secure-api-key"})
    assert response.status_code == 415
    assert "Unsupported Media Type" in response.get_data(as_text=True)

# ✅ TC_FLOW_009_ValidRequestWithHeaders
def test_valid_request_with_headers(client):
    payload = {
        "alert_id": "TC009",
        "timestamp": "2025-10-03T11:50:00Z",
        "source_system": "BankX",
        "alert_type": "suspicious_transfer",
        "severity": "medium",
        "risk_score": 70,
        "affected_assets": ["bank-server-02"],
        "raw_log": "transfer flagged for review",
        "status": "open"
    }
    response = client.post("/alerts", json=payload, headers=API_HEADERS)
    assert response.status_code == 200
    assert response.get_json()["message"] == "Alert received"
