# Sentinel AI Alert Intake API

A modular, audit-friendly alert ingestion pipeline built for cloud-native environments. This API accepts structured security alerts, enforces schema validation, and prepares data for downstream enrichment, triage, or compliance workflows.

## 📦 Project Structure

sentinel-ai-defense-system/ 
├── src/ # Flask app logic 
│ └── app.py 
├── tests/ # Pytest suite for schema and error validation 
│ └── test_app.py 
├── scripts/ # Utility scripts for smoke testing 
│ └── test_alert.sh 
├── requirements.txt # Python dependencies 
├── zappa_settings.json # AWS Lambda + API Gateway config 
└── venv/ # Local virtual environment (excluded from Git)

## 🚀 Deployment

This API is deployed serverlessly using [Zappa](https://github.com/zappa/Zappa) on AWS Lambda.

To deploy or update:

```bash
zappa update dev
## 🔐 API Endpoint

**POST** `/dev`

### Request Headers

```http
Content-Type: application/json
x-api-key: your-client-key

# Request body Example
{
  "alert_id": "test-001",
  "timestamp": "2025-10-03T20:00:00Z",
  "source_system": "SentinelOne",
  "alert_type": "unauthorized_access",
  "severity": "medium",
  "risk_score": 75,
  "raw_log": "login failed",
  "status": "open",
  "affected_assets": [
    {
      "account_id": "acct-123",
      "customer_id": "cust-456"
    }
  ]
}

# Response
{
  "alert_id": "test-001",
  "message": "Alert received"
}

---

## 🧪 Testing

### 1. Run schema validation tests

Use `pytest` to validate your API logic and error handling:

```bash
pytest tests/test_app.py -v

# Send a live alert to the deployed API

./scripts/test_alert.sh


---
## 📜 Features

- Modular Flask app with strict schema enforcement
- Audit-friendly logging for every alert
- Positive and negative test coverage with pytest
- Curl-based smoke testing for live endpoint
- Zappa deployment for serverless scalability
- API key authentication via `x-api-key` header

---

## 🧭 Roadmap

- Add enrichment logic for alert triage and prioritization
- Generate OpenAPI documentation for client onboarding
- Integrate CI/CD pipeline with GitHub Actions
- Route alerts to downstream systems (e.g., SQS, DynamoDB)
- Add alert deduplication and replay protection

## 👤 Maintainer

**Sekhar** — Cloud Architect & API Orchestrator  
Focused on clarity, auditability, and real-world readiness.  
Specialized in modular cloud platforms, agentic AI orchestration, and client-trusted API design.



