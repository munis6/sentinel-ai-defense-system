#!/bin/bash

# ✅ Replace with your actual API Gateway URL and API key
API_URL="https://s7dyudpmkl.execute-api.us-east-1.amazonaws.com/dev"
API_KEY="your-client-key"

# ✅ Alert payload (valid schema)
PAYLOAD='{
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
}'

# ✅ Send the request
curl -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "$PAYLOAD"
