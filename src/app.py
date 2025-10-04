from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
import logging

# ✅ Stream-safe logging for AWS Lambda (no file writes)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# ✅ Required fields for schema validation
REQUIRED_FIELDS = [
    "alert_id", "timestamp", "source_system", "alert_type",
    "severity", "risk_score", "affected_assets", "raw_log", "status"
]

# ✅ Allowed lifecycle status values
ALLOWED_STATUS = {"open", "in_progress", "closed"}

# ✅ Health check + schema documentation
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "✅ Secure Alert Intake API is live",
        "status": "healthy",
        "expected_payload": {
            "alert_id": "string",
            "timestamp": "ISO 8601 UTC",
            "source_system": "SIEM/XDR name",
            "alert_type": "e.g. brute_force, phishing",
            "severity": "low | medium | high | critical",
            "risk_score": "numeric",
            "affected_assets": ["hostname", "IP", "user"],
            "geo_location": "optional",
            "raw_log": "original event data",
            "correlation_id": "optional",
            "status": "open | in_progress | closed",
            "assigned_team": "optional",
            "notes": "optional",
            "callback_url": "optional"
        }
    }), 200

# ✅ Alert intake endpoint with schema enforcement
@app.route("/", methods=["POST"])
def receive_alert():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    # 🔍 Validate required fields
    missing = [field for field in REQUIRED_FIELDS if field not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 422

    # 🔍 Validate timestamp format
    try:
        datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        return jsonify({"error": "Invalid timestamp format"}), 422

    # 🔍 Validate status enum
    if data["status"] not in ALLOWED_STATUS:
        return jsonify({"error": "Invalid status value"}), 422

    # 🧾 Audit log entry
    logging.info(f"Received alert: {data['alert_id']} | Type: {data['alert_type']} | Severity: {data['severity']}")

    # 🧩 Placeholder for enrichment, routing, or storage
    # e.g., enrich_alert(data), route_to_team(data), store_in_db(data)

    return jsonify({"message": "Alert received", "alert_id": data["alert_id"]}), 200
