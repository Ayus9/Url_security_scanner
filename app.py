from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from utils.local_analyzer import analyze_url
from utils.virustotal import check_virustotal
from utils.zap_scanner import run_zap_scan
from utils.risk_calculator import calculate_aggregate_risk

app = Flask(__name__)
CORS(app)

app.config["VT_API_KEY"] = os.environ.get("VT_API_KEY", "")
app.config["ZAP_URL"]    = os.environ.get("ZAP_URL", "http://localhost:8080")
app.config["ZAP_KEY"]    = os.environ.get("ZAP_KEY", "changeme")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/report")
def report():
    return render_template("report.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "vt_ready": bool(app.config["VT_API_KEY"]),
        "zap_url": app.config["ZAP_URL"],
    })

@app.route("/api/scan", methods=["POST"])
def scan():
    body    = request.get_json(force=True) or {}
    url     = (body.get("url") or "").strip()
    run_vt  = bool(body.get("virustotal", False))
    run_zap = bool(body.get("zap", False))

    if not url:
        return jsonify({"error": "URL is required"}), 400

    local = analyze_url(url)
    if "error" in local:
        return jsonify({"error": local["error"]}), 400

    result = {"local": local}

    if run_vt:
        result["virustotal"] = check_virustotal(url, app.config["VT_API_KEY"])
    if run_zap:
        result["zap"] = run_zap_scan(url, app.config["ZAP_URL"], app.config["ZAP_KEY"])

    result["aggregate_score"] = calculate_aggregate_risk(
        local["score"],
        result.get("virustotal"),
        result.get("zap"),
    )
    return jsonify(result)

@app.route("/api/virustotal", methods=["POST"])
def vt_only():
    body = request.get_json(force=True) or {}
    url  = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(check_virustotal(url, app.config["VT_API_KEY"]))

@app.route("/api/zap", methods=["POST"])
def zap_only():
    body = request.get_json(force=True) or {}
    url  = (body.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(run_zap_scan(url, app.config["ZAP_URL"], app.config["ZAP_KEY"]))

if __name__ == "__main__":
    print("=" * 50)
    print("  Smart URL Security Scanner")
    print("  Open: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, port=5000)