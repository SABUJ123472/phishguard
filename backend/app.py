import os
import re
import logging
import datetime
import threading
import time
from collections import deque

import joblib
import requests
import numpy as np
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from model import extract_features, features_to_array, get_suspicious_reasons
from database import save_scan, get_recent_scans, get_stats, search_scans, is_connected

# Load .env for local development only
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
IS_PRODUCTION = os.environ.get("RENDER") == "true" or os.environ.get("ENV") == "production"
ALLOWED_ORIGINS = [
    "https://sabuj123472.github.io",
    "https://phishguard-sneg.onrender.com",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
]

# Resolve frontend folder — docs (GitHub Pages) or frontend (local)
_base = os.path.dirname(__file__)
FRONTEND = os.path.abspath(os.path.join(_base, "..", "docs"))
if not os.path.isdir(FRONTEND):
    FRONTEND = os.path.abspath(os.path.join(_base, "..", "frontend"))
log.info("Serving frontend from: %s", FRONTEND)

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=FRONTEND, static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB max body

CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=False)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
    on_breach=lambda limit: log.warning("Rate limit hit: %s from %s", limit, request.remote_addr),
)

# ── ML Model ──────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(_base, "phishing_model.pkl")
try:
    model = joblib.load(MODEL_PATH)
    log.info("ML model loaded")
except Exception:
    model = None
    log.warning("Model not found — using rule-based fallback")

# ── In-memory scan log (fallback when DB is unavailable) ─────────────────────
scan_log: deque = deque(maxlen=100)
_scan_log_lock = threading.Lock()

# ── Known phishing domains ────────────────────────────────────────────────────
KNOWN_PHISHING_DOMAINS = {
    "secure-paypa1-login.com", "paypal-secure.update-account.com",
    "amazon-login.verify-now.net", "google-security-alert.com",
    "apple-id.confirm-account.info", "microsoft-support.tech",
    "login.facebook-secure.com", "ebay.account-verify.net",
    "netflix-billing.update-info.com", "bankofamerica.secure-login.xyz",
}

URL_RE  = re.compile(r'^https?://', re.IGNORECASE)
MAX_URL = 2048

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    h = response.headers
    h["X-Content-Type-Options"]  = "nosniff"
    h["X-Frame-Options"]         = "SAMEORIGIN"
    h["X-XSS-Protection"]        = "1; mode=block"
    h["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    h["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
    # No caching for API responses
    if request.path.startswith(("/analyze", "/recent", "/health", "/stats", "/search")):
        h["Cache-Control"] = "no-store, no-cache, must-revalidate"
        h["Pragma"]        = "no-cache"
    else:
        # Cache static assets for 1 hour
        h["Cache-Control"] = "public, max-age=3600"
    return response

# ── Request timing ────────────────────────────────────────────────────────────
@app.before_request
def start_timer():
    g.start = time.monotonic()

@app.after_request
def log_response(response):
    ms = round((time.monotonic() - g.start) * 1000, 1)
    log.info("%s %s %s %sms", request.method, request.path, response.status_code, ms)
    return response

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_):
    if not request.path.startswith(("/analyze", "/recent", "/health", "/stats", "/search")):
        try:
            return send_from_directory(FRONTEND, "index.html")
        except Exception:
            pass
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(429)
def rate_limited(_):
    return jsonify({"error": "Too many requests — please slow down"}), 429

@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Request body too large"}), 413

@app.errorhandler(500)
def server_error(e):
    log.error("Unhandled error: %s", e, exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# ── Helpers ───────────────────────────────────────────────────────────────────
def _check_threat_intel(url: str) -> bool:
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=5)
        if resp.status_code == 200:
            return url.lower() in resp.text.lower()
    except Exception:
        pass
    return False

def _check_known_list(url: str) -> bool:
    try:
        import tldextract
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower() in KNOWN_PHISHING_DOMAINS
    except Exception:
        return False

def _rule_based_score(f: dict) -> float:
    s = 0
    if f["has_ip"]:                 s += 25
    if not f["has_https"]:          s += 15
    if f["brand_similarity"]:       s += 30
    if f["has_suspicious_keyword"]: s += 15
    if f["num_at"] > 0:             s += 20
    if f["double_slash_redirect"]:  s += 10
    if f["url_length"] > 75:        s += 10
    if f["num_hyphens"] > 3:        s += 10
    if f["subdomain_count"] > 2:    s += 10
    return min(float(s), 99.0)

def _analyze_url_internal(url: str) -> dict | None:
    if not URL_RE.match(url):
        url = "http://" + url
    features = extract_features(url)
    if not features:
        return None

    confirmed  = _check_known_list(url) or _check_threat_intel(url)

    if model is not None:
        arr        = features_to_array(features).reshape(1, -1)
        prob       = float(model.predict_proba(arr)[0][1])
        confidence = round(prob * 100, 1)
    else:
        confidence = _rule_based_score(features)
        prob       = confidence / 100.0

    if confirmed:
        confidence = max(confidence, 97.0)
        prob       = max(prob, 0.97)

    if prob >= 0.75 or confirmed:
        risk, verdict = "HIGH",   "PHISHING"
    elif prob >= 0.45:
        risk, verdict = "MEDIUM", "SUSPICIOUS"
    else:
        risk, verdict = "LOW",    "SAFE"

    reasons = get_suspicious_reasons(features)
    if confirmed:
        reasons.insert(0, "URL found in threat intelligence database")

    return {
        "url":               url,
        "verdict":           verdict,
        "risk":              risk,
        "confidence":        confidence,
        "confirmed_phishing":confirmed,
        "reasons":           reasons,
        "features": {
            "url_length":          features["url_length"],
            "has_https":           bool(features["has_https"]),
            "has_ip":              bool(features["has_ip"]),
            "subdomain_count":     features["subdomain_count"],
            "suspicious_keywords": bool(features["has_suspicious_keyword"]),
            "brand_similarity":    bool(features["brand_similarity"]),
        },
        "time": datetime.datetime.now(datetime.UTC).isoformat(),
    }

# ── Seed log on startup ───────────────────────────────────────────────────────
def _seed_log():
    seed_urls = [
        "http://secure-paypa1-login.com/verify",
        "http://amaz0n-verify.net/signin",
        "https://www.google.com",
        "http://login-secure-banking.xyz/auth",
        "https://github.com",
        "http://netflix-billing.update-info.com",
        "https://www.microsoft.com",
        "http://paypal-secure.update-account.com",
        "https://stackoverflow.com",
        "http://apple-id.confirm-account.info",
        "https://www.amazon.com",
        "http://192.168.1.1/bank/login",
        "https://www.linkedin.com",
        "http://google-security-alert.com/login",
        "https://www.youtube.com",
    ]
    base_time = datetime.datetime.now(datetime.UTC)
    for i, url in enumerate(seed_urls):
        result = _analyze_url_internal(url)
        if result:
            result["time"] = (base_time - datetime.timedelta(minutes=i * 4)).isoformat()
            with _scan_log_lock:
                scan_log.append(result)
        time.sleep(0.05)
    log.info("Scan log seeded with %d entries", len(scan_log))

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
@limiter.limit("30 per minute")
def analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if len(url) > MAX_URL:
        return jsonify({"error": f"URL too long (max {MAX_URL} chars)"}), 400
    if any(c in url for c in ("\n", "\r", "\x00")):
        return jsonify({"error": "Invalid URL characters"}), 400

    if not URL_RE.match(url):
        url = "http://" + url

    result = _analyze_url_internal(url)
    if not result:
        return jsonify({"error": "Could not parse URL"}), 422

    with _scan_log_lock:
        scan_log.appendleft(result)
    save_scan(result)
    log.info("Analyzed %s → %s (%.1f%%)", url, result["verdict"], result["confidence"])
    return jsonify(result)

@app.route("/health", methods=["GET"])
@limiter.exempt
def health():
    return jsonify({
        "status":        "ok",
        "model_loaded":  model is not None,
        "db_connected":  is_connected(),
        "scan_log_size": len(scan_log),
        "version":       "1.0.0",
    })

@app.route("/recent", methods=["GET"])
@limiter.limit("60 per minute")
def recent():
    try:
        limit = min(int(request.args.get("limit", 20)), 100)
    except ValueError:
        limit = 20
    db_results = get_recent_scans(limit)
    with _scan_log_lock:
        fallback = list(scan_log)[:limit]
    return jsonify(db_results if db_results else fallback)

@app.route("/stats", methods=["GET"])
@limiter.limit("60 per minute")
def stats():
    return jsonify(get_stats())

@app.route("/search", methods=["GET"])
@limiter.limit("20 per minute")
def search():
    q = request.args.get("q", "").strip()
    if not q or len(q) < 3:
        return jsonify({"error": "Query must be at least 3 characters"}), 400
    if len(q) > 200:
        return jsonify({"error": "Query too long"}), 400
    try:
        limit = min(int(request.args.get("limit", 20)), 50)
    except ValueError:
        limit = 20
    return jsonify(search_scans(q, limit))

@app.route("/")
def index():
    return send_from_directory(FRONTEND, "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Forbidden"}), 403
    return send_from_directory(FRONTEND, filename)

# ── Startup ───────────────────────────────────────────────────────────────────
threading.Thread(target=_seed_log, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
