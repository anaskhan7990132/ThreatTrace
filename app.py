"""ThreatTrace Flask application and local JSON API."""
from __future__ import annotations

import csv
from copy import deepcopy
from datetime import datetime, timezone
from io import StringIO
import json
from pathlib import Path
import threading

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from analyzer import analyze_log
from config import (
    ALLOWED_EXTENSIONS, BASE_DIR, DEFAULT_FAILURE_THRESHOLD, DEFAULT_WINDOW_MINUTES,
    HOST, MAX_LINE_CHARS, MAX_LOG_LINES, MAX_REQUEST_BYTES, MAX_UPLOAD_BYTES,
    PORT, DEBUG, SECRET_KEY,
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
    JSON_SORT_KEYS=False,
)
_state_lock = threading.RLock()
_current: dict | None = None


def _empty_analysis() -> dict:
    return {
        "summary": {
            "total_events": 0, "successful_logins": 0, "failed_logins": 0,
            "unique_source_ips": 0, "suspicious_activity": 0, "alert_count": 0,
            "malformed_lines": 0,
            "severity_counts": {"info": 0, "low": 0, "medium": 0, "high": 0},
            "alerts_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "timeline": [], "failed_by_ip": [],
        },
        "events": [], "alerts": [], "malformed": [],
        "settings": {"failure_threshold": DEFAULT_FAILURE_THRESHOLD, "window_minutes": DEFAULT_WINDOW_MINUTES},
    }


def _get_analysis() -> dict:
    with _state_lock:
        return deepcopy(_current if _current is not None else _empty_analysis())


def _set_analysis(value: dict) -> dict:
    global _current
    with _state_lock:
        _current = deepcopy(value)
        return deepcopy(_current)


def _json_error(message: str, status: int = 400, **details):
    body = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


def _parse_options(payload: dict) -> tuple[int, int]:
    try:
        threshold = int(payload.get("threshold", DEFAULT_FAILURE_THRESHOLD))
        window_minutes = int(payload.get("window_minutes", DEFAULT_WINDOW_MINUTES))
    except (TypeError, ValueError):
        raise ValueError("threshold and window_minutes must be integers") from None
    if not 2 <= threshold <= 100:
        raise ValueError("threshold must be between 2 and 100")
    if not 1 <= window_minutes <= 1_440:
        raise ValueError("window_minutes must be between 1 and 1440")
    return threshold, window_minutes


def _analyze_and_store(log_text: str, threshold: int, window_minutes: int):
    result = analyze_log(log_text, threshold, window_minutes, MAX_LOG_LINES, MAX_LINE_CHARS)
    result["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result["source"] = "uploaded_or_pasted_log"
    _set_analysis(result)
    return result


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    return response


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    return _json_error("Request exceeds the allowed upload size (5 MB log limit).", 413)


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return _json_error("API endpoint not found.", 404)
    return "Not found", 404


@app.errorhandler(500)
def server_error(_error):
    app.logger.exception("Unhandled ThreatTrace server error")
    return _json_error("An internal error occurred. No raw log content was recorded.", 500)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    result = _get_analysis()
    return jsonify({"status": "ok", "app": "ThreatTrace", "version": "1.0.0",
                    "analysis_loaded": result["summary"]["total_events"] > 0 or bool(result["malformed"])})


@app.post("/api/analyze")
def analyze():
    payload: dict = {}
    log_text: str | None = None
    source = "uploaded_or_pasted_log"

    if request.files:
        uploaded = request.files.get("file")
        if uploaded is None:
            return _json_error("Use the multipart field name 'file'.")
        original_name = uploaded.filename or ""
        if not original_name.strip():
            return _json_error("Choose a .log or .txt file.")
        # The file is never written to disk; reject path-looking names regardless.
        if "/" in original_name or "\\" in original_name or original_name in {".", ".."}:
            return _json_error("File paths are not accepted; upload a file by name only.")
        safe_name = secure_filename(original_name)
        if not safe_name or Path(safe_name).suffix.lower() not in ALLOWED_EXTENSIONS:
            return _json_error("Unsupported file type. Upload a plain-text .log or .txt file.")
        raw = uploaded.stream.read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            return _json_error("File exceeds the 5 MB upload limit.", 413)
        try:
            log_text = raw.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError:
            return _json_error("File must use UTF-8 text encoding.")
        payload = request.form.to_dict(flat=True)
    else:
        if not request.is_json:
            return _json_error("Send a UTF-8 .log/.txt file or a JSON body with log_text/sample.", 415)
        payload_value = request.get_json(silent=True)
        if not isinstance(payload_value, dict):
            return _json_error("JSON body must be an object.")
        payload = payload_value
        if payload.get("sample") is True:
            try:
                log_text = (BASE_DIR / "sample_logs" / "auth.log").read_text(encoding="utf-8")
            except OSError:
                return _json_error("Bundled sample log is unavailable.", 500)
            source = "synthetic_sample"
        elif isinstance(payload.get("log_text"), str):
            log_text = payload["log_text"]
            if len(log_text.encode("utf-8")) > MAX_UPLOAD_BYTES:
                return _json_error("Log text exceeds the 5 MB limit.", 413)
        else:
            return _json_error("JSON body must contain a string log_text or sample=true.")

    try:
        threshold, window_minutes = _parse_options(payload)
        result = _analyze_and_store(log_text or "", threshold, window_minutes)
    except ValueError as exc:
        status = 413 if "maximum of" in str(exc) else 400
        return _json_error(str(exc), status)
    result["source"] = source
    _set_analysis(result)
    return jsonify({
        "message": "Analysis completed.", "summary": result["summary"],
        "alerts": result["alerts"], "events": result["events"],
        "malformed": result["malformed"], "settings": result["settings"],
        "generated_at": result["generated_at"], "source": source,
    })


@app.get("/api/current")
def current_analysis():
    """Return the current normalized in-memory analysis for dashboard restoration."""
    analysis = _get_analysis()
    return jsonify({
        "summary": analysis["summary"], "alerts": analysis["alerts"],
        "events": analysis["events"], "malformed": analysis["malformed"],
        "settings": analysis["settings"], "generated_at": analysis.get("generated_at"),
        "source": analysis.get("source", "empty"),
    })


@app.get("/api/stats")
def stats():
    analysis = _get_analysis()
    return jsonify(analysis["summary"])


@app.get("/api/alerts")
def alerts():
    analysis = _get_analysis()
    return jsonify({"alerts": analysis["alerts"], "total": len(analysis["alerts"])})


@app.get("/api/events")
def events():
    analysis = _get_analysis()
    items = list(analysis["events"])
    q = request.args.get("q", "").strip().lower()[:200]
    event_type = request.args.get("event_type", "").strip().lower()
    ip_filter = request.args.get("ip", "").strip()[:64]
    severity = request.args.get("severity", "").strip().lower()
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()
    valid_types = {"success_login", "failed_login"}
    valid_severities = {"info", "low", "medium", "high"}
    if event_type and event_type not in valid_types:
        return _json_error("Invalid event_type filter.")
    if severity and severity not in valid_severities:
        return _json_error("Invalid severity filter.")
    try:
        if start:
            start = datetime.fromisoformat(start.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if end:
            end = datetime.fromisoformat(end.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return _json_error("Invalid start/end timestamp; use ISO-8601.")
    if start and end and start > end:
        return _json_error("start must be earlier than or equal to end.")
    filtered = []
    for item in items:
        if event_type and item["event_type"] != event_type:
            continue
        if ip_filter and ip_filter not in (item["source_ip"] or ""):
            continue
        if severity and item["severity"] != severity:
            continue
        if start and item["timestamp"] < start:
            continue
        if end and item["timestamp"] > end:
            continue
        if q and q not in " ".join(str(item.get(k, "")) for k in ("username", "source_ip", "host", "description", "event_type")).lower():
            continue
        filtered.append(item)
    try:
        page = max(1, int(request.args.get("page", "1")))
        page_size = min(200, max(1, int(request.args.get("page_size", "100"))))
    except ValueError:
        return _json_error("page and page_size must be integers.")
    start_at = (page - 1) * page_size
    return jsonify({"events": filtered[start_at:start_at + page_size], "total": len(filtered),
                    "page": page, "page_size": page_size})


@app.get("/api/export/csv")
def export_csv():
    analysis = _get_analysis()
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=["timestamp", "event_type", "username", "source_ip", "host", "severity", "suspicious", "description", "line_number"])
    writer.writeheader()
    for event in analysis["events"]:
        writer.writerow({key: event.get(key, "") for key in writer.fieldnames})
    response = Response("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="threattrace-report.csv"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/export/json")
def export_json():
    analysis = _get_analysis()
    payload = {
        "application": "ThreatTrace", "version": "1.0.0",
        "generated_at": analysis.get("generated_at"), "source": analysis.get("source", "empty"),
        "settings": analysis["settings"], "summary": analysis["summary"],
        "alerts": analysis["alerts"], "events": analysis["events"], "malformed": analysis["malformed"],
    }
    response = Response(json.dumps(payload, indent=2, ensure_ascii=False), mimetype="application/json; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="threattrace-report.json"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/clear")
def clear_results():
    global _current
    with _state_lock:
        _current = None
    return jsonify({"message": "Results cleared.", "summary": _empty_analysis()["summary"]})


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)
