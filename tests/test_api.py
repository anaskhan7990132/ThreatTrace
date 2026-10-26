"""Flask API integration tests. These require the dependencies in requirements.txt."""
import io
import json
import pytest

pytest.importorskip("flask")
from app import app


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        test_client.post("/api/clear")
        yield test_client
        test_client.post("/api/clear")


def test_health_and_dashboard(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json["status"] == "ok"
    assert client.get("/").status_code == 200
    assert b"ThreatTrace" in client.get("/").data


def test_sample_analysis_stats_alerts_and_events(client):
    response = client.post("/api/analyze", json={"sample": True})
    assert response.status_code == 200
    body = response.json
    assert body["source"] == "synthetic_sample"
    assert body["summary"]["total_events"] == 12
    assert body["summary"]["successful_logins"] == 3
    assert body["summary"]["failed_logins"] == 9
    assert body["summary"]["alert_count"] == 1
    assert body["summary"]["malformed_lines"] >= 2
    assert client.get("/api/stats").json["total_events"] == 12
    assert client.get("/api/current").json["generated_at"]
    assert client.get("/api/current").json["source"] == "synthetic_sample"
    assert client.get("/api/alerts").json["total"] == 1
    assert client.get("/api/events?event_type=failed_login").json["total"] == 9
    assert client.get("/api/events?ip=203.0.113.44&severity=high").json["total"] == 6


def test_json_log_analysis_and_configuration_validation(client):
    payload = {"log_text": "2026-10-23T12:00:00Z node sshd[2]: Accepted password for kim from 192.0.2.2 port 22 ssh2", "threshold": 4, "window_minutes": 3}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    assert response.json["summary"]["successful_logins"] == 1
    assert response.json["settings"] == {"failure_threshold": 4, "window_minutes": 3}
    bad = client.post("/api/analyze", json={"log_text": "", "threshold": 1})
    assert bad.status_code == 400
    assert "threshold" in bad.json["error"]


def test_upload_validation_and_success(client):
    bad_extension = client.post("/api/analyze", data={"file": (io.BytesIO(b"hello"), "logs.csv")}, content_type="multipart/form-data")
    assert bad_extension.status_code == 400
    assert "Unsupported file type" in bad_extension.json["error"]
    traversal = client.post("/api/analyze", data={"file": (io.BytesIO(b"hello"), "../auth.log")}, content_type="multipart/form-data")
    assert traversal.status_code == 400
    assert "File paths" in traversal.json["error"]
    uploaded = client.post("/api/analyze", data={"file": (io.BytesIO(b"2026-10-23T12:00:00Z node sshd[1]: Accepted password for sam from 192.0.2.1 port 22 ssh2"), "auth.log")}, content_type="multipart/form-data")
    assert uploaded.status_code == 200
    assert uploaded.json["summary"]["successful_logins"] == 1


def test_oversized_upload_and_invalid_encoding(client):
    too_large = client.post("/api/analyze", data={"file": (io.BytesIO(b"x" * (5 * 1024 * 1024 + 1)), "large.log")}, content_type="multipart/form-data")
    assert too_large.status_code == 413
    invalid = client.post("/api/analyze", data={"file": (io.BytesIO(b"\xff\xfe\x00"), "invalid.txt")}, content_type="multipart/form-data")
    assert invalid.status_code == 400
    assert "UTF-8" in invalid.json["error"]


def test_exports_are_real_downloads(client):
    client.post("/api/analyze", json={"sample": True})
    csv_response = client.get("/api/export/csv")
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.content_type
    assert b"source_ip" in csv_response.data
    assert b"203.0.113.44" in csv_response.data
    json_response = client.get("/api/export/json")
    assert json_response.status_code == 200
    report = json.loads(json_response.data.decode("utf-8"))
    assert report["application"] == "ThreatTrace"
    assert len(report["events"]) == 12
    assert "Content-Disposition" in json_response.headers


def test_event_filters_errors_and_clear(client):
    client.post("/api/analyze", json={"sample": True})
    assert client.get("/api/events?severity=unknown").status_code == 400
    assert client.get("/api/events?start=bad-time").status_code == 400
    assert client.get("/api/events?start=2026-10-24T00:00:00Z&end=2026-10-23T00:00:00Z").status_code == 400
    response = client.post("/api/clear")
    assert response.status_code == 200
    assert client.get("/api/stats").json["total_events"] == 0


def test_api_errors_are_json_and_security_headers_present(client):
    bad = client.post("/api/analyze", json={"nonsense": True})
    assert bad.status_code == 400
    assert bad.is_json
    health = client.get("/api/health")
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert health.headers["X-Frame-Options"] == "DENY"
