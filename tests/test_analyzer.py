from analyzer import analyze_log, parse_line


def iso_line(timestamp, outcome="Failed", username="alice", ip="203.0.113.10"):
    return f"{timestamp} host-a sshd[100]: {outcome} password for {username} from {ip} port 43210 ssh2"


def test_parses_successful_login_and_normalizes_timestamp():
    event = parse_line("2026-10-23T12:00:00+02:00 host-a sshd[10]: Accepted publickey for maya from 192.0.2.4 port 22 ssh2", 1)
    assert event is not None
    assert event["event_type"] == "success_login"
    assert event["username"] == "maya"
    assert event["source_ip"] == "192.0.2.4"
    assert event["timestamp"] == "2026-10-23T10:00:00Z"
    assert event["severity"] == "info"


def test_parses_failed_login():
    event = parse_line("Oct 23 12:00:00 host-a sshd[10]: Failed password for invalid user admin from 203.0.113.10 port 3211 ssh2", 9)
    assert event["event_type"] == "failed_login"
    assert event["username"] == "admin"
    assert event["source_ip"] == "203.0.113.10"
    assert event["line_number"] == 9


def test_five_failures_in_ten_minutes_create_alert_and_match_metrics():
    rows = [iso_line(f"2026-10-23T12:0{i}:00Z", username=f"user{i}") for i in range(5)]
    result = analyze_log("\n".join(rows))
    assert result["summary"]["total_events"] == 5
    assert result["summary"]["failed_logins"] == 5
    assert result["summary"]["suspicious_activity"] == 5
    assert result["summary"]["alert_count"] == 1
    assert result["alerts"][0]["source_ip"] == "203.0.113.10"
    assert result["alerts"][0]["threshold"] == 5
    assert all(event["severity"] == "high" and event["suspicious"] for event in result["events"])
    assert "not proof of compromise" in result["alerts"][0]["explanation"]


def test_custom_threshold_and_rolling_window():
    in_window = [iso_line(f"2026-10-23T12:0{i}:00Z", username=f"u{i}") for i in range(3)]
    distant = iso_line("2026-10-23T12:10:00Z", username="late")
    result = analyze_log("\n".join(in_window + [distant]), threshold=3, window_minutes=2)
    assert result["summary"]["alert_count"] == 1
    assert result["summary"]["suspicious_activity"] == 3
    assert result["events"][-1]["suspicious"] is False
    assert result["settings"] == {"failure_threshold": 3, "window_minutes": 2}


def test_attempts_spread_outside_window_do_not_trigger():
    rows = [iso_line(f"2026-10-23T12:{minute:02d}:00Z", username=f"u{minute}") for minute in (0, 11, 22, 33, 44)]
    result = analyze_log("\n".join(rows), threshold=5, window_minutes=10)
    assert result["summary"]["alert_count"] == 0
    assert result["summary"]["suspicious_activity"] == 0


def test_empty_and_malformed_lines_are_safe_and_reported():
    result = analyze_log("\nnot an auth log\n2026-10-23Tbad host sshd: Accepted password for joe from 192.0.2.3\n")
    assert result["events"] == []
    assert result["summary"]["total_events"] == 0
    assert result["summary"]["malformed_lines"] == 2
    assert {item["line"] for item in result["malformed"]} == {2, 3}
    assert all("raw" not in item for item in result["malformed"])


def test_json_auth_record_is_supported():
    line = '{"timestamp":"2026-10-23T12:00:00Z","event_type":"login_failed","username":"ops","source_ip":"198.51.100.19"}'
    result = analyze_log(line)
    assert result["summary"]["failed_logins"] == 1
    assert result["events"][0]["username"] == "ops"


def test_invalid_ip_and_json_errors_are_reported_not_raised():
    result = analyze_log(
        '{"timestamp":"2026-10-23T12:00:00Z","event":"failed","source_ip":"999.1.2.3"}\n'
        '{not json}\n'
    )
    assert result["summary"]["malformed_lines"] == 2
    assert result["events"] == []


def test_threshold_window_and_line_limits_are_validated():
    import pytest
    with pytest.raises(ValueError, match="threshold"):
        analyze_log("", threshold=1)
    with pytest.raises(ValueError, match="window_minutes"):
        analyze_log("", window_minutes=0)
    with pytest.raises(ValueError, match="maximum of 2 lines"):
        analyze_log("a\nb\nc", max_lines=2)


def test_oversized_line_is_reported_and_skipped():
    result = analyze_log("x" * 10, max_line_chars=5)
    assert result["summary"]["malformed_lines"] == 1
    assert result["malformed"][0]["reason"] == "Line exceeds configured maximum length"
