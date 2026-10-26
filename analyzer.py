"""Local-only SSH authentication log parsing and transparent brute-force heuristics.

Supported input formats:
* OpenSSH syslog lines, e.g. ``Oct 23 12:00:00 host sshd[123]: Failed password for alice from 203.0.113.7 port 1234 ssh2``.
* ISO-8601 timestamped OpenSSH lines, e.g. ``2026-10-23T12:00:00Z host sshd[123]: Accepted publickey for alice from 192.0.2.8 port 22 ssh2``.
* One JSON object per line with ``timestamp``, ``event_type`` (or ``event``), and optional ``username``, ``source_ip``, ``host`` fields.

Raw input lines are deliberately not returned or retained in the result. This is a
heuristic analyzer, not an intrusion verdict or a substitute for log correlation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Any

SYSLOG_PREFIX = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[A-Za-z0-9_.-]{1,253})\s+sshd(?:\[\d+\])?:\s*(?P<message>.*)$",
    re.IGNORECASE,
)
ISO_PREFIX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[A-Za-z0-9_.-]{1,253})\s+sshd(?:\[\d+\])?:\s*(?P<message>.*)$",
    re.IGNORECASE,
)
SSH_RESULT = re.compile(
    r"^(?P<outcome>Accepted|Failed)\s+(?P<method>[A-Za-z0-9_/-]+)\s+for\s+"
    r"(?:(?:invalid)\s+user\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<ip>[0-9A-Fa-f:.]+)(?:\s|$)", re.IGNORECASE,
)
PAM_FAILURE = re.compile(r"authentication failure.*?rhost=(?P<ip>[0-9A-Fa-f:.]+).*?(?:user=(?P<username>[^\s]+))?", re.IGNORECASE)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

_SUCCESS_NAMES = {"success", "successful", "login_success", "success_login", "accepted", "successful_login"}
_FAILURE_NAMES = {"failure", "failed", "login_failed", "failed_login", "failure_login", "authentication_failure"}
_MONTHS = {name.lower(): number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}


def _safe_text(value: Any, fallback: str = "unknown", limit: int = 128) -> str:
    if value is None:
        return fallback
    text = CONTROL_CHARS.sub("", str(value)).strip()
    return (text[:limit] if text else fallback)


def normalize_timestamp(value: str, default_year: int | None = None) -> str:
    """Convert ISO-8601 or a syslog timestamp into UTC, second precision."""
    value = value.strip()
    if re.match(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", value):
        month, day, clock = value.split(maxsplit=2)
        dt = datetime.strptime(f"{default_year or datetime.now(timezone.utc).year} {month.title()} {int(day)} {clock}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        candidate = value.replace("Z", "+00:00")
        # Offset +HHMM is accepted by fromisoformat as well as +HH:MM.
        dt = datetime.fromisoformat(candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_ip(value: Any) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValueError("Invalid source IP address") from None


def _json_event(line: str, line_no: int) -> dict[str, Any] | None:
    if not line.lstrip().startswith("{"):
        return None
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        raise ValueError("Malformed JSON record") from None
    if not isinstance(value, dict):
        raise ValueError("JSON record must be an object")
    timestamp = value.get("timestamp") or value.get("time")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("JSON record requires a timestamp")
    raw_type = value.get("event_type", value.get("event", ""))
    kind = str(raw_type).strip().lower().replace("-", "_").replace(" ", "_")
    if kind in _SUCCESS_NAMES or kind.startswith("login_success"):
        event_type = "success_login"
    elif kind in _FAILURE_NAMES or kind.startswith("login_failed"):
        event_type = "failed_login"
    else:
        raise ValueError("Unsupported authentication event_type")
    try:
        normalized = normalize_timestamp(timestamp)
    except (ValueError, OverflowError):
        raise ValueError("Invalid timestamp") from None
    source_ip = _validate_ip(value.get("source_ip", value.get("ip")))
    username = _safe_text(value.get("username"))
    host = _safe_text(value.get("host"), "unknown", 253)
    return _make_event(line_no, normalized, host, username, source_ip, event_type, "JSON authentication record")


def _make_event(line_no: int, timestamp: str, host: str, username: str,
                source_ip: str | None, event_type: str, method: str) -> dict[str, Any]:
    is_success = event_type == "success_login"
    description = ("Successful" if is_success else "Failed") + f" SSH {method} login for {username}"
    if source_ip:
        description += f" from {source_ip}"
    return {
        "id": line_no,
        "line_number": line_no,
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "host": host,
        "severity": "info" if is_success else "medium",
        "suspicious": False,
        "description": description,
    }


def parse_line(raw_line: str, line_no: int) -> dict[str, Any] | None:
    """Parse one supported authentication record; raise ValueError for bad/unsupported lines."""
    line = raw_line.strip()
    if not line:
        return None
    json_record = _json_event(line, line_no)
    if json_record is not None:
        return json_record

    match = ISO_PREFIX.match(line)
    if match:
        timestamp_text = match.group("timestamp")
        host = match.group("host")
        message = match.group("message")
    else:
        match = SYSLOG_PREFIX.match(line)
        if not match:
            raise ValueError("Unsupported log format")
        timestamp_text = f"{match.group('month').title()} {match.group('day')} {match.group('clock')}"
        host = match.group("host")
        message = match.group("message")

    try:
        timestamp = normalize_timestamp(timestamp_text)
    except (ValueError, OverflowError):
        raise ValueError("Invalid timestamp") from None

    result = SSH_RESULT.match(message)
    if result:
        event_type = "success_login" if result.group("outcome").lower() == "accepted" else "failed_login"
        username = _safe_text(result.group("username"))
        try:
            source_ip = _validate_ip(result.group("ip"))
        except ValueError:
            raise ValueError("Invalid source IP address") from None
        return _make_event(line_no, timestamp, host, username, source_ip,
                           event_type, _safe_text(result.group("method"), "authentication", 32))

    pam = PAM_FAILURE.search(message)
    if pam:
        try:
            source_ip = _validate_ip(pam.group("ip"))
        except ValueError:
            raise ValueError("Invalid source IP address") from None
        username = _safe_text(pam.group("username"))
        return _make_event(line_no, timestamp, host, username, source_ip, "failed_login", "PAM authentication")

    raise ValueError("Unsupported authentication event")


def _event_dt(event: dict[str, Any]) -> datetime:
    return datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def analyze_log(text: str, threshold: int = 5, window_minutes: int = 10,
                max_lines: int = 10_000, max_line_chars: int = 8_192) -> dict[str, Any]:
    """Analyze text in memory and return only normalized event data and parser diagnostics."""
    if not isinstance(text, str):
        raise TypeError("Log content must be text")
    if threshold < 2 or threshold > 100:
        raise ValueError("threshold must be between 2 and 100")
    if window_minutes < 1 or window_minutes > 1_440:
        raise ValueError("window_minutes must be between 1 and 1440")
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise ValueError(f"Log contains more than the maximum of {max_lines} lines")

    events: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if len(line) > max_line_chars:
            issues.append({"line": line_no, "reason": "Line exceeds configured maximum length"})
            continue
        try:
            event = parse_line(line, line_no)
            if event is not None:
                events.append(event)
        except ValueError as exc:
            issues.append({"line": line_no, "reason": str(exc)})

    events.sort(key=lambda item: (item["timestamp"], item["line_number"]))
    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_type"] == "failed_login" and event["source_ip"]:
            failures_by_ip[event["source_ip"]].append(event)

    alerts: list[dict[str, Any]] = []
    window_seconds = window_minutes * 60
    for ip, ip_events in failures_by_ip.items():
        ip_events.sort(key=lambda item: (item["timestamp"], item["line_number"]))
        left = 0
        best_window: list[dict[str, Any]] = []
        suspicious_ids: set[int] = set()
        for right, event in enumerate(ip_events):
            current_dt = _event_dt(event)
            while left <= right and (current_dt - _event_dt(ip_events[left])).total_seconds() > window_seconds:
                left += 1
            if right - left + 1 >= threshold:
                qualifying = ip_events[left:right + 1]
                suspicious_ids.update(item["id"] for item in qualifying)
                if len(qualifying) > len(best_window):
                    best_window = list(qualifying)
        if suspicious_ids:
            for event in ip_events:
                if event["id"] in suspicious_ids:
                    event["suspicious"] = True
                    event["severity"] = "high"
            matched = [item for item in ip_events if item["id"] in suspicious_ids]
            usernames = sorted({item["username"] for item in matched})
            alerts.append({
                "id": f"bruteforce-{ip}",
                "type": "possible_brute_force",
                "severity": "high",
                "source_ip": ip,
                "failure_count": len(suspicious_ids),
                "peak_window_count": len(best_window),
                "window_minutes": window_minutes,
                "threshold": threshold,
                "first_seen": matched[0]["timestamp"],
                "last_seen": matched[-1]["timestamp"],
                "usernames": usernames[:10],
                "explanation": (
                    f"Observed at least {threshold} failed login events from {ip} within "
                    f"{window_minutes} minutes. This matches ThreatTrace's possible brute-force "
                    "heuristic; it is an indicator for review, not proof of compromise. "
                    "Shared NATs, misconfigured clients, or monitoring gaps can cause false positives."
                ),
            })

    alerts.sort(key=lambda item: (-item["peak_window_count"], item["source_ip"]))
    severity_counts = Counter(event["severity"] for event in events)
    success_count = sum(event["event_type"] == "success_login" for event in events)
    failure_count = sum(event["event_type"] == "failed_login" for event in events)
    ip_counts = Counter(event["source_ip"] for event in events
                        if event["event_type"] == "failed_login" and event["source_ip"])
    timeline_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"success": 0, "failed": 0})
    for event in events:
        bucket = event["timestamp"][:13] + ":00Z"
        key = "success" if event["event_type"] == "success_login" else "failed"
        timeline_counts[bucket][key] += 1
    timeline = [
        {"timestamp": bucket, "success": values["success"], "failed": values["failed"]}
        for bucket, values in sorted(timeline_counts.items())
    ]
    summary = {
        "total_events": len(events),
        "successful_logins": success_count,
        "failed_logins": failure_count,
        "unique_source_ips": len({e["source_ip"] for e in events if e["source_ip"]}),
        "suspicious_activity": sum(1 for event in events if event["suspicious"]),
        "alert_count": len(alerts),
        "malformed_lines": len(issues),
        "severity_counts": {key: severity_counts.get(key, 0) for key in ("info", "low", "medium", "high")},
        "alerts_by_severity": {"critical": 0, "high": sum(a["severity"] == "high" for a in alerts),
                               "medium": sum(a["severity"] == "medium" for a in alerts),
                               "low": sum(a["severity"] == "low" for a in alerts)},
        "timeline": timeline,
        "failed_by_ip": [{"source_ip": ip, "count": count} for ip, count in ip_counts.most_common(10)],
    }
    return {
        "summary": summary,
        "events": events,
        "alerts": alerts,
        "malformed": issues[:500],
        "settings": {"failure_threshold": threshold, "window_minutes": window_minutes},
    }
