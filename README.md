# ThreatTrace — Cybersecurity Log Analyzer

**Detect Suspicious Activity. Trace Threats. Strengthen Security.**

ThreatTrace is a local-first, defensive log-analysis dashboard for cybersecurity students and analysts. It parses supported SSH authentication records, calculates event statistics, highlights repeated login failures, explains each rule match, and exports an event report to CSV or JSON. Analysis is performed by Python on the machine running the Flask server; uploaded logs are processed in memory and never saved as uploaded files.

> **Ethical use:** Analyze synthetic logs or logs you are authorized to access. ThreatTrace is a learning and triage aid, not proof that a system has been compromised. It does not perform credential attacks, network scanning, exploitation, or automated blocking.

## Features

- Dark responsive dashboard with ThreatTrace shield/radar-inspired branding.
- Flask REST API and plain HTML/CSS/JavaScript frontend.
- Supported OpenSSH `auth.log` records and one-JSON-object-per-line authentication events.
- Successful and failed login parsing, timestamps, usernames, source IPs, and host names.
- Rule-driven possible brute-force alerts with editable threshold and time window.
- Overview metrics, activity timeline, failed attempts per IP, severity counts, alert explanations, searchable/filterable events, and parser diagnostics.
- `.log` / `.txt` UTF-8 upload with a 5 MB limit and a 10,000-line processing limit.
- CSV and JSON report downloads.
- Synthetic sample logs containing reserved example IP ranges and intentionally malformed lines.
- pytest coverage for parser behavior and Flask API routes.
- No paid APIs, keys, hosted AI model, or database required. The latest result is held in process memory and can be cleared.

## Technology stack

- Python 3
- Flask / Werkzeug
- HTML5, CSS, JavaScript
- Chart.js for charts when its CDN copy is available; a local canvas fallback supports offline charts
- pytest
- Git

## Project layout

```text
threattrace/
├── app.py                    # Flask app, API routes, upload checks and exports
├── analyzer.py               # Parser, analysis summary, and detection rule
├── config.py                 # Safe defaults and limits
├── requirements.txt
├── README.md
├── .gitignore
├── .env.example
├── sample_logs/
│   └── auth.log              # Synthetic SSH/authentication records
├── templates/
│   └── index.html            # Dashboard shell
├── static/
│   ├── css/style.css
│   └── js/dashboard.js       # API wiring and interactive dashboard
└── tests/
    ├── test_analyzer.py
    └── test_api.py
```

## macOS / VS Code setup

These commands assume the project folder is named `threattrace` and is open in VS Code. If you downloaded the generated project ZIP, unzip it first and open the extracted `threattrace` folder.

1. Open the folder in VS Code using **File → Open Folder…**, or from Terminal:

   ```bash
   cd /path/to/threattrace
   code .
   ```

   Replace `/path/to/threattrace` with the real location on your Mac. If the `code` command is unavailable, open VS Code and select **File → Open Folder…**.

2. Confirm Python and create a virtual environment:

   ```bash
   python3 --version
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

3. Start the local web app:

   ```bash
   python app.py
   ```

4. Open the dashboard at [http://127.0.0.1:5000](http://127.0.0.1:5000). Click **Load sample logs** to populate the dashboard with synthetic data, or choose a `.log` / `.txt` authentication file.

5. Run the automated tests in another Terminal tab, from the project root with `.venv` active:

   ```bash
   python -m pytest -q
   ```

6. Stop the server by focusing its Terminal tab and pressing `Control + C`. Leave the virtual environment with `deactivate` if desired.

### Optional environment settings

The defaults bind only to `127.0.0.1`, use port `5000`, and disable debug mode. `.env.example` documents optional variables; Flask does not automatically load a `.env` file in this project, so export overrides in the current shell, for example:

```bash
export THREATTRACE_PORT=5050
python app.py
```

Do not expose the development server to an untrusted network. This project is intended for local learning and review, not internet-facing production deployment.

## Using the synthetic sample

Choose **Load sample logs** in the dashboard. The button posts `{ "sample": true }` to the local `/api/analyze` endpoint, which reads `sample_logs/auth.log`. The sample includes successful logins, failed logins, six repeated failures from `203.0.113.44` during a short period, other source IPs, one JSON record, and unsupported/malformed lines. The addresses are documentation ranges reserved for examples; the events and identities are fictional.

Raw uploaded content is not written to disk and is not returned in API responses. Only normalized event fields and bounded parser diagnostics remain in the latest in-memory result. The API does not persist analysis between process restarts. The latest report is shared by clients of the same local server process, so this single-user demonstration should not be deployed as a multi-user service.

## Detection rule

**TT-AUTH-001 — Possible SSH brute-force activity**

- Default threshold: **5 failed login events** from the same source IP.
- Default window: **10 minutes**, calculated as a rolling time window.
- Configurable limits: threshold from 2–100; time window from 1–1,440 minutes.
- When any rolling window qualifies, the related failed events from that IP are marked `high` severity and one alert is created per source IP.
- Successful logins receive `info`; ordinary failed logins receive `medium` until they belong to a qualifying window.
- Malformed or unsupported lines are counted and reported by line number without echoing the raw input.

This is deliberately simple and transparent. It cannot tell whether a login succeeded through a different log source; does not deduplicate events from multiple collectors; does not detect distributed attempts across many IPs; and cannot account for NAT, proxies, clock drift, missing events, or every SSH/PAM message variant. Repeated failures can be legitimate. Treat a match as a lead to investigate, not as proof of malicious activity or compromise.

## Supported input formats

### OpenSSH syslog

```text
Oct 23 09:00:02 lab-gateway sshd[1101]: Accepted publickey for maya from 192.0.2.18 port 50122 ssh2
Oct 23 09:01:11 lab-gateway sshd[1103]: Failed password for invalid user admin from 203.0.113.44 port 51201 ssh2
```

The traditional syslog form has no year or timezone; ThreatTrace uses the current UTC year and assumes UTC for these timestamps. ISO timestamped records are normalized to UTC.

### JSON Lines

One JSON object per line with `timestamp`, `event_type` (or `event`), and optional `username`, `source_ip`, and `host`:

```json
{"timestamp":"2026-10-23T09:19:00Z","event_type":"login_failed","username":"qa-user","source_ip":"198.51.100.88","host":"lab-gateway"}
```

Supported event labels include `success`, `login_success`, `accepted`, `failure`, `failed`, `login_failed`, and `authentication_failure` (including documented underscore/hyphen variants). Source IP addresses, when supplied, must be valid IPv4 or IPv6 addresses.

## API reference

Responses are JSON for API routes unless the endpoint is a report download. Most errors use `{ "error": "readable explanation" }`. The current analysis is in server memory.

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Health/version and whether an analysis result is loaded |
| `GET /api/current` | Restore the current normalized in-memory analysis in the dashboard |
| `POST /api/analyze` | Analyze `multipart/form-data` field `file` or JSON `{ "log_text": "..." }`; use `{ "sample": true }` for bundled sample data |
| `GET /api/stats` | Counts, severity groupings, timeline series, and top failed-login IPs |
| `GET /api/alerts` | Alert objects and count |
| `GET /api/events` | Event list with optional query filters and pagination |
| `GET /api/export/csv` | CSV download of normalized events |
| `GET /api/export/json` | JSON download with summary, alerts, events, and diagnostics |
| `POST /api/clear` | Clear the active in-memory result |

`POST /api/analyze` accepts optional `threshold` and `window_minutes`. Example for local testing:

```bash
curl -s http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"sample":true,"threshold":5,"window_minutes":10}'

curl -s 'http://127.0.0.1:5000/api/events?event_type=failed_login&severity=high'
curl -OJ http://127.0.0.1:5000/api/export/csv
curl -OJ http://127.0.0.1:5000/api/export/json
```

Event filters: `q`, `event_type`, `ip`, `severity`, `start`, `end`, `page`, and `page_size`. Time filter inputs should be ISO-8601 timestamps. `page_size` is capped at 200. Uploads require a `.log` or `.txt` filename and UTF-8 text, are limited to 5 MB, and are processed up to 10,000 lines (each up to 8,192 characters).

## Reports and example output

The JSON report shape includes `application`, `version`, `generated_at`, `source`, `settings`, `summary`, `alerts`, `events`, and `malformed`. A representative summary for the bundled sample should include 12 parsed events, 3 successful logins, 9 failed logins, and one possible-brute-force alert under the default rule. Malformed-line counts depend on the lines in the sample file; generated results are calculated live.

## Testing

```bash
python -m pytest -q
```

The analyzer tests do not need Flask. The API integration suite requires the dependencies declared in `requirements.txt`. Tests cover parser formats, timezone normalization, threshold/window behavior, malformed input, upload type/path/size/encoding validation, endpoint responses, filtering, exports, and security headers.

## Screenshots

No screenshots are committed in the starter repository. Capture your own local dashboard after running the application and place verified images under a `screenshots/` folder before adding them to this section. Do not use fabricated UI evidence.

## GitHub repository preparation

- **Repository name:** `threattrace`
- **Suggested description:** `Local-first Python/Flask cybersecurity log analyzer with SSH authentication parsing, transparent brute-force heuristics, a responsive dashboard, and CSV/JSON reports.`
- **Suggested topics:** `cybersecurity`, `python`, `flask`, `log-analysis`, `blue-team`, `security-monitoring`, `authentication-logs`, `pytest`, `dashboard`

From the project folder, after reviewing the changes:

```bash
git init
git add .
git status
git commit -m "Build ThreatTrace cybersecurity log analyzer"
# Create an empty repository named threattrace on GitHub, then run:
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/threattrace.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Do not commit real authentication logs, `.env` files, tokens, private IP inventories, or screenshots containing sensitive data.
