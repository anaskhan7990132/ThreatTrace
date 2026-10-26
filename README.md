# ThreatTrace — Cybersecurity Log Analyzer

A local-first defensive authentication-log analyzer built with Python, Flask, HTML, CSS, and JavaScript. It highlights suspicious login patterns and can optionally use Groq AI to explain alerts.

## Features
- Parse supported SSH authentication logs and JSON-lines events
- Identify repeated login failures and possible brute-force activity
- Interactive dashboard with filters and timeline
- Export CSV/JSON reports
- Optional Groq AI alert explanations
- pytest automated tests

## Safety
Use only synthetic logs or logs you are authorized to analyze. Never commit `.env`, API keys, virtual environments, or real sensitive logs.

See the full project instructions and setup guide in this repository.