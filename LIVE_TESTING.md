# ThreatTrace — Live Testing Checklist (macOS / VS Code)

This guide is for testing your local copy. It does not claim that Flask endpoints or a browser session have already been verified in another computer's environment.

## A. Open the right folder

1. Download and extract the ThreatTrace project ZIP.
2. In VS Code choose **File → Open Folder…** and select the inner `threattrace` folder.
3. Choose **Terminal → New Terminal**. All commands below should run from the folder containing `app.py`.

Confirm the files are present:

```bash
pwd
ls
```

You should see `app.py`, `analyzer.py`, `requirements.txt`, `sample_logs`, `static`, `templates`, and `tests`.

## B. Install the dependencies

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If package installation fails, check the exact pip error and confirm the Mac has internet access. Do not run the app with a different Python interpreter from the one used to install dependencies.

## C. Run automated tests

```bash
python -m pytest -q
```

The local test result reported by the developer was 18 passing tests. Re-run the tests in your own environment after making code changes.

## D. Start the local server

```bash
python app.py
```

Keep this terminal open. The expected local address is `http://127.0.0.1:5000`.

Open the dashboard: <http://127.0.0.1:5000>

## E. Verify real API responses in a second terminal

Open **Terminal → New Terminal** and run these while the server remains running.

Health endpoint (expected HTTP 200 and JSON with `"status":"ok"`):

```bash
curl -i http://127.0.0.1:5000/api/health
```

Analyze the bundled synthetic sample:

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"sample":true}'
```

Check summary statistics:

```bash
curl -s http://127.0.0.1:5000/api/stats
```

Test CSV and JSON reports:

```bash
curl -f -o threattrace-report.csv http://127.0.0.1:5000/api/export/csv
curl -f -o threattrace-report.json http://127.0.0.1:5000/api/export/json
ls -lh threattrace-report.csv threattrace-report.json
```

Test a file upload with the included synthetic log:

```bash
curl -s -X POST http://127.0.0.1:5000/api/analyze \
  -F 'file=@sample_logs/ThreatTrace_Test_Logs.log'
```

## F. Browser checklist

In the dashboard:

- Click **Load Sample Logs**; confirm metrics populate.
- Confirm the alerts section shows the potential brute-force alert.
- Search and filter the event table.
- Upload `sample_logs/ThreatTrace_Test_Logs.log`.
- Download CSV and JSON reports.
- Click refresh and clear-results; confirm the page responds without errors.
- Resize the browser to a mobile width and check navigation/layout.

## G. Stop the server

Return to the terminal running `python app.py` and press **Control + C**.

## H. Publish to GitHub

Only commit the source files and synthetic sample logs. Do not commit `.env`, API keys, virtual environments, or real sensitive logs. This local development server is not configured as a production internet-facing service.
