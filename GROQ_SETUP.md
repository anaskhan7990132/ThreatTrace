# ThreatTrace — Groq API Setup (macOS / VS Code)

This integration uses Groq's OpenAI-compatible Chat Completions endpoint. The API key stays in your local `.env` file and is never embedded in frontend JavaScript.

## 1. Configure `.env`

Create `.env` beside `app.py` (or update the existing one). Keep the following settings and paste your own key locally:

```dotenv
GROQ_API_KEY=your_actual_groq_key_here
GROQ_MODEL=openai/gpt-oss-120b
```

Do not share the key, commit `.env`, or paste the key into chat. `.gitignore` excludes `.env`.

Create a key at https://console.groq.com/keys. Model IDs and availability can change; if this model is unavailable to your account, check https://console.groq.com/docs/models and set `GROQ_MODEL` to a currently available chat model.

## 2. Install dependencies and run

In the VS Code terminal, from the directory containing `app.py`:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
python app.py
```

Open http://127.0.0.1:5000, click **Load Sample Logs**, open the alerts section, then click **Explain with AI** on an alert. The API call only sends a generic detection type, severity, failed-attempt count, threshold, and time window—not raw log lines, usernames, hostnames, IP addresses, or timestamps.

## 3. Test the key without revealing it

The dashboard health response shows whether a Groq key is configured:

```bash
curl -s http://127.0.0.1:5000/api/health
```

Look for `"ai_enabled":true`. This only checks whether a key is present, not whether Groq accepts it. The definitive test is clicking **Explain with AI** after an alert appears.

If the request fails with an authentication/model error, recheck the `.env` key/model and restart `python app.py`. If you receive a rate-limit response, wait or check the limits shown in your Groq account. Never print or share the API key while troubleshooting.
