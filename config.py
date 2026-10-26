"""Configuration for ThreatTrace. Defaults are safe for local educational use."""
from __future__ import annotations
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_REQUEST_BYTES = MAX_UPLOAD_BYTES + 128 * 1024  # multipart form overhead
MAX_LOG_LINES = 10_000
MAX_LINE_CHARS = 8_192
DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 10
MIN_FAILURE_THRESHOLD = 2
MAX_FAILURE_THRESHOLD = 100
MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 1_440
ALLOWED_EXTENSIONS = {".log", ".txt"}
SECRET_KEY = os.environ.get("THREATTRACE_SECRET_KEY", "local-development-only-change-me")
HOST = os.environ.get("THREATTRACE_HOST", "127.0.0.1")
PORT = int(os.environ.get("THREATTRACE_PORT", "5000"))
DEBUG = os.environ.get("THREATTRACE_DEBUG", "0").lower() in {"1", "true", "yes"}
