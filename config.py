# SiteGuard configuration.
#
# Every setting below can be overridden with an environment variable
# (useful on hosted platforms like Render — see README "Deploying").
# Plain values here are the local defaults. Do NOT commit real SMTP
# passwords or API tokens to version control — use env vars / a .env file
# (.env is git-ignored).

import os


def _env(name, default=""):
    return os.environ.get(name, default)


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


# --- Scanning ---------------------------------------------------------------
SCAN_INTERVAL_WEEKS = _env_int("SITEGUARD_SCAN_INTERVAL_WEEKS", 1)  # re-scan cadence
UPTIME_INTERVAL_MINUTES = _env_int("SITEGUARD_UPTIME_INTERVAL_MINUTES", 30)  # uptime probe cadence
REQUEST_TIMEOUT = _env_int("SITEGUARD_REQUEST_TIMEOUT", 15)          # seconds per request
USER_AGENT = _env("SITEGUARD_USER_AGENT",
                 "SiteGuard/1.0 (+security-monitoring; authorized scans only)")

# Only scan sites you own or have written permission to test.
# Probing admin paths on third-party sites without authorization may be illegal.

# --- Storage ----------------------------------------------------------------
DATABASE_PATH = _env("SITEGUARD_DATABASE_PATH", "data/siteguard.db")

# --- Flask ------------------------------------------------------------------
SECRET_KEY = _env("SITEGUARD_SECRET_KEY", "change-me-to-a-random-value")
HOST = _env("SITEGUARD_HOST", "127.0.0.1")
# Render and similar hosts inject PORT themselves — respect it first.
PORT = _env_int("PORT", _env_int("SITEGUARD_PORT", 5000))
DEBUG = _env_bool("SITEGUARD_DEBUG", False)

# --- Email alerts -----------------------------------------------------------
# When a scan finds NEW high-severity findings, SiteGuard tries to email
# ALERT_EMAIL_TO. If SMTP_ENABLED is False (default), alerts are skipped
# gracefully and a note is written to the log — nothing crashes.
SMTP_ENABLED = _env_bool("SITEGUARD_SMTP_ENABLED", False)
SMTP_HOST = _env("SITEGUARD_SMTP_HOST", "")            # e.g. "smtp.gmail.com"
SMTP_PORT = _env_int("SITEGUARD_SMTP_PORT", 587)
SMTP_USER = _env("SITEGUARD_SMTP_USER", "")            # full login username
SMTP_PASSWORD = _env("SITEGUARD_SMTP_PASSWORD", "")    # app password — keep out of git
SMTP_FROM = _env("SITEGUARD_SMTP_FROM", "")            # e.g. "siteguard@example.com"
SMTP_USE_TLS = _env_bool("SITEGUARD_SMTP_USE_TLS", True)
ALERT_EMAIL_TO = _env("SITEGUARD_ALERT_EMAIL_TO", "")
ALERT_ON_NEW_HIGH = _env_bool("SITEGUARD_ALERT_ON_NEW_HIGH", True)

# --- WhatsApp alerts --------------------------------------------------------
# WhatsApp alerting is a STUB (see alerts/whatsapp.py). Fill these in when the
# WhatsApp Business API integration is implemented.
WHATSAPP_ENABLED = _env_bool("SITEGUARD_WHATSAPP_ENABLED", False)
WHATSAPP_API_URL = _env("SITEGUARD_WHATSAPP_API_URL", "")
WHATSAPP_API_TOKEN = _env("SITEGUARD_WHATSAPP_API_TOKEN", "")
WHATSAPP_TO_NUMBER = _env("SITEGUARD_WHATSAPP_TO_NUMBER", "")  # E.164, e.g. "+919812345678"
