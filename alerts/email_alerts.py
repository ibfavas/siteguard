"""
Email alerts for new high-severity findings.

Graceful by design: if SMTP is not configured (the default), or if sending
fails for any reason, the function logs a note and returns False. Scanning
and the dashboard NEVER depend on email working.
"""

import logging
import smtplib
from email.message import EmailMessage

import config

log = logging.getLogger("siteguard.alerts.email")


def _smtp_configured():
    return (config.SMTP_ENABLED and config.SMTP_HOST
            and config.SMTP_USER and config.ALERT_EMAIL_TO)


def send_alert_email(subject, body):
    """Try to send an email. Returns True on success, False otherwise."""
    if not _smtp_configured():
        log.info("Email alert skipped: SMTP not configured "
                 "(set SMTP_* in config.py). Subject was: %s", subject)
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = config.SMTP_FROM or config.SMTP_USER
        msg["To"] = config.ALERT_EMAIL_TO
        msg.set_content(body)

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT,
                           timeout=20) as server:
            if config.SMTP_USE_TLS:
                server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
            server.send_message(msg)
        log.info("Email alert sent to %s: %s", config.ALERT_EMAIL_TO, subject)
        return True
    except Exception as exc:
        log.warning("Email alert FAILED (graceful): %s", exc)
        return False


def alert_new_high_findings(domain, new_high_findings):
    """Alert the site owner about newly discovered high-severity findings."""
    if not config.ALERT_ON_NEW_HIGH or not new_high_findings:
        return False
    lines = [
        f"SiteGuard found {len(new_high_findings)} NEW high-severity issue(s) "
        f"on {domain}:",
        "",
    ]
    for f in new_high_findings:
        lines.append(f"- {f['title']}")
        lines.append(f"  Why it matters: {f['explanation']}")
        lines.append(f"  Fix: {f['fix']}")
        lines.append("")
    lines.append("Log in to the SiteGuard dashboard for full details.")
    return send_alert_email(
        f"[SiteGuard] {len(new_high_findings)} new high-severity issue(s) on {domain}",
        "\n".join(lines),
    )
