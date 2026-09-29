"""
SiteGuard — website security monitoring for small businesses.

Run with:  python app.py
Then open: http://127.0.0.1:5000

This starts both the web dashboard and the APScheduler background
scheduler that re-scans every active site once per SCAN_INTERVAL_WEEKS.
"""

import logging
import threading

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, redirect, render_template, request, url_for, flash

import config
import db
import ui
from scanner import checks, engine
from alerts import email_alerts, whatsapp

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s: %(message)s")
log = logging.getLogger("siteguard")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


# ---------------------------------------------------------------------------
# Scan workers
# ---------------------------------------------------------------------------
def run_scan_for_site(site_id, scan_id=None):
    """Run a full scan for one site, store it, and fire alerts if needed.

    The scan is registered as 'running' first so the UI can show progress
    instead of silently displaying the previous scan's findings. Routes
    register the scan synchronously (to avoid a race where the page renders
    before the worker thread starts) and pass the id in; the scheduler
    passes nothing and the scan is registered here.
    """
    site = db.get_site(site_id)
    if not site:
        log.warning("scan requested for unknown site id %s", site_id)
        return
    domain = site["domain"]
    if scan_id is None:
        scan_id = db.start_scan(site_id)
    log.info("starting scan %s for %s", scan_id, domain)
    try:
        previous = db.get_site_state(site_id)
        result = engine.run_scan(domain, previous_state=previous)
        grade, new_high = db.finish_scan(scan_id, result)
        log.info("scan %s for %s finished: grade=%s, findings=%d",
                 scan_id, domain, grade, len(result["findings"]))
        if result["ok"] and new_high:
            email_alerts.alert_new_high_findings(domain, new_high)
            # WhatsApp stub: logs until the Business API is integrated.
            whatsapp.send_whatsapp_alert(
                f"SiteGuard: {len(new_high)} new high-severity issue(s) on {domain}.")
    except Exception:
        db.fail_scan(scan_id, "scan worker crashed; see server logs")
        log.exception("scan crashed for site %s (%s)", site_id, domain)


def probe_uptime_once(site_id):
    """Single up/down probe for one site (used on add/startup so the
    dashboard isn't empty for the first 30 minutes)."""
    site = db.get_site(site_id)
    if not site:
        return
    try:
        ok, status_code, ms = checks.check_uptime(site["domain"])
    except Exception:
        log.exception("uptime probe crashed for %s", site["domain"])
        ok, status_code, ms = False, None, None
    db.record_uptime(site["id"], ok, status_code, ms)


def scan_all_active_sites():
    """Scheduled job: scan every active site."""
    for site in db.list_sites():
        if site["active"]:
            run_scan_for_site(site["id"])


def run_uptime_round():
    """
    Scheduled job (every UPTIME_INTERVAL_MINUTES): lightweight up/down
    probe for every active site. Alerts only after 2 CONSECUTIVE failures,
    so a single flapping probe doesn't spam anyone.
    """
    for site in db.list_sites():
        if not site["active"]:
            continue
        domain = site["domain"]
        try:
            ok, status_code, ms = checks.check_uptime(domain)
        except Exception:
            log.exception("uptime check crashed for %s", domain)
            ok, status_code, ms = False, None, None
        db.record_uptime(site["id"], ok, status_code, ms)
        log.info("uptime %s: ok=%s status=%s ms=%s", domain, ok,
                 status_code, ms)

        recent = db.get_last_uptime_results(site["id"], 3)
        # Entering the down state: this check and the previous one both
        # failed, and the one before that was fine (or doesn't exist).
        # This fires exactly one alert per outage.
        if len(recent) >= 2 and not recent[0] and not recent[1]:
            if len(recent) < 3 or recent[2]:
                detail = (f"Last probe: HTTP {status_code} in {ms} ms."
                          if status_code else "Last probe: connection failed.")
                email_alerts.send_alert_email(
                    f"[SiteGuard] {domain} appears to be DOWN",
                    f"SiteGuard's uptime monitor could not reach {domain} on "
                    f"2 consecutive checks (every {config.UPTIME_INTERVAL_MINUTES} "
                    f"minutes).\n{detail}\n"
                    "Log in to the SiteGuard dashboard for details.")
                # WhatsApp stub: logs until the Business API is integrated.
                whatsapp.send_whatsapp_alert(
                    f"SiteGuard: {domain} appears to be DOWN (2 failed checks).")


@app.template_filter("humants")
def humants(value):
    """'2026-09-29T02:45:23+00:00' -> '29 Sep 2026, 02:45 UTC' (or 'today …')."""
    if not value:
        return "never"
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        label = dt.strftime("%d %b %Y, %H:%M UTC")
        if dt.date() == now.date():
            label = "today, " + dt.strftime("%H:%M UTC")
        elif (now.date() - dt.date()).days == 1:
            label = "yesterday, " + dt.strftime("%H:%M UTC")
        return label
    except Exception:
        return str(value)


GRADE_MEANINGS = {
    "A": "Excellent — nothing important found",
    "B": "Good — only minor issues",
    "C": "Fair — several issues to fix",
    "D": "Poor — important issues found",
    "F": "Critical — needs urgent attention",
}

SEVERITY_BLURBS = {
    "high": "Fix these first — they are the most likely to be abused.",
    "medium": "Worth fixing soon — real weaknesses, harder to abuse.",
    "low": "Minor hardening — good hygiene, low urgency.",
    "info": "Background checks — nothing for you to do.",
}


@app.template_filter("grade_meaning")
def grade_meaning_filter(grade):
    return GRADE_MEANINGS.get(grade, "")


@app.template_filter("sparkline")
def sparkline_filter(grades):
    """Inline SVG trend sparkline for a list of grades (oldest first)."""
    return ui.sparkline_svg(grades)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def site_overview(site):
    """Per-site summary dict used by the dashboard, sites and alerts pages."""
    latest_id = db.get_latest_completed_scan_id(site["id"])
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    if latest_id:
        scan = db.get_scan(latest_id)
        counts = db.count_by_severity(scan["findings"])
    uptime = db.get_latest_uptime(site["id"])
    uptime_pct = db.get_uptime_pct(site["id"], 24)
    uptime_strip = db.get_uptime_strip(site["id"], 24)
    running = db.is_scan_running(site["id"])
    action = counts["high"] + counts["medium"] + counts["low"]
    trend = db.get_grade_history(site["id"])
    return {"site": site, "counts": counts, "actionable": action,
            "uptime": uptime, "uptime_pct": uptime_pct,
            "uptime_strip": uptime_strip, "trend": trend,
            "scanning": bool(running)}


@app.route("/")
def dashboard():
    overviews = [site_overview(s) for s in db.list_sites()]
    grades = [o["site"]["last_grade"] for o in overviews
              if o["site"]["last_grade"]]
    pcts = [o["uptime_pct"] for o in overviews if o["uptime_pct"] is not None]
    need_attention = sorted(
        (o for o in overviews if o["actionable"] > 0),
        key=lambda o: (o["counts"]["high"], o["counts"]["medium"]),
        reverse=True)
    stats = {
        "sites": len(overviews),
        "added_this_month": ui.sites_added_this_month(
            [o["site"] for o in overviews]),
        "need_attention": len(need_attention),
        "avg_grade": ui.average_grade(grades),
        "uptime_24h": round(sum(pcts) / len(pcts), 1) if pcts else None,
    }
    recent_scans = db.get_recent_scans(8)
    any_scanning = any(o["scanning"] for o in overviews)
    return render_template("dashboard.html", stats=stats,
                           need_attention=need_attention,
                           recent_scans=recent_scans,
                           any_scanning=any_scanning,
                           alert_count=alert_count(),
                           active="dashboard")


@app.route("/sites")
def sites():
    overviews = [site_overview(s) for s in db.list_sites()]
    any_scanning = any(o["scanning"] for o in overviews)
    return render_template("sites.html", sites=overviews,
                           any_scanning=any_scanning,
                           alert_count=alert_count(),
                           active="sites")


def alert_count():
    """Number of active alert items (for the sidebar badge)."""
    return len(db.collect_alerts())


@app.route("/alerts")
def alerts():
    items = db.collect_alerts()
    delivery = {
        "email": bool(config.SMTP_ENABLED and config.ALERT_EMAIL_TO),
        "whatsapp": bool(config.WHATSAPP_ENABLED),
    }
    return render_template("alerts.html", items=items, delivery=delivery,
                           alert_count=len(items), active="alerts")


@app.route("/settings")
def settings():
    cfg = {
        "scan_interval_weeks": config.SCAN_INTERVAL_WEEKS,
        "uptime_interval_minutes": config.UPTIME_INTERVAL_MINUTES,
        "request_timeout": config.REQUEST_TIMEOUT,
        "user_agent": config.USER_AGENT,
        "smtp_enabled": config.SMTP_ENABLED,
        "alert_email_to": config.ALERT_EMAIL_TO,
        "alert_on_new_high": config.ALERT_ON_NEW_HIGH,
        "whatsapp_enabled": config.WHATSAPP_ENABLED,
    }
    return render_template("settings.html", cfg=cfg,
                           alert_count=alert_count(),
                           active="settings")


@app.route("/sites/add", methods=["POST"])
def add_site():
    raw = request.form.get("domain", "")
    domain = engine.normalize_domain(raw)
    if not domain or "." not in domain:
        flash(f"'{raw}' doesn't look like a valid domain.", "error")
        return redirect(url_for("sites"))
    site_id = db.add_site(domain)
    if site_id is None:
        flash(f"{domain} is already being monitored.", "error")
    else:
        flash(f"Added {domain}. Starting first scan…", "ok")
        # Register the scan synchronously so the dashboard never renders
        # in the gap before the worker thread starts.
        scan_id = db.start_scan(site_id)
        threading.Thread(target=run_scan_for_site, args=(site_id, scan_id),
                         daemon=True).start()
        # Immediate uptime probe so the dashboard isn't empty for 30 min.
        threading.Thread(target=probe_uptime_once, args=(site_id,),
                         daemon=True).start()
    return redirect(url_for("sites"))


@app.route("/sites/<int:site_id>/delete", methods=["POST"])
def delete_site(site_id):
    site = db.get_site(site_id)
    db.remove_site(site_id)
    flash(f"Removed {site['domain']}." if site else "Site removed.", "ok")
    return redirect(url_for("sites"))


@app.route("/sites/<int:site_id>/scan", methods=["POST"])
def scan_now(site_id):
    site = db.get_site(site_id)
    if not site:
        flash("Unknown site.", "error")
        return redirect(url_for("sites"))
    if db.is_scan_running(site_id):
        flash(f"A scan is already running for {site['domain']} —"
              " this page refreshes itself when it finishes.", "ok")
    else:
        flash(f"Scan started for {site['domain']} — it takes a couple of"
              " minutes; this page refreshes itself when it finishes.", "ok")
        # Register synchronously: avoids a race where the page renders
        # before the worker thread marks the scan as running.
        scan_id = db.start_scan(site_id)
        threading.Thread(target=run_scan_for_site, args=(site_id, scan_id),
                         daemon=True).start()
    return redirect(url_for("site_detail", site_id=site_id))


@app.route("/sites/<int:site_id>")
def site_detail(site_id):
    site = db.get_site(site_id)
    if not site:
        flash("Unknown site.", "error")
        return redirect(url_for("sites"))
    running = db.is_scan_running(site_id)
    latest_id = db.get_latest_completed_scan_id(site_id)
    latest = db.get_scan(latest_id) if latest_id else None
    findings = db.sort_findings(latest["findings"]) if latest else []
    grouped = {"high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        grouped.setdefault(f["severity"], []).append(f)
    history = db.get_scan_history(site_id)
    diff = db.get_scan_diff(site_id)
    if diff:
        diff["new"] = db.sort_findings(diff["new"])
        diff["fixed"] = db.sort_findings(diff["fixed"])
    trend = db.get_grade_history(site_id)
    overviews = [site_overview(s) for s in db.list_sites()]
    return render_template("site.html", site=site, latest=latest,
                           grouped=grouped, history=history,
                           diff=diff, trend=trend,
                           scanning=bool(running), running_since=(
                               running["started_at"] if running else None),
                           blurbs=SEVERITY_BLURBS,
                           alert_count=alert_count(),
                           active="sites")


@app.route("/sites/<int:site_id>/scans/<int:scan_id>")
def scan_detail(site_id, scan_id):
    site = db.get_site(site_id)
    data = db.get_scan(scan_id)
    if not site or not data or data["scan"]["site_id"] != site_id:
        flash("Unknown scan.", "error")
        return redirect(url_for("sites"))
    findings = db.sort_findings(data["findings"])
    grouped = {"high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        grouped.setdefault(f["severity"], []).append(f)
    overviews = [site_overview(s) for s in db.list_sites()]
    return render_template("scan.html", site=site, scan=data["scan"],
                           grouped=grouped, blurbs=SEVERITY_BLURBS,
                           alert_count=alert_count(),
                           active="sites")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(scan_all_active_sites, "interval",
                      weeks=config.SCAN_INTERVAL_WEEKS,
                      id="weekly-siteguard-scan",
                      max_instances=1, coalesce=True)
    scheduler.add_job(run_uptime_round, "interval",
                      minutes=config.UPTIME_INTERVAL_MINUTES,
                      id="siteguard-uptime",
                      max_instances=1, coalesce=True)
    scheduler.start()
    log.info("scheduler started: every site re-scanned every %s week(s); "
             "uptime probed every %s minute(s)",
             config.SCAN_INTERVAL_WEEKS, config.UPTIME_INTERVAL_MINUTES)
    return scheduler


# ---------------------------------------------------------------------------
# Initialization — runs on import so production servers (gunicorn) get the
# database and the background scheduler too, not just `python app.py`.
# Keep gunicorn to ONE worker: two workers would run the scheduler twice.
# ---------------------------------------------------------------------------
def init_app():
    import os
    os.makedirs(os.path.dirname(config.DATABASE_PATH) or ".", exist_ok=True)
    db.init_db()
    scheduler = start_scheduler()
    # One immediate uptime round on startup so the dashboard has data
    # within seconds instead of waiting for the first 30-minute tick.
    threading.Thread(
        target=lambda: [probe_uptime_once(s["id"]) for s in db.list_sites()
                        if s["active"]],
        daemon=True).start()
    return scheduler


scheduler = init_app()


if __name__ == "__main__":
    # use_reloader=False: the reloader would double-start the scheduler
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG,
            use_reloader=False)
