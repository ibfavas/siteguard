"""SQLite storage for sites, scans, findings and per-site state."""

import json
import sqlite3
from datetime import datetime, timezone

import config

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_scan_at TEXT,
            last_grade TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL REFERENCES sites(id),
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,      -- 'ok' | 'failed'
            grade TEXT,
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id),
            site_id INTEGER NOT NULL REFERENCES sites(id),
            check_name TEXT NOT NULL,
            severity TEXT NOT NULL,    -- info | low | medium | high
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            fix TEXT NOT NULL,
            details TEXT               -- JSON blob
        );
        CREATE TABLE IF NOT EXISTS site_state (
            site_id INTEGER PRIMARY KEY REFERENCES sites(id),
            content_hash TEXT,
            content_text TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS uptime_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL REFERENCES sites(id),
            checked_at TEXT NOT NULL,
            ok INTEGER NOT NULL,          -- 1 = reachable, 0 = down
            status_code INTEGER,          -- nullable
            response_ms INTEGER           -- nullable
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_site ON scans(site_id);
        CREATE INDEX IF NOT EXISTS idx_uptime_site ON uptime_checks(site_id);
    """)
    # Lightweight migrations for databases created by older versions.
    for stmt in (
        "ALTER TABLE site_state ADD COLUMN struct_hash TEXT",
        "ALTER TABLE site_state ADD COLUMN change_history TEXT",
    ):
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    conn.close()


# --- sites -----------------------------------------------------------------
def add_site(domain):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO sites (domain, active, created_at) VALUES (?, 1, ?)",
            (domain, _now()))
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None  # already tracked
    finally:
        conn.close()


def remove_site(site_id):
    conn = get_db()
    conn.execute("DELETE FROM findings WHERE site_id = ?", (site_id,))
    conn.execute("DELETE FROM scans WHERE site_id = ?", (site_id,))
    conn.execute("DELETE FROM site_state WHERE site_id = ?", (site_id,))
    conn.execute("DELETE FROM uptime_checks WHERE site_id = ?", (site_id,))
    conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
    conn.commit()
    conn.close()


def list_sites():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM sites ORDER BY created_at").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_site(site_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_latest_completed_scan_id(site_id):
    """Newest scan that actually finished ('ok' or 'failed').

    Findings pages must use this, never the raw latest row: while a scan
    is running, the raw latest row has no findings yet and the page would
    misleadingly keep showing the previous scan's results.
    """
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM scans WHERE site_id = ? AND status != 'running'"
        " ORDER BY id DESC LIMIT 1",
        (site_id,)).fetchone()
    conn.close()
    return row["id"] if row else None


def get_site_state(site_id):
    conn = get_db()
    row = conn.execute(
        "SELECT content_hash, content_text, struct_hash, change_history"
        " FROM site_state WHERE site_id = ?",
        (site_id,)).fetchone()
    conn.close()
    if row and row["content_hash"]:
        hist = {}
        try:
            hist = json.loads(row["change_history"] or "{}")
        except Exception:
            hist = {}
        return {
            "hash": row["content_hash"],
            "text": row["content_text"] or "",
            "struct_hash": row["struct_hash"],
            "struct_seq": hist.get("seq", ""),
            "text_changes": list(hist.get("text") or []),
            "struct_changes": list(hist.get("struct") or []),
        }
    return None


# --- uptime monitoring ----------------------------------------------------
def record_uptime(site_id, ok, status_code, response_ms):
    conn = get_db()
    conn.execute(
        "INSERT INTO uptime_checks (site_id, checked_at, ok, status_code,"
        " response_ms) VALUES (?, ?, ?, ?, ?)",
        (site_id, _now(), 1 if ok else 0, status_code, response_ms))
    # Keep the table bounded: drop rows older than 30 days per site.
    conn.execute(
        """DELETE FROM uptime_checks WHERE site_id = ?
           AND checked_at < datetime('now', '-30 days')""",
        (site_id,))
    conn.commit()
    conn.close()


def get_latest_uptime(site_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM uptime_checks WHERE site_id = ? ORDER BY id DESC LIMIT 1",
        (site_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_last_uptime_results(site_id, limit=3):
    """Most-recent uptime results, newest first: [True, False, ...]."""
    conn = get_db()
    rows = conn.execute(
        "SELECT ok FROM uptime_checks WHERE site_id = ? ORDER BY id DESC LIMIT ?",
        (site_id, limit)).fetchall()
    conn.close()
    return [bool(r["ok"]) for r in rows]


def get_uptime_strip(site_id, hours=24, max_blocks=48):
    """Uptime results for the strip chart, oldest first.

    Returns [{"ok": bool, "at": iso_ts}, ...], capped at max_blocks.
    Empty list when there is no data yet.
    """
    conn = get_db()
    rows = conn.execute(
        """SELECT ok, checked_at FROM uptime_checks
           WHERE site_id = ? AND checked_at >= datetime('now', ?)
           ORDER BY id ASC""",
        (site_id, f"-{int(hours)} hours")).fetchall()
    conn.close()
    rows = rows[-max_blocks:]
    return [{"ok": bool(r["ok"]), "at": r["checked_at"]} for r in rows]


def get_uptime_pct(site_id, hours=24):
    """Percentage of successful checks in the last `hours`. None if no data."""
    conn = get_db()
    row = conn.execute(
        """SELECT COUNT(*) AS total, COALESCE(SUM(ok), 0) AS up
           FROM uptime_checks
           WHERE site_id = ? AND checked_at >= datetime('now', ?)""",
        (site_id, f"-{int(hours)} hours")).fetchone()
    conn.close()
    total = row["total"] or 0
    if not total:
        return None
    return round(100.0 * row["up"] / total, 1)


# --- scans & findings ------------------------------------------------------
def compute_grade(findings):
    """A-F grade from finding counts. 'check_failed' findings are info: no penalty."""
    score = 100
    for f in findings:
        sev = f["severity"] if isinstance(f, dict) else f
        if sev == "high":
            score -= 25
        elif sev == "medium":
            score -= 10
        elif sev == "low":
            score -= 3
    score = max(score, 0)
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def save_scan(site_id, result):
    """Persist a scan result. Returns (scan_id, grade, new_high_findings).

    Thin wrapper around start_scan/finish_scan for one-shot callers.
    """
    scan_id = start_scan(site_id)
    grade, new_high = finish_scan(scan_id, result)
    return scan_id, grade, new_high


def start_scan(site_id):
    """Register a scan as 'running' and return its scan id.

    Any older scan for this site that is still marked 'running' (e.g. the
    process died mid-scan) is marked 'failed' first, so a stale row can
    never masquerade as an in-progress scan.
    """
    conn = get_db()
    conn.execute(
        "UPDATE scans SET status = 'failed', finished_at = ?,"
        " error = 'interrupted: superseded by a newer scan'"
        " WHERE site_id = ? AND status = 'running'",
        (_now(), site_id))
    cur = conn.execute(
        "INSERT INTO scans (site_id, started_at, finished_at, status, grade, error)"
        " VALUES (?, ?, NULL, 'running', NULL, NULL)",
        (site_id, _now()))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def fail_scan(scan_id, error):
    """Mark a running scan as failed (e.g. the worker crashed)."""
    conn = get_db()
    conn.execute(
        "UPDATE scans SET status = 'failed', finished_at = ?, error = ?"
        " WHERE id = ? AND status = 'running'",
        (_now(), str(error)[:500], scan_id))
    conn.commit()
    conn.close()


def finish_scan(scan_id, result):
    """Store a finished scan's findings/state and mark it ok/failed.

    Returns (grade, new_high_findings).
    """
    conn = get_db()
    row = conn.execute("SELECT site_id FROM scans WHERE id = ?",
                       (scan_id,)).fetchone()
    if not row:
        conn.close()
        raise ValueError(f"unknown scan id {scan_id}")
    site_id = row["site_id"]

    # previous high-severity titles, for "new high" alerting. Only
    # completed scans count — the row being finished is still 'running'
    # at this point, so it is excluded by the status filter.
    prev = conn.execute(
        """SELECT f.title FROM findings f
           JOIN scans s ON s.id = f.scan_id
           WHERE s.site_id = ? AND f.severity = 'high' AND s.status = 'ok'
             AND s.id = (SELECT MAX(id) FROM scans
                         WHERE site_id = ? AND status = 'ok')""",
        (site_id, site_id)).fetchall()
    prev_high_titles = {r["title"] for r in prev}

    grade = compute_grade(result["findings"]) if result["ok"] else None
    conn.execute(
        "UPDATE scans SET finished_at = ?, status = ?, grade = ?, error = ?"
        " WHERE id = ?",
        (_now(), "ok" if result["ok"] else "failed", grade,
         result.get("error"), scan_id))

    for f in result["findings"]:
        conn.execute(
            "INSERT INTO findings (scan_id, site_id, check_name, severity, title,"
            " explanation, fix, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, site_id, f["check"], f["severity"], f["title"],
             f["explanation"], f["fix"], json.dumps(f.get("details") or {})))

    if result.get("content_state"):
        st = result["content_state"]
        history = json.dumps({
            "text": list(st.get("text_changes") or [])[-5:],
            "struct": list(st.get("struct_changes") or [])[-5:],
            "seq": (st.get("struct_seq") or "")[:12000],
        })
        conn.execute(
            "INSERT INTO site_state (site_id, content_hash, content_text,"
            " struct_hash, change_history, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(site_id) DO UPDATE SET"
            " content_hash=excluded.content_hash,"
            " content_text=excluded.content_text,"
            " struct_hash=excluded.struct_hash,"
            " change_history=excluded.change_history,"
            " updated_at=excluded.updated_at",
            (site_id, st.get("hash"), (st.get("text") or "")[:20000],
             st.get("struct_hash"), history, _now()))

    conn.execute("UPDATE sites SET last_scan_at = ?, last_grade = ? WHERE id = ?",
                 (_now(), grade, site_id))
    conn.commit()
    conn.close()

    new_high = [f for f in result["findings"]
                if f["severity"] == "high" and f["title"] not in prev_high_titles]
    return grade, new_high


def is_scan_running(site_id):
    """True if this site has a scan currently marked 'running'."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, started_at FROM scans WHERE site_id = ? AND status = 'running'"
        " ORDER BY id DESC LIMIT 1", (site_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_scan(scan_id):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    findings = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY check_name",
        (scan_id,)).fetchall()
    conn.close()
    if not scan:
        return None
    return {"scan": dict(scan), "findings": [dict(f) for f in findings]}


def get_scan_history(site_id, limit=20):
    conn = get_db()
    rows = conn.execute(
        """SELECT s.*, COUNT(f.id) AS finding_count,
                  SUM(CASE WHEN f.severity='high' THEN 1 ELSE 0 END) AS highs,
                  SUM(CASE WHEN f.severity='medium' THEN 1 ELSE 0 END) AS mediums
           FROM scans s LEFT JOIN findings f ON f.scan_id = s.id
           WHERE s.site_id = ? GROUP BY s.id ORDER BY s.id DESC LIMIT ?""",
        (site_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_grade_history(site_id, limit=12):
    """Grades of recent completed scans, oldest first. For trend sparklines."""
    conn = get_db()
    rows = conn.execute(
        "SELECT grade FROM scans WHERE site_id = ? AND status = 'ok'"
        " AND grade IS NOT NULL ORDER BY id DESC LIMIT ?",
        (site_id, limit)).fetchall()
    conn.close()
    return [r["grade"] for r in reversed(rows)]


def get_recent_scans(limit=8):
    """Latest scans across all sites, newest first, with domain attached."""
    conn = get_db()
    rows = conn.execute(
        """SELECT s.id, s.site_id, s.started_at, s.finished_at, s.status,
                  s.grade, d.domain
           FROM scans s JOIN sites d ON d.id = s.site_id
           ORDER BY s.id DESC LIMIT ?""",
        (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def collect_alerts():
    """Active alert items across all sites, most urgent first.

    Each item: {"kind", "site", "title", "detail", "at"} where kind is
    "down" (latest uptime probe failed) or "new_high" (a high-severity
    finding appeared in the latest scan diff).
    """
    items = []
    for site in list_sites():
        uptime = get_latest_uptime(site["id"])
        if uptime and not uptime["ok"]:
            items.append({
                "kind": "down",
                "site": site,
                "title": f"{site['domain']} appears to be down",
                "detail": "The last uptime probe could not reach it.",
                "at": uptime["checked_at"],
            })
        diff = get_scan_diff(site["id"])
        if diff:
            for f in diff["new"]:
                if f["severity"] == "high":
                    items.append({
                        "kind": "new_high",
                        "site": site,
                        "title": f["title"],
                        "detail": f"New high-severity finding on"
                                  f" {site['domain']} ({f['check_name']}).",
                        "at": site["last_scan_at"],
                    })
    order = {"down": 0, "new_high": 1}
    return sorted(items, key=lambda i: order.get(i["kind"], 9))


def _diff_findings(prev, latest):
    """Pure diff of two finding lists. Identity = (check_name, title)."""
    key = lambda f: (f["check_name"] if isinstance(f, dict) else f["check_name"],
                     f["title"] if isinstance(f, dict) else f["title"])
    prev_keys = {key(f) for f in prev}
    latest_keys = {key(f) for f in latest}
    prev_by_key = {key(f): f for f in prev}
    new = [f for f in latest if key(f) not in prev_keys]
    fixed = [prev_by_key[k] for k in prev_keys - latest_keys]
    return {"new": new, "fixed": fixed}


def get_scan_diff(site_id):
    """What changed between the two latest completed ('ok') scans.

    Returns {"new": [...], "fixed": [...], "prev_id": id} or None when
    there are fewer than two completed scans to compare.
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT id FROM scans WHERE site_id = ? AND status = 'ok'"
        " ORDER BY id DESC LIMIT 2",
        (site_id,)).fetchall()
    if len(rows) < 2:
        conn.close()
        return None
    latest_id, prev_id = rows[0]["id"], rows[1]["id"]
    latest = [dict(r) for r in conn.execute(
        "SELECT check_name, title, severity FROM findings WHERE scan_id = ?",
        (latest_id,)).fetchall()]
    prev = [dict(r) for r in conn.execute(
        "SELECT check_name, title, severity FROM findings WHERE scan_id = ?",
        (prev_id,)).fetchall()]
    conn.close()
    diff = _diff_findings(prev, latest)
    diff["prev_id"] = prev_id
    return diff


def count_by_severity(findings):
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"] if isinstance(f, dict) else f["severity"]
        if sev in counts:
            counts[sev] += 1
    return counts


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
