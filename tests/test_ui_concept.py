"""Unit tests for the UI concept pass: sparkline, scan diff, grade history,
uptime strip.

Run: cd ~/workspace/siteguard && ./venv/bin/python tests/test_ui_concept.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db
import ui

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          (f" — {detail}" if detail and not cond else ""))


# ---------------------------------------------------------------- sparkline
check("sparkline: empty -> ''", ui.sparkline_svg([]) == "")
check("sparkline: single grade -> ''", ui.sparkline_svg(["A"]) == "")
check("sparkline: one real grade + junk -> ''",
      ui.sparkline_svg(["A", None, "Z"]) == "")

svg_up = ui.sparkline_svg(["C", "B", "A"])
check("sparkline: improving trend is green",
      "<svg" in svg_up and "#15803d" in svg_up)
check("sparkline: worsening trend is red",
      "#c0392b" in ui.sparkline_svg(["A", "B", "F"]))
check("sparkline: flat trend is grey",
      "#6b7a8d" in ui.sparkline_svg(["B", "B"]))
pts = svg_up.split('points="')[1].split('"')[0].split(" ")
check("sparkline: one point per grade", len(pts) == 3, f"got {pts}")
check("sparkline: svg has accessible label",
      'aria-label="grade trend:' in svg_up)
check("sparkline: last point is marked",
      svg_up.count("<circle") == 1)


# ------------------------------------------------------- pure finding diff
def _f(check_name, title, severity="low"):
    return {"check_name": check_name, "title": title, "severity": severity}


PREV = [_f("hsts", "Missing HSTS includeSubDomains"),
        _f("xss", "Reflected XSS in search", "high")]
LATEST = [_f("hsts", "Missing HSTS includeSubDomains"),
          _f("csp", "No Content-Security-Policy", "medium")]

d = db._diff_findings(PREV, LATEST)
check("diff: detects the new finding",
      [f["title"] for f in d["new"]] == ["No Content-Security-Policy"])
check("diff: detects the fixed finding",
      [f["title"] for f in d["fixed"]] == ["Reflected XSS in search"])
d_same = db._diff_findings(PREV, list(PREV))
check("diff: identical scans -> nothing new/fixed",
      d_same["new"] == [] and d_same["fixed"] == [])
d_empty = db._diff_findings([], LATEST)
check("diff: empty previous -> everything is new",
      len(d_empty["new"]) == 2 and d_empty["fixed"] == [])
check("diff: same title under another check is a different finding",
      len(db._diff_findings([_f("a", "Same title")],
                            [_f("b", "Same title")])["new"]) == 1)


# ------------------------------------------------- db-backed (temp sqlite)
def tmpdb():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    config.DATABASE_PATH = path
    db.init_db()
    return path


def add_scan(site_id, grade=None, status="ok", findings=()):
    conn = db.get_db()
    cur = conn.execute(
        "INSERT INTO scans (site_id, started_at, finished_at, status, grade)"
        " VALUES (?, '2026-01-01T00:00:00+00:00',"
        " '2026-01-01T00:01:00+00:00', ?, ?)",
        (site_id, status, grade))
    scan_id = cur.lastrowid
    for f in findings:
        conn.execute(
            "INSERT INTO findings (scan_id, site_id, check_name, severity,"
            " title, explanation, fix) VALUES (?, ?, ?, ?, ?, '', '')",
            (scan_id, site_id, f["check_name"], f["severity"], f["title"]))
    conn.commit()
    conn.close()
    return scan_id


def fresh_site(domain="example.com"):
    path = tmpdb()
    site_id = db.add_site(domain)
    return path, site_id


# --- get_scan_diff
path, sid = fresh_site()
s1 = add_scan(sid, "C", findings=[_f("hsts", "Missing HSTS"),
                                 _f("old", "Old issue", "high")])
s2 = add_scan(sid, "B", findings=[_f("hsts", "Missing HSTS"),
                                 _f("new", "New issue", "medium")])
diff = db.get_scan_diff(sid)
check("scan_diff: returns prev scan id", diff["prev_id"] == s1)
check("scan_diff: new finding detected",
      [f["title"] for f in diff["new"]] == ["New issue"])
check("scan_diff: fixed finding detected",
      [f["title"] for f in diff["fixed"]] == ["Old issue"])
os.unlink(path)

path, sid = fresh_site()
add_scan(sid, "A", findings=[_f("hsts", "Missing HSTS")])
check("scan_diff: single scan -> None", db.get_scan_diff(sid) is None)
os.unlink(path)

path, sid = fresh_site()
s1 = add_scan(sid, "C", findings=[_f("hsts", "Missing HSTS")])
add_scan(sid, None, status="failed")  # failed scans are not diffed
s3 = add_scan(sid, "B", findings=[_f("hsts", "Missing HSTS"),
                                 _f("new", "Brand new", "low")])
diff = db.get_scan_diff(sid)
check("scan_diff: skips failed scans",
      diff["prev_id"] == s1 and len(diff["new"]) == 1)
os.unlink(path)

# --- get_grade_history
path, sid = fresh_site()
add_scan(sid, "C")
add_scan(sid, None, status="failed")   # excluded: failed
add_scan(sid, "B")
add_scan(sid, None, status="ok")       # excluded: no grade
add_scan(sid, "A")
check("get_grade_history: oldest-first, ok+graded only",
      db.get_grade_history(sid) == ["C", "B", "A"])
check("get_grade_history: honors limit",
      db.get_grade_history(sid, limit=2) == ["B", "A"])
os.unlink(path)

# --- get_uptime_strip
path, sid = fresh_site()
for ok in (True, False, True):
    db.record_uptime(sid, ok, 200 if ok else None, 120)
strip = db.get_uptime_strip(sid)
check("uptime_strip: oldest first",
      [c["ok"] for c in strip] == [True, False, True])
check("uptime_strip: carries timestamps",
      all(c["at"] for c in strip))
for ok in [True] * 60:
    db.record_uptime(sid, ok, 200, 100)
check("uptime_strip: capped at 48 blocks",
      len(db.get_uptime_strip(sid)) == 48)
os.unlink(path)

path, sid = fresh_site("nodata.example")
check("uptime_strip: no data -> []", db.get_uptime_strip(sid) == [])
os.unlink(path)


# ------------------------------------------------- stat helpers (ui.py)
check("average_grade: empty -> None", ui.average_grade([]) is None)
check("average_grade: mean of A,A,B -> A",
      ui.average_grade(["A", "A", "B"]) == "A")
check("average_grade: mean of C,D -> D",
      ui.average_grade(["C", "D"]) == "D")
check("average_grade: ignores junk", ui.average_grade(["A", "Z", None]) == "A")

from datetime import datetime, timezone
now = datetime.now(timezone.utc)
this_month = now.strftime("%Y-%m-01T00:00:00+00:00")
sites = [{"created_at": this_month},
         {"created_at": "2020-01-15T00:00:00+00:00"},
         {"created_at": "not-a-date"}]
check("sites_added_this_month: counts current month only",
      ui.sites_added_this_month(sites, now) == 1)


# ------------------------------------------------- recent scans + alerts
path, sid = fresh_site()
s1 = add_scan(sid, "C")
path2, sid2 = None, None
# second site in the same db
sid2 = db.add_site("other.example")
s2 = add_scan(sid2, "A")
recent = db.get_recent_scans(2)
check("get_recent_scans: newest first with domains",
      [r["id"] for r in recent] == [s2, s1]
      and recent[0]["domain"] == "other.example")
check("get_recent_scans: honors limit",
      len(db.get_recent_scans(1)) == 1)
os.unlink(path)

# alerts: one site down, one with a new high finding
path, sid = fresh_site()
db.record_uptime(sid, False, None, None)
add_scan(sid, "D", findings=[_f("hsts", "Missing HSTS")])
add_scan(sid, "F", findings=[_f("hsts", "Missing HSTS"),
                             _f("xss", "Reflected XSS", "high")])
items = db.collect_alerts()
kinds = [i["kind"] for i in items]
check("collect_alerts: finds down + new_high",
      kinds == ["down", "new_high"], f"got {kinds}")
check("collect_alerts: items carry site + text",
      all(i["site"]["domain"] == "example.com" and i["title"]
          for i in items))
os.unlink(path)

path, sid = fresh_site("quiet.example")
db.record_uptime(sid, True, 200, 50)
add_scan(sid, "A", findings=[])
add_scan(sid, "A", findings=[])
check("collect_alerts: quiet site -> no items",
      db.collect_alerts() == [])
os.unlink(path)


print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
