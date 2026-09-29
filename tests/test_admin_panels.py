"""Unit tests: admin-panel check stays quiet on non-WordPress sites.

Covers: WP paths gated on WordPress detection, soft-404 with dynamic
content, login-page heuristic, and the 403-on-WP-path case.

Run: cd ~/workspace/siteguard && ./venv/bin/python tests/test_admin_panels.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

from scanner import checks as C

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


class Resp:
    def __init__(self, text="", status=200, url="https://example.com/"):
        self.text = text
        self.status_code = status
        self.url = url
        self.headers = {}


LOGIN_FORM = ('<html><body><form action="/login">'
              '<input name="username"><input type="password" name="pwd">'
              '<button>Log In</button></form></body></html>')
WP_LOGIN_FORM = ('<html><body><form name="loginform" id="loginform">'
                 '<input type="text" name="log"><input type="password" name="pwd">'
                 '<input type="submit" value="Log In"></form></body></html>')


def make_fetch(routes):
    """routes: {url_suffix: Resp or Exception} — unmatched suffixes 404."""
    def fake_fetch(url, *a, **k):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return Resp("Not found", 404)
    return fake_fetch


def panel_findings(findings):
    return [f for f in findings
            if f["check"] == "admin_panels" and "Login/admin page" in f["title"]]


def panels_ok(findings):
    return any(f["check"] == "admin_panels"
               and "No exposed admin panels" in f["title"]
               for f in findings)


# --- 1. non-WP site, dynamic soft-404 on WP paths -> silence -----------------
routes = {
    "/siteguard-404-probe-a1b2c3d4e5.html":
        Resp("Not found. Request id 11111 rendered at 10:00:01.", 200),
    "/wp-admin/":
        Resp("Not found. Request id 22222 rendered at 10:00:02.", 200),
    "/wp-login.php":
        Resp("Not found. Request id 33333 rendered at 10:00:03.", 200),
    "/wp-json/": Resp("Not found", 404),
    "https://nwp.example/": Resp("<html><body>plain site</body></html>", 200),
    "/.git/HEAD": Resp("Not found", 404),
    "/.env": Resp("Not found", 404),
}
with patch.object(C, "fetch", side_effect=make_fetch(routes)):
    fs = C.check_admin_panels("https://nwp.example/")
titles = panel_findings(fs)
check("non-wp dynamic soft-404: no panel findings", titles == [],
      f"got {[f['title'] for f in titles]}")
check("non-wp dynamic soft-404: panels_ok info present", panels_ok(fs))

# --- 2. WP site with a real wp-login page -> MEDIUM ---------------------------
routes = {
    "/siteguard-404-probe-a1b2c3d4e5.html": Resp("Not found", 404),
    "/wp-json/": Resp('{"namespaces":["wp/v2"]}', 200),
    "/wp-login.php": WP_LOGIN_FORM and Resp(WP_LOGIN_FORM, 200),
    "/wp-admin/": Resp("", 302),
    "/.git/HEAD": Resp("Not found", 404),
    "/.env": Resp("Not found", 404),
}
with patch.object(C, "fetch", side_effect=make_fetch(routes)):
    fs = C.check_admin_panels("https://wp.example/")
wp_hits = [f for f in panel_findings(fs) if "wp-login" in f["title"]]
check("wp site real login: wp-login.php flagged MEDIUM",
      len(wp_hits) == 1 and wp_hits[0]["severity"] == "medium",
      f"got {[(f['title'], f['severity']) for f in wp_hits]}")

# --- 3. non-WP site with a REAL /admin login page -> still flagged ------------
routes = {
    "/siteguard-404-probe-a1b2c3d4e5.html": Resp("Not found", 404),
    "/wp-json/": Resp("Not found", 404),
    "https://app.example/": Resp("<html><body>laravel app</body></html>", 200),
    "/admin/": Resp(LOGIN_FORM, 200),
    "/.git/HEAD": Resp("Not found", 404),
    "/.env": Resp("Not found", 404),
}
with patch.object(C, "fetch", side_effect=make_fetch(routes)):
    fs = C.check_admin_panels("https://app.example/")
admin_hits = [f for f in panel_findings(fs) if "/admin/" in f["title"]]
check("non-wp real /admin login: still flagged MEDIUM",
      len(admin_hits) == 1 and admin_hits[0]["severity"] == "medium")
check("non-wp real /admin: wp paths not probed at all",
      not any("wp-" in f["title"] for f in panel_findings(fs)))

# --- 4. non-WP site, 403 on /wp-admin (WAF) -> no LOW --------------------------
routes = {
    "/siteguard-404-probe-a1b2c3d4e5.html": Resp("Not found", 404),
    "/wp-json/": Resp("Not found", 404),
    "https://waf.example/": Resp("<html><body>plain</body></html>", 200),
    "/wp-admin/": Resp("Forbidden", 403),
    "/.git/HEAD": Resp("Not found", 404),
    "/.env": Resp("Not found", 404),
}
with patch.object(C, "fetch", side_effect=make_fetch(routes)):
    fs = C.check_admin_panels("https://waf.example/")
check("non-wp 403 on /wp-admin: no LOW finding",
      panel_findings(fs) == [], f"got {[f['title'] for f in panel_findings(fs)]}")

# --- 5. 200 marketing page on /login (no login markers) -> silence -------------
routes = {
    "/siteguard-404-probe-a1b2c3d4e5.html": Resp("Not found", 404),
    "/wp-json/": Resp("Not found", 404),
    "https://mkt.example/": Resp("<html><body>plain</body></html>", 200),
    "/login": Resp("<html><body>Download our app to log in!</body></html>", 200),
    "/.git/HEAD": Resp("Not found", 404),
    "/.env": Resp("Not found", 404),
}
with patch.object(C, "fetch", side_effect=make_fetch(routes)):
    fs = C.check_admin_panels("https://mkt.example/")
check("200 non-login /login page: not flagged",
      panel_findings(fs) == [])

# --- 6. _is_soft_404 unit checks ----------------------------------------------
base = {"status": 200, "length": 100, "text": "page not found error 404"}
check("soft404 exact match",
      C._is_soft_404(Resp("page not found error 404", 200), base))
check("soft404 digit-normalized",
      C._is_soft_404(Resp("page not found error 405", 200), base))
check("soft404 fuzzy (>0.92)",
      C._is_soft_404(Resp("page not found err0r 404!", 200), base))
check("soft404 rejects login page",
      not C._is_soft_404(Resp(LOGIN_FORM, 200), base))
check("soft404 rejects non-200 baseline",
      not C._is_soft_404(Resp("page not found error 404", 200),
                         {"status": 404, "length": 100,
                          "text": "page not found error 404"}))

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
