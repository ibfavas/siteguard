"""Unit tests for scanner/checks_extra.py — all network/DNS mocked.

NOTE: checks_extra imports `fetch` directly (`from scanner.checks import
fetch`), so homepage fetches are mocked via patch.object(X, "fetch").
Helpers accessed as C.<name> (e.g. C._download_capped) are patched on C.

Run: cd ~/workspace/siteguard && ./venv/bin/python tests/test_checks_extra.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

from scanner import checks_extra as X
from scanner import checks as C

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))


class Resp:
    def __init__(self, text="", status=200, url="https://example.com/", headers=None):
        self.text = text
        self.status_code = status
        self.url = url
        self.headers = headers or {}

    def json(self):
        import json
        return json.loads(self.text)


# --- CVSS v3 vector scoring -------------------------------------------------
check("cvss_6.1", X._cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1)
check("cvss_10.0", X._cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0)
check("cvss_9.8", X._cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8)
check("cvss_7.5", X._cvss_v3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5)
check("cvss_0.0", X._cvss_v3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N") == 0.0)
check("cvss_garbage", X._cvss_v3_base_score("not a vector") is None)
check("cvss_v2_rejected", X._cvss_v3_base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None)

# _max_cvss with a real OSV-shaped entry (vector string, like the live API)
vuln = {"id": "GHSA-6c3j-c64m-qhgq", "aliases": ["CVE-2019-11358"],
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}]}
check("max_cvss_vector", X._max_cvss(vuln) == 6.1, f"got {X._max_cvss(vuln)}")
check("max_cvss_qual_fallback",
      X._max_cvss({"severity": [], "database_specific": {"severity": "high"}}) == 8.0)
check("max_cvss_unscored", X._max_cvss({"severity": []}) == 0.0)
check("max_cvss_numeric", X._max_cvss({"severity": [{"type": "X", "score": 7.2}]}) == 7.2)
# severity mapping is deliberately conservative: only CVSS 9.0+ is HIGH
check("sev_mapping", (X._cvss_severity(10.0), X._cvss_severity(8.1),
                      X._cvss_severity(6.1), X._cvss_severity(2.0))
      == ("high", "medium", "low", "low"))

# --- SRI classification -----------------------------------------------------
check("sri_abs_cross", X._is_external_script("https://cdn.x.com/a.js", "https://example.com/") is True)
check("sri_abs_same", X._is_external_script("https://example.com/a.js", "https://example.com/") is False)
check("sri_proto_cross", X._is_external_script("//cdn.x.com/a.js", "https://example.com/") is True)
check("sri_proto_same", X._is_external_script("//example.com/a.js", "https://example.com/") is False)
check("sri_relative", X._is_external_script("/static/a.js", "https://example.com/") is False)
check("sri_data", X._is_external_script("data:text/javascript,1", "https://example.com/") is False)

html = ('<script src="https://cdn.x.com/no-integ.js"></script>'
        '<script src="https://cdn.x.com/yes-integ.js" integrity="sha384-abc"></script>'
        '<script src="//example.com/same-host.js"></script>'
        '<script src="/local.js"></script>')
with patch.object(X, "fetch", return_value=Resp(html)):
    f = X.check_script_integrity("https://example.com")
check("sri_finding", len(f) == 1 and f[0]["severity"] == "low"
      and "no-integ.js" in f[0]["explanation"]
      and "same-host.js" not in f[0]["explanation"], str([x["title"] for x in f]))

with patch.object(X, "fetch", return_value=Resp('<script src="/local.js"></script>')):
    f = X.check_script_integrity("https://example.com")
check("sri_na", f[0]["severity"] == "info" and "No external scripts" in f[0]["title"], f[0]["title"])

# --- HTTPS redirect ----------------------------------------------------------
def fake_get_factory(status, location=None):
    def _get(url, **kw):
        return Resp(status=status, headers={"Location": location} if location else {})
    return _get

with patch("requests.get", side_effect=fake_get_factory(301, "https://example.com/")):
    f = X.check_https_redirect("example.com")
check("redir_ok", f[0]["severity"] == "info", str(f[0]["title"]))

with patch("requests.get", side_effect=fake_get_factory(200)):
    f = X.check_https_redirect("example.com")
check("redir_serves_http", f[0]["severity"] == "medium")

with patch("requests.get", side_effect=fake_get_factory(301, "http://example.com/")):
    f = X.check_https_redirect("example.com")
check("redir_not_https", f[0]["severity"] == "medium")

import requests as _rq
with patch("requests.get", side_effect=_rq.exceptions.ConnectionError("refused")):
    f = X.check_https_redirect("example.com")
check("redir_port_closed", f[0]["severity"] == "info" and "closed" in f[0]["title"].lower())

# --- Source maps --------------------------------------------------------------
sm_html = '<script src="https://example.com/app.js"></script>'
app_js = b"console.log(1);\n//# sourceMappingURL=app.js.map\n"
good_map = b'{"version":3,"sources":["a.ts"],"mappings":"AAAA"}'
html_404 = b"<html><body>not found</body></html>"


def run_sm(map_body, map_status=200):
    with patch.object(C, "_download_capped", return_value=app_js):
        def fake_fetch(url, **kw):
            if url.endswith(".map"):
                return Resp(map_body.decode(), status=map_status)
            return Resp(sm_html)
        with patch.object(X, "fetch", side_effect=fake_fetch):
            return X.check_sourcemaps("https://example.com")


f = run_sm(good_map)
check("sm_exposed", len(f) == 1 and f[0]["severity"] == "high", str([x["title"] for x in f]))
f = run_sm(html_404)
check("sm_404_not_exposed", f[0]["severity"] == "info")
f = run_sm(good_map, map_status=404)
check("sm_map_404", f[0]["severity"] == "info")

with patch.object(C, "_download_capped", return_value=b"console.log(1);"):
    with patch.object(X, "fetch", return_value=Resp(sm_html)):
        f = X.check_sourcemaps("https://example.com")
check("sm_no_directive", f[0]["severity"] == "info")

# --- OSV CVE lookup ------------------------------------------------------------
osv_vuln = {"id": "GHSA-xxxx", "aliases": ["CVE-2020-11022"],
            "severity": [{"type": "CVSS_V3",
                          "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]}
# that vector scores 10.0 -> HIGH under the conservative mapping
with patch.object(X, "_detect_js_libraries", return_value=[("jquery", "3.4.1")]):
    with patch.object(X, "_osv_query", return_value=([osv_vuln], None)):
        f = X.check_js_cves("https://example.com")
check("osv_high", len(f) == 1 and f[0]["severity"] == "high"
      and "CVE-2020-11022" in f[0]["explanation"]
      and "10.0" in f[0]["explanation"], str([(x["severity"], x["title"]) for x in f]))

with patch.object(X, "_detect_js_libraries", return_value=[("jquery", "3.7.1")]):
    with patch.object(X, "_osv_query", return_value=([], None)):
        f = X.check_js_cves("https://example.com")
check("osv_none", f[0]["severity"] == "info" and "No known CVEs" in f[0]["title"])

with patch.object(X, "_detect_js_libraries", return_value=[("jquery", "3.4.1")]):
    with patch.object(X, "_osv_query", return_value=(None, "boom")):
        f = X.check_js_cves("https://example.com")
check("osv_down_is_unknown", "unreachable" in f[0]["explanation"].lower(), f[0]["title"])

with patch.object(X, "_detect_js_libraries", return_value=[]):
    f = X.check_js_cves("https://example.com")
check("osv_na", f[0]["severity"] == "info")

# --- CAA ------------------------------------------------------------------------
class FakeCAA:
    def __init__(self, flags, tag, value):
        self.flags, self.tag, self.value = flags, tag, value


def caa_query_factory(mapping):
    def _q(name, rdtype, lifetime=10):
        if name in mapping:
            v = mapping[name]
            if v == "ERR":
                return None, Exception("dns fail")
            return v, None
        return [], None
    return _q


with patch.object(X, "_dns_query", side_effect=caa_query_factory(
        {"example.com": [FakeCAA(0, "issue", "letsencrypt.org")]})):
    f = X.check_dns_caa("example.com")
check("caa_ok", f[0]["severity"] == "info" and "letsencrypt.org" in f[0]["explanation"])

with patch.object(X, "_dns_query", side_effect=caa_query_factory({})):
    f = X.check_dns_caa("example.com")
check("caa_missing", f[0]["severity"] == "low")

with patch.object(X, "_dns_query", side_effect=caa_query_factory(
        {"example.com": [FakeCAA(0, "issue", "letsencrypt.org")]})):
    f = X.check_dns_caa("www.example.com")  # walks up per RFC 8659
check("caa_walkup", f[0]["severity"] == "info")

with patch.object(X, "_dns_query", side_effect=caa_query_factory({"example.com": "ERR"})):
    f = X.check_dns_caa("example.com")
check("caa_failed_is_unknown", "failed" in f[0]["explanation"].lower(), f[0]["title"])

# --- MTA-STS ----------------------------------------------------------------------
def mta_factory(txts, policy_body="version: STSv1\nmode: enforce\nmx: m.example.com\n",
                policy_status=200):
    def fake_txt(name):
        return txts

    def fake_get(url, **kw):
        return Resp(policy_body, status=policy_status)
    return fake_txt, fake_get


txt, get = mta_factory(["v=STSv1; id=1"])
with patch.object(C, "_txt_records", side_effect=txt), patch("requests.get", side_effect=get):
    f = X.check_mta_sts("example.com")
check("mta_enforce", f[0]["severity"] == "info")

txt, get = mta_factory(["v=STSv1; id=1"], policy_body="version: STSv1\nmode: testing\n")
with patch.object(C, "_txt_records", side_effect=txt), patch("requests.get", side_effect=get):
    f = X.check_mta_sts("example.com")
check("mta_testing", f[0]["severity"] == "low" and "testing" in f[0]["title"].lower())

txt, get = mta_factory(["v=STSv1; id=1"], policy_body="version: STSv1\nmode: none\n")
with patch.object(C, "_txt_records", side_effect=txt), patch("requests.get", side_effect=get):
    f = X.check_mta_sts("example.com")
check("mta_none", f[0]["severity"] == "low" and "disables enforcement" in f[0]["title"].lower())

txt, get = mta_factory(["v=STSv1; id=1"], policy_body="garbage", policy_status=200)
with patch.object(C, "_txt_records", side_effect=txt), patch("requests.get", side_effect=get):
    f = X.check_mta_sts("example.com")
check("mta_broken", f[0]["severity"] == "medium")

txt, get = mta_factory([])
with patch.object(C, "_txt_records", side_effect=txt), patch("requests.get", side_effect=get):
    f = X.check_mta_sts("example.com")
check("mta_missing", f[0]["severity"] == "low" and "No MTA-STS" in f[0]["title"])

with patch.object(C, "_txt_records", return_value=None):
    f = X.check_mta_sts("example.com")
check("mta_dnsfail_unknown", "failed" in f[0]["explanation"].lower(), f[0]["title"])

# --- DNSSEC -------------------------------------------------------------------------
with patch.object(X, "_dns_query", return_value=([object()], None)):
    f = X.check_dnssec("example.com")
check("dnssec_ok", f[0]["severity"] == "info")

with patch.object(X, "_dns_query", return_value=([], None)):
    f = X.check_dnssec("example.com")
check("dnssec_missing", f[0]["severity"] == "low")

with patch.object(X, "_dns_query", return_value=(None, Exception("timeout"))):
    f = X.check_dnssec("example.com")
check("dnssec_failed_unknown", "failed" in f[0]["explanation"].lower(), f[0]["title"])

# --- HSTS quality ----------------------------------------------------------------------
def hsts_resp(value):
    return Resp("", headers={"Strict-Transport-Security": value},
                url="https://example.com/")


with patch.object(X, "fetch", return_value=hsts_resp(
        "max-age=63072000; includeSubDomains; preload")):
    with patch.object(X, "_preload_status",
                      return_value=("preloaded", "is good. ", "No action needed.")):
        f = X.check_hsts_quality("https://example.com")
# perfect HSTS: no warnings, only the INFO preload-status note
check("hsts_perfect", len(f) == 1 and f[0]["severity"] == "info"
      and "preload" in f[0]["title"].lower(), str([x["title"] for x in f]))

with patch.object(X, "fetch", return_value=hsts_resp("max-age=1000")):
    f = X.check_hsts_quality("https://example.com")
keys = [x["title"] for x in f]
check("hsts_weak", len(f) == 2 and all(x["severity"] == "low" for x in f), str(keys))

with patch.object(X, "fetch", return_value=Resp("", headers={})):
    f = X.check_hsts_quality("https://example.com")
check("hsts_absent_no_dup", f == [], "security_headers already reports it")

check("hsts_parse", X._parse_hsts('max-age="31536000"; includeSubDomains') ==
      {"max-age": "31536000", "includesubdomains": True})

# --- Error disclosure ------------------------------------------------------------------
with patch.object(X, "fetch", return_value=Resp(
        "<html>Traceback (most recent call last): File \"/app/x.py\"</html>", status=404)):
    f = X.check_error_disclosure("https://example.com")
check("err_disclosed", f[0]["severity"] == "medium"
      and "Traceback" in f[0]["explanation"], f[0]["title"])

with patch.object(X, "fetch", return_value=Resp("<html>404 not found</html>", status=404)):
    f = X.check_error_disclosure("https://example.com")
check("err_clean", f[0]["severity"] == "info")

# --- robots.txt ----------------------------------------------------------------------------
robots = "User-agent: *\nDisallow: /admin/\nDisallow: /public/\nDisallow: /.git/\n"
with patch.object(X, "fetch", return_value=Resp(robots)):
    f = X.check_robots_txt("https://example.com")
check("robots_sensitive", f[0]["severity"] == "info" and "/admin/" in f[0]["explanation"]
      and "/.git/" in f[0]["explanation"] and "/public/" not in f[0]["explanation"],
      f[0]["explanation"][:120])

with patch.object(X, "fetch", return_value=Resp("User-agent: *\nDisallow: /public/\n")):
    f = X.check_robots_txt("https://example.com")
check("robots_ok", "sensitive" not in f[0]["title"].lower(), f[0]["title"])

with patch.object(X, "fetch", return_value=Resp("", status=404)):
    f = X.check_robots_txt("https://example.com")
check("robots_missing", "no robots" in f[0]["title"].lower(), f[0]["title"])

print()
print(f"{len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("FAILURES:", FAIL)
    sys.exit(1)
