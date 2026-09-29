"""Unit tests for extended JS library coverage in SiteGuard.

Covers React, react-dom, Vue and modern Angular detection:
- URL version-string patterns (incl. npm "@x/y@1.2.3" CDN form)
- no false positives (preact, vue-router, angularjs vs angular)
- honest version thresholds (vue 2.x flagged, 3.x not; angular 10.2.4/11.0.4
  flagged, 10.2.5/11.0.5/12.x not; react-dom has no below-rule because its
  CVE was fixed in patch releases with vulnerable neighbours)
- content-hash fingerprints of real vulnerable releases
- per-version fixed_in advice

All network mocked. Run: cd ~/workspace/siteguard && ./venv/bin/python tests/test_js_libraries.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

from scanner import checks as C
from scanner import checks_extra as X
from scanner.jslib_hashes import VULN_JS_HASHES

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


def _run_check(html):
    """Run check_js_libraries against a fake homepage."""
    with patch.object(C, "fetch", return_value=Resp(html)):
        return C.check_js_libraries("https://example.com")


def _vuln_libs(findings):
    return [(f["details"].get("library"), f["details"].get("version"))
            for f in findings
            if f.get("check") == "js_libraries" and f["details"].get("library")]


# --- URL pattern detection ---------------------------------------------------
# react-dom 16.x must NOT be flagged by the version-string pass (patch-level
# exceptions make a below-rule dishonest); it must be *detected* though.
found = _vuln_libs(_run_check('<script src="https://unpkg.com/react-dom@16.4.1/umd/react-dom.production.min.js"></script>'))
check("reactdom_no_below_rule", found == [], f"got {found}")
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="https://unpkg.com/react-dom@16.4.1/umd/react-dom.production.min.js"></script>'))
check("reactdom_detected_for_osv", detected == [("react-dom", "16.4.1")], f"got {detected}")

# react vs react-dom ordering: react-dom URL must not be claimed as react
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="/js/react-dom-18.2.0.min.js"></script>'))
check("reactdom_not_react", detected == [("react-dom", "18.2.0")], f"got {detected}")

# plain react detection
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"></script>'))
check("react_detected", detected == [("react", "18.2.0")], f"got {detected}")

# preact must NOT match the react pattern
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="https://cdn.example.com/preact-10.5.0.min.js"></script>'))
check("preact_no_false_positive", detected == [], f"got {detected}")

# vue 2.x flagged (ReDoS, all of 2.x), vue 3.x not
found = _vuln_libs(_run_check('<script src="https://cdn.jsdelivr.net/npm/vue@2.7.16/dist/vue.min.js"></script>'))
check("vue2_flagged", found == [("vue", "2.7.16")], f"got {found}")
found = _vuln_libs(_run_check('<script src="https://cdn.jsdelivr.net/npm/vue@3.4.0/dist/vue.global.prod.js"></script>'))
check("vue3_not_flagged", found == [], f"got {found}")

# vue-router must NOT match the vue pattern
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="https://unpkg.com/vue-router@4.1.6/dist/vue-router.global.js"></script>'))
check("vue_router_no_false_positive", detected == [], f"got {detected}")

# angular: 10.2.4 and 11.0.4 flagged; 10.2.5, 11.0.5, 12.x not
for ver, should_flag in [("10.2.4", True), ("11.0.4", True),
                         ("10.2.5", False), ("11.0.5", False), ("12.0.0", False)]:
    found = _vuln_libs(_run_check(
        f'<script src="https://cdn.example.com/@angular/core@{ver}/bundles/core.umd.min.js"></script>'))
    check(f"angular_{ver}", (found != []) == should_flag, f"got {found}")

# angularjs must still be detected as angularjs, not angular
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.7.9/angular.min.js"></script>'))
check("angularjs_not_angular", detected == [("angularjs", "1.7.9")], f"got {detected}")

# npm @ form for existing libs (regression: @ was previously missed)
detected = X._detect_js_libraries("https://example.com",
                                  Resp('<script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"></script>'))
check("jquery_at_form", detected == [("jquery", "3.4.1")], f"got {detected}")

# --- content-hash fingerprints ----------------------------------------------
# The DB must contain exactly the releases we hashed from jsDelivr
# (verified genuine by their license/version banners before hashing).
NEW_HASHES = {
    "0dcb93a5c7859e1fa909ffe239b591ec329bfea81bf5e059ecb1b6f7e1ca7058": ("react-dom", "16.0.0"),
    "4b589e536a85f6707a1f2e4018c1425ed6fe73e8ed4346452ee24949f28f86b9": ("react-dom", "16.1.0"),
    "77485f185036d3da0d6449c427c64928b97df99305788ac80221736924916395": ("react-dom", "16.1.1"),
    "f61ac9c43e0842c58774da732e424a606898fd211914925252ac9e64f34a77c8": ("react-dom", "16.2.0"),
    "a15dd3609e69da9d2a5c0dae4f731ea6eec529ad191f4a4b5b6840e5d9beed5e": ("react-dom", "16.3.0"),
    "f66fd73f63a0e04d8c8afbc4af8d6d9547e34e45b58e33bbbac91b417ee03114": ("react-dom", "16.3.1"),
    "96b84a25a5984c39eab253b08ff07c7f3e9ba9e848480eb8c284112ea04a0db0": ("react-dom", "16.3.2"),
    "aaceabb9d1a1c4f32fd95ab6432621fc34e7d3955ef31527e9698171abf5e998": ("react-dom", "16.4.0"),
    "cbba3f6f7e49ca36f5f7027ffc65239bce1b2e5f989660c69a7c29819bf337ee": ("react-dom", "16.4.1"),
    "9174c425c445377df4562ad9165ea08fdf9433a808296d7de5f619791df10e17": ("vue", "2.6.14"),
    "d601f229247b261d18181988f7337b3f652165187f3c22a109821a50ea96a0f9": ("vue", "2.7.14"),
    "3c1d4b0c549e8de9d4a9bafb12ab70b6a1ac747d07293b98c5b25b6632999afd": ("vue", "2.7.16"),
    "1663a489eda8bec4b42132036735b4415cc60e407d88e1bd6c6e4034a8c099f6": ("angular", "10.2.4"),
    "ea69cc02526f075b51f8f878b073e82d4d90d6e2357eec8eb755492a4ee70155": ("angular", "11.0.4"),
}
# Real assertions: every new hash must resolve to its (lib, version).
for h, expected in NEW_HASHES.items():
    check(f"hashdb_has_{expected[0]}_{expected[1]}",
          VULN_JS_HASHES.get(h) == expected,
          f"got {VULN_JS_HASHES.get(h)}")
check("hash_unknown_none", C._hash_lookup(b"not a real library file") is None)

# end-to-end: hash pass flags a self-hosted vulnerable copy with no version in URL
with patch.object(C, "fetch", return_value=Resp('<script src="/assets/bundle-abc123.js"></script>')), \
     patch.object(C, "_download_capped", return_value=b"fake-bytes"), \
     patch.object(C, "_hash_lookup", return_value=("react-dom", "16.4.1")):
    findings = C.check_js_libraries("https://example.com")
    found = _vuln_libs(findings)
    fixed = [f["details"].get("fixed_in") for f in findings
             if f.get("check") == "js_libraries" and f["details"].get("library")]
check("hash_pass_flags_reactdom", found == [("react-dom", "16.4.1")], f"got {found}")
check("hash_pass_fixed_in", fixed == ["16.4.2"], f"got {fixed}")

# --- fixed_in advice ----------------------------------------------------------
check("fixedin_reactdom_1641", C._fixed_in_for("react-dom", "16.4.1") == "16.4.2")
check("fixedin_reactdom_1600", C._fixed_in_for("react-dom", "16.0.0") == "16.0.1")
check("fixedin_reactdom_1632", C._fixed_in_for("react-dom", "16.3.2") == "16.3.3")
check("fixedin_vue", C._fixed_in_for("vue", "2.7.16") == "3.x")
check("fixedin_angular_1024", C._fixed_in_for("angular", "10.2.4") == "10.2.5")
check("fixedin_angular_1104", C._fixed_in_for("angular", "11.0.4") == "11.0.5")
check("fixedin_jquery_unchanged", C._fixed_in_for("jquery", "3.4.1") == "3.5.0")

# --- OSV mapping ---------------------------------------------------------------
check("npm_react", X.NPM_NAMES.get("react") == "react")
check("npm_react_dom", X.NPM_NAMES.get("react-dom") == "react-dom")
check("npm_vue", X.NPM_NAMES.get("vue") == "vue")
check("npm_angular", X.NPM_NAMES.get("angular") == "@angular/core")

# --- hash DB size sanity ---------------------------------------------------------
check("hashdb_28", len(VULN_JS_HASHES) == 28, f"got {len(VULN_JS_HASHES)}")
libs = {lib for lib, _ver in VULN_JS_HASHES.values()}
check("hashdb_8_libs", libs == {"jquery", "bootstrap", "angularjs", "lodash", "moment",
                                "react-dom", "vue", "angular"}, f"got {libs}")

print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
sys.exit(1 if FAIL else 0)
