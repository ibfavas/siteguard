"""
Additional SiteGuard checks (batch 2).

Same conventions as scanner/checks.py:
- Every check returns a list of finding dicts.
- If a check cannot run, emit a "check_failed" finding (severity info) —
  the area is UNKNOWN, never reported as clean.
- All user-facing text lives in scanner/strings.py.
- Non-intrusive only: plain GETs, DNS lookups, TLS handshakes, one
  identifying User-Agent. No port scanning, no exploitation, nothing noisy.
"""

import base64
import os
import re
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

import dns.resolver
import requests

from scanner import checks as C
from scanner.checks import (
    INFO, LOW, MEDIUM, HIGH, TIMEOUT, HEADERS,
    make_finding, check_failed, fetch,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _dns_query(name, rdtype, lifetime=10):
    """DNS lookup returning (answers, None), ([], None) when the record type
    simply doesn't exist, or (None, error) when the lookup itself failed."""
    try:
        ans = dns.resolver.resolve(name, rdtype, lifetime=lifetime)
        return list(ans), None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except Exception as exc:
        return None, exc


def _open_tls_sock(domain, timeout=10):
    """TCP socket to domain:443, via HTTP CONNECT when an egress proxy is set.
    Raises on failure."""
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if proxy:
        p = urlparse(proxy)
        sock = socket.create_connection((p.hostname, p.port or 8080),
                                        timeout=timeout)
        try:
            req = (f"CONNECT {domain}:443 HTTP/1.1\r\n"
                   f"Host: {domain}:443\r\n")
            if p.username:
                creds = base64.b64encode(
                    f"{p.username}:{p.password or ''}".encode()).decode()
                req += f"Proxy-Authorization: Basic {creds}\r\n"
            req += "\r\n"
            sock.sendall(req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if not resp.startswith(b"HTTP/1.1 200") \
                    and not resp.startswith(b"HTTP/1.0 200"):
                raise ConnectionError(
                    f"proxy CONNECT rejected: {resp[:60]!r}")
            return sock
        except Exception:
            sock.close()
            raise
    return socket.create_connection((domain, 443), timeout=timeout)


# ---------------------------------------------------------------------------
# 19. TLS configuration — old protocol versions and weak ciphers
# ---------------------------------------------------------------------------
TLS_VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]

# Cipher aliases offered on purpose: if the server completes a handshake
# with ONLY these on offer, it genuinely supports weak encryption.
WEAK_CIPHER_OFFER = "RC4:DES:3DES:EXPORT:@SECLEVEL=0"

# Fallback patterns for the negotiated cipher of a normal handshake.
WEAK_CIPHER_PATTERNS = ("RC4", "DES-CBC", "3DES", "-MD5", "NULL", "anon")


def _tls_handshake(domain, version=None, ciphers=None):
    """Attempt a TLS handshake. Returns (True, cipher_name) on success,
    (False, None) on refusal/failure. Never raises."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Lower the client security level so we can genuinely probe old
        # protocols/ciphers — otherwise the *client* policy would refuse
        # before the server ever gets a say.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass
        if version is not None:
            ctx.minimum_version = version
            ctx.maximum_version = version
        if ciphers:
            try:
                ctx.set_ciphers(ciphers)
            except Exception:
                return False, None
        sock = _open_tls_sock(domain)
        try:
            tls = ctx.wrap_socket(sock, server_hostname=domain)
        except Exception:
            sock.close()
            return False, None
        with tls:
            cipher = tls.cipher()
            return True, (cipher[0] if cipher else None)
    except Exception:
        return False, None


def check_tls_config(domain):
    check = "tls_config"
    try:
        results = {}
        for label, ver in TLS_VERSIONS:
            ok, _ = _tls_handshake(domain, version=ver)
            results[label] = ok
        if not any(results.values()):
            return [check_failed(check, "could not complete any TLS handshake")]

        findings = []
        for label in ("TLS 1.0", "TLS 1.1"):
            if results.get(label):
                findings.append(make_finding(
                    check, MEDIUM, "tls_old_version",
                    {"version": label}, version=label))

        # Weak ciphers: offer nothing but weak ones. A completed handshake
        # proves the server will negotiate them.
        weak_cipher = None
        ok, cipher = _tls_handshake(domain, version=ssl.TLSVersion.TLSv1_2,
                                    ciphers=WEAK_CIPHER_OFFER)
        if ok:
            weak_cipher = cipher or "a weak cipher"
        else:
            # Fallback: inspect what a normal TLS 1.2 handshake negotiates.
            ok2, cipher2 = _tls_handshake(domain,
                                          version=ssl.TLSVersion.TLSv1_2)
            if ok2 and cipher2 and any(
                    p in cipher2.upper() for p in WEAK_CIPHER_PATTERNS):
                weak_cipher = cipher2
        if weak_cipher:
            findings.append(make_finding(
                check, MEDIUM, "tls_weak_cipher",
                {"cipher": weak_cipher}, cipher=weak_cipher))

        if not results.get("TLS 1.3"):
            best = next((label for label, _ in reversed(TLS_VERSIONS)
                         if results.get(label)), "unknown")
            findings.append(make_finding(
                check, INFO, "tls_no_tls13", {"best": best}, best=best))

        if not findings:
            versions = ", ".join(label for label, _ in TLS_VERSIONS
                                 if results.get(label))
            findings.append(make_finding(
                check, INFO, "tls_ok", {"versions": versions},
                versions=versions))
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 20. HTTP -> HTTPS redirect
# ---------------------------------------------------------------------------
def check_https_redirect(domain):
    check = "https_redirect"
    try:
        try:
            r = requests.get(f"http://{domain}/", headers=HEADERS,
                             timeout=TIMEOUT, allow_redirects=False)
        except requests.exceptions.ConnectionError:
            # Port 80 closed/refused: visitors can only use HTTPS. Ideal.
            return [make_finding(check, INFO, "http_closed", {})]
        except Exception as exc:
            return [check_failed(check, f"HTTP probe failed: {exc}")]

        if r.status_code in (301, 302, 303, 307, 308):
            target = urljoin(f"http://{domain}/",
                             r.headers.get("Location", ""))
            if target.lower().startswith("https://"):
                return [make_finding(check, INFO, "http_redirect_ok", {})]
            detail = (f"redirects, but only to {target or '(nowhere)'} "
                      f"(not HTTPS). ")
            return [make_finding(check, MEDIUM, "http_no_redirect",
                                 {"detail": detail}, detail=detail)]
        if r.status_code < 400:
            detail = (f"serves the site directly over HTTP "
                      f"(status {r.status_code}). ")
            return [make_finding(check, MEDIUM, "http_no_redirect",
                                 {"detail": detail}, detail=detail)]
        return [check_failed(
            check, f"plain HTTP answered with unexpected status "
                   f"{r.status_code}")]
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 21. Subresource integrity on external scripts
# ---------------------------------------------------------------------------
class _ScriptIntegrityParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []  # (src, has_integrity)

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        src = integ = None
        for k, v in attrs:
            kl = k.lower()
            if kl == "src":
                src = (v or "").strip()
            elif kl == "integrity":
                integ = (v or "").strip()
        if src:
            self.scripts.append((src, bool(integ)))


def _is_external_script(src, page_url):
    low = src.lower()
    if low.startswith(("data:", "blob:", "javascript:")):
        return False
    page_host = urlparse(page_url).netloc.lower()

    def _host(s):
        try:
            return urlparse(s).netloc.lower()
        except Exception:
            return None

    if low.startswith("//"):
        # Protocol-relative: same-origin iff the host matches the page.
        host = _host("https:" + src)
        return host is not None and host != page_host
    if low.startswith(("http://", "https://")):
        host = _host(low)
        return host is None or host != page_host
    return False  # relative URL: same origin


def check_script_integrity(base_url, homepage_resp=None):
    check = "script_integrity"
    try:
        resp = homepage_resp or fetch(base_url)
        page_url = resp.url or base_url
        parser = _ScriptIntegrityParser()
        try:
            parser.feed(resp.text or "")
        except Exception:
            pass
        seen = set()
        external = 0
        missing = []
        for src, has_integ in parser.scripts:
            if src in seen:
                continue
            seen.add(src)
            if not _is_external_script(src, page_url):
                continue
            external += 1
            if not has_integ:
                missing.append(src)
        if external == 0:
            return [make_finding(check, INFO, "sri_na", {})]
        if not missing:
            return [make_finding(check, INFO, "sri_ok",
                                 {"count": external}, count=external)]
        shown = ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else "")
        return [make_finding(check, LOW, "sri_missing",
                             {"count": len(missing), "srcs": shown},
                             count=len(missing), srcs=shown)]
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 22. Exposed JavaScript source maps
# ---------------------------------------------------------------------------
SOURCEMAP_MAX_SCRIPTS = 6
_SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s'\";]+)",
                           re.IGNORECASE)


def _sourcemap_url(script_url, text):
    """Resolve a sourceMappingURL comment (searched in the tail of the file,
    where the directive lives). Returns None for inline (data:) maps."""
    m = _SOURCEMAP_RE.search((text or "")[-4096:])
    if not m:
        return None
    ref = m.group(1).strip()
    if ref.lower().startswith("data:"):
        return None
    return urljoin(script_url, ref)


def _looks_like_sourcemap(resp):
    """True only if the URL returns parseable source-map JSON. A 404 HTML
    page must never count."""
    if resp.status_code != 200:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    return (isinstance(data, dict) and "mappings" in data
            and "sources" in data)


def check_sourcemaps(base_url, homepage_resp=None):
    check = "sourcemaps"
    try:
        resp = homepage_resp or fetch(base_url)
        parser = C._ScriptSrcParser()
        try:
            parser.feed(resp.text or "")
        except Exception:
            pass
        seen = set()
        checked = 0
        exposed = []
        for src in parser.srcs:
            s = (src or "").strip()
            if not s or s in seen:
                continue
            seen.add(s)
            low = s.lower()
            if low.startswith(("data:", "blob:")):
                continue
            url = (s if low.startswith(("http://", "https://"))
                   else urljoin(base_url + "/", s))
            if not url.lower().startswith(("http://", "https://")):
                continue
            if checked >= SOURCEMAP_MAX_SCRIPTS:
                break
            data = C._download_capped(url)
            checked += 1
            if not data:
                continue
            map_url = _sourcemap_url(url, data.decode("utf-8", "replace"))
            if not map_url:
                continue
            try:
                mr = fetch(map_url)
            except Exception:
                continue
            if _looks_like_sourcemap(mr):
                exposed.append(map_url)
                if len(exposed) >= 3:
                    break
        findings = [make_finding(check, HIGH, "sourcemap_exposed",
                                 {"url": u}, url=u) for u in exposed]
        if not findings:
            findings.append(make_finding(check, INFO, "sourcemaps_ok", {}))
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 23. Known CVEs for detected JS libraries (via the OSV database)
# ---------------------------------------------------------------------------
OSV_API = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 15
OSV_MAX_LIBS = 5

# Our internal lib names -> npm package names (AngularJS 1.x is "angular").
NPM_NAMES = {"jquery": "jquery", "bootstrap": "bootstrap",
             "angularjs": "angular", "lodash": "lodash", "moment": "moment",
             "react": "react", "react-dom": "react-dom", "vue": "vue",
             "angular": "@angular/core"}


def _detect_js_libraries(base_url, homepage_resp=None):
    """Detect JS library versions via URL patterns and content hashes.
    Returns [(lib, version)]. Detection only — no verdicts."""
    resp = homepage_resp or fetch(base_url)
    parser = C._ScriptSrcParser()
    try:
        parser.feed(resp.text or "")
    except Exception:
        pass
    seen_srcs = set()
    srcs = []
    for src in parser.srcs:
        s = (src or "").strip()
        if s and s not in seen_srcs:
            seen_srcs.add(s)
            srcs.append(s)

    detected = []
    seen_versions = set()
    flagged_srcs = set()
    for src in srcs:  # pass 1: version strings in the URL
        for lib, pattern in C.JS_PATTERNS:
            m = pattern.search(src)
            if not m:
                continue
            key = (lib, m.group(1))
            if key not in seen_versions:
                seen_versions.add(key)
                detected.append(key)
            flagged_srcs.add(src)
            break
    hashed = 0
    for src in srcs:  # pass 2: content-hash fingerprinting
        if src in flagged_srcs or hashed >= C.HASH_MAX_SCRIPTS:
            continue
        low = src.lower()
        if low.startswith(("data:", "blob:")):
            continue
        url = (src if low.startswith(("http://", "https://"))
               else urljoin(base_url + "/", src))
        if not url.lower().startswith(("http://", "https://")):
            continue
        data = C._download_capped(url)
        hashed += 1
        match = C._hash_lookup(data)
        if match and match not in seen_versions:
            seen_versions.add(match)
            detected.append(match)
    return detected


def _osv_query(npm_name, version):
    """Query osv.dev. Returns (vulns, None) or (None, error)."""
    try:
        r = requests.post(OSV_API,
                          json={"package": {"name": npm_name,
                                            "ecosystem": "npm"},
                                "version": version},
                          headers=HEADERS, timeout=OSV_TIMEOUT)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json().get("vulns") or [], None
    except Exception as exc:
        return None, exc


def _cve_ids(vuln):
    ids = [a for a in (vuln.get("aliases") or [])
           if isinstance(a, str) and a.startswith("CVE-")]
    vid = vuln.get("id", "")
    if isinstance(vid, str) and vid.startswith("CVE-") and vid not in ids:
        ids.insert(0, vid)
    return ids


# CVSS v3.0/v3.1 base-score computation from the vector string.
# OSV's severity[].score is a vector like "CVSS:3.1/AV:N/AC:L/..." — NOT a
# number — so we implement the FIRST specification formula directly. This is
# the exact published algorithm, verified against reference vectors.
_CVSS_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},      # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},     # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_roundup(v):
    """CVSS v3.1 roundup: smallest 1-decimal number >= v."""
    i = int(v * 100000 + 0.5)
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def _cvss_v3_base_score(vector):
    """Base score (0.0-10.0) for a CVSS v3.x vector string.
    Returns None when the vector cannot be parsed."""
    try:
        parts = vector.strip().split("/")
        if len(parts) < 2 or not parts[0].upper().startswith("CVSS:3."):
            return None
        m = {}
        for p in parts[1:]:
            if ":" not in p:
                return None
            k, v = p.split(":", 1)
            m[k.upper()] = v.upper()
        changed = m.get("S") == "C"
        pr_tab = _CVSS_V3["PR_C"] if changed else _CVSS_V3["PR"]
        av = _CVSS_V3["AV"][m["AV"]]
        ac = _CVSS_V3["AC"][m["AC"]]
        pr = pr_tab[m["PR"]]
        ui = _CVSS_V3["UI"][m["UI"]]
        c = _CVSS_V3["C"][m["C"]]
        i_ = _CVSS_V3["I"][m["I"]]
        a = _CVSS_V3["A"][m["A"]]
    except (KeyError, AttributeError):
        return None
    iss = 1.0 - (1.0 - c) * (1.0 - i_) * (1.0 - a)
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    if changed:
        raw = min(1.08 * (impact + exploit), 10.0)
    else:
        raw = min(impact + exploit, 10.0)
    return _cvss_roundup(raw)


# GHSA qualitative severity -> numeric midpoint of the CVSS qualitative band.
_GHSA_QUALITATIVE = {"critical": 9.5, "high": 8.0,
                     "moderate": 5.5, "low": 2.0}


def _max_cvss(vuln):
    """Best numeric CVSS score for an OSV vuln entry.

    Prefers an exact v3 base score computed from the vector string. Falls
    back to the GHSA qualitative severity when no parseable vector exists.
    Returns 0.0 only when the vuln is genuinely unscored."""
    best, scored = 0.0, False
    for s in vuln.get("severity") or []:
        score = s.get("score")
        val = None
        if isinstance(score, (int, float)):
            val = float(score)
        elif isinstance(score, str):
            val = _cvss_v3_base_score(score)
        # CVSS v4 vectors: no exact offline formula is implemented, so an
        # unscored v4 entry falls through to the qualitative fallback below.
        if val is not None:
            scored = True
            best = max(best, val)
    if not scored:
        qual = str((vuln.get("database_specific") or {})
                   .get("severity", "")).lower()
        best = _GHSA_QUALITATIVE.get(qual, 0.0)
    return round(best, 1)


def _cvss_severity(score):
    if score >= 9.0:
        return HIGH
    if score >= 7.0:
        return MEDIUM
    return LOW


def check_js_cves(base_url, homepage_resp=None):
    check = "js_cves"
    try:
        try:
            detected = _detect_js_libraries(base_url, homepage_resp)
        except Exception as exc:
            return [check_failed(check, f"library detection failed: {exc}")]
        if not detected:
            return [make_finding(check, INFO, "js_cves_na", {})]
        if not any(NPM_NAMES.get(lib) for lib, _v in detected):
            # Detected libraries we have no OSV package mapping for:
            # nothing to look up.
            return [make_finding(check, INFO, "js_cves_na", {})]

        findings = []
        libs_checked = []
        attempted = failed = 0
        for lib, version in detected[:OSV_MAX_LIBS]:
            npm_name = NPM_NAMES.get(lib)
            if not npm_name:
                continue
            libs_checked.append(f"{lib} {version}")
            attempted += 1
            vulns, _err = _osv_query(npm_name, version)
            if vulns is None:
                failed += 1
                continue
            if not vulns:
                continue
            all_cves, worst, worst_cve = [], 0.0, None
            for v in vulns:
                score = _max_cvss(v)
                for cve in _cve_ids(v):
                    all_cves.append(cve)
                    if score > worst:
                        worst, worst_cve = score, cve
            if not all_cves:  # vulns recorded under non-CVE ids (e.g. GHSA)
                all_cves = [str(v.get("id", "?")) for v in vulns[:5]]
            cve_list = (", ".join(all_cves[:5])
                        + (" ..." if len(all_cves) > 5 else ""))
            worst_txt = (f" (worst: {worst_cve}, CVSS {worst:.1f})"
                         if worst_cve and worst else "")
            findings.append(make_finding(
                check, _cvss_severity(worst) if worst else LOW, "js_cve",
                {"library": lib, "version": version, "cves": cve_list},
                library=lib, version=version, count=len(all_cves),
                vuln_word=("vulnerability" if len(all_cves) == 1
                           else "vulnerabilities"),
                cve_list=cve_list, worst=worst_txt,
                fixed_in=C._fixed_in_for(lib, version)))
        if attempted and failed == attempted:
            return [check_failed(check, "vulnerability database unreachable")]
        if not findings:
            return [make_finding(
                check, INFO, "js_cves_none",
                {"libs": ", ".join(libs_checked)}, libs=", ".join(libs_checked))]
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 24. CAA DNS record
# ---------------------------------------------------------------------------
def check_dns_caa(domain):
    check = "dns_caa"
    # RFC 8659 section 3: if no CAA at the exact name, walk up the tree —
    # a CAA record on the parent domain applies to its children.
    name = domain
    records, err = _dns_query(name, "CAA")
    while records is not None and not records and "." in name:
        name = name.split(".", 1)[1]
        records, err = _dns_query(name, "CAA")
    if records is None:
        return [check_failed(check, f"CAA lookup failed: {err}")]
    if not records:
        return [make_finding(check, LOW, "caa_missing", {})]
    parts = []
    for r in records:
        try:
            val = r.value.decode() if isinstance(r.value, bytes) else r.value
            parts.append(f'{r.flags} {r.tag} "{val}"')
        except Exception:
            parts.append(str(r).strip())
    txt = ", ".join(parts)
    return [make_finding(check, INFO, "caa_ok", {"records": txt}, records=txt)]


# ---------------------------------------------------------------------------
# 25. MTA-STS email protection
# ---------------------------------------------------------------------------
def check_mta_sts(domain):
    check = "email_mta_sts"
    try:
        txts = C._txt_records("_mta-sts." + domain)
    except Exception as exc:
        return [check_failed(check, f"MTA-STS lookup failed: {exc}")]
    if txts is None:
        return [check_failed(check, "MTA-STS lookup failed (DNS error)")]
    if not any("v=STSv1" in t for t in txts):
        return [make_finding(check, LOW, "mta_sts_missing",
                             {"domain": domain}, domain=domain)]

    # DNS advertises MTA-STS: the policy file must exist and be valid,
    # otherwise senders may fail delivery.
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                         allow_redirects=True)
        body = r.text or ""
        status = r.status_code
    except Exception as exc:
        detail = f"the policy file could not be fetched ({exc})."
        return [make_finding(check, MEDIUM, "mta_sts_broken",
                             {"domain": domain, "detail": detail},
                             domain=domain, detail=detail)]
    vals = {}
    for line in body.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            vals[k.strip().lower()] = v.strip()
    if status != 200 or vals.get("version") != "STSv1" or "mode" not in vals:
        detail = "the policy file is missing or invalid."
        return [make_finding(check, MEDIUM, "mta_sts_broken",
                             {"domain": domain, "detail": detail},
                             domain=domain, detail=detail)]
    mode = vals["mode"].lower()
    if mode == "enforce":
        return [make_finding(check, INFO, "mta_sts_ok", {})]
    if mode == "testing":
        return [make_finding(check, LOW, "mta_sts_testing", {})]
    if mode == "none":
        # Valid mode per RFC 8461: policy published but explicitly
        # not enforcing — senders get no protection.
        return [make_finding(check, LOW, "mta_sts_none", {})]
    detail = f"it uses an unknown mode '{vals['mode']}'."
    return [make_finding(check, MEDIUM, "mta_sts_broken",
                         {"domain": domain, "detail": detail},
                         domain=domain, detail=detail)]


# ---------------------------------------------------------------------------
# 26. DNSSEC
# ---------------------------------------------------------------------------
def check_dnssec(domain):
    check = "dnssec"
    records, err = _dns_query(domain, "DS")
    if records is None:
        return [check_failed(check, f"DNSSEC lookup failed: {err}")]
    if not records:
        return [make_finding(check, LOW, "dnssec_missing", {})]
    return [make_finding(check, INFO, "dnssec_ok", {})]


# ---------------------------------------------------------------------------
# 27. HSTS quality — max-age, includeSubDomains, preload status
# ---------------------------------------------------------------------------
HSTS_PRELOAD_API = "https://hstspreload.org/api/v2/status"
HSTS_MIN_AGE = 15768000  # 6 months; preload requires 1 year


def _parse_hsts(value):
    directives = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip().lower()] = v.strip().strip('"')
        else:
            directives[part.lower()] = True
    return directives


def _human_seconds(secs):
    if secs >= 31536000:
        return f"{secs / 31536000:.1f} years"
    if secs >= 86400:
        return f"{secs / 86400:.1f} days"
    if secs >= 3600:
        return f"{secs / 3600:.1f} hours"
    return f"{secs} seconds"


def _preload_status(domain):
    """(status, detail, fix) for the hsts_preload_status string."""
    try:
        r = requests.get(HSTS_PRELOAD_API, params={"domain": domain},
                         headers=HEADERS, timeout=10)
        st = (r.json().get("status") or "unknown").lower()
    except Exception:
        return ("unknown",
                "asks for preloading, but we could not verify its status. ",
                "No action needed.")
    if st == "preloaded":
        return ("preloaded",
                "is active and your domain is on the browser preload list. ",
                "No action needed.")
    if st == "pending":
        return ("pending",
                "is active but your domain is still queued for the preload "
                "list. ",
                "No action needed — pending entries are usually added within "
                "a few months.")
    return (st,
            f"is active but the preload list reports status '{st}'. ",
            "Check the requirements at hstspreload.org: HTTPS on the domain "
            "and all subdomains, max-age of at least one year.")


def check_hsts_quality(base_url, homepage_resp=None):
    check = "hsts_quality"
    try:
        resp = homepage_resp or fetch(base_url)
        raw = resp.headers.get("Strict-Transport-Security")
        if not raw:
            return []  # security_headers already reports the missing header
        d = _parse_hsts(raw)
        findings = []
        try:
            max_age = int(d.get("max-age", "0"))
        except (ValueError, TypeError):
            max_age = 0
        if max_age < HSTS_MIN_AGE:
            human = _human_seconds(max_age)
            findings.append(make_finding(
                check, LOW, "hsts_short_maxage",
                {"max_age": max_age, "human": human},
                max_age=max_age, human=human))
        if "includesubdomains" not in d:
            findings.append(make_finding(check, LOW, "hsts_no_subdomains",
                                         {}))
        if "preload" in d:
            domain = urlparse(resp.url or base_url).netloc
            status, detail, fix = _preload_status(domain)
            findings.append(make_finding(
                check, INFO, "hsts_preload_status",
                {"status": status}, status=status, detail=detail, fix=fix))
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 28. Verbose error pages — stack traces and internals on 404s
# ---------------------------------------------------------------------------
_ERROR_MARKERS = [
    "Traceback (most recent call last)",  # Python
    "Fatal error: ",                       # PHP
    "PHP Parse error",                     # PHP
    "Server Error in '/' Application",     # ASP.NET
    "NullReferenceException",              # .NET
    "ActionView::Template::Error",         # Rails
    "django.core.exceptions",              # Django
]


def check_error_disclosure(base_url):
    check = "error_disclosure"
    try:
        token = os.urandom(8).hex()
        try:
            r = fetch(f"{base_url}/siteguard-probe-{token}.html")
        except Exception as exc:
            return [check_failed(check, f"could not fetch error page: {exc}")]
        text = r.text or ""
        hits = [m for m in _ERROR_MARKERS if m in text]
        if hits:
            return [make_finding(check, MEDIUM, "error_disclosure",
                                 {"evidence": hits[0]}, evidence=hits[0])]
        return [make_finding(check, INFO, "error_pages_ok", {})]
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 29. robots.txt analysis
# ---------------------------------------------------------------------------
_ROBOTS_SENSITIVE = ("admin", "login", "wp-admin", "wp-login", "backup",
                     ".git", "config", "database", ".sql", "private",
                     "secret", "dev", "staging", "test", "phpmyadmin",
                     "dashboard")


def check_robots_txt(base_url):
    check = "robots_txt"
    try:
        try:
            r = fetch(base_url + "/robots.txt")
        except Exception as exc:
            return [check_failed(check, f"could not fetch robots.txt: {exc}")]
        if r.status_code != 200:
            return [make_finding(check, INFO, "robots_missing", {})]
        disallows = []
        for line in (r.text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"(?i)disallow\s*:\s*(\S+)", line)
            if m and m.group(1) != "/":
                disallows.append(m.group(1))
        sensitive = sorted({d for d in disallows
                            if any(s in d.lower()
                                   for s in _ROBOTS_SENSITIVE)})
        if sensitive:
            shown = (", ".join(sensitive[:8])
                     + (" ..." if len(sensitive) > 8 else ""))
            return [make_finding(check, INFO, "robots_sensitive",
                                 {"paths": shown}, paths=shown)]
        return [make_finding(check, INFO, "robots_ok", {})]
    except Exception as exc:
        return [check_failed(check, exc)]
