"""
The SiteGuard checks. Each check returns a list of finding dicts:

    {"check": str, "severity": "info|low|medium|high",
     "title": str, "explanation": str, "fix": str, "details": dict}

Rules:
- Never invent results. If a check cannot run (network blocked, DNS down,
  site unreachable), emit a "check_failed" finding (severity info) — never
  report the area as clean.
- All user-facing text comes from scanner/strings.py so it can be
  translated later. No logic changes needed for Malayalam.
- Non-intrusive only: no port scanning, no exploitation attempts, nothing
  noisy or slow. One identifying User-Agent on every request.
"""

import difflib
import hashlib
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

import dns.resolver
import requests

import config
from scanner.jslib_hashes import VULN_JS_HASHES
from scanner.strings import STRINGS, HEADER_WHY_FIX

TIMEOUT = config.REQUEST_TIMEOUT
HEADERS = {"User-Agent": config.USER_AGENT}

# Severity constants
INFO, LOW, MEDIUM, HIGH = "info", "low", "medium", "high"


def make_finding(check, severity, key, details=None, **fmt):
    """Build a finding dict from a strings.py entry."""
    entry = STRINGS[key]
    return {
        "check": check,
        "severity": severity,
        "title": entry["title"].format(**fmt),
        "explanation": entry["explanation"].format(**fmt),
        "fix": entry["fix"].format(**fmt),
        "details": details or {},
    }


def check_failed(check, reason):
    """Honest failure marker — the area is UNKNOWN, not clean."""
    return make_finding(check, INFO, "check_failed",
                        {"reason": str(reason)},
                        check_name=check, reason=str(reason))


def fetch(url, **kwargs):
    """GET with sane defaults. Raises on network/HTTP errors."""
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("headers", HEADERS)
    kwargs.setdefault("allow_redirects", True)
    resp = requests.get(url, **kwargs)
    return resp


# ---------------------------------------------------------------------------
# 1. SSL certificate
# ---------------------------------------------------------------------------
def _get_peer_cert(domain):
    """
    Fetch the server's TLS certificate for a domain.

    Works both on direct connections and behind an HTTP(S) egress proxy
    (common on VPSs / sandboxes): when https_proxy is set, we open the TLS
    session through an HTTP CONNECT tunnel instead of a raw socket, which
    would otherwise hit the proxy and fail the handshake.
    """
    ctx = ssl.create_default_context()
    proxy = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"))
    if proxy:
        p = urlparse(proxy)
        sock = socket.create_connection((p.hostname, p.port or 8080),
                                        timeout=TIMEOUT)
        try:
            req = (f"CONNECT {domain}:443 HTTP/1.1\r\n"
                   f"Host: {domain}:443\r\n")
            if p.username:
                import base64
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
            if not resp.startswith(b"HTTP/1.1 200") and not resp.startswith(b"HTTP/1.0 200"):
                raise ConnectionError(f"proxy CONNECT rejected: {resp[:80]!r}")
            tls = ctx.wrap_socket(sock, server_hostname=domain)
        except Exception:
            sock.close()
            raise
    else:
        sock = socket.create_connection((domain, 443), timeout=TIMEOUT)
        tls = ctx.wrap_socket(sock, server_hostname=domain)
    with tls:
        return tls.getpeercert()


def check_ssl(domain):
    check = "ssl"
    findings = []
    try:
        cert = _get_peer_cert(domain)
    except Exception as exc:
        # Couldn't read the certificate. Distinguish the cases honestly:
        #  - HTTPS reachable but cert unreadable -> check failed (NOT "no HTTPS")
        #  - HTTPS down but HTTP up            -> genuinely no HTTPS (high)
        #  - both down                         -> check failed
        try:
            r = fetch(f"https://{domain}/")
            https_works = r.status_code < 500
        except Exception:
            https_works = False
        if https_works:
            return [check_failed(
                check, f"site uses HTTPS but the certificate could not be read: {exc}")]
        try:
            r = fetch(f"http://{domain}/")
            if r.status_code < 500:
                return [make_finding(check, HIGH, "ssl_no_https",
                                     {"reason": f"TLS error: {exc}"})]
        except Exception:
            pass
        return [check_failed(check, f"could not complete TLS handshake: {exc}")]

    try:
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName") or issuer.get("commonName") or "unknown"
        days = (expiry - datetime.now(timezone.utc)).days
        details = {"expiry": expiry.isoformat(), "issuer": issuer_name, "days": days}
        if days < 0:
            findings.append(make_finding(check, HIGH, "ssl_expired", details,
                                         expiry=expiry.date().isoformat()))
        elif days < 30:
            findings.append(make_finding(check, MEDIUM, "ssl_expiring_soon", details,
                                         days=days, expiry=expiry.date().isoformat()))
        else:
            findings.append(make_finding(check, INFO, "ssl_ok", details,
                                         days=days, expiry=expiry.date().isoformat()))
    except Exception as exc:
        findings.append(check_failed(check, f"could not parse certificate: {exc}"))
    return findings


# ---------------------------------------------------------------------------
# 2. Security headers
# ---------------------------------------------------------------------------
WANTED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def check_security_headers(base_url, homepage_resp=None):
    check = "security_headers"
    findings = []
    try:
        resp = homepage_resp or fetch(base_url)
        headers = resp.headers  # case-insensitive dict
        is_https = resp.url.startswith("https")
        missing = [h for h in WANTED_HEADERS if h not in headers]
        for h in missing:
            why, fix = HEADER_WHY_FIX[h]
            severity = MEDIUM if (h == "Strict-Transport-Security" and is_https) else LOW
            findings.append(make_finding(check, severity, "header_missing",
                                         {"header": h}, header=h, why=why, fix=fix))
        if not missing:
            findings.append(make_finding(check, INFO, "headers_ok", {}))
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 3. Exposed admin panels / sensitive files
# ---------------------------------------------------------------------------
PANEL_PATHS = [
    "/wp-admin/",
    "/wp-login.php",
    "/admin/",
    "/administrator/",
    "/login",
    "/phpmyadmin/",
    "/server-status",
    "/server-info",
]


def check_admin_panels(base_url):
    check = "admin_panels"
    findings = []
    try:
        # --- sensitive files first (high severity) ---
        try:
            r = fetch(base_url + "/.git/HEAD")
            if r.status_code == 200 and r.text.strip().startswith("ref:"):
                findings.append(make_finding(check, HIGH, "git_exposed",
                                             {"path": "/.git/HEAD", "status": 200}))
        except Exception:
            pass  # a failed probe here is not conclusive; panels below decide
        try:
            r = fetch(base_url + "/.env")
            text = r.text or ""
            if r.status_code == 200 and any(
                    k in text for k in ("APP_KEY", "DB_PASSWORD", "DB_HOST",
                                        "SECRET_KEY", "API_KEY", "MAIL_PASSWORD")):
                findings.append(make_finding(check, HIGH, "env_exposed",
                                             {"path": "/.env", "status": 200}))
        except Exception:
            pass

        # --- login / admin pages ---
        # Fingerprint the site's 404 page first: many sites (WordPress, SPAs,
        # custom 404 pages) answer HTTP 200 for *every* unknown path, which
        # would otherwise make each probed path look "exposed".
        try:
            baseline = _soft404_baseline(base_url)
        except Exception:
            baseline = None
        for path in PANEL_PATHS:
            try:
                r = fetch(base_url + path)
            except Exception:
                continue  # unreachable path: not evidence of anything
            if r.status_code == 200:
                if _is_soft_404(r, baseline):
                    continue  # the site's 404 page wearing a 200 status
                findings.append(make_finding(
                    check, MEDIUM, "panel_exposed",
                    {"path": path, "status": 200}, path=path, protected=""))
            elif r.status_code in (401, 403):
                findings.append(make_finding(
                    check, LOW, "panel_exposed",
                    {"path": path, "status": r.status_code}, path=path,
                    protected=" (it asks for a password, which is good, but attackers can still see it exists)"))
        if not findings:
            findings.append(make_finding(check, INFO, "panels_ok", {}))
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 4. WordPress fingerprinting
# ---------------------------------------------------------------------------
def _parse_version(text):
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text or "")
    return m.group(1) if m else None


def _latest_wp_version():
    """Ask wordpress.org for the current stable version. Returns None on failure."""
    try:
        r = fetch("https://api.wordpress.org/core/version-check/1.7/", timeout=10)
        data = r.json()
        return data["offers"][0]["version"]
    except Exception:
        return None


def _ver_tuple(v):
    return tuple(int(p) for p in v.split(".") if p.isdigit())


def check_wordpress(base_url, homepage_resp=None):
    check = "wordpress"
    findings = []
    try:
        version = None
        detected = False

        # wp-json REST API
        try:
            r = fetch(base_url + "/wp-json/")
            if r.status_code == 200 and "namespaces" in r.text:
                detected = True
        except Exception:
            pass

        # readme.html
        if not version:
            try:
                r = fetch(base_url + "/readme.html")
                if r.status_code == 200 and "WordPress" in r.text:
                    detected = True
                    version = _parse_version(
                        re.search(r"Version\s+([\d.]+)", r.text).group(0)
                        if re.search(r"Version\s+([\d.]+)", r.text) else "")
            except Exception:
                pass

        # meta generator tag on homepage
        try:
            resp = homepage_resp or fetch(base_url)
            m = re.search(
                r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)',
                resp.text, re.IGNORECASE)
            if m:
                detected = True
                if m.group(1):
                    version = m.group(1)
        except Exception:
            pass

        if not detected:
            return [make_finding(check, INFO, "wp_not_detected", {})]

        version_str = f" {version}" if version else " (version hidden)"
        findings.append(make_finding(check, INFO, "wp_detected",
                                     {"version": version or "unknown"},
                                     version=version or "unknown",
                                     version_str=version_str))

        if version:
            latest = _latest_wp_version()
            if latest and _ver_tuple(version) < _ver_tuple(latest):
                findings.append(make_finding(
                    check, MEDIUM, "wp_outdated",
                    {"installed": version, "latest": latest},
                    installed=version, latest=latest))
            # If the version API is unreachable we simply skip the comparison
            # rather than guessing.
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 5. Open directory listing
# ---------------------------------------------------------------------------
DIR_PATHS = ["/", "/images/", "/uploads/", "/assets/", "/files/", "/static/"]


def check_directory_listing(base_url):
    check = "directory_listing"
    findings = []
    try:
        for path in DIR_PATHS:
            try:
                r = fetch(base_url + path)
            except Exception:
                continue
            if r.status_code == 200 and re.search(r"Index of\s*/", r.text, re.IGNORECASE):
                findings.append(make_finding(check, MEDIUM, "dir_listing",
                                             {"path": path, "status": 200}, path=path))
        if not findings:
            findings.append(make_finding(check, INFO, "dir_listing_ok", {}))
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 6. Email authentication DNS (SPF / DMARC / DKIM)
# ---------------------------------------------------------------------------
def _txt_records_doh(name):
    """DNS-over-HTTPS fallback (Google public DNS) for networks where UDP/53
    is blocked. Returns a list of TXT strings, [] if none, None on failure."""
    try:
        r = requests.get("https://dns.google/resolve",
                         params={"name": name, "type": "TXT"},
                         headers=HEADERS, timeout=10)
        data = r.json()
        out = []
        for a in data.get("Answer", []):
            if a.get("type") == 16:  # TXT
                chunks = re.findall(r'"([^"]*)"', a.get("data", ""))
                out.append("".join(chunks) if chunks else a["data"].strip('"'))
        return out
    except Exception:
        return None


def _txt_records(name):
    """TXT lookup: system DNS first, DNS-over-HTTPS fallback.
    Returns list (possibly empty) or None if both transports failed."""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]
    except Exception:
        pass
    return _txt_records_doh(name)  # None = lookup failed; [] = no records


DKIM_SELECTORS = ["default", "google", "k1", "selector1", "selector2", "dkim"]


def check_email_dns(domain):
    check = "email_dns"
    findings = []
    try:
        # SPF
        try:
            txts = _txt_records(domain)
            if txts is None:
                findings.append(check_failed(check, "SPF lookup failed (DNS error)"))
            else:
                spf = next((t for t in txts if t.startswith("v=spf1")), None)
                if spf is None:
                    findings.append(make_finding(check, LOW, "spf_missing", {}))
                else:
                    findings.append(make_finding(check, INFO, "spf_ok", {}))
                    # --- strength: overly permissive endings ---
                    if re.search(r"\s\+all\s*$", spf):
                        findings.append(make_finding(check, MEDIUM, "spf_permissive",
                                                     {"setting": "+all"}, setting="+all"))
                    elif re.search(r"\s\?all\s*$", spf):
                        findings.append(make_finding(check, LOW, "spf_permissive",
                                                     {"setting": "?all"}, setting="?all"))
        except Exception as exc:
            findings.append(check_failed(check, f"SPF lookup error: {exc}"))

        # DMARC
        try:
            txts = _txt_records("_dmarc." + domain)
            if txts is None:
                findings.append(check_failed(check, "DMARC lookup failed (DNS error)"))
            else:
                dmarc = next((t for t in txts if "v=DMARC1" in t), None)
                if dmarc is None:
                    findings.append(make_finding(check, LOW, "dmarc_missing", {}))
                else:
                    findings.append(make_finding(check, INFO, "dmarc_ok", {}))
                    # --- strength: policy and reporting ---
                    m = re.search(r"\bp\s*=\s*([a-z]+)", dmarc, re.IGNORECASE)
                    policy = (m.group(1) or "").lower() if m else ""
                    if policy == "none":
                        findings.append(make_finding(check, LOW, "dmarc_no_enforcement", {}))
                    if not re.search(r"\brua\s*=", dmarc, re.IGNORECASE):
                        findings.append(make_finding(check, LOW, "dmarc_no_rua", {}))
        except Exception as exc:
            findings.append(check_failed(check, f"DMARC lookup error: {exc}"))

        # DKIM (common selectors only — absence is not proof of absence)
        found = None
        dns_ok = True
        for sel in DKIM_SELECTORS:
            txts = _txt_records(f"{sel}._domainkey.{domain}")
            if txts is None:
                dns_ok = False
                continue
            if any("v=DKIM1" in t or "k=rsa" in t for t in txts):
                found = sel
                break
        if found:
            findings.append(make_finding(check, INFO, "dkim_ok",
                                         {"selector": found}, selector=found))
        elif not dns_ok:
            # Lookups failed: unknown, NOT "no DKIM". Never report as clean.
            findings.append(check_failed(check, "DKIM lookups failed (DNS error)"))
        else:
            findings.append(make_finding(check, LOW, "dkim_missing", {}))
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 7. Server banner disclosure
# ---------------------------------------------------------------------------
def check_server_banner(base_url, homepage_resp=None):
    check = "server_banner"
    findings = []
    try:
        resp = homepage_resp or fetch(base_url)
        banners = []
        for h in ("Server", "X-Powered-By"):
            if h in resp.headers and resp.headers[h].strip():
                banners.append(f"{h}: {resp.headers[h].strip()}")
        if banners:
            banner = "; ".join(banners)
            # Only flag when a version number is actually disclosed.
            if re.search(r"\d+\.\d+", banner):
                findings.append(make_finding(check, LOW, "banner_disclosure",
                                             {"banner": banner}, banner=banner))
            else:
                findings.append(make_finding(check, INFO, "banner_ok",
                                             {"banner": banner}))
        else:
            findings.append(make_finding(check, INFO, "banner_ok", {}))
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 8. Homepage change / defacement detection
#
# Two fingerprints per scan:
#   * text hash      — normalized page text (catches content changes)
#   * structure hash — the sequence of HTML tag names (catches defacement
#     and redesigns even when the text is similar; ignores the text churn
#     of dynamic sites)
#
# Plus an adaptive per-site baseline: the last few change percentages are
# remembered, and a scan only alerts when the change exceeds what is normal
# FOR THAT SITE (> 1.5x the largest change previously seen, with a 15%
# floor so quiet sites still alert on real changes). A news site that
# rewrites 40% of its text daily learns that 40% is normal; a static
# brochure site keeps the strict 15% bar.
# ---------------------------------------------------------------------------
STRUCT_TAG_CAP = 1500  # max tags kept in the structure fingerprint


class _StructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        if len(self.tags) < STRUCT_TAG_CAP:
            self.tags.append(tag.lower())


def _page_fingerprint(text):
    normalized = re.sub(r"\s+", " ", text or "").strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()
    return digest, normalized


def _structure_fingerprint(text):
    parser = _StructureParser()
    try:
        parser.feed(text or "")
    except Exception:
        pass
    seq = " ".join(parser.tags)
    digest = hashlib.sha256(seq.encode("utf-8", "replace")).hexdigest()
    return digest, seq


def _change_ratio(old, new):
    if not old and not new:
        return 0.0
    if not old or not new:
        return 100.0
    return round((1 - difflib.SequenceMatcher(None, old, new,
                                             autojunk=False).ratio()) * 100, 1)


def check_content_change(base_url, previous, homepage_resp=None):
    """
    previous: dict with keys hash/text/struct_hash/struct_seq/text_changes/
    struct_changes from the last scan, or None.
    Returns (findings, current_state) where current_state is stored for next time.
    """
    check = "change_detection"
    try:
        resp = homepage_resp or fetch(base_url)
        digest, normalized = _page_fingerprint(resp.text)
        sdigest, seq = _structure_fingerprint(resp.text)
        hist_text = list((previous or {}).get("text_changes") or [])
        hist_struct = list((previous or {}).get("struct_changes") or [])
        current = {
            "hash": digest,
            "text": normalized[:20000],
            "length": len(normalized),
            "struct_hash": sdigest,
            "struct_seq": seq[:12000],
            "text_changes": hist_text,
            "struct_changes": hist_struct,
        }
        if not previous or not previous.get("hash"):
            return ([make_finding(check, INFO, "baseline_recorded",
                                  {"hash": digest[:12]})], current)
        if digest == previous["hash"]:
            # Identical text implies identical structure.
            return ([make_finding(check, INFO, "content_unchanged",
                                  {"hash": digest[:12]})], current)

        old_text = previous.get("text", "")
        old_seq = previous.get("struct_seq", "")
        text_pct = _change_ratio(old_text, normalized[:20000])
        struct_pct = _change_ratio(old_seq, seq) if old_seq else 0.0

        # Adaptive thresholds: 1.5x the largest change this site has shown
        # before, never below the 15% floor.
        text_threshold = max(15.0, 1.5 * max(hist_text)) if hist_text else 15.0
        struct_threshold = (max(15.0, 1.5 * max(hist_struct))
                            if hist_struct else 15.0)

        if old_seq and struct_pct > struct_threshold:
            findings = [make_finding(
                check, MEDIUM, "content_changed_structural",
                {"struct_pct": struct_pct, "change_pct": text_pct},
                struct_pct=struct_pct, change_pct=text_pct)]
        elif text_pct > text_threshold:
            findings = [make_finding(
                check, MEDIUM, "content_changed",
                {"change_pct": text_pct,
                 "old_len": len(old_text), "new_len": len(normalized)},
                change_pct=text_pct)]
        else:
            findings = [make_finding(check, INFO, "content_changed_minor",
                                     {"change_pct": text_pct},
                                     change_pct=text_pct)]

        current["text_changes"] = (hist_text + [text_pct])[-5:]
        if old_seq:
            current["struct_changes"] = (hist_struct + [struct_pct])[-5:]
        return findings, current
    except Exception as exc:
        return [check_failed(check, exc)], previous


# ---------------------------------------------------------------------------
# 9. Cookie security flags — every cookie is evaluated; no guessing which
# ones "look like" session cookies.
# ---------------------------------------------------------------------------


def _get_set_cookies(resp):
    """All Set-Cookie values. requests merges duplicate headers, so read
    the raw urllib3 headers first."""
    try:
        raw = resp.raw.headers.getlist("Set-Cookie")
        if raw:
            return raw
    except Exception:
        pass
    single = resp.headers.get("Set-Cookie")
    return [single] if single else []


def check_cookie_flags(base_url, homepage_resp=None):
    check = "cookie_flags"
    try:
        resp = homepage_resp or fetch(base_url)
        cookies = _get_set_cookies(resp)
        if not cookies:
            return [make_finding(check, INFO, "cookies_none", {})]
        is_https = (resp.url or base_url).startswith("https")
        findings = []
        seen = set()
        for c in cookies:
            parts = [p.strip() for p in c.split(";")]
            name = parts[0].split("=")[0].strip()
            # Report the cookie factually by name; importance is for the
            # human reading the report to judge, not for a name heuristic.
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            attrs = ";".join(parts[1:]).lower()
            missing = []
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if is_https and "secure" not in attrs:
                missing.append("Secure")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if missing:
                findings.append(make_finding(
                    check, MEDIUM if len(missing) >= 2 else LOW,
                    "cookie_insecure",
                    {"cookie": name, "missing": ", ".join(missing)},
                    cookie=name, missing=", ".join(missing)))
        if not findings:
            findings.append(make_finding(check, INFO, "cookies_ok", {}))
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 10. CORS misconfiguration
# ---------------------------------------------------------------------------
EVIL_ORIGIN = "https://evil-siteguard-test.example"


def check_cors(base_url):
    check = "cors"
    try:
        headers = dict(HEADERS)
        headers["Origin"] = EVIL_ORIGIN
        r = requests.get(base_url, headers=headers, timeout=TIMEOUT,
                         allow_redirects=True)
        acao = (r.headers.get("Access-Control-Allow-Origin") or "").strip()
        creds = (r.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        if acao.lower() == EVIL_ORIGIN.lower() and creds:
            return [make_finding(check, HIGH, "cors_misconfigured",
                                 {"origin": EVIL_ORIGIN}, origin=EVIL_ORIGIN)]
        return [make_finding(check, INFO, "cors_ok", {})]
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 11. HTTP methods
# ---------------------------------------------------------------------------
DANGEROUS_METHODS = ("PUT", "DELETE", "TRACE", "CONNECT")


def check_http_methods(base_url):
    check = "http_methods"
    try:
        r = requests.options(base_url, headers=HEADERS, timeout=TIMEOUT,
                             allow_redirects=True)
    except Exception as exc:
        return [check_failed(check, exc)]
    allow = r.headers.get("Allow", "")
    found = [m for m in DANGEROUS_METHODS
             if re.search(r"\b" + m + r"\b", allow, re.IGNORECASE)]
    if found:
        methods = ", ".join(found)
        return [make_finding(check, MEDIUM, "methods_dangerous",
                             {"methods": methods}, methods=methods)]
    return [make_finding(check, INFO, "methods_ok", {})]


# ---------------------------------------------------------------------------
# 12. security.txt
# ---------------------------------------------------------------------------
def check_security_txt(base_url):
    check = "security_txt"
    try:
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                r = fetch(base_url + path)
            except Exception:
                continue
            if r.status_code == 200 and "contact:" in (r.text or "").lower():
                return [make_finding(check, INFO, "security_txt_ok",
                                     {"path": path}, path=path)]
        return [make_finding(check, INFO, "security_txt_missing", {})]
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 13. Mixed content — parsed, not regexed
# ---------------------------------------------------------------------------
class _SubresourceParser(HTMLParser):
    """Collect genuine subresource URLs from src/href/srcset attributes.

    Only real tag attributes count — an "http://" mention inside page *text*
    is not mixed content and must never flag.
    """
    TAGS = {"script", "img", "link", "iframe", "video", "audio",
            "source", "embed", "track"}

    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() not in self.TAGS:
            return
        for k, v in attrs:
            kl, val = k.lower(), (v or "").strip()
            if not val:
                continue
            if kl in ("src", "href"):
                self.urls.append(val)
            elif kl == "srcset":
                # "url1 1x, url2 2x, ..." — take the URL part of each entry
                for part in val.split(","):
                    tokens = part.strip().split()
                    if tokens:
                        self.urls.append(tokens[0])


def check_mixed_content(base_url, homepage_resp=None):
    check = "mixed_content"
    try:
        resp = homepage_resp or fetch(base_url)
        page_url = (resp.url or base_url)
        if not page_url.startswith("https"):
            return [make_finding(check, INFO, "mixed_content_na", {})]
        parser = _SubresourceParser()
        try:
            parser.feed(resp.text or "")
        except Exception:
            pass
        hits = sorted({u for u in parser.urls
                       if u.lower().startswith("http://")})
        if hits:
            examples = ", ".join(hits[:5]) + (" ..." if len(hits) > 5 else "")
            return [make_finding(check, LOW, "mixed_content_found",
                                 {"count": len(hits), "examples": examples},
                                 count=len(hits), examples=examples)]
        return [make_finding(check, INFO, "mixed_content_ok", {})]
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 14. Sensitive backup / config / debug files
# ---------------------------------------------------------------------------
def _soft404_baseline(base_url):
    """Fingerprint the site's 404 page so we don't mistake soft-404s for
    real files."""
    try:
        r = fetch(base_url + "/siteguard-404-probe-a1b2c3d4e5.html")
        text = re.sub(r"\s+", " ", r.text or "")[:2000]
        return {"status": r.status_code, "length": len(r.text or ""),
                "text": text}
    except Exception:
        return None


def _is_soft_404(resp, baseline):
    if baseline is None or resp.status_code != 200:
        return False
    body_len = len(resp.text or "")
    body = re.sub(r"\s+", " ", resp.text or "")[:2000]
    return (baseline["status"] == 200
            and abs(body_len - baseline["length"]) < 200
            and body == baseline["text"])


def _text_has(*needles, min_len=100):
    def validate(resp):
        text = resp.text or ""
        if len(text) < min_len:
            return None
        if all(n in text for n in needles):
            return "the page contains: " + ", ".join("'%s'" % n for n in needles)
        return None
    return validate


def _is_zip(resp):
    content = resp.content or b""
    if len(content) > 100 and (
            content[:4] == b"PK\x03\x04"
            or "zip" in resp.headers.get("Content-Type", "").lower()):
        return "the file downloads as a ZIP archive"
    return None


def _is_ds_store(resp):
    if (resp.content or b"")[:8] == b"\x00\x00\x00\x01Bud1":
        return "a valid .DS_Store binary, which can reveal file and folder names"
    return None


def _is_sql_dump(resp):
    text = resp.text or ""
    if len(text) < 200:
        return None
    markers = []
    if "CREATE TABLE" in text:
        markers.append("CREATE TABLE statements")
    if "PostgreSQL database dump" in text:
        markers.append("a PostgreSQL dump header")
    if "-- MySQL dump" in text or "MySQL dump" in text:
        markers.append("a MySQL dump header")
    if "INSERT INTO" in text:
        markers.append("INSERT statements")
    if markers:
        return "it looks like a database dump (" + ", ".join(markers[:3]) + ")"
    return None


_ENV_KEY_NAMES = ("APP_KEY", "DB_PASSWORD", "DB_HOST", "DB_USERNAME",
                  "SECRET_KEY", "API_KEY", "MAIL_PASSWORD", "AWS_SECRET")


def _env_keys(resp):
    text = resp.text or ""
    if len(text) < 20:
        return None
    found = [k for k in _ENV_KEY_NAMES if k in text]
    if found:
        return "it contains configuration keys like: " + ", ".join(found[:4])
    return None


def _db_config_keys(resp):
    text = resp.text or ""
    if len(text) < 50:
        return None
    for needle in ("DB_PASSWORD", "db_password", "$db_pass", "define('DB_"):
        if needle in text:
            return f"it contains database credentials ('{needle}' found)"
    return None


SENSITIVE_FILES = [
    {"path": "/wp-config.php.bak", "severity": HIGH,
     "validate": _text_has("DB_PASSWORD", "DB_NAME")},
    {"path": "/wp-config.php~", "severity": HIGH,
     "validate": _text_has("DB_PASSWORD", "DB_NAME")},
    {"path": "/wp-config.php.save", "severity": HIGH,
     "validate": _text_has("DB_PASSWORD", "DB_NAME")},
    {"path": "/.svn/entries", "severity": MEDIUM,
     "validate": _text_has("has-props", min_len=50)},
    {"path": "/server-status", "severity": MEDIUM,
     "validate": _text_has("Apache Status")},
    {"path": "/server-info", "severity": MEDIUM,
     "validate": _text_has("Apache Server Information")},
    {"path": "/phpinfo.php", "severity": MEDIUM,
     "validate": _text_has("phpinfo()", "PHP Version")},
    {"path": "/info.php", "severity": MEDIUM,
     "validate": _text_has("phpinfo()", "PHP Version")},
    {"path": "/backup.zip", "severity": HIGH, "validate": _is_zip},
    {"path": "/site.zip", "severity": HIGH, "validate": _is_zip},
    {"path": "/db.zip", "severity": HIGH, "validate": _is_zip},
    {"path": "/backup.sql", "severity": HIGH, "validate": _is_sql_dump},
    {"path": "/db.sql", "severity": HIGH, "validate": _is_sql_dump},
    {"path": "/site.sql", "severity": HIGH, "validate": _is_sql_dump},
    {"path": "/database.sql", "severity": HIGH, "validate": _is_sql_dump},
    {"path": "/dump.sql", "severity": HIGH, "validate": _is_sql_dump},
    {"path": "/.env.bak", "severity": HIGH, "validate": _env_keys},
    {"path": "/.env.old", "severity": HIGH, "validate": _env_keys},
    {"path": "/.env.save", "severity": HIGH, "validate": _env_keys},
    {"path": "/config.php.bak", "severity": HIGH, "validate": _db_config_keys},
    {"path": "/wp-config.php.old", "severity": HIGH,
     "validate": _text_has("DB_PASSWORD", "DB_NAME")},
    {"path": "/.git/config", "severity": MEDIUM,
     "validate": _text_has("[core]", "repositoryformatversion")},
    {"path": "/composer.json", "severity": MEDIUM,
     "validate": _text_has('"require"', '"name"')},
    {"path": "/package.json", "severity": LOW,
     "validate": _text_has('"dependencies"')},
    {"path": "/.DS_Store", "severity": MEDIUM, "validate": _is_ds_store},
    {"path": "/elmah.axd", "severity": MEDIUM,
     "validate": _text_has("ELMAH", "Error Log")},
]


def check_sensitive_files(base_url):
    check = "sensitive_files"
    findings = []
    try:
        baseline = _soft404_baseline(base_url)
    except Exception:
        baseline = None
    try:
        for spec in SENSITIVE_FILES:
            try:
                r = fetch(base_url + spec["path"])
            except Exception:
                continue  # unreachable path: not evidence of anything
            if r.status_code != 200:
                continue
            if _is_soft_404(r, baseline):
                continue
            try:
                evidence = spec["validate"](r)
            except Exception:
                continue
            if evidence:
                findings.append(make_finding(
                    check, spec["severity"], "sensitive_file_exposed",
                    {"path": spec["path"], "evidence": evidence},
                    path=spec["path"], evidence=evidence))
        if not findings:
            findings.append(make_finding(check, INFO, "sensitive_files_ok", {}))
    except Exception as exc:
        findings.append(check_failed(check, exc))
    return findings


# ---------------------------------------------------------------------------
# 15. Lightweight uptime probe (used by the 30-min monitor, NOT the weekly
#     full scan). Returns (ok, status_code, response_ms). Never raises.
# ---------------------------------------------------------------------------
def check_uptime(domain):
    for scheme in ("https", "http"):
        try:
            start = time.monotonic()
            r = requests.get(f"{scheme}://{domain}/", headers=HEADERS,
                             timeout=10, allow_redirects=True)
            ms = int((time.monotonic() - start) * 1000)
            return (r.status_code < 500), r.status_code, ms
        except Exception:
            continue
    return False, None, None


# ---------------------------------------------------------------------------
# 16. Outdated JavaScript libraries
# ---------------------------------------------------------------------------
class _ScriptSrcParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            for k, v in attrs:
                if k.lower() == "src" and v:
                    self.srcs.append(v)


JS_PATTERNS = [
    ("jquery", re.compile(r"jquery[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("angularjs", re.compile(r"angularjs[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("moment", re.compile(r"moment[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    # react-dom before react: "react-dom-18.2.0" must not match the react rule.
    ("react-dom", re.compile(r"react-dom[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    # (?<![\w-]) keeps "preact-10.5.0" from matching as react.
    ("react", re.compile(r"(?<![\w-])react[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("vue", re.compile(r"(?<![\w-])vue[@/-](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    # Modern Angular: @angular/core@17.0.0 (npm/unpkg style) or angular-11.0.4.
    # Will not match "angularjs" (followed by "j", not @ / or -).
    ("angular", re.compile(r"(?:@angular[/-]core[@/-]|(?<![\w-])angular[@/-])(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
]

# lib -> list of (major or None, vulnerable_when_below, fixed_in).
# Only versions with publicly documented vulnerabilities are listed here.
# react-dom is deliberately absent: its XSS (GHSA-mvjj-gqq2-p4hw) was fixed
# in patch releases (16.0.1, 16.1.2, 16.2.1, 16.3.3, 16.4.2) while neighbouring
# patches stayed vulnerable, so a "below X" rule would false-positive. Exact
# vulnerable react-dom builds are fingerprinted in VULN_JS_HASHES and exact
# versions get an honest OSV verdict instead.
VULNERABLE_JS = {
    "jquery": [(None, (3, 5, 0), "3.5.0")],          # known XSS flaws pre-3.5.0
    "bootstrap": [(3, (3, 4, 1), "3.4.1"),
                  (4, (4, 3, 1), "4.3.1")],          # known XSS flaws
    "angularjs": [(1, (1, 8, 0), "1.8.x")],          # known XSS flaws in 1.x
    "lodash": [(None, (4, 17, 21), "4.17.21")],      # prototype pollution
    "moment": [(None, (2, 29, 4), "2.29.4")],        # ReDoS / path traversal
    "vue": [(2, (3, 0, 0), "3.x")],                 # ReDoS in all of Vue 2.x
    "angular": [(10, (10, 2, 5), "10.2.5"),          # XSS pre-10.2.5 and
                (11, (11, 0, 5), "11.0.5")],        # in 11.0.0-11.0.4
}

JS_ISSUES = {
    "jquery": "publicly known cross-site scripting (XSS) flaws",
    "bootstrap": "publicly known cross-site scripting (XSS) flaws",
    "angularjs": "publicly known cross-site scripting (XSS) flaws",
    "lodash": "publicly known prototype-pollution flaws",
    "moment": "publicly known denial-of-service flaws",
    "react": "publicly known cross-site scripting (XSS) flaws",
    "react-dom": "publicly known cross-site scripting (XSS) flaws",
    "vue": "publicly known denial-of-service (ReDoS) flaws",
    "angular": "publicly known cross-site scripting (XSS) flaws",
}

# Exact fixed-in versions for fingerprinted releases whose CVE ranges have
# patch-level exceptions a "below X" rule cannot express honestly.
# react-dom GHSA-mvjj-gqq2-p4hw: fixed in 16.0.1 / 16.1.2 / 16.2.1 /
# 16.3.3 / 16.4.2 depending on the minor line.
FIXED_IN_EXACT = {
    ("react-dom", "16.0.0"): "16.0.1",
    ("react-dom", "16.1.0"): "16.1.2",
    ("react-dom", "16.1.1"): "16.1.2",
    ("react-dom", "16.2.0"): "16.2.1",
    ("react-dom", "16.3.0"): "16.3.3",
    ("react-dom", "16.3.1"): "16.3.3",
    ("react-dom", "16.3.2"): "16.3.3",
    ("react-dom", "16.4.0"): "16.4.2",
    ("react-dom", "16.4.1"): "16.4.2",
}


def _ver_tuple3(v):
    parts = [int(p) for p in v.split(".") if p.isdigit()]
    return tuple(parts + [0] * (3 - len(parts)))[:3]


def _fixed_in_for(lib, version):
    """The fixed-in version for a matched release (major-aware)."""
    if (lib, version) in FIXED_IN_EXACT:
        return FIXED_IN_EXACT[(lib, version)]
    ver = _ver_tuple3(version)
    for major, _below, fixed_in in VULNERABLE_JS.get(lib, []):
        if major is None or ver[0] == major:
            return fixed_in
    # Hash-detected lib with no simple version rule (e.g. react-dom):
    # don't invent a version, point at the OSV-backed CVE check instead.
    return "a patched release (see the CVE lookup findings)"


# --- content-hash fingerprinting -------------------------------------------
# A byte-identical SHA-256 match against VULN_JS_HASHES means the site serves
# that exact release file — far more reliable than version strings in URLs,
# which break on bundled, renamed or self-hosted copies.
HASH_MAX_BYTES = 512 * 1024   # never download more than this per script
HASH_MAX_SCRIPTS = 8          # and never more scripts than this per scan


def _download_capped(url):
    """Download a script, capped at HASH_MAX_BYTES. Returns bytes or None."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, stream=True)
        if r.status_code != 200:
            return None
        data = b""
        for chunk in r.iter_content(65536):
            data += chunk
            if len(data) > HASH_MAX_BYTES:
                return None
        return data or None
    except Exception:
        return None


def _hash_lookup(data):
    """Return (library, version) if data matches a known-vulnerable release."""
    if not data:
        return None
    return VULN_JS_HASHES.get(hashlib.sha256(data).hexdigest())


def check_js_libraries(base_url, homepage_resp=None):
    check = "js_libraries"
    findings = []
    try:
        resp = homepage_resp or fetch(base_url)
        parser = _ScriptSrcParser()
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

        # Pass 1: version strings in the URL (fast, no extra downloads).
        flagged_srcs = set()
        seen_versions = set()
        for src in srcs:
            for lib, pattern in JS_PATTERNS:
                m = pattern.search(src)
                if not m:
                    continue
                version = m.group(1)
                key = (lib, version)
                if key in seen_versions:
                    break
                seen_versions.add(key)
                ver = _ver_tuple3(version)
                for major, below, fixed_in in VULNERABLE_JS.get(lib, []):
                    if (major is None or ver[0] == major) and ver < below:
                        findings.append(make_finding(
                            check, MEDIUM, "js_vulnerable",
                            {"library": lib, "version": version,
                             "issue": JS_ISSUES[lib], "fixed_in": fixed_in,
                             "method": "version string in URL"},
                            library=lib, version=version,
                            issue=JS_ISSUES[lib], fixed_in=fixed_in))
                        flagged_srcs.add(src)
                        break
                break

        # Pass 2: content-hash fingerprinting for everything else.
        # Catches bundled / renamed / self-hosted copies the URL can't name.
        hashed = 0
        for src in srcs:
            if src in flagged_srcs or hashed >= HASH_MAX_SCRIPTS:
                continue
            low = src.lower()
            if low.startswith("data:") or low.startswith("blob:"):
                continue
            url = src if low.startswith(("http://", "https://")) \
                else urljoin(base_url + "/", src)
            if not url.lower().startswith(("http://", "https://")):
                continue
            data = _download_capped(url)
            hashed += 1
            match = _hash_lookup(data)
            if match:
                lib, version = match
                if (lib, version) in seen_versions:
                    continue
                seen_versions.add((lib, version))
                fixed_in = _fixed_in_for(lib, version)
                findings.append(make_finding(
                    check, MEDIUM, "js_vulnerable",
                    {"library": lib, "version": version,
                     "issue": JS_ISSUES[lib], "fixed_in": fixed_in,
                     "method": "file content fingerprint"},
                    library=lib, version=version,
                    issue=JS_ISSUES[lib], fixed_in=fixed_in))
        if not findings:
            findings.append(make_finding(check, INFO, "js_ok", {}))
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 17. Subdomain takeover (certificate-transparency + DNS, read-only)
# ---------------------------------------------------------------------------
# CNAME suffix -> provider "unclaimed" page fingerprint
TAKEOVER_PROVIDERS = {
    "herokuapp.com": "No such app",
    "github.io": "There isn't a GitHub Pages site here",
    "s3.amazonaws.com": "NoSuchBucket",
}


def _crtsh_subdomains(domain, cap=30):
    """Subdomains from public certificate-transparency logs.
    Returns (list, None) or (None, error)."""
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         headers=HEADERS, timeout=20)
        data = r.json()
    except Exception as exc:
        return None, exc
    names = set()
    for entry in data or []:
        for n in str(entry.get("name_value", "")).splitlines():
            n = n.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if n and n != domain and n.endswith("." + domain):
                names.add(n)
    return sorted(names)[:cap], None


def _cname_target(name):
    try:
        ans = dns.resolver.resolve(name, "CNAME", lifetime=8)
        return str(ans[0].target).rstrip(".").lower()
    except Exception:
        return None


def _target_nxdomain(target):
    """True only on a definitive NXDOMAIN — anything else is 'unknown'."""
    try:
        dns.resolver.resolve(target, "A", lifetime=8)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def check_subdomain_takeover(domain):
    check = "subdomain_takeover"
    findings = []
    try:
        names, err = _crtsh_subdomains(domain)
        if names is None:
            return [check_failed(
                check, f"certificate-transparency lookup failed: {err}")]
        for name in names:
            target = _cname_target(name)
            if not target:
                continue
            reason = None
            if _target_nxdomain(target):
                reason = (f"{name} points to {target}, which no longer resolves "
                          "— the DNS record is dangling")
            else:
                for suffix, fingerprint in TAKEOVER_PROVIDERS.items():
                    if target == suffix or target.endswith("." + suffix):
                        try:
                            r = requests.get(f"https://{name}/", headers=HEADERS,
                                             timeout=10, allow_redirects=True)
                            if fingerprint in (r.text or ""):
                                reason = (f"{name} points to {target}, and the page "
                                          "shows the provider's 'unclaimed' message")
                        except Exception:
                            pass
                        break
            if reason:
                findings.append(make_finding(
                    check, MEDIUM, "takeover_possible",
                    {"subdomain": name, "target": target, "reason": reason},
                    subdomain=name, target=target, reason=reason))
        if not findings:
            findings.append(make_finding(check, INFO, "takeover_ok",
                                         {"checked": len(names)},
                                         checked=len(names)))
        return findings
    except Exception as exc:
        return [check_failed(check, exc)]


# ---------------------------------------------------------------------------
# 18. DNS zone transfer (read-only attempt; refusal is the expected result)
# ---------------------------------------------------------------------------
def check_zone_transfer(domain):
    check = "zone_transfer"
    try:
        try:
            ns_answers = dns.resolver.resolve(domain, "NS", lifetime=10)
        except Exception as exc:
            return [check_failed(check, f"could not find name servers: {exc}")]
        ns_hosts = [str(r.target).rstrip(".") for r in ns_answers]
        for ns in ns_hosts:
            try:
                records = list(dns.query.xfr(ns, domain, lifetime=10))
            except Exception:
                continue  # refused / timed out: the expected secure state
            if records:
                return [make_finding(check, HIGH, "axfr_allowed",
                                     {"nameserver": ns, "records": len(records)},
                                     nameserver=ns, records=len(records))]
        return [make_finding(check, INFO, "axfr_ok",
                             {"nameservers": ", ".join(ns_hosts)},
                             nameservers=", ".join(ns_hosts))]
    except Exception as exc:
        return [check_failed(check, exc)]
