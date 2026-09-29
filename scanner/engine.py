"""Scan orchestration: normalize domain, pick scheme, run all checks."""

from scanner import checks
from scanner import checks_extra

CHECK_NAMES = [
    "ssl",
    "security_headers",
    "admin_panels",
    "wordpress",
    "directory_listing",
    "email_dns",
    "server_banner",
    "change_detection",
    "cookie_flags",
    "cors",
    "http_methods",
    "security_txt",
    "mixed_content",
    "sensitive_files",
    "js_libraries",
    "subdomain_takeover",
    "zone_transfer",
    # batch 2
    "tls_config",
    "https_redirect",
    "script_integrity",
    "sourcemaps",
    "js_cves",
    "dns_caa",
    "email_mta_sts",
    "dnssec",
    "hsts_quality",
    "error_disclosure",
    "robots_txt",
]


def normalize_domain(raw):
    """Turn user input ('https://example.com/', ' example.com ') into 'example.com'."""
    d = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split(":")[0]  # drop port if given
    return d


def _pick_base_url(domain):
    """Prefer HTTPS; fall back to HTTP. Returns (base_url, error)."""
    try:
        r = checks.fetch(f"https://{domain}/")
        if r.status_code < 500:
            return f"https://{domain}", None
    except Exception as https_exc:
        try:
            r = checks.fetch(f"http://{domain}/")
            if r.status_code < 500:
                return f"http://{domain}", None
        except Exception as http_exc:
            return None, f"HTTPS failed ({https_exc}); HTTP failed ({http_exc})"
        return None, f"HTTPS failed ({https_exc})"
    return f"https://{domain}", None


def _safe_run(fn, *args):
    """Run one check; any unexpected crash becomes a check_failed finding."""
    try:
        return fn(*args)
    except Exception as exc:  # belt and braces — checks handle their own errors too
        return [checks.check_failed(fn.__name__.replace("check_", ""), exc)]


def run_scan(domain, previous_state=None):
    """
    Run all checks against a domain.

    previous_state: {"hash":..., "text":...} from the last scan (for change
    detection), or None on first scan.

    Returns {"ok": bool, "domain":..., "base_url":..., "findings": [...],
             "content_state": {...}|None, "error": str|None}
    """
    domain = normalize_domain(domain)
    if not domain or "." not in domain:
        return {"ok": False, "domain": domain, "base_url": None,
                "findings": [], "content_state": None,
                "error": f"'{domain}' does not look like a valid domain."}

    base_url, err = _pick_base_url(domain)
    if base_url is None:
        # Site unreachable: every check is UNKNOWN, not clean.
        findings = [checks.check_failed(name, f"site unreachable: {err}")
                    for name in CHECK_NAMES]
        return {"ok": False, "domain": domain, "base_url": None,
                "findings": findings, "content_state": previous_state,
                "error": err}

    try:
        homepage_resp = checks.fetch(base_url)
    except Exception as exc:
        homepage_resp = None
        homepage_error = str(exc)
    else:
        homepage_error = None

    findings = []
    findings += _safe_run(checks.check_ssl, domain)
    findings += _safe_run(checks.check_security_headers, base_url, homepage_resp)
    findings += _safe_run(checks.check_admin_panels, base_url, homepage_resp)
    findings += _safe_run(checks.check_wordpress, base_url, homepage_resp)
    findings += _safe_run(checks.check_directory_listing, base_url)
    findings += _safe_run(checks.check_email_dns, domain)
    findings += _safe_run(checks.check_server_banner, base_url, homepage_resp)
    findings += _safe_run(checks.check_cookie_flags, base_url, homepage_resp)
    findings += _safe_run(checks.check_cors, base_url)
    findings += _safe_run(checks.check_http_methods, base_url)
    findings += _safe_run(checks.check_security_txt, base_url)
    findings += _safe_run(checks.check_mixed_content, base_url, homepage_resp)
    findings += _safe_run(checks.check_sensitive_files, base_url)
    findings += _safe_run(checks.check_js_libraries, base_url, homepage_resp)
    findings += _safe_run(checks.check_subdomain_takeover, domain)
    findings += _safe_run(checks.check_zone_transfer, domain)
    # batch 2
    findings += _safe_run(checks_extra.check_tls_config, domain)
    findings += _safe_run(checks_extra.check_https_redirect, domain)
    findings += _safe_run(checks_extra.check_script_integrity,
                          base_url, homepage_resp)
    findings += _safe_run(checks_extra.check_sourcemaps, base_url, homepage_resp)
    findings += _safe_run(checks_extra.check_js_cves, base_url, homepage_resp)
    findings += _safe_run(checks_extra.check_dns_caa, domain)
    findings += _safe_run(checks_extra.check_mta_sts, domain)
    findings += _safe_run(checks_extra.check_dnssec, domain)
    findings += _safe_run(checks_extra.check_hsts_quality,
                          base_url, homepage_resp)
    findings += _safe_run(checks_extra.check_error_disclosure, base_url)
    findings += _safe_run(checks_extra.check_robots_txt, base_url)

    content_state = previous_state
    if homepage_error and homepage_resp is None:
        findings.append(checks.check_failed(
            "change_detection", f"could not fetch homepage: {homepage_error}"))
    else:
        change_findings, content_state = checks.check_content_change(
            base_url, previous_state, homepage_resp)
        findings += change_findings

    return {"ok": True, "domain": domain, "base_url": base_url,
            "findings": findings, "content_state": content_state, "error": None}
