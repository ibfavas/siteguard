"""
All user-facing finding text lives here, in English.

Each entry: title, explanation (plain language for a non-technical site
owner), fix (what to do about it). Entries may use {placeholders} filled
in by the scanner.

To add Malayalam later: create STRINGS_ML with the same keys and pick the
mapping based on a language setting. No scanner logic needs to change.
"""

STRINGS = {
    # --- SSL ---------------------------------------------------------------
    "ssl_ok": {
        "title": "SSL certificate is valid",
        "explanation": "Your site's security certificate (the thing that makes "
                       "the padlock appear in browsers) is valid and expires in "
                       "{days} days, on {expiry}.",
        "fix": "No action needed. SiteGuard will warn you as the expiry date approaches.",
    },
    "ssl_expiring_soon": {
        "title": "SSL certificate expires in {days} days",
        "explanation": "Your site's security certificate expires on {expiry}. If it "
                       "expires, visitors will see a scary warning page and may not "
                       "trust your site.",
        "fix": "Renew the certificate before {expiry}. If you use Let's Encrypt or your "
               "hosting provider's auto-renewal, check that auto-renewal is working.",
    },
    "ssl_expired": {
        "title": "SSL certificate has EXPIRED",
        "explanation": "Your site's security certificate expired on {expiry}. Visitors "
                       "right now see a security warning instead of your website, which "
                       "drives customers away.",
        "fix": "Renew the certificate immediately through your hosting provider or "
               "certificate issuer, then verify the padlock appears in a browser.",
    },
    "ssl_no_https": {
        "title": "Site does not use HTTPS",
        "explanation": "Your site loads over plain HTTP with no security certificate. "
                       "Anything visitors type (passwords, contact forms, payment details) "
                       "can be seen by others on the network, and browsers label the site "
                       "'Not Secure'.",
        "fix": "Install a free certificate from Let's Encrypt (most hosts offer one-click "
               "setup) and redirect all HTTP traffic to HTTPS.",
    },
    # --- Security headers ---------------------------------------------------
    "header_missing": {
        "title": "Missing security header: {header}",
        "explanation": "Your site does not send the '{header}' instruction to browsers. "
                       "{why} Without it, your visitors are less protected.",
        "fix": "{fix}",
    },
    "headers_ok": {
        "title": "Security headers look good",
        "explanation": "Your site sends all the recommended browser-protection headers "
                       "we check for.",
        "fix": "No action needed.",
    },
    # --- Exposed admin panels ----------------------------------------------
    "panel_exposed": {
        "title": "Login/admin page publicly reachable: {path}",
        "explanation": "The page {path} on your site is reachable by anyone on the "
                       "internet{protected}. Attackers routinely scan the internet for "
                       "these pages and try to guess passwords.",
        "fix": "Make sure it uses a strong, unique password and two-factor authentication. "
               "If possible, restrict access to this page to your own IP address, or move "
               "it to a non-standard address.",
    },
    "git_exposed": {
        "title": "Source code repository exposed (/.git/HEAD)",
        "explanation": "Your site's private code history is downloadable by anyone. This "
                       "can leak passwords, API keys and your full source code.",
        "fix": "Block public access to the .git folder on your web server immediately, "
               "and rotate any passwords or API keys that were stored in the code.",
    },
    "env_exposed": {
        "title": "Configuration file exposed (/.env)",
        "explanation": "Your site's secret configuration file is readable by anyone. It "
                       "usually contains database passwords and API keys.",
        "fix": "Block public access to the .env file immediately and change every "
               "password and key listed inside it.",
    },
    "panels_ok": {
        "title": "No exposed admin panels found",
        "explanation": "We probed common login and admin addresses and none of them "
                       "responded publicly.",
        "fix": "No action needed.",
    },
    # --- WordPress ----------------------------------------------------------
    "wp_detected": {
        "title": "Site runs WordPress {version}",
        "explanation": "We detected that your site is built with WordPress{version_str}. "
                       "WordPress is a common target, so keeping it updated matters.",
        "fix": "Keep WordPress, themes and plugins updated. Remove plugins you don't use.",
    },
    "wp_outdated": {
        "title": "WordPress is out of date ({installed} < {latest})",
        "explanation": "Your site runs WordPress {installed}, but {latest} is the newest "
                       "release. Old versions are the most common way small business sites "
                       "get hacked — attackers specifically target known flaws in old versions.",
        "fix": "Back up your site, then update WordPress, your theme and all plugins from "
               "the WordPress dashboard (Dashboard > Updates).",
    },
    "wp_not_detected": {
        "title": "WordPress not detected",
        "explanation": "We could not find traces of WordPress on this site, so the "
                       "WordPress-specific checks were skipped.",
        "fix": "No action needed.",
    },
    # --- Directory listing --------------------------------------------------
    "dir_listing": {
        "title": "Folder contents visible at {path}",
        "explanation": "Visiting {path} shows a plain list of all files in that folder. "
                       "This lets strangers browse files you may not intend to share.",
        "fix": "Turn off directory listing in your web server settings (ask your hosting "
               "provider), or place an empty index.html file in the folder.",
    },
    "dir_listing_ok": {
        "title": "No open folder listings found",
        "explanation": "The common folders we checked do not reveal their file lists.",
        "fix": "No action needed.",
    },
    # --- Email DNS ----------------------------------------------------------
    "spf_missing": {
        "title": "No SPF record for email",
        "explanation": "Your domain has no SPF record, which tells the world which mail "
                       "servers may send email as you. Without it, attackers can more "
                       "easily send fake emails pretending to be your business, and your "
                       "real emails are more likely to land in spam.",
        "fix": "Add a TXT record to your domain's DNS, e.g. \"v=spf1 include:_spf.google.com ~all\" "
               "(replace with your actual mail provider's value). Your email provider's help "
               "pages have the exact record to use.",
    },
    "spf_ok": {
        "title": "SPF record present",
        "explanation": "Your domain publishes an SPF record, which helps mail servers "
                       "verify that email claiming to be from you is genuine.",
        "fix": "No action needed.",
    },
    "dmarc_missing": {
        "title": "No DMARC record for email",
        "explanation": "Your domain has no DMARC record, which tells mail servers what to "
                       "do with suspicious email pretending to be from you. Without it, "
                       "fake invoices or messages sent in your business's name are harder "
                       "to stop.",
        "fix": "Add a TXT record at _dmarc.{domain}, e.g. \"v=DMARC1; p=quarantine; rua=mailto:you@{domain}\". "
               "Start with p=none to monitor, then move to quarantine or reject.",
    },
    "dmarc_ok": {
        "title": "DMARC record present",
        "explanation": "Your domain publishes a DMARC policy, which helps stop email "
                       "spoofing using your business name.",
        "fix": "No action needed.",
    },
    "dkim_missing": {
        "title": "No DKIM record found (common selectors)",
        "explanation": "We could not find a DKIM email-signing record under the usual "
                       "names. DKIM cryptographically signs your outgoing email so "
                       "receivers can trust it really came from you.",
        "fix": "Enable DKIM in your email provider's admin panel and publish the TXT "
               "record they give you in your DNS.",
    },
    "dkim_ok": {
        "title": "DKIM record found ({selector})",
        "explanation": "Your domain publishes a DKIM signing record, which helps prove "
                       "your outgoing email is genuine.",
        "fix": "No action needed.",
    },
    # --- Server banners -----------------------------------------------------
    "banner_disclosure": {
        "title": "Server software version disclosed",
        "explanation": "Your site tells every visitor exactly which server software it "
                       "runs ({banner}). Attackers use this to pick attacks known to work "
                       "against that version.",
        "fix": "Hide or shorten the Server header (and X-Powered-By) in your web server "
               "configuration so it no longer advertises version numbers.",
    },
    "banner_ok": {
        "title": "No server version disclosed",
        "explanation": "Your site does not advertise its server software version in "
                       "response headers.",
        "fix": "No action needed.",
    },
    # --- Change / defacement detection --------------------------------------
    "baseline_recorded": {
        "title": "Homepage baseline recorded",
        "explanation": "This is the first scan, so SiteGuard saved a fingerprint of your "
                       "homepage. Future scans will compare against it and warn you if the "
                       "page changes unexpectedly.",
        "fix": "No action needed.",
    },
    "content_changed": {
        "title": "Homepage content changed since last scan",
        "explanation": "Your homepage looks notably different from the last scan "
                       "({change_pct}% of the page text changed — more than is normal "
                       "for this site). This can be normal (a redesign, new banner), but "
                       "unexpected changes can also mean the site was defaced or hacked.",
        "fix": "Open your site and check that it looks as you expect. If you did not "
               "make these changes, contact your hosting provider or developer immediately.",
    },
    "content_changed_structural": {
        "title": "Homepage structure changed significantly since last scan",
        "explanation": "The underlying structure of your homepage changed by {struct_pct}% "
                       "since the last scan (page text changed {change_pct}%). Big "
                       "structural changes are unusual for routine updates — redesigns and "
                       "defacement both rewrite the page layout, while normal daily edits "
                       "only change the text.",
        "fix": "Open your site and check that it looks as you expect. If you did not "
               "make these changes, contact your hosting provider or developer immediately.",
    },
    "content_unchanged": {
        "title": "Homepage unchanged since last scan",
        "explanation": "Your homepage matches the fingerprint from the previous scan — "
                       "no unexpected changes.",
        "fix": "No action needed.",
    },
    "content_changed_minor": {
        "title": "Homepage changed slightly since last scan",
        "explanation": "Your homepage differs a little from the last scan ({change_pct}% "
                       "of the page text changed) — within what is normal for this site. "
                       "SiteGuard learns how much your site usually changes, so routine "
                       "updates don't raise alarms.",
        "fix": "No action needed unless you notice something you didn't change.",
    },
    # --- Check failures (honest, never reported as clean) -------------------
    "check_failed": {
        "title": "Check could not run: {check_name}",
        "explanation": "The '{check_name}' check did not complete ({reason}). This is NOT a "
                       "clean result — the check simply couldn't run, so nothing is known "
                       "about this area.",
        "fix": "Re-run the scan later. If it keeps failing, check that the site is "
               "reachable and that outbound network access is allowed.",
    },
    # --- Cookie flags -------------------------------------------------------
    "cookie_insecure": {
        "title": "Cookie '{cookie}' is missing protection: {missing}",
        "explanation": "Your site sets a cookie called '{cookie}' without {missing}. "
                       "These flags are the standard protections for cookies: without them, "
                       "the cookie is easier to steal or misuse, and a stolen cookie can "
                       "let an attacker act as the logged-in user.",
        "fix": "When setting this cookie, add the missing flags: HttpOnly (hides it from "
               "JavaScript), Secure (only sent over HTTPS), and SameSite=Lax or Strict "
               "(blocks cross-site sending). Your developer can do this in a few lines.",
    },
    "cookies_ok": {
        "title": "Cookies are properly protected",
        "explanation": "Every cookie we could see on your homepage carries the recommended "
                       "HttpOnly, Secure and SameSite protections.",
        "fix": "No action needed.",
    },
    "cookies_none": {
        "title": "No cookies set on homepage",
        "explanation": "The homepage did not set any cookies, so there was nothing to "
                       "check here.",
        "fix": "No action needed.",
    },
    # --- CORS ----------------------------------------------------------------
    "cors_misconfigured": {
        "title": "CORS misconfiguration: any website can read your site's responses",
        "explanation": "Your site answers requests from '{origin}' — a domain we made up "
                       "for the test — and allows credentials. That means ANY malicious "
                       "website can make your visitors' browsers send requests to your site "
                       "and read the replies, which can leak private data.",
        "fix": "Only allow origins you actually own in Access-Control-Allow-Origin, and "
               "never combine a wildcard or reflected origin with "
               "Access-Control-Allow-Credentials: true. Ask your developer to review the "
               "CORS settings.",
    },
    "cors_ok": {
        "title": "CORS policy looks safe",
        "explanation": "Your site does not reflect untrusted origins with credentials "
                       "allowed.",
        "fix": "No action needed.",
    },
    # --- Email auth strength -------------------------------------------------
    "spf_permissive": {
        "title": "SPF record is too permissive ({setting})",
        "explanation": "Your SPF record ends with '{setting}', which effectively tells mail "
                       "servers that almost anyone may send email as your business. This "
                       "makes it much easier for attackers to send convincing fake emails "
                       "in your name.",
        "fix": "Change the end of your SPF record to '~all' (soft-fail) or '-all' "
               "(hard-fail) once you have listed your real mail servers.",
    },
    "dmarc_no_enforcement": {
        "title": "DMARC policy is monitor-only (p=none)",
        "explanation": "Your DMARC policy is 'p=none', which only watches — mail servers "
                       "take no action against fake emails sent in your business's name. "
                       "Monitoring is a fine first step, but it doesn't stop spoofing.",
        "fix": "After watching the aggregate reports for a few weeks, move to "
               "'p=quarantine' and later 'p=reject' so fakes actually get blocked.",
    },
    "dmarc_no_rua": {
        "title": "DMARC has no reporting address",
        "explanation": "Your DMARC record has no 'rua' address, so you receive no reports "
                       "about who is sending email as your domain — including attackers. "
                       "You're flying blind.",
        "fix": "Add 'rua=mailto:you@yourdomain' to your DMARC record so you get "
               "aggregate reports.",
    },
    # --- HTTP methods --------------------------------------------------------
    "methods_dangerous": {
        "title": "Risky HTTP methods enabled: {methods}",
        "explanation": "Your server advertises these HTTP methods: {methods}. Methods like "
                       "PUT and DELETE can let attackers upload or remove files, and TRACE "
                       "can help steal cookies. Most small business sites never need them.",
        "fix": "Disable PUT, DELETE, TRACE and CONNECT in your web server configuration, "
               "keeping only GET, POST, HEAD and OPTIONS.",
    },
    "methods_ok": {
        "title": "No risky HTTP methods advertised",
        "explanation": "Your server does not advertise PUT, DELETE, TRACE or CONNECT.",
        "fix": "No action needed.",
    },
    # --- security.txt --------------------------------------------------------
    "security_txt_missing": {
        "title": "No security.txt contact file",
        "explanation": "Your site has no security.txt file, which is the standard way to "
                       "tell security researchers how to report a vulnerability they find. "
                       "Without it, well-meaning reports may never reach you.",
        "fix": "Publish a small text file at /.well-known/security.txt containing a "
               "'Contact:' line with an email address (see securitytxt.org).",
    },
    "security_txt_ok": {
        "title": "security.txt contact file present",
        "explanation": "Your site publishes a security.txt file at {path}, so researchers "
                       "know how to report vulnerabilities to you.",
        "fix": "No action needed.",
    },
    # --- Mixed content --------------------------------------------------------
    "mixed_content_found": {
        "title": "Insecure resources loaded on secure page ({count})",
        "explanation": "Your HTTPS page loads {count} resource(s) over plain HTTP "
                       "(e.g. {examples}). Browsers may block these, breaking parts of "
                       "your page, and attackers on the network can tamper with them.",
        "fix": "Change those resource URLs from http:// to https://, or host the files "
               "on your own secure server.",
    },
    "mixed_content_ok": {
        "title": "No mixed content found",
        "explanation": "Your HTTPS homepage does not load resources over plain HTTP.",
        "fix": "No action needed.",
    },
    "mixed_content_na": {
        "title": "Mixed-content check not applicable",
        "explanation": "The site does not use HTTPS, so the mixed-content check does not "
                       "apply (the missing-HTTPS finding already covers this).",
        "fix": "No action needed.",
    },
    # --- Sensitive files ------------------------------------------------------
    "sensitive_file_exposed": {
        "title": "Sensitive file publicly accessible: {path}",
        "explanation": "The file {path} on your site is downloadable by anyone. {evidence} "
                       "Files like this routinely leak passwords, source code and server "
                       "details to attackers.",
        "fix": "Remove the file from the public web folder (or block access to it in your "
               "server configuration). If it contained passwords or keys, change them "
               "immediately.",
    },
    "sensitive_files_ok": {
        "title": "No exposed backup or config files found",
        "explanation": "We probed common backup, config and debug file locations and none "
                       "of them returned sensitive content.",
        "fix": "No action needed.",
    },
    # --- Outdated JS libraries -------------------------------------------------
    "js_vulnerable": {
        "title": "Outdated JavaScript library: {library} {version}",
        "explanation": "Your site loads {library} version {version}, which has publicly "
                       "known vulnerabilities ({issue}; fixed in {fixed_in}). Attackers "
                       "specifically scan for sites running these old versions.",
        "fix": "Update {library} to version {fixed_in} or newer. If it's bundled with a "
               "theme or plugin, update that instead.",
    },
    "js_ok": {
        "title": "JavaScript libraries look current",
        "explanation": "The common JavaScript libraries we could detect on your homepage "
                       "are not running versions with publicly known vulnerabilities.",
        "fix": "No action needed.",
    },
    # --- Subdomain takeover ----------------------------------------------------
    "takeover_possible": {
        "title": "Potential subdomain takeover: {subdomain}",
        "explanation": "{reason}. An attacker could claim this hostname on the hosting "
                       "provider and serve their own content under your business's domain "
                       "name — visitors would trust it because it looks like your site. "
                       "NOTE: this is a potential issue flagged automatically — please "
                       "verify it manually before treating it as confirmed.",
        "fix": "If you no longer use this subdomain, delete its DNS record. If you do "
               "use it, make sure the service it points to is claimed and active under "
               "your account.",
    },
    "takeover_ok": {
        "title": "No obvious subdomain takeover risk",
        "explanation": "We checked {checked} subdomain(s) found in public certificate "
                       "records and none pointed at dead or unclaimed services.",
        "fix": "No action needed.",
    },
    # --- Zone transfer ----------------------------------------------------------
    "axfr_allowed": {
        "title": "DNS zone transfer allowed (serious misconfiguration)",
        "explanation": "Your name server {nameserver} gave us a full copy of your DNS "
                       "zone ({records} records) when asked. This hands attackers a "
                       "complete map of your infrastructure — every subdomain and server "
                       "— making further attacks much easier.",
        "fix": "Restrict DNS zone transfers (AXFR) to your secondary name servers only. "
               "In BIND this is the 'allow-transfer' setting; your DNS provider's help "
               "pages show where to change it.",
    },
    "axfr_ok": {
        "title": "DNS zone transfer properly refused",
        "explanation": "Your name servers ({nameservers}) refused to hand out a copy of "
                       "your DNS zone, which is the correct, secure behavior.",
        "fix": "No action needed.",
    },
    # --- TLS configuration ------------------------------------------------------
    "tls_old_version": {
        "title": "Outdated TLS version still enabled: {version}",
        "explanation": "Your server still accepts {version}, an old encryption protocol "
                       "with known weaknesses. Modern browsers no longer need it, so "
                       "keeping it on only helps attackers — especially on public Wi-Fi.",
        "fix": "Disable {version} on your server or hosting panel and keep only TLS 1.2 "
               "and 1.3 enabled. (On Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3. On "
               "Nginx: ssl_protocols TLSv1.2 TLSv1.3.)",
    },
    "tls_weak_cipher": {
        "title": "Server accepts weak encryption (ciphers)",
        "explanation": "Your server agreed to encrypt traffic with {cipher}, a weak "
                       "cipher that attackers can realistically break. Even though "
                       "stronger options exist, a weak cipher being available at all "
                       "lets attackers force its use.",
        "fix": "Disable weak ciphers (RC4, DES/3DES, MD5-based and anything under "
               "128-bit) in your server configuration and prefer AES-GCM or "
               "ChaCha20-Poly1305 cipher suites.",
    },
    "tls_no_tls13": {
        "title": "TLS 1.3 not enabled",
        "explanation": "Your server negotiates up to {best}, but not TLS 1.3. TLS 1.3 is "
                       "faster (quicker handshakes) and removes several legacy "
                       "weaknesses by design.",
        "fix": "Enable TLS 1.3 alongside TLS 1.2 if your server software supports it "
               "(OpenSSL 1.1.1+, recent Nginx/Apache). No downside for visitors.",
    },
    "tls_ok": {
        "title": "TLS configuration looks good",
        "explanation": "Your server only accepts modern encryption (TLS {versions}) and "
                       "refused all the weak ciphers we tested.",
        "fix": "No action needed.",
    },
    # --- HTTP to HTTPS redirect -------------------------------------------------
    "http_no_redirect": {
        "title": "Plain HTTP does not redirect to HTTPS",
        "explanation": "Visiting the insecure http:// version of your site {detail} "
                       "Anyone on the network (coffee-shop Wi-Fi, ISPs) can see or "
                       "modify what visitors do there, and attackers can keep them on "
                       "the insecure version.",
        "fix": "Redirect all HTTP traffic to HTTPS with a 301 redirect. Most hosting "
               "panels have a 'force HTTPS' switch; otherwise add the redirect rule to "
               "your server configuration.",
    },
    "http_redirect_ok": {
        "title": "HTTP correctly redirects to HTTPS",
        "explanation": "The insecure http:// version of your site immediately sends "
                       "visitors to the secure https:// version.",
        "fix": "No action needed.",
    },
    "http_closed": {
        "title": "Plain HTTP port is closed",
        "explanation": "Your server does not answer on the insecure HTTP port at all, "
                       "so visitors can only ever reach the secure HTTPS version.",
        "fix": "No action needed.",
    },
    # --- Subresource integrity --------------------------------------------------
    "sri_missing": {
        "title": "External scripts without integrity check ({count})",
        "explanation": "These third-party scripts load without a tamper check: {srcs} "
                       "If the provider's server is hacked (or the connection is "
                       "interfered with), malicious code would run on your site with no "
                       "warning.",
        "fix": "Add an 'integrity' attribute (SRI hash) to each external <script> tag. "
               "Generate it with: openssl dgst -sha384 -binary file.js | openssl "
               "base64 -A, then add integrity=\"sha384-...\" crossorigin=\"anonymous\".",
    },
    "sri_ok": {
        "title": "External scripts have integrity checks",
        "explanation": "All {count} third-party script(s) on your homepage carry an "
                       "integrity hash, so browsers will refuse them if they are "
                       "tampered with.",
        "fix": "No action needed.",
    },
    "sri_na": {
        "title": "No external scripts to check",
        "explanation": "Your homepage loads no third-party scripts, so there is nothing "
                       "to tamper-check.",
        "fix": "No action needed.",
    },
    # --- Source maps ------------------------------------------------------------
    "sourcemap_exposed": {
        "title": "JavaScript source map publicly exposed",
        "explanation": "The file {url} is downloadable by anyone. Source maps contain "
                       "your original, unminified source code — including comments, "
                       "internal paths, and sometimes API keys or logic you did not "
                       "intend to publish.",
        "fix": "Stop deploying .map files to your live site (keep them for debugging "
               "only), or block them in your server configuration. Then rotate any "
               "secrets that were visible in the exposed source.",
    },
    "sourcemaps_ok": {
        "title": "No exposed source maps found",
        "explanation": "We checked the scripts on your homepage and none of them leak "
                       "a downloadable source map.",
        "fix": "No action needed.",
    },
    # --- JS library CVEs (OSV) --------------------------------------------------
    "js_cve": {
        "title": "{library} {version} has {count} known {vuln_word}",
        "explanation": "The {library} version your site loads ({version}) is affected by "
                       "{cve_list}{worst}. These are publicly documented flaws — "
                       "attackers specifically scan for sites running these versions.",
        "fix": "Update {library} to {fixed_in} or newer, then re-scan to confirm the "
               "warnings clear.",
    },
    "js_cves_none": {
        "title": "No known CVEs for detected libraries",
        "explanation": "We looked up {libs} in a public vulnerability database and found "
                       "no recorded CVEs for the exact versions your site loads.",
        "fix": "No action needed — but keep libraries updated anyway.",
    },
    "js_cves_na": {
        "title": "No JavaScript libraries to look up",
        "explanation": "No recognizable JavaScript libraries were detected on your "
                       "homepage, so there was nothing to check against the "
                       "vulnerability database.",
        "fix": "No action needed.",
    },
    # --- CAA --------------------------------------------------------------------
    "caa_missing": {
        "title": "No CAA DNS record",
        "explanation": "Your DNS has no CAA record, which means any certificate "
                       "authority in the world is allowed to issue certificates for "
                       "your domain. A compromised or tricked CA could issue a fake "
                       "certificate for your site.",
        "fix": "Add a CAA record in your DNS panel allowing only your certificate "
               "issuer, e.g.: 0 issue \"letsencrypt.org\" (plus 'issuewild' if you "
               "use wildcard certificates).",
    },
    "caa_ok": {
        "title": "CAA record restricts certificate issuance",
        "explanation": "Your DNS CAA record ({records}) limits which certificate "
                       "authorities may issue certificates for your domain.",
        "fix": "No action needed.",
    },
    # --- MTA-STS -----------------------------------------------------------------
    "mta_sts_missing": {
        "title": "No MTA-STS email protection",
        "explanation": "Your domain publishes no MTA-STS policy, so sending mail "
                       "servers cannot verify they are talking to your real mail "
                       "server over encrypted SMTP. Attackers on the network path can "
                       "strip encryption or impersonate your mail server.",
        "fix": "Publish an _mta-sts TXT record and a policy file at "
               "https://mta-sts.{domain}/.well-known/mta-sts.txt (start with "
               "'mode: testing', move to 'enforce' after monitoring reports).",
    },
    "mta_sts_testing": {
        "title": "MTA-STS is in testing mode",
        "explanation": "Your MTA-STS policy exists but is set to 'testing', which only "
                       "asks senders to report problems — it does not enforce "
                       "encrypted delivery.",
        "fix": "After watching the TLS reports for a couple of weeks with no failures, "
               "switch the policy file's mode to 'enforce'.",
    },
    "mta_sts_none": {
        "title": "MTA-STS policy explicitly disables enforcement",
        "explanation": "Your MTA-STS policy file sets mode to 'none', which tells "
                       "sending mail servers not to enforce encrypted delivery — "
                       "the policy exists but protects nothing.",
        "fix": "Change the policy file's mode from 'none' to 'enforce' (via "
               "'testing' first while you monitor the TLS reports).",
    },
    "mta_sts_broken": {
        "title": "MTA-STS is misconfigured",
        "explanation": "Your DNS advertises MTA-STS ({detail}), but the policy file is "
                       "missing or invalid. Senders that honor MTA-STS may fail to "
                       "deliver your email or fall back to insecure delivery.",
        "fix": "Either publish a valid policy file at "
               "https://mta-sts.{domain}/.well-known/mta-sts.txt or remove the "
               "_mta-sts DNS record until you are ready.",
    },
    "mta_sts_ok": {
        "title": "MTA-STS email protection is enforced",
        "explanation": "Your MTA-STS policy requires mail servers to verify your "
                       "server's identity and use encrypted SMTP.",
        "fix": "No action needed.",
    },
    # --- DNSSEC ------------------------------------------------------------------
    "dnssec_missing": {
        "title": "DNSSEC not enabled",
        "explanation": "Your domain's DNS responses are not cryptographically signed. "
                       "Without DNSSEC, attackers who can interfere with DNS (public "
                       "Wi-Fi, compromised resolvers) can redirect your visitors to a "
                       "fake copy of your site.",
        "fix": "Enable DNSSEC in your DNS provider's panel (they publish the DS record "
               "to your domain registry). Most major providers offer it as a switch.",
    },
    "dnssec_ok": {
        "title": "DNSSEC is enabled",
        "explanation": "Your domain publishes DNSSEC signatures, so resolvers can "
                       "verify your DNS responses have not been tampered with.",
        "fix": "No action needed.",
    },
    # --- HSTS quality -------------------------------------------------------------
    "hsts_short_maxage": {
        "title": "HSTS max-age is short ({max_age} seconds)",
        "explanation": "Your HSTS policy only lasts {max_age} seconds "
                       "({human}). HSTS protects return visitors, but a short window "
                       "means the protection lapses quickly — and browsers require at "
                       "least a year before they will preload your site.",
        "fix": "Raise max-age to 31536000 (one year): "
               "'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    },
    "hsts_no_subdomains": {
        "title": "HSTS does not cover subdomains",
        "explanation": "Your HSTS policy lacks 'includeSubDomains', so it protects only "
                       "the exact domain scanned — not mail., blog., shop. or any other "
                       "subdomain, which attackers could target instead.",
        "fix": "Add includeSubDomains to the header (only after confirming HTTPS works "
               "on every subdomain): 'Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains'.",
    },
    "hsts_preload_status": {
        "title": "HSTS preload status: {status}",
        "explanation": "Your HSTS header {detail} Browsers ship with a built-in list "
                       "of sites that must always use HTTPS — being on it protects "
                       "even first-time visitors.",
        "fix": "{fix}",
    },
    # --- Error page disclosure ----------------------------------------------------
    "error_disclosure": {
        "title": "Error page leaks technical details",
        "explanation": "Requesting a page that does not exist returned a technical "
                       "error message ({evidence}). These messages reveal your "
                       "programming language, frameworks and file paths — a useful "
                       "reconnaissance gift for attackers.",
        "fix": "Turn off detailed error pages in production (debug mode off) and show "
               "visitors a generic error page instead.",
    },
    "error_pages_ok": {
        "title": "Error pages do not leak details",
        "explanation": "Your site's error pages reveal no stack traces or internal "
                       "technical details.",
        "fix": "No action needed.",
    },
    # --- robots.txt ----------------------------------------------------------------
    "robots_sensitive": {
        "title": "robots.txt advertises sensitive paths",
        "explanation": "Your robots.txt tells search engines (and anyone who reads it) "
                       "to stay away from: {paths} Attackers read robots.txt too — it "
                       "works as a map of the parts of your site you consider sensitive.",
        "fix": "Do not rely on robots.txt to hide anything. Protect sensitive areas "
               "with real authentication, and keep the Disallow list to genuinely "
               "public-but-unwanted paths (search pages, print views).",
    },
    "robots_ok": {
        "title": "robots.txt looks fine",
        "explanation": "Your robots.txt does not advertise any sensitive-looking paths.",
        "fix": "No action needed.",
    },
    "robots_missing": {
        "title": "No robots.txt found",
        "explanation": "Your site has no robots.txt file. That is harmless — search "
                       "engines simply crawl everything — but a minimal one is good "
                       "practice.",
        "fix": "Optional: add a small robots.txt allowing normal crawling and pointing "
               "at your sitemap.",
    },
}

# Plain-language "why it matters" blurbs for missing security headers.
HEADER_WHY_FIX = {
    "Strict-Transport-Security": (
        "It forces browsers to always use the secure HTTPS version of your site, "
        "blocking attackers from downgrading visitors to an insecure connection.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your "
        "server configuration (only after confirming HTTPS works everywhere).",
    ),
    "Content-Security-Policy": (
        "It tells browsers which sources of scripts and content are allowed, which is "
        "the main defense against attackers injecting malicious scripts into your pages.",
        "Add a Content-Security-Policy header. Start with a report-only policy to avoid "
        "breaking your site, then enforce it.",
    ),
    "X-Frame-Options": (
        "It stops attackers from loading your site invisibly inside their own pages "
        "(clickjacking), where they can trick your visitors into clicking things.",
        "Send 'X-Frame-Options: SAMEORIGIN' (or use frame-ancestors in your CSP).",
    ),
    "X-Content-Type-Options": (
        "It stops browsers from guessing file types, which blocks a class of attacks "
        "where uploaded files are executed as scripts.",
        "Send 'X-Content-Type-Options: nosniff'.",
    ),
    "Referrer-Policy": (
        "It controls how much of your page address is shared with other sites when "
        "visitors click links, protecting visitor privacy.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' (a safe default).",
    ),
    "Permissions-Policy": (
        "It lets you switch off powerful browser features (camera, microphone, "
        "geolocation) that your site does not need, shrinking what a script "
        "injection attack could abuse.",
        "Send a Permissions-Policy header disabling what you don't use, e.g. "
        "'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
    ),
}
