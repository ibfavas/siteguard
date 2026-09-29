# SiteGuard — website security monitoring for small businesses

A minimal, honest website security scanner. Add a client's domain, get a
plain-language security report (SSL, headers, exposed admin pages, WordPress
version, email DNS, change detection), and have it re-scan automatically every
week. Built for a one-person VAPT freelancer: zero budget, runs locally.

**Important:** only scan sites you own or have written permission to test.
Probing admin paths on third-party sites without authorization may be illegal.

## Quick start

```bash
cd ~/workspace/siteguard
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

`python app.py` starts both the dashboard and the background scheduler
(re-scans every active site once a week, per `SCAN_INTERVAL_WEEKS` in
`config.py`). The scheduler also starts under production servers
(`gunicorn app:app`) — initialization runs on import.

## How to use

1. **Add a site** — type a domain (e.g. `example.com`) in the "Add a site"
   box and hit *Add & scan*. The first scan starts automatically in the
   background; the site page shows a "Scan in progress" banner and refreshes
   itself when the results land (a full scan takes a couple of minutes).
2. **Scan now** — the *Scan now* button on the dashboard or a site page runs
   an immediate scan. While it runs, the previous finished scan's results
   stay visible underneath the progress banner, clearly labeled.
3. **Read the report** — each site page shows an A–F grade, findings grouped
   by severity (High / Medium / Low / Info), and for every finding a
   plain-language "What this means" plus "How to fix it". Click any older
   entry under *Scan history* to see that scan's full report.
4. **Remove a site** — *Remove* deletes the site and all its scan data.

## What gets checked

| # | Check | What it does |
|---|-------|--------------|
| 1 | SSL certificate | Validity, days to expiry, issuer |
| 2 | Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| 3 | Exposed admin panels | Probes `/wp-admin`, `/admin`, `/login`, `/phpmyadmin`, `/.git/HEAD`, `/.env`, … |
| 4 | WordPress | Detects WP, reads version, compares with wordpress.org latest |
| 5 | Directory listing | Looks for `Index of /` on common paths |
| 6 | Email DNS | SPF, DMARC, DKIM (common selectors) via DNS — plus strength: permissive `+all`/`?all`, `p=none`, missing `rua` |
| 7 | Server banners | Flags version numbers in `Server` / `X-Powered-By` headers |
| 8 | Change detection | Text + DOM-structure fingerprints; adaptive per-site baseline — alerts only when a change exceeds the site's own normal variance (15% floor) |
| 9 | Cookie flags | **Every** cookie checked for missing `HttpOnly` / `Secure` / `SameSite`, named in the finding |
| 10 | CORS | Tests whether the site reflects an untrusted `Origin` with credentials |
| 11 | HTTP methods | Flags risky methods advertised via `OPTIONS` (PUT, DELETE, TRACE, CONNECT) |
| 12 | security.txt | Checks for a `/.well-known/security.txt` contact file (informational) |
| 13 | Mixed content | Parses real `src`/`href`/`srcset` subresources on HTTPS pages (page-text mentions of `http://` never flag) |
| 14 | Sensitive files | Probes backup/config/debug paths (`wp-config.php.bak`, `backup.zip`, `phpinfo.php`, `.DS_Store`, …) with soft-404 filtering |
| 15 | JS libraries | Detects outdated jQuery / Bootstrap / AngularJS / Lodash / Moment via URL versions **and** SHA-256 content fingerprints of the actual release files |
| 16 | Subdomain takeover | Finds subdomains (certificate transparency) pointing at dead/unclaimed services |
| 17 | Zone transfer | Attempts DNS AXFR — HIGH only if it actually succeeds |

**Uptime monitoring** runs separately from the weekly full scan: every 30 minutes
(`UPTIME_INTERVAL_MINUTES`) each active site gets a lightweight reachability
probe. Results go to the `uptime_checks` table; the dashboard shows the latest
status and the last-24h uptime %. An alert is sent only after **2 consecutive**
failures, so one flapping probe doesn't spam anyone.

If a check **cannot run** (network blocked, DNS down, site unreachable), it is
recorded as *"Check could not run"* — never as clean. No results are invented.

## Configuration (`config.py`)

Every setting below can also be set via an **environment variable**
(useful on hosted platforms — no code edits needed):

| Setting | Env var | Default |
|---|---|---|
| `SCAN_INTERVAL_WEEKS` | `SITEGUARD_SCAN_INTERVAL_WEEKS` | `1` |
| `UPTIME_INTERVAL_MINUTES` | `SITEGUARD_UPTIME_INTERVAL_MINUTES` | `30` |
| `REQUEST_TIMEOUT` | `SITEGUARD_REQUEST_TIMEOUT` | `15` |
| `SECRET_KEY` | `SITEGUARD_SECRET_KEY` | `change-me…` |
| `HOST` / `PORT` | `SITEGUARD_HOST` / `PORT` | `127.0.0.1` / `5000` |
| `SMTP_ENABLED` … | `SITEGUARD_SMTP_ENABLED` … | off / empty |
| `WHATSAPP_*` | `SITEGUARD_WHATSAPP_*` | off / empty |

- **Email alerts**: set `SITEGUARD_SMTP_ENABLED=true` and fill in
  `SITEGUARD_SMTP_HOST`, `SITEGUARD_SMTP_PORT`, `SITEGUARD_SMTP_USER`,
  `SITEGUARD_SMTP_PASSWORD`, `SITEGUARD_ALERT_EMAIL_TO`. When a scan finds
  *new* high-severity findings, an email is attempted; if sending fails (or
  SMTP is unconfigured) it is skipped gracefully and logged — scanning never
  breaks because of email.
- **WhatsApp alerts**: `alerts/whatsapp.py` is a clearly-marked **stub**.
  The `send_whatsapp_alert()` function only logs until the WhatsApp Business
  API integration is implemented (TODO in the module docstring).

## Deploying (free hosting)

SiteGuard is fully automatic as long as it keeps running — the scheduler
re-scans every site on schedule with zero clicks. Your laptop sleeping
pauses it, so for real hands-off operation, host it:

### Render (free tier, ~5 minutes)

1. Push this folder to a GitHub repo.
2. In Render: **New → Blueprint** and point it at the repo
   (`render.yaml` is included), or **New → Web Service** manually with:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app --workers 1 --timeout 120 --bind 0.0.0.0:$PORT`
3. Set any `SITEGUARD_*` env vars you need in Render's dashboard
   (a random `SITEGUARD_SECRET_KEY` is auto-generated by the blueprint;
   Render injects `PORT` itself).

⚠️ **Free-tier caveat:** Render's free disks are ephemeral — the SQLite
database (sites + scan history) resets when the service restarts. Fine for
the MVP and demos; once you have paying customers, attach a persistent disk
or move the storage to PostgreSQL.

Alternatives with free tiers: PythonAnywhere, Railway, or Oracle Cloud's
always-free VM (persistent disk included).

## Open source

SiteGuard is MIT-licensed (see `LICENSE`) — the scanner and dashboard are
public, and that's a feature: transparency builds trust for a security
tool, and the repo doubles as portfolio work.

The business is **not** the code — it's the hosted monitoring, the alerts,
and your expert review. A shop owner will never self-host a Flask app;
they pay for someone watching their site and explaining fixes in plain
language.

Rules for the public repo:
- Never commit real secrets — use env vars (`.env` is git-ignored).
- Never commit customer data — `data/` is git-ignored; the demo database
  stays local.

## Project layout

```
siteguard/
├── app.py                  # Flask app, routes, scheduler startup
├── config.py               # all settings (scan cadence, SMTP, alerts)
├── db.py                   # SQLite storage (sites, scans, findings, state)
├── requirements.txt
├── scanner/
│   ├── engine.py           # orchestrates the 8 checks per domain
│   ├── checks.py           # the checks themselves
│   └── strings.py          # ALL user-facing text (English; add Malayalam here later)
├── alerts/
│   ├── email_alerts.py     # SMTP alerts, graceful when unconfigured
│   └── whatsapp.py         # STUB — TODO: WhatsApp Business API
├── templates/              # dashboard.html, site.html, scan.html, base.html
├── static/style.css        # vanilla CSS, no frameworks
└── data/siteguard.db       # created on first run (git-ignored)
```

## Data & honesty notes

- The SQLite database lives in `data/` (created automatically, git-ignored).
- Grades: start at 100, −25 per high, −10 per medium, −3 per low finding;
  A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F. "Check could not run" findings are
  informational and don't affect the grade.
- Change detection stores a text hash **and** a DOM-structure fingerprint of the
  homepage, plus the site's recent change history (up to 5 scans). A scan raises
  a medium finding only when the text or structure change exceeds the site's own
  learned normal variance (1.5× its largest previous change, 15% floor); smaller
  changes are informational. The first scan only records the baseline.

## Troubleshooting

- **Port 5000 in use**: change `PORT` in `config.py`.
- **Slow first scan**: each check has a 15s timeout; a full scan of a slow
  site can take ~1–2 minutes. Scans run in background threads — the UI stays
  responsive.
- **DNS checks fail locally**: the email-DNS check needs outbound UDP/53.
  If your network blocks it, those findings will honestly say "check could
  not run".
