<div align="center">

```
      ▄▄▄       ██▀███    ▄████  █    ██   ██████ 
     ▒████▄    ▓██ ▒ ██▒ ██▒ ▀█▒ ██  ▓██▒▒██    ▒ 
     ▒██  ▀█▄  ▓██ ░▄█ ▒▒██░▄▄▄░▓██  ▒██░░ ▓██▄   
     ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█  ██▓▓▓█  ░██░  ▒   ██▒
      ▓█   ▓██▒░██▓ ▒██▒░▒▓███▀▒▒▒█████▓ ▒██████▒▒
      ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ░▒   ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░
```

# Argus — Vulnerability Management System

### The all-seeing, self-hosted platform for continuous web & network security assessment.

*Discover your attack surface, scan it automatically, triage every finding, and ship a report — from one dashboard and one CLI.*

<br>

![status](https://img.shields.io/badge/status-stable-brightgreen)
![python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![license](https://img.shields.io/badge/license-MIT-7c3aed)
![cost](https://img.shields.io/badge/cost-%240%20forever-success)
![platform](https://img.shields.io/badge/Kali%20%7C%20Debian%20%7C%20Docker-ready-informational)

<sub>by <b>T4WF1Q</b> · built for authorized security research</sub>

</div>

---

> ### ⚠️ Authorized use only
> Argus is a real offensive-security scanner. Point it **only** at systems you own, a deliberately vulnerable lab (DVWA / OWASP Juice Shop), or assets that are **explicitly in scope of a bug-bounty or VDP program**. A built-in **scope allowlist fails closed** — nothing is scanned unless you authorize it first. Unauthorized scanning may be illegal. See [`LICENSE`](LICENSE).

---

## Overview

Most people run a vulnerability scanner the way you'd use a flashlight — point, click, read the output, forget. Real security posture doesn't work like that. Your attack surface changes every week: a new subdomain goes live, a dependency ships a CVE, someone pushes a misconfigured header. A one-off scan is stale the moment it finishes.

**Argus is built around the opposite idea: set it once, and let it watch forever.** You register a target — a single host, a web app, or an entire bug-bounty program's root domain — and Argus takes it from there. It enumerates the subdomains, probes which ones are alive and what they run, scans each for the OWASP Top 10 and known CVEs, deduplicates the results into a clean finding list, scores the overall risk, alerts you on anything critical, and writes a polished report. On a schedule. Unattended. Every day.

Everything runs on **your** machine — a laptop, a Kali VM, a Raspberry Pi, or a free cloud box. No SaaS, no telemetry, no per-scan pricing. The data never leaves your control, and the whole stack is open source and free.

It is honest about its limits, too. No scanner detects 100% of the OWASP Top 10 — categories like *Insecure Design* and *Logging Failures* need a human. So Argus pairs automated scanning with a built-in **manual review checklist**, giving you a single, truthful picture of coverage instead of a false sense of security.

## Why security researchers like it

- **One source of truth.** Subdomains, live hosts, open ports, findings, triage state and reports — all in one place, not scattered across a dozen tool outputs.
- **Real-time visibility.** A live WebSocket console streams every scan step and pops each new finding onto the dashboard the instant it's discovered.
- **Bug-bounty native.** Give it a root domain; it finds the subdomains, filters them back through your scope rules, and only ever touches what you're authorized to test.
- **Triage that remembers.** Mark a finding *fixed* and Argus re-verifies it on the next scan — if the bug comes back, it reopens automatically. No silent regressions.
- **Terminal-first option.** A clean `Typer` + `Rich` CLI mirrors the whole dashboard, so you can scan, watch live, and pull reports without leaving your shell.
- **Portfolio-grade.** A coherent FastAPI backend, a real automation pipeline, a designed dashboard, and a documented architecture — the kind of project that stands up in an interview.

## Feature highlights

| | |
|---|---|
| 🔎 **Attack-surface discovery** | Subdomain enumeration (`subfinder`) + liveness & tech fingerprinting (`httpx`) |
| 🛡️ **OWASP Top 10 engine** | Findings auto-tagged A01–A10; `nuclei`, `nmap`, and built-in HTTP/TLS checks |
| 📋 **Manual review checklist** | 26 curated checks for the categories scanners can't catch |
| ⚡ **Live dashboard** | Risk score, OWASP heat-grid, real-time console, finding feed, attack-surface map |
| 🧹 **Dedup & triage** | `open → in_progress → fixed → verified`, with auto-reopen on regression |
| ⏰ **Always-on automation** | Daily full scans, change-watch re-scans, daily CVE-template refresh |
| 📄 **Auto reports** | Executive summary, OWASP breakdown, checklist coverage — HTML + PDF |
| 🔔 **Alerts** | Telegram / Discord notifications on new high & critical findings |
| 🔒 **Scope guard** | Allowlist / denylist with wildcard + CIDR support; the safety core |
| 💸 **Zero cost** | 100% free and open source; runs with no external tools at all (adds depth when they're present) |

## Architecture

```
          ┌──────────────┐        REST + WebSocket        ┌───────────────────────┐
   CLI ──▶ │   FastAPI    │ ◀───────────────────────────── │   Web dashboard       │
 (Typer)   │  app + API   │                                │  overview · findings  │
           │  + scheduler │                                │  live · checklist     │
           └──────┬───────┘                                └───────────────────────┘
                  │ enqueue                                         ▲
           ┌──────▼───────┐    ┌──────────────────────────┐        │ live events
           │  worker /    │───▶│ scanners                 │────────┘ (WebSocket bus)
           │  pipeline    │    │  http-checks · nuclei ·  │
           └──────┬───────┘    │  nmap · subfinder · httpx│
                  │            └──────────────────────────┘
           ┌──────▼───────┐
           │  SQLite      │   assets · subdomains · scans · findings · checklist · events
           └──────────────┘
```

The pipeline is a linear, observable chain — every stage logs to the database **and** publishes a live event, so the dashboard and CLI both update in real time:

```
RECON ──▶ PROBE ──▶ SCAN ──▶ DEDUP ──▶ SCORE ──▶ ALERT ──▶ REPORT ──▶ (re-verify next run)
```

## OWASP Top 10 coverage

| Category | Automated | Covered by |
|---|:---:|---|
| **A01** Broken Access Control | partial | nuclei · checklist |
| **A02** Cryptographic Failures | ✅ | http-checks (TLS, HSTS) · nuclei |
| **A03** Injection | ✅ | nuclei · checklist |
| **A04** Insecure Design | manual | **checklist** |
| **A05** Security Misconfiguration | ✅ | http-checks (headers) · nmap · nuclei |
| **A06** Vulnerable & Outdated Components | ✅ | nuclei (CVE templates) |
| **A07** Authentication Failures | partial | http-checks (cookies) · nuclei · checklist |
| **A08** Software & Data Integrity | partial | nuclei · checklist |
| **A09** Logging & Monitoring Failures | manual | **checklist** |
| **A10** Server-Side Request Forgery | ✅ | nuclei · checklist |

## Quick start — Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/<your-username>/argus.git
cd argus
./setup.sh            # creates a venv, installs deps, generates your API key
./run.sh              # serves the dashboard on http://127.0.0.1:8000
```

Open **http://127.0.0.1:8000**, paste the API key that `setup.sh` printed, and hit **New Scan**.

### Practise on a legal target

```bash
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# "localhost" is already in the default allowlist — just scan http://localhost:3000
```

### Or run the whole thing in Docker

```bash
export T4WF1Q_API_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
docker compose up --build          # app on 127.0.0.1:8000
docker compose --profile lab up    # also launches Juice Shop on :3000
```

> **Full-depth scanning** is optional. Argus ships with pure-Python HTTP/TLS checks that always produce findings. Install `nmap`, `nuclei`, `httpx`, and `subfinder` on Kali to unlock CVE templates, port scanning, and subdomain discovery — `setup.sh` prints the exact commands.

## Using the dashboard

| View | What it's for |
|---|---|
| **Overview** | Program-wide risk score, OWASP exposure grid, recent scans & findings |
| **Assets** | Every target under assessment, with per-asset risk and scan controls |
| **Findings** | Filterable, deduplicated vulnerability list; click any row to triage |
| **Live Scan** | Real-time console + finding feed as a scan runs |
| **OWASP Checklist** | Manual review tracker, per asset, with pass/fail/n-a states |
| **Reports** | Browse and open every auto-generated report |
| **Scope** | View the allowlist and test whether a target is authorized |

## Using the CLI

```bash
argus login --server http://127.0.0.1:8000 --key <API_KEY>
argus scope check example.com                         # authorized?
argus scan http://localhost:3000 --profile owasp-full
argus scan example.com --kind program --profile recon # bug-bounty subdomain hunt
argus watch                                           # live-tail the scan console
argus findings --severity critical
argus report --asset <asset-id>
```

*(The CLI entry point is `cli/t4wf1q.py`; alias it to `argus` for convenience.)*

**Scan profiles:** `owasp-full` (recon + web + network) · `web` · `recon` · `network` · `quick`.

## Always-on automation

Configured in `config.yaml → automation`:

- **`full_scan_cron_hour`** — a complete scan of every asset, daily.
- **`change_watch_minutes`** — a fast re-probe on an interval to catch new or changed surface.
- **`update_templates_daily`** — refreshes nuclei templates so freshly published CVEs are tested without you lifting a finger.

Every scan ends by writing a report and firing alerts on any new high/critical finding.

## Exposing the dashboard (free)

Keep the server bound to `127.0.0.1` and tunnel it — no open ports, free HTTPS:

```bash
cloudflared tunnel --url http://localhost:8000
```

For a permanent address, pair a free subdomain (DuckDNS) with an *Always Free* cloud VM. Only set `server.host: 0.0.0.0` behind a reverse proxy or tunnel, and always keep a strong `auth.api_key`.

## Scope safety — how Argus stays legal

Every scan request passes through `ScopeGuard` before a single packet is sent. A target is rejected unless it matches an `allow` rule, and always rejected if it matches a `deny` rule. A plain domain in the allowlist authorizes its subdomains too; `*.wildcards` and CIDR ranges are supported. This is precisely what makes unattended automation safe — **do not disable it on hosts you don't control.**

## Project layout

```
t4wf1q/
├── main.py          FastAPI app — REST + WebSocket + dashboard
├── pipeline.py      scan orchestration worker
├── scheduler.py     daily / change-watch automation
├── scope.py         allowlist guard (the safety core)
├── scoring.py       severity, CVSS, risk score, OWASP mapping
├── db.py            SQLite data layer
├── report.py        HTML / PDF report generator
├── checklist.py     OWASP manual-review catalog
├── alerts.py        Telegram / Discord delivery
├── scanners/        http-checks · nuclei · nmap · recon (subfinder + httpx)
├── templates/       report.html.j2
└── static/          dashboard — index.html · app.js · style.css
cli/t4wf1q.py        Typer + Rich command-line interface
```

## Roadmap

- [ ] OWASP ZAP active-scan, `testssl.sh`, and Trivy / Semgrep integrations (wrapper scaffolding is ready)
- [ ] Per-technology nuclei template profiles
- [ ] One-click export to Jira / GitHub issues
- [ ] Multi-user roles and shared programs

## License & disclaimer

Released under the [MIT License](LICENSE). Argus is a tool; how you aim it is your responsibility. The authors accept no liability for misuse. Findings are machine-generated and should be manually validated before disclosure.

<div align="center">
<br>
<sub><b>Argus</b> · an all-seeing vulnerability management system · crafted by <b>T4WF1Q</b></sub>
</div>
