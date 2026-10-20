"""Web-app scanner adapters: nikto, testssl.sh, wpscan, dalfox.

Each runs the real tool when present and degrades gracefully (a scan event,
never a crash) when it isn't. Outputs are parsed into the common Finding
schema with OWASP tagging, CVSS/CVE where available, and a confidence level.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from urllib.parse import urlparse

from .base import Finding, ScanContext, run, tool_available
from ..scoring import normalize_severity, guess_owasp

# ---------------------------------------------------------------- nikto
_NIKTO_SKIP = ("server:", "target ip", "target hostname", "target port",
               "start time", "end time", "host(s) tested", "retrieved",
               "scan terminated", "requests:")


def nikto(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("nikto", "nikto")
    out: list[Finding] = []
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "nikto not installed — skipping web-server checks")
        return out
    for url in urls:
        host = urlparse(url).hostname
        ctx.log("info", f"nikto: scanning {url}")
        code, so, se = run([bin_, "-host", url, "-nointeractive", "-ask", "no", "-maxtime", "120s"], timeout=240)
        for line in so.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            msg = line[2:].strip()
            low = msg.lower()
            if any(s in low for s in _NIKTO_SKIP) or not msg:
                continue
            sev = "medium" if ("osvdb" in low or "cve" in low or "vulnerab" in low) else "low"
            out.append(Finding(
                title=msg[:120], severity=sev, owasp=guess_owasp(msg),
                host=host, location=url, source="nikto",
                description=msg, confidence="medium",
                remediation="Review the flagged item and harden the web server configuration.",
            ))
    ctx.log("info", f"nikto: {len(out)} finding(s)")
    return out


# ---------------------------------------------------------------- testssl.sh
_TESTSSL_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                "LOW": "low", "WARN": "low"}


def testssl(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("testssl", "testssl.sh")
    out: list[Finding] = []
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "testssl.sh not installed — skipping TLS assessment")
        return out
    https = [u for u in urls if u.startswith("https://")]
    for url in https:
        host = urlparse(url).hostname
        ctx.log("info", f"testssl: assessing TLS on {host}")
        fd, path = tempfile.mkstemp(suffix=".json", prefix="argus_testssl_")
        os.close(fd)
        try:
            run([bin_, "--quiet", "--color", "0", "--severity", "LOW",
                 "--jsonfile", path, url], timeout=300)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            ctx.log("warn", f"testssl parse failed for {host}: {e}")
            data = []
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        entries = data if isinstance(data, list) else data.get("scanResult", [])
        for e in entries if isinstance(entries, list) else []:
            sev = _TESTSSL_SEV.get(str(e.get("severity", "")).upper())
            if not sev:
                continue
            out.append(Finding(
                title=f"TLS: {e.get('id', 'issue')}", severity=sev, owasp="A02",
                host=host, location=f"{host}:443", source="testssl",
                description=e.get("finding"), confidence="high",
                cve=(", ".join(e.get("cve", "").split()) or None) if e.get("cve") else None,
                remediation="Disable weak protocols/ciphers; use a modern TLS configuration.",
            ))
    ctx.log("info", f"testssl: {len(out)} finding(s)")
    return out


# ---------------------------------------------------------------- wpscan
def wpscan(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("wpscan", "wpscan")
    out: list[Finding] = []
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "wpscan not installed — skipping WordPress checks")
        return out
    for url in urls:
        host = urlparse(url).hostname
        ctx.log("info", f"wpscan: {url}")
        code, so, se = run([bin_, "--url", url, "--format", "json", "--no-banner",
                            "--random-user-agent"], timeout=400)
        try:
            data = json.loads(so)
        except ValueError:
            continue
        for slug, info in (data.get("plugins") or {}).items():
            for v in info.get("vulnerabilities", []) or []:
                refs = v.get("references", {}) or {}
                cve = ", ".join(f"CVE-{c}" for c in refs.get("cve", [])) or None
                out.append(Finding(
                    title=f"WordPress plugin '{slug}': {v.get('title', 'vulnerability')}"[:140],
                    severity="high", owasp="A06", host=host, location=url, source="wpscan",
                    description=v.get("title"), cve=cve, confidence="high",
                    remediation="Update or remove the affected WordPress plugin/theme.",
                ))
        iv = (data.get("version") or {}).get("vulnerabilities", []) or []
        for v in iv:
            out.append(Finding(
                title=f"WordPress core: {v.get('title', 'vulnerability')}"[:140],
                severity="high", owasp="A06", host=host, location=url, source="wpscan",
                description=v.get("title"), confidence="high",
                remediation="Update WordPress core to a patched version.",
            ))
    ctx.log("info", f"wpscan: {len(out)} finding(s)")
    return out


# ---------------------------------------------------------------- dalfox (XSS)
def dalfox(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("dalfox", "dalfox")
    out: list[Finding] = []
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "dalfox not installed — skipping XSS testing")
        return out
    # Only test URLs that carry query parameters.
    targets = [u for u in urls if "?" in u and "=" in u]
    if not targets:
        ctx.log("info", "dalfox: no parameterized URLs to test")
        return out
    for url in targets:
        host = urlparse(url).hostname
        ctx.log("info", f"dalfox: testing {url}")
        code, so, se = run([bin_, "url", url, "--format", "json", "--silence",
                            "--no-spinner"], timeout=180)
        try:
            data = json.loads(so) if so.strip() else []
        except ValueError:
            data = []
        for poc in data if isinstance(data, list) else []:
            out.append(Finding(
                title="Cross-Site Scripting (XSS)", severity="high", owasp="A03",
                host=host, location=poc.get("data") or url, source="dalfox",
                description=f"XSS confirmed via parameter '{poc.get('param', '?')}'.",
                evidence=(poc.get("data") or "")[:200], cwe="CWE-79", confidence="high",
                remediation="Context-encode output and validate input; apply a strict CSP.",
            ))
    ctx.log("info", f"dalfox: {len(out)} finding(s)")
    return out
