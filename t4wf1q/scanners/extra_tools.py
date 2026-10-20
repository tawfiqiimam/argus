"""Adapters for the remaining spec tools: Amass, OWASP ZAP (baseline),
OWASP Dependency-Check and SQLMap.

Safety defaults:
- ZAP runs the BASELINE scan (passive rules + short spider), never the active scanner.
- SQLMap runs only when the asset has an explicit `allow_intrusive` flag, uses
  level 1 / risk 1 / techniques BEU, extracts no data, and tests at most 3 URLs.
- Every tool runs with an argument list (no shell), a timeout, and a private temp dir.
Parsers are pure functions so they can be unit-tested without the tools installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from urllib.parse import urlparse

from ..scoring import guess_owasp, normalize_severity
from .base import Finding, ScanContext, run, tool_available
from .code_extra import _local_path

_TAG = re.compile(r"<[^>]+>")


def _text(s) -> str:
    return _TAG.sub("", str(s or "")).strip()


# ---------------------------------------------------------------- Amass (passive)
def amass_enum(ctx: ScanContext, root: str) -> list[str]:
    bin_ = ctx.scanners_cfg.get("amass", "amass")
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "amass not installed — skipping passive enumeration")
        return []
    ctx.log("info", f"amass: passive enumeration of {root}")
    _, out, _ = run([bin_, "enum", "-passive", "-silent", "-d", root], timeout=600)
    hosts = sorted({
        h for h in (line.strip().lower().rstrip(".") for line in out.splitlines())
        if h and (h == root or h.endswith("." + root))
    })
    ctx.log("info", f"amass: {len(hosts)} host(s)")
    return hosts


# ---------------------------------------------------------------- OWASP ZAP baseline
_ZAP_SEV = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_ZAP_CONF = {"3": "high", "2": "medium"}


def parse_zap(data: dict, fallback_host: str | None, fallback_url: str) -> list[Finding]:
    out: list[Finding] = []
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            if str(a.get("confidence", "")) == "0":   # ZAP's own "false positive" marker
                continue
            risk = str(a.get("riskcode", "0"))
            cweid = str(a.get("cweid", "") or "")
            cwe = f"CWE-{cweid}" if cweid.isdigit() and cweid != "0" else None
            instances = [i for i in (a.get("instances") or []) if isinstance(i, dict)]
            uri = (instances[0].get("uri") if instances else None) or fallback_url
            title = _text(a.get("name") or a.get("alert") or "ZAP alert")
            out.append(Finding(
                title=f"ZAP: {title}"[:140],
                severity=_ZAP_SEV.get(risk, "info"),
                owasp=guess_owasp(title, _text(a.get("desc"))),
                host=urlparse(uri).hostname or fallback_host,
                location=uri,
                source="zap",
                cwe=cwe,
                description=_text(a.get("desc"))[:1500],
                evidence=f"{len(instances)} instance(s) flagged by ZAP baseline",
                remediation=_text(a.get("solution"))[:1000] or "Review the ZAP alert and apply the recommended fix.",
                confidence=_ZAP_CONF.get(str(a.get("confidence", "")), "low"),
            ))
    return out


def _zap_bin(ctx: ScanContext) -> str | None:
    name = ctx.scanners_cfg.get("zap_baseline", "zap-baseline.py")
    if tool_available(name):
        return name
    for p in ("/usr/share/zaproxy/zap-baseline.py", "/usr/share/zaproxy/zap-baseline"):
        if os.path.exists(p):
            return p
    return None


def zap_baseline(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    bin_ = _zap_bin(ctx)
    if not bin_:
        ctx.log("warn", "zap-baseline not found — skipping OWASP ZAP (sudo apt install zaproxy)")
        return []
    out: list[Finding] = []
    for url in urls[:3]:
        host = urlparse(url).hostname
        tmp = tempfile.mkdtemp(prefix="argus_zap_")
        rep = os.path.join(tmp, "zap.json")
        ctx.log("info", f"zap: baseline (passive rules + short spider) on {host}")
        try:
            run([bin_, "-t", url, "-J", rep, "-m", "2", "-I"], timeout=900)
            with open(rep, encoding="utf-8") as fh:
                out += parse_zap(json.load(fh), host, url)
        except (OSError, ValueError) as e:
            ctx.log("warn", f"zap: no usable report for {host} ({type(e).__name__})")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    ctx.log("info", f"zap: {len(out)} finding(s)")
    return out


# ---------------------------------------------------------------- OWASP Dependency-Check
def parse_depcheck(data: dict) -> list[Finding]:
    out: list[Finding] = []
    for dep in data.get("dependencies", []) or []:
        fname = dep.get("fileName") or dep.get("filePath") or "dependency"
        for v in dep.get("vulnerabilities", []) or []:
            name = str(v.get("name", "vulnerability"))
            score = (v.get("cvssv3") or {}).get("baseScore") or (v.get("cvssv2") or {}).get("score")
            cwes = [str(c) for c in (v.get("cwes") or [])]
            out.append(Finding(
                title=f"{fname}: {name}"[:140],
                severity=normalize_severity(v.get("severity")),
                cvss=float(score) if score else None,
                owasp="A06",
                location=fname,
                source="dependency-check",
                cve=name if name.startswith("CVE-") else None,
                cwe=", ".join(cwes) or None,
                description=_text(v.get("description"))[:1500],
                evidence=f"vulnerable component: {fname}",
                remediation="Upgrade the affected component to a patched version.",
                confidence="high",
            ))
    return out


def dependency_check(ctx: ScanContext) -> list[Finding]:
    path = _local_path(ctx)
    if not path:
        return []
    bin_ = ctx.scanners_cfg.get("dependency_check", "dependency-check")
    if not tool_available(bin_):
        ctx.log("warn", "dependency-check not installed — skipping (OWASP Dependency-Check)")
        return []
    tmp = tempfile.mkdtemp(prefix="argus_depcheck_")
    cmd = [bin_, "--project", "argus-scan", "--scan", path, "--format", "JSON", "--out", tmp]
    if ctx.scanners_cfg.get("depcheck_noupdate"):
        cmd.append("--noupdate")
    ctx.log("info", f"dependency-check: scanning {path}")
    try:
        run(cmd, timeout=1800)
        with open(os.path.join(tmp, "dependency-check-report.json"), encoding="utf-8") as fh:
            findings = parse_depcheck(json.load(fh))
    except (OSError, ValueError) as e:
        ctx.log("warn", f"dependency-check: no report produced ({type(e).__name__})")
        findings = []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ctx.log("info", f"dependency-check: {len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------- SQLMap (gated)
_SQLI_PARAM = re.compile(r"Parameter: (\S+) \((\w+)\)")


def parse_sqlmap(stdout: str, url: str) -> list[Finding]:
    low = stdout.lower()
    if "is vulnerable" not in low and "identified the following injection point" not in low:
        return []
    params = sorted({p for p, _ in _SQLI_PARAM.findall(stdout)}) or ["unknown"]
    return [Finding(
        title="SQL injection candidate (sqlmap confirmed an injectable parameter)",
        severity="high",
        owasp="A03",
        cwe="CWE-89",
        host=urlparse(url).hostname,
        location=url,
        source="sqlmap",
        description=(f"sqlmap reports injectable parameter(s): {', '.join(params)}. "
                     "Verify manually. No data was extracted."),
        evidence=f"Parameters: {', '.join(params)}",
        remediation="Use parameterized queries or prepared statements and validate input on the server.",
        confidence="high",
    )]


def sqlmap(ctx: ScanContext, urls: list[str], allow_intrusive: bool) -> list[Finding]:
    if not allow_intrusive:
        ctx.log("warn", "sqlmap: skipped, intrusive modules are not enabled for this target")
        return []
    bin_ = ctx.scanners_cfg.get("sqlmap", "sqlmap")
    if not tool_available(bin_):
        ctx.log("warn", "sqlmap not installed — skipping SQL injection checks")
        return []
    out: list[Finding] = []
    for url in [u for u in urls if "?" in u and "=" in u][:3]:
        tmp = tempfile.mkdtemp(prefix="argus_sqlmap_")
        ctx.log("info", f"sqlmap: low-risk check (level 1, risk 1) on {urlparse(url).hostname}")
        try:
            _, so, _ = run([bin_, "-u", url, "--batch", "--level", "1", "--risk", "1",
                            "--technique", "BEU", "--smart", "--timeout", "10", "--retries", "1",
                            "--random-agent", "--disable-coloring", "--flush-session",
                            "--output-dir", tmp], timeout=600)
            out += parse_sqlmap(so, url)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    ctx.log("info", f"sqlmap: {len(out)} finding(s)")
    return out
