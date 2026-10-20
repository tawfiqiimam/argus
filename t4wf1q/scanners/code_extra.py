"""Source-code / dependency / secrets adapters: gitleaks, trivy, semgrep.

These run against a local path (a cloned repo or a directory) referenced by the
asset target. They degrade gracefully when the tool isn't installed.
"""
from __future__ import annotations

import json
import os

from .base import Finding, ScanContext, run, tool_available
from ..scoring import normalize_severity


def _local_path(ctx: ScanContext) -> str | None:
    target = ctx.asset.get("target", "")
    if target.startswith("file://"):
        target = target[7:]
    if os.path.isdir(target):
        return target
    return None


# ---------------------------------------------------------------- gitleaks
def gitleaks(ctx: ScanContext) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("gitleaks", "gitleaks")
    out: list[Finding] = []
    path = _local_path(ctx)
    if not path:
        return out
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "gitleaks not installed — skipping secret detection")
        return out
    ctx.log("info", f"gitleaks: scanning {path}")
    rep = os.path.join(path, ".argus_gitleaks.json")
    run([bin_, "detect", "--source", path, "--report-format", "json",
         "--report-path", rep, "--no-banner", "--exit-code", "0"], timeout=300)
    try:
        with open(rep, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        data = []
    finally:
        try:
            os.unlink(rep)
        except OSError:
            pass
    for h in data if isinstance(data, list) else []:
        out.append(Finding(
            title=f"Exposed secret: {h.get('RuleID', 'secret')}", severity="high",
            owasp="A05", location=f"{h.get('File')}:{h.get('StartLine')}", source="gitleaks",
            description=h.get("Description"),
            evidence="[redacted secret match]", cwe="CWE-798", confidence="high",
            remediation="Revoke the exposed credential and purge it from git history.",
        ))
    ctx.log("info", f"gitleaks: {len(out)} finding(s)")
    return out


# ---------------------------------------------------------------- trivy
def trivy(ctx: ScanContext) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("trivy", "trivy")
    out: list[Finding] = []
    path = _local_path(ctx)
    if not path:
        return out
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "trivy not installed — skipping dependency scan")
        return out
    ctx.log("info", f"trivy: scanning {path}")
    code, so, se = run([bin_, "fs", "--quiet", "--format", "json", "--scanners",
                        "vuln,secret,misconfig", path], timeout=400)
    try:
        data = json.loads(so)
    except ValueError:
        return out
    for res in data.get("Results", []) or []:
        loc = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(Finding(
                title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('VulnerabilityID')}"[:140],
                severity=normalize_severity(v.get("Severity")), owasp="A06",
                location=loc, source="trivy", description=v.get("Title") or v.get("Description"),
                cve=v.get("VulnerabilityID") if str(v.get("VulnerabilityID", "")).startswith("CVE") else None,
                cvss=_trivy_cvss(v), confidence="high",
                remediation=f"Upgrade to {v.get('FixedVersion')}" if v.get("FixedVersion") else "Upgrade the affected package.",
                reference=[v.get("PrimaryURL")] if v.get("PrimaryURL") else [],
            ))
        for m in res.get("Misconfigurations", []) or []:
            out.append(Finding(
                title=f"Misconfig: {m.get('Title')}"[:140],
                severity=normalize_severity(m.get("Severity")), owasp="A05",
                location=loc, source="trivy", description=m.get("Description"),
                confidence="medium", remediation=m.get("Resolution"),
            ))
    ctx.log("info", f"trivy: {len(out)} finding(s)")
    return out


def _trivy_cvss(v: dict) -> float | None:
    cvss = v.get("CVSS") or {}
    for vendor in cvss.values():
        for k in ("V3Score", "V2Score"):
            if vendor.get(k):
                return float(vendor[k])
    return None


# ---------------------------------------------------------------- semgrep
def semgrep(ctx: ScanContext) -> list[Finding]:
    bin_ = ctx.scanners_cfg.get("semgrep", "semgrep")
    out: list[Finding] = []
    path = _local_path(ctx)
    if not path:
        return out
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "semgrep not installed — skipping SAST")
        return out
    ctx.log("info", f"semgrep: scanning {path}")
    code, so, se = run([bin_, "--config", "auto", "--json", "--quiet", path], timeout=600)
    try:
        data = json.loads(so)
    except ValueError:
        return out
    _sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for r in data.get("results", []) or []:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)
        out.append(Finding(
            title=r.get("check_id", "code finding").split(".")[-1][:120],
            severity=_sev.get(str(extra.get("severity", "")).upper(), "low"),
            owasp="A03", location=f"{r.get('path')}:{r.get('start', {}).get('line')}",
            source="semgrep", description=extra.get("message"),
            cwe=cwe, confidence="medium",
            remediation="Review and fix the flagged code pattern.",
            reference=[meta.get("source")] if meta.get("source") else [],
        ))
    ctx.log("info", f"semgrep: {len(out)} finding(s)")
    return out
