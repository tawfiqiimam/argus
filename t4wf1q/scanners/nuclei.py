"""Nuclei wrapper — the primary web/CVE/misconfig scanner."""
from __future__ import annotations

import json
import subprocess

from .base import Finding, ScanContext, tool_available
from ..scoring import normalize_severity, guess_owasp


def scan(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    cfg = ctx.scanners_cfg
    bin_ = cfg.get("nuclei", "nuclei")
    findings: list[Finding] = []

    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "nuclei not installed — skipping template scan "
                        "(install: go install .../nuclei@latest && nuclei -update-templates)")
        return findings

    rate = str(cfg.get("nuclei_rate_limit", 150))
    ctx.log("info", f"nuclei: scanning {len(urls)} target(s) @ rate {rate}")
    stdin = "\n".join(urls)
    try:
        p = subprocess.run(
            [bin_, "-silent", "-jsonl", "-rate-limit", rate,
             "-severity", "low,medium,high,critical"],
            input=stdin, capture_output=True, text=True, timeout=1800, check=False,
        )
    except Exception as e:  # pragma: no cover
        ctx.log("warn", f"nuclei failed: {e}")
        return findings

    for line in p.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        info = j.get("info", {})
        name = info.get("name") or j.get("template-id", "nuclei finding")
        sev = normalize_severity(info.get("severity"))
        classif = info.get("classification") or {}
        cvss = classif.get("cvss-score")
        tags = " ".join(info.get("tags", []) if isinstance(info.get("tags"), list) else [str(info.get("tags"))])
        findings.append(Finding(
            title=name,
            severity=sev,
            cvss=float(cvss) if cvss else None,
            owasp=guess_owasp(name, tags, j.get("template-id", "")),
            host=j.get("host"),
            location=j.get("matched-at") or j.get("matched") or j.get("host"),
            source="nuclei",
            description=info.get("description"),
            evidence=(j.get("extracted-results") and ", ".join(map(str, j["extracted-results"])))
                     or j.get("matcher-name"),
            remediation=info.get("remediation"),
            reference=info.get("reference") or [],
        ))

    ctx.log("info", f"nuclei: {len(findings)} finding(s)")
    return findings
