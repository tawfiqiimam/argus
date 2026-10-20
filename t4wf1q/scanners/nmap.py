"""Nmap wrapper — port/service discovery with light vuln hints."""
from __future__ import annotations

import re

from .base import Finding, ScanContext, run, tool_available

RISKY_PORTS = {
    21: ("FTP exposed", "medium", "A05"),
    23: ("Telnet exposed (cleartext)", "high", "A02"),
    139: ("SMB/NetBIOS exposed", "medium", "A05"),
    445: ("SMB exposed", "high", "A05"),
    3389: ("RDP exposed", "high", "A05"),
    3306: ("MySQL exposed to network", "medium", "A05"),
    5432: ("PostgreSQL exposed to network", "medium", "A05"),
    6379: ("Redis exposed (often unauthenticated)", "high", "A05"),
    27017: ("MongoDB exposed", "high", "A05"),
    9200: ("Elasticsearch exposed", "high", "A05"),
}

_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$")


def scan(ctx: ScanContext, hosts: list[str]) -> list[Finding]:
    cfg = ctx.scanners_cfg
    bin_ = cfg.get("nmap", "nmap")
    findings: list[Finding] = []
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "nmap not installed — skipping port scan")
        return findings

    top = str(cfg.get("nmap_top_ports", 1000))
    for host in hosts:
        ctx.log("info", f"nmap: scanning top {top} ports on {host}")
        code, out, err = run([bin_, "-T4", "-sV", "--top-ports", top, host], timeout=900)
        if code not in (0, 124):
            ctx.log("warn", f"nmap error on {host}: {err.strip()[:120]}")
            continue
        open_ports = []
        for line in out.splitlines():
            m = _PORT_RE.match(line.strip())
            if not m:
                continue
            port = int(m.group(1))
            service = m.group(3)
            version = (m.group(4) or "").strip()
            open_ports.append(f"{port}/{service}")
            if port in RISKY_PORTS:
                title, sev, owasp = RISKY_PORTS[port]
                findings.append(Finding(
                    title=f"{title} on {host}:{port}",
                    severity=sev, owasp=owasp, host=host, location=f"{host}:{port}",
                    source="nmap",
                    description=f"Service '{service} {version}' reachable on port {port}.",
                    evidence=line.strip(),
                    remediation="Restrict the port with a firewall/ACL or require authentication/VPN.",
                ))
        if open_ports:
            ctx.log("info", f"nmap {host}: open -> {', '.join(open_ports)}")
    ctx.log("info", f"nmap: {len(findings)} notable exposure(s)")
    return findings
